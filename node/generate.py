import os
import yaml
from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field

from langchain.chat_models import init_chat_model
from langchain.agents import create_agent

from .utils import NetworkBlueprint
from state import GraphState
from tools.search_vuln_image import search_vulnerability_image
from config import config
from logger import get_logger, set_log_context, log_step, log_error


generate_prompt = """
You are a Network Architect. Design a logical network topology based on the user's request.

## COMPLEXITY LEVELS

- **simple**: < 5 nodes, static routing, linear or star topology.
- **medium**: 5-15 nodes, static routing, multiple layers (e.g., Internet -> Edge -> DMZ -> Internal).
- **complex**: > 15 nodes OR explicit OSPF/BGP requirement. **MUST use FRR/OSPF capable routers.**

## DESIGN RULES

1. **Naming**: Use kebab-case (lowercase with hyphens), NO spaces or underscores.
2. **Subnet Logic**: 
   - Nodes in the same `connected_subnets` list are Layer 2 connected.
   - If a subnet has > 2 nodes, the system will automatically inject a switch. You do NOT need to define switch nodes manually unless explicitly requested.
3. **Routers**: A node is a router if it connects to 2 or more different subnets.
4. **Abstraction**: Do NOT define IP addresses, interface names (eth1), or static routes. The Builder system handles IPAM and routing.

## IMAGE FLAVORS GUIDE

- **Standard**: `kali`, `alpine`, `ubuntu`, `redis`, `nginx`
- **Routing**: `alpine` (for simple/medium), `frr` (for complex/OSPF)
- **Vulnerability**: If the user asks for a CVE, use the search tool. **Put the exact image name found (e.g., "vulfocus/log4j2-...") into the `image_flavor` field.**

## FEW-SHOT EXAMPLES

### Example 1: Simple Lab (2 nodes)
**User Request:**
"Create a simple lab with a Kali attacker and a Redis target on the same network."

**Output:**
```json
{{
  "lab_name": "simple-redis-lab",
  "complexity": "simple",
  "subnets": ["dmz"],
  "nodes": [
    {{
      "name": "attacker",
      "role": "endpoint",
      "image_flavor": "kali",
      "connected_subnets": ["dmz"]
    }},
    {{
      "name": "redis-target",
      "role": "endpoint",
      "image_flavor": "redis",
      "connected_subnets": ["dmz"]
    }}
  ]
}}
```

### Example 2: Medium Lab (5 nodes, 2 isolation zones)
**User Request:**
"I need an MVP pentest lab with 5-8 machines. External Zone has Kali and Edge Router. Internal Zone has Core Router, Log4j target, and Redis."

**Output:**
```json
{{
  "lab_name": "mvp-pentest-lab",
  "complexity": "medium",
  "subnets": ["external", "transit", "internal"],
  "nodes": [
    {{
      "name": "attacker",
      "role": "endpoint",
      "image_flavor": "kali",
      "connected_subnets": ["external"]
    }},
    {{
      "name": "edge-router",
      "role": "router",
      "image_flavor": "alpine",
      "connected_subnets": ["external", "transit"]
    }},
    {{
      "name": "core-router",
      "role": "router",
      "image_flavor": "alpine",
      "connected_subnets": ["transit", "internal"]
    }},
    {{
      "name": "log4j-target",
      "role": "endpoint",
      "image_flavor": "vulfocus/log4j2-rce-2021-12-09:latest",  // <-- Note: Exact image from tool
      "connected_subnets": ["internal"]
    }},
    {{
      "name": "redis-server",
      "role": "endpoint",
      "image_flavor": "redis",
      "connected_subnets": ["internal"]
    }}
  ]
}}
```

### Example 3: Complex Lab (OSPF, multiple routers)
**User Request:**
"Design a complex enterprise network with 3 sites connected via OSPF. HQ has servers, branches have clients"

**Output:**
```json
{{
  "lab_name": "enterprise-ospf-lab",
  "complexity": "complex",
  "subnets": ["hq-lan", "branch-a-lan", "branch-b-lan", "wan-backbone"],
  "nodes": [
    {{
      "name": "hq-router",
      "role": "router",
      "image_flavor": "frr",  // <-- CRITICAL: Use FRR for complex/OSPF
      "connected_subnets": ["hq-lan", "wan-backbone"]
    }},
    {{
      "name": "branch-a-router",
      "role": "router",
      "image_flavor": "frr",
      "connected_subnets": ["branch-a-lan", "wan-backbone"]
    }},
    {{
      "name": "branch-b-router",
      "role": "router",
      "image_flavor": "frr",
      "connected_subnets": ["branch-b-lan", "wan-backbone"]
    }},
    {{
      "name": "hq-server",
      "role": "endpoint",
      "image_flavor": "ubuntu",
      "connected_subnets": ["hq-lan"]
    }},
    {{
      "name": "branch-a-client",
      "role": "endpoint",
      "image_flavor": "alpine",
      "connected_subnets": ["branch-a-lan"]
    }}
  ]
}}
```

### Example 4: Multi-Switch Lab
**User Request:**
"Create a DMZ network with 5 web servers all connected to a single firewall."

**Output:**
```json
{{
  "lab_name": "dmz-cluster-lab",
  "complexity": "medium",
  "subnets": ["dmz"],
  "nodes": [
    {{
      "name": "firewall",
      "role": "router",
      "image_flavor": "alpine",
      "connected_subnets": ["dmz"]
    }},
    {{
      "name": "web-01",
      "role": "endpoint",
      "image_flavor": "nginx",
      "connected_subnets": ["dmz"]
    }},
    {{
      "name": "web-02",
      "role": "endpoint",
      "image_flavor": "nginx",
      "connected_subnets": ["dmz"]
    }},
    {{
      "name": "web-03",
      "role": "endpoint",
      "image_flavor": "nginx",
      "connected_subnets": ["dmz"]
    }}
    // Note: No 'switch' node defined here. The Builder detects 4 nodes in 'dmz' and auto-injects it.
  ]
}}
```


## YOUR TASK

Based on the user's request, design a logical network topology following the schema and examples above.
- Check if the user needs specific vulnerabilities. If so, call search_vulnerability_image first.
- Use the exact image name returned by the tool in the image_flavor field.

"""




def generate(state: GraphState) -> Dict[str, Any]:
    """
    Generate 节点：使用 LLM 生成网络拓扑蓝图。

    Args:
        state: 当前工作流状态

    Returns:
        更新后的状态字典
    """
    logger = get_logger("node.generate")
    set_log_context(stage="generate")

    try:
        model = init_chat_model(
            model_provider="openai",
            model=config.llm_model,
            temperature=0.3,
            base_url=config.base_url,
            api_key=config.api_key
        )

        agent = create_agent(
            model=model,
            system_prompt=generate_prompt,
            tools=[search_vulnerability_image],
            response_format=NetworkBlueprint
        )

        log_step(logger, "Generating network topology", status="start")

        # 调用 LLM
        result = agent.invoke({
            "messages": [{"role": "user", "content": state["user_request"]}]
        })

        # 提取结构化响应
        if "structured_response" in result:
            blueprint = result["structured_response"]
        else:
            raise ValueError(
                f"No structured_response in result. Keys: {list(result.keys())}"
            )

        log_step(
            logger,
            "Blueprint generated",
            status="success",
            complexity=blueprint.complexity,
            nodes=len(blueprint.nodes),
            subnets=len(blueprint.subnets)
        )

        return {"blueprint": blueprint}

    except Exception as e:
        log_error(logger, e, "Failed to generate network topology")
        return {"error_logs": f"Generate failed: {str(e)}"}

if __name__ == "__main__":
    user_request = """
    I need an MVP pentest lab with 5-8 machines.
    It must have 2 layers of network isolation:
    1. External Zone (DMZ): Contains a Kali attacker and an Edge Router.
    2. Internal Zone: Contains a Core Router, a Log4j vulnerable target, and a Redis server.
    
    Requirements:
    - The Attacker connects to Edge Router.
    - Edge Router connects to Core Router.
    - Core Router connects to the Internal Zone.
    - Ensure static routes are configured so the Attacker can reach the Internal Zone via the routers.
    - Configure sysctls for routers.
    - Use 'alpine' for routers and 'kalilinux' for attacker.
    """
