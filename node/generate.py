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
You are a Network Architect. Design a logical network topology based on the user's scenario request.

## SCENARIO TYPES

### Scenario A: Single-Layer Network
- **Structure**: Flat network, all nodes in the same Layer 2 domain
- **Components**: Exactly 1 vulnerability target + N normal endpoints (attacker, servers, etc.)
- **Use Case**: Basic penetration testing, vulnerability research, simple CTF
- **Routing**: Static routing within a single subnet
- **Example**: Kali attacker + Redis vul-target in same network

### Scenario B: Three-Layer Enterprise Network
- **Structure**: Hierarchical three-layer architecture (Edge → Distribution → Core/Access)
- **Components**: All components from Scenario A, distributed across multiple isolated zones
- **Layers**:
  - **Edge Layer**: External-facing, internet simulation, DMZ
  - **Distribution Layer**: Aggregation, routing between zones, transit networks
  - **Core/Access Layer**: Internal networks, production servers, database tier
- **Use Case**: Enterprise pentesting, lateral movement practice, network segmentation testing
- **Routing**: Static routing via multiple routers, cross-zone communication
- **Example**: Internet → Edge Router → [DMZ, Transit] → Core Router → [Internal Zone with servers]

### Scenario C: Firewall-Protected Network (Reserved)
- **Structure**: Based on Scenario A or B, with additional firewall nodes
- **Components**: All components from Scenario A/B + firewall nodes
- **Firewall**: Reserved interface, implementation pending
- **Note**: For now, design the topology as if firewalls will be added later. Mark firewall placement points in the design.

## DESIGN RULES

1. **Naming**: Use kebab-case (lowercase with hyphens), NO spaces or underscores.
2. **Subnet Logic**:
   - Nodes in the same `connected_subnets` list are Layer 2 connected.
   - If a subnet has > 2 nodes, the system will automatically inject a switch. You do NOT need to define switch nodes manually unless explicitly requested.
3. **Routers**: A node is a router if it connects to 2 or more different subnets.
4. **Abstraction**: Do NOT define IP addresses, interface names (eth1), or static routes. The Builder system handles IPAM and routing.

## IMAGE FLAVORS GUIDE

- **Standard**: `kali`, `alpine`, `ubuntu`, `redis`, `nginx`
- **Routing**:  `frr` (for OSPF)
- **Vulnerability (vul-target)**: For Vulhub vulnerability targets, use `role: "vul-target"`.
  - Set `image_flavor: ""` (empty string)
  - Set `container_path` to the Vulhub path returned by the search_vulnerability_image tool
  - Example: `container_path: "/Path/to/vulhub/activemq/CVE-2023-46604"`

## ROLE FIELD GUIDE

- **endpoint**: Standard containers (kali, ubuntu, redis, nginx). Set `image_flavor`, leave `container_path` empty/null.
- **router**: Router nodes. Set `image_flavor` (alpine/frr), leave `container_path` empty/null.
- **vul-target**: External Vulhub containers with vulnerabilities. Call search_vulnerability_image first to get the `container_path`, then set `role: "vul-target"`, `image_flavor: ""`, and `container_path` from the search result.
  - For scenario B/C with multiple vul-targets, call search_vulnerability_image for each target.
  - The location of the vulnerable machine in the topology is determined by its type, role, and runtime_lang.
- **firewall**: Reserved for future firewall nodes. For now, just mark placement points in the design.
## SCENARIO EXAMPLES

### Example 1: Scenario A - Simple Single-Layer Lab
**User Request:**
"Create a Scenario A lab with Kali attacker, Redis CVE-2022-0543 target, and 2 normal servers."

**Output:**
```json
{{
  "lab_name": "redis-simple-lab",
  "scenario": "A",
  "subnets": ["dmz"],
  "nodes": [
    {{
      "name": "attacker",
      "role": "endpoint",
      "image_flavor": "kali",
      "container_path": null,
      "connected_subnets": ["dmz"]
    }},
    {{
      "name": "redis-target",
      "role": "vul-target",
      "image_flavor": "",
      "container_path": "/Path/to/vulhub/redis/CVE-2022-0543",
      "connected_subnets": ["dmz"]
    }},
    {{
      "name": "web-server",
      "role": "endpoint",
      "image_flavor": "nginx",
      "container_path": null,
      "connected_subnets": ["dmz"]
    }},
    {{
      "name": "app-server",
      "role": "endpoint",
      "image_flavor": "ubuntu",
      "container_path": null,
      "connected_subnets": ["dmz"]
    }}
  ]
}}
```
**Components**: 1 vul-target (redis) + 3 normal endpoints (attacker, web-server, app-server)

### Example 2: Scenario B - Three-Layer Enterprise Network
**User Request:**
"Create a Scenario B enterprise lab with Kali attacker in external zone, Log4j Web server in DMZ, and Redis database plus file server in internal zone."

**Output:**
```json
{{
  "lab_name": "enterprise-three-layer-lab",
  "scenario": "B",
  "subnets": ["external", "dmz", "internal"],
  "nodes": [
    {{
      "name": "attacker",
      "role": "endpoint",
      "image_flavor": "kali",
      "container_path": null,
      "connected_subnets": ["external"]
    }},
    {{
      "name": "edge-router",
      "role": "router",
      "image_flavor": "alpine",
      "container_path": null,
      "connected_subnets": ["external", "dmz"]
    }},
    {{
      "name": "core-router",
      "role": "router",
      "image_flavor": "alpine",
      "container_path": null,
      "connected_subnets": ["dmz", "internal"]
    }},
    {{
      "name": "log4j-target",
      "role": "vul-target",
      "image_flavor": "",
      "container_path": "/Path/to/vulhub/log4j/CVE-2021-44228",
      "connected_subnets": ["dmz"]
    }},
    {{
      "name": "redis-server",
      "role": "endpoint",
      "image_flavor": "redis",
      "container_path": null,
      "connected_subnets": ["internal"]
    }},
    {{
      "name": "file-server",
      "role": "endpoint",
      "image_flavor": "ubuntu",
      "container_path": null,
      "connected_subnets": ["internal"]
    }}
  ]
}}
```
**Architecture**: External (attacker) → DMZ (log4j vul-target) → Internal (redis, file-server normal endpoints)
**Components**: 1 vul-target (log4j) + 4 normal endpoints (attacker, redis-server, file-server, 2 routers)

### Example 3: Scenario C - Firewall-Protected Network (Reserved)
**User Request:**
"Create a Scenario C lab with Kali attacker, Nginx and Redis vul-targets in different zones, plus normal application servers."

**Output:**
```json
{{
  "lab_name": "firewall-protected-lab",
  "scenario": "C",
  "subnets": ["external", "dmz", "transit", "internal"],
  "nodes": [
    {{
      "name": "attacker",
      "role": "endpoint",
      "image_flavor": "kali",
      "container_path": null,
      "connected_subnets": ["external"]
    }},
    {{
      "name": "edge-router",
      "role": "router",
      "image_flavor": "alpine",
      "container_path": null,
      "connected_subnets": ["external", "dmz"]
    }},
    {{
      "name": "dmz-router",
      "role": "router",
      "image_flavor": "alpine",
      "container_path": null,
      "connected_subnets": ["dmz", "transit"]
    }},
    {{
      "name": "core-router",
      "role": "router",
      "image_flavor": "alpine",
      "container_path": null,
      "connected_subnets": ["transit", "internal"]
    }},
    {{
      "name": "web-target",
      "role": "vul-target",
      "image_flavor": "",
      "container_path": "/Path/to/vulhub/nginx/CVE-2013-2028",
      "connected_subnets": ["dmz"]
    }},
    {{
      "name": "app-server",
      "role": "endpoint",
      "image_flavor": "ubuntu",
      "container_path": null,
      "connected_subnets": ["dmz"]
    }},
    {{
      "name": "db-target",
      "role": "vul-target",
      "image_flavor": "",
      "container_path": "/Path/to/vulhub/redis/CVE-2022-0543",
      "connected_subnets": ["internal"]
    }},
    {{
      "name": "file-server",
      "role": "endpoint",
      "image_flavor": "alpine",
      "container_path": null,
      "connected_subnets": ["internal"]
    }}
  ]
}}
```
**Note**: Firewall nodes are reserved for future implementation. The topology design should include appropriate placement points (e.g., between external-dmz, dmz-transit, transit-internal).
**Components**: 2 vul-targets (nginx, redis) + 5 normal endpoints (attacker, app-server, file-server, 3 routers)

## YOUR TASK

Based on the user's request, design a logical network topology following the scenario type (A/B/C).
- Identify the scenario type from the user's request
- Call search_vulnerability_image first if vulnerability targets are needed
- Use the exact image name returned by the tool in the image_flavor field
- For Scenario C, design the topology with firewall placement points in mind

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
            scenario=blueprint.scenario,
            nodes=len(blueprint.nodes),
            subnets=len(blueprint.subnets)
        )

        return {"blueprint": blueprint}

    except Exception as e:
        log_error(logger, e, "Failed to generate network topology")
        return {"error_logs": f"Generate failed: {str(e)}"}

if __name__ == "__main__":
    user_request = """
    创建一个场景A的简单渗透测试实验室：
    - 1 个 Kali Linux 作为攻击机
    - 1 个 Redis 服务器作为靶机,包含CVE-2022-0543漏洞
    - 1 个 Alpine 路由器连接它们
    """

    # 测试代码
    from state import initial_state
    state = initial_state()
    state["user_request"] = user_request
    result = generate(state)

    if "blueprint" in result:
        blueprint = result["blueprint"]
        print(f"Lab Name: {blueprint.lab_name}")
        print(f"Scenario: {blueprint.scenario}")
        print(f"Subnets: {blueprint.subnets}")
        print(f"Nodes: {len(blueprint.nodes)}")
        for node in blueprint.nodes:
            print(f"  - {node.name}: {node.role} ({node.image_flavor})")
    else:
        print(f"Error: {result.get('error_logs')}")
