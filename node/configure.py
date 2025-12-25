import json
import yaml
from typing import Dict, Any, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from langchain.agents import create_agent
from langchain.chat_models import init_chat_model

from state import GraphState
from containerlab_tools import node_config_tool
from config import LLM_MODEL, BASE_URL, API_KEY


configure_prompt = """
You are a Network Configuration Specialist working inside containerlab containers.

Your task is to verify and fix network configuration for a single node.

CONFIGURATION CHECKLIST:
1. Check if IP tools are installed (iproute2, iputils-ping, net-tools)
2. Verify each interface has the correct IP address configured
3. Verify the default route is configured
4. Verify interfaces are UP
5. Test connectivity with ping if needed

DIAGNOSIS COMMANDS:
- Check interfaces: "ip addr show" or "ip a"
- Check routes: "ip route show" or "ip r"
- Check tools: "which ip", "which ping"

FIX COMMANDS:
- Install tools (Alpine): "apk add --no-cache iproute2 iputils-ping net-tools"
- Install tools (Debian/Ubuntu/Kali): "apt-get update && apt-get install -y iproute2 iputils-ping net-tools"
- Configure IP: "ip addr add <ip>/<mask> dev <interface>"
- Bring up interface: "ip link set <interface> up"
- Set default route: "ip route replace default via <gateway_ip>"

VERIFICATION:
After applying fixes, always verify by running "ip addr show" to confirm.

Report your findings clearly:
- ✅ PASS if all checks succeed
- ❌ FAIL if issues persist
- Return detailed logs of what you checked and fixed.
"""


def configure(state: GraphState):
    """
    Configure ALL nodes in parallel using ThreadPoolExecutor.

    Process:
    1. Parse inspect_data to get all containers
    2. Read YAML file to get expected configurations and network topology
    3. Configure all nodes in parallel (each node gets its own agent)
    4. Aggregate results and update state

    State updates:
    - is_complete=True after all nodes processed
    - Single-pass, no iteration needed
    """
    inspect_data = state.get("inspect_data", {})
    yaml_path = state.get("yaml_path")

    # Parse nodes from inspect data
    containers = []
    lab_name = ""
    for lab, nodes in inspect_data.items():
        lab_name = lab
        if isinstance(nodes, list):
            containers.extend(nodes)

    if not containers:
        print("⚠️ No containers found in inspect_data")
        return {"is_complete": True}

    # Read YAML file to get expected configuration and network topology
    yaml_content = {}
    nodes_config = {}
    links = []
    if yaml_path:
        try:
            with open(yaml_path, 'r', encoding='utf-8') as f:
                yaml_content = yaml.safe_load(f) or {}
            topology = yaml_content.get("topology", {})
            nodes_config = topology.get("nodes", {})
            links = topology.get("links", [])
        except Exception as e:
            print(f"⚠️ Failed to read YAML file {yaml_path}: {e}")

    print(f"\n🔧 [Stage 2] Configuring {len(containers)} nodes in parallel...")

    # Prepare configuration tasks for all nodes
    config_tasks = []

    for container in containers:
        container_name = container.get("name", "")
        # Extract short node name: clab-simple-router-lab-attacker -> attacker
        node_short_name = container_name.replace(f"clab-{lab_name}-", "")

        # Get expected config from YAML
        expected_config = nodes_config.get(node_short_name, {})
        exec_commands = expected_config.get("exec", [])

        config_tasks.append({
            "container": container,
            "container_name": container_name,
            "node_short_name": node_short_name,
            "exec_commands": exec_commands
        })

    # Configure all nodes in parallel
    results = _configure_nodes_parallel(config_tasks)

    # Print summary
    success_count = sum(1 for r in results if r["success"])
    fail_count = len(results) - success_count

    print(f"\n{'='*60}")
    print(f"📊 Configuration Summary:")
    print(f"   ✅ Success: {success_count}/{len(results)}")
    print(f"   ❌ Failed:  {fail_count}/{len(results)}")
    print(f"{'='*60}")

    # Print failed nodes if any
    for result in results:
        if not result["success"]:
            print(f"   ❌ {result['node']}: {result['message']}")

    return {"is_complete": True}


def _configure_nodes_parallel(tasks: List[Dict]) -> List[Dict]:
    """
    Configure multiple nodes in parallel using ThreadPoolExecutor.

    Each node gets its own agent instance for configuration.
    """
    results = []

    # Use ThreadPoolExecutor for parallel execution
    # Limit workers to avoid overwhelming the system
    max_workers = min(len(tasks), 5)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_task = {
            executor.submit(_configure_single_node, task): task
            for task in tasks
        }

        # Collect results as they complete
        for future in as_completed(future_to_task):
            task = future_to_task[future]
            try:
                result = future.result()
                results.append(result)

                # Print progress immediately
                status = "✅" if result["success"] else "❌"
                print(f"   {status} {result['node']}: {result['message']}")

            except Exception as e:
                results.append({
                    "node": task["node_short_name"],
                    "success": False,
                    "message": f"Exception: {str(e)}"
                })
                print(f"   ❌ {task['node_short_name']}: Exception - {str(e)}")

    return results


def _configure_single_node(task: Dict) -> Dict:
    """
    Configure a single node using a dedicated agent.

    Returns:
        Dict with keys: node, success, message, logs
    """
    container_name = task["container_name"]
    node_short_name = task["node_short_name"]
    exec_commands = task.get("exec_commands", [])
    container = task["container"]

    # Build configuration task for the agent
    config_task = _build_config_task(
        container_name=container_name,
        expected_commands=exec_commands,
        node_short_name=node_short_name
    )

    # Initialize model and agent for this node
    model = init_chat_model(
        model_provider="openai",
        model=LLM_MODEL,
        temperature=0.1,
        base_url=BASE_URL,
        api_key=API_KEY
    )

    agent = create_agent(
        model=model,
        system_prompt=configure_prompt,
        tools=[node_config_tool]
    )

    try:
        # Invoke the agent
        result = agent.invoke({
            "messages": [
                {"role": "user", "content": config_task}
            ]
        })

        # Extract agent response
        # According to LangChain forum: Filter for the last assistant (AIMessage) and use .text property
        # Source: https://forum.langchain.com/t/how-to-retireve-the-final-ai-message-after-invoke/2078
        messages = result.get("messages", [])
        # Find the last AIMessage (in case graph ends on a ToolMessage)
        last_ai_message = None
        for msg in reversed(messages):
            if hasattr(msg, 'type') and msg.type == 'ai':
                last_ai_message = msg
                break

        if last_ai_message and hasattr(last_ai_message, 'text'):
            # .text safely extracts human-readable text from content
            agent_response = last_ai_message.text
        elif last_ai_message and hasattr(last_ai_message, 'content'):
            # Fallback for older versions
            content = last_ai_message.content
            agent_response = str(content) if not isinstance(content, str) else content
        else:
            agent_response = ""

        # Check if configuration was successful
        config_success = _check_config_success(agent_response)

        if config_success:
            return {
                "node": node_short_name,
                "success": True,
                "message": "Configured successfully",
                "logs": agent_response
            }
        else:
            return {
                "node": node_short_name,
                "success": False,
                "message": "Configuration issues detected",
                "logs": agent_response
            }

    except Exception as e:
        return {
            "node": node_short_name,
            "success": False,
            "message": f"Exception: {str(e)}",
            "logs": str(e)
        }


def _build_config_task(
    container_name: str,
    expected_commands: List[str],
    node_short_name: str
) -> str:
    """Build the configuration task prompt for the agent."""
    task = f"""
Configure the node: {container_name}

EXPECTED CONFIGURATION (from YAML):
The following commands should have been executed during container startup:
"""
    for cmd in expected_commands:
        task += f"  - {cmd}\n"

    task += f"""
YOUR TASK:
1. First, DIAGNOSE the current state:
   - Run "ip addr show" to see all interfaces and their IPs
   - Run "ip route show" to see routing table
   - Check if 'ip' command is available (run "which ip" or "ip addr")

2. VERIFY the configuration:
   - Check if interfaces have IP addresses assigned
   - Check if default route exists (for endpoints)
   - Check if interfaces are UP (not DOWN)

3. FIX any issues you find:
   - If 'ip' command not found, install tools:
     * For Alpine: "apk add --no-cache iproute2 iputils-ping net-tools"
     * For Debian/Ubuntu/Kali: "apt-get update && apt-get install -y iproute2 iputils-ping net-tools"
   - If interface has no IP, configure it based on expected commands
   - If interface is DOWN, bring it UP: "ip link set <interface> up"
   - If route missing, add it: "ip route replace default via <gateway>"

4. VERIFY your fixes:
   - Run "ip addr show" again to confirm IPs are configured
   - Run "ip route show" to confirm routes exist

IMPORTANT:
- Container name: {container_name}
- Use the node_config_tool with the exact container name
- Always run verification commands after applying fixes
- Be concise in your response

Begin your diagnosis and configuration now.
"""
    return task


def _check_config_success(response: str) -> bool:
    """Check if the configuration response indicates success."""
    # Success indicators in agent response
    success_indicators = [
        "✅",
        "pass",
        "configured successfully",
        "all checks passed",
        "verification complete",
        "interfaces are up",
        "ip address configured",
        "route configured",
        "configuration is correct"
    ]

    response_lower = response.lower()
    for indicator in success_indicators:
        if indicator in response_lower:
            return True

    # Check for inet addresses in response (indicates IP is configured)
    if "inet " in response and "up" in response_lower:
        return True

    # Default to success if no obvious failure indicators
    failure_indicators = [
        "failed",
        "error:",
        "not found",
        "command failed",
        "unable to"
    ]
    for indicator in failure_indicators:
        if indicator in response_lower:
            return False

    return True



