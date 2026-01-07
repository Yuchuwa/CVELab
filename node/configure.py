"""Configure 节点：容器内网络配置

负责在部署后的容器中配置网络接口和路由。
"""
import json
import yaml
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from langchain.agents import create_agent
from langchain.chat_models import init_chat_model

from state import GraphState
from tools.containerlab_tools import node_config_tool
from config import config
from logger import get_logger, set_log_context, log_step, log_error


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


def configure(state: GraphState) -> Dict[str, Any]:
    """
    Configure 节点：并行配置所有容器的网络接口。

    工作流程:
    1. 解析 inspect_data 获取所有容器
    2. 读取 YAML 文件获取预期配置
    3. 并行配置所有节点（每个节点有独立的 agent）
    4. 聚合结果并更新状态

    Args:
        state: 当前工作流状态

    Returns:
        更新后的状态字典
    """
    logger = get_logger("node.configure")
    set_log_context(stage="configure")

    inspect_data = state.get("inspect_data", {})
    yaml_path = state.get("yaml_path")

    # 解析容器列表
    containers = []
    lab_name = ""
    try:
        for lab, nodes in inspect_data.items():
            lab_name = lab
            if isinstance(nodes, list):
                containers.extend(nodes)

        if not containers:
            logger.warning("No containers found in inspect_data")
            return {"is_complete": True}

    except Exception as e:
        log_error(logger, e, "Failed to parse inspect_data")
        return {"is_complete": True}  # 非致命错误，继续流程

    # 读取 YAML 文件
    nodes_config = {}
    if yaml_path:
        try:
            with open(yaml_path, 'r', encoding='utf-8') as f:
                yaml_content = yaml.safe_load(f) or {}
            topology = yaml_content.get("topology", {})
            nodes_config = topology.get("nodes", {})
            logger.debug(f"Loaded YAML config with {len(nodes_config)} nodes")
        except Exception as e:
            log_error(logger, e, f"Failed to read YAML file {yaml_path}")
            # 继续进行，但使用空配置

    log_step(
        logger,
        "Configuring nodes in parallel",
        status="start",
        total_nodes=len(containers)
    )

    # 准备配置任务
    config_tasks = _prepare_config_tasks(containers, lab_name, nodes_config, logger)

    # 并行配置所有节点
    results = _configure_nodes_parallel(config_tasks, logger)

    # 输出汇总
    success_count = sum(1 for r in results if r["success"])
    fail_count = len(results) - success_count

    log_step(
        logger,
        "Node configuration completed",
        status="success" if fail_count == 0 else "fail",
        total=len(results),
        success=success_count,
        failed=fail_count
    )

    # 记录失败的节点
    if fail_count > 0:
        logger.error(f"Failed to configure {fail_count} node(s):")
        for result in results:
            if not result["success"]:
                logger.error(f"  - {result['node']}: {result['message']}")
                logger.debug(f"    Logs: {result.get('logs', '')[:200]}...")

    return {"is_complete": True}


def _prepare_config_tasks(
    containers: List[Dict],
    lab_name: str,
    nodes_config: Dict,
    logger: Any
) -> List[Dict]:
    """准备配置任务列表。

    Args:
        containers: 容器列表
        lab_name: 实验室名称
        nodes_config: 节点配置字典
        logger: logger 实例

    Returns:
        配置任务列表
    """
    config_tasks = []

    for container in containers:
        try:
            container_name = container.get("name", "")
            # 提取短节点名: clab-simple-router-lab-attacker -> attacker
            node_short_name = container_name.replace(f"clab-{lab_name}-", "")

            # 获取预期配置
            expected_config = nodes_config.get(node_short_name, {})
            exec_commands = expected_config.get("exec", [])

            config_tasks.append({
                "container": container,
                "container_name": container_name,
                "node_short_name": node_short_name,
                "exec_commands": exec_commands
            })

            logger.debug(f"Prepared config task for node: {node_short_name}")

        except Exception as e:
            logger.warning(f"Failed to prepare config task for container: {e}")

    return config_tasks


def _configure_nodes_parallel(
    tasks: List[Dict],
    logger: Any
) -> List[Dict]:
    """使用 ThreadPoolExecutor 并行配置多个节点。

    每个节点获得独立的 agent 实例进行配置。

    Args:
        tasks: 配置任务列表
        logger: logger 实例

    Returns:
        配置结果列表
    """
    results = []

    # 限制并发数，避免系统过载
    max_workers = min(len(tasks), config.max_configure_workers)

    logger.debug(f"Starting parallel configuration with {max_workers} workers")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务
        future_to_task = {
            executor.submit(_configure_single_node, task): task
            for task in tasks
        }

        # 收集结果
        for future in as_completed(future_to_task):
            task = future_to_task[future]
            try:
                result = future.result()
                results.append(result)

                # 实时输出进度
                status = "✅" if result["success"] else "❌"
                node_name = result.get("node", task.get("node_short_name", "unknown"))
                logger.info(f"  {status} {node_name}: {result['message']}")

            except Exception as e:
                log_error(logger, e, f"Exception during configuration of {task.get('node_short_name')}")
                results.append({
                    "node": task["node_short_name"],
                    "success": False,
                    "message": f"Exception: {str(e)}",
                    "logs": str(e)
                })

    return results


def _configure_single_node(task: Dict) -> Dict:
    """使用专用的 agent 配置单个节点。

    Args:
        task: 配置任务字典

    Returns:
        结果字典，包含 node, success, message, logs
    """
    logger = get_logger("node.configure")
    set_log_context(node=task.get("node_short_name", "unknown"))

    container_name = task["container_name"]
    node_short_name = task["node_short_name"]
    exec_commands = task.get("exec_commands", [])

    try:
        # 构建配置任务
        config_task = _build_config_task(
            container_name=container_name,
            expected_commands=exec_commands,
            node_short_name=node_short_name
        )

        # 初始化模型和 agent
        model = init_chat_model(
            model_provider="openai",
            model=config.llm_model,
            temperature=0.1,  # 低温度，更确定性的配置
            base_url=config.base_url,
            api_key=config.api_key
        )

        agent = create_agent(
            model=model,
            system_prompt=configure_prompt,
            tools=[node_config_tool]
        )

        logger.debug(f"Configuring node {node_short_name}...")

        # 调用 agent
        result = agent.invoke({
            "messages": [{"role": "user", "content": config_task}]
        })

        # 提取 agent 响应
        agent_response = _extract_agent_response(result)

        # 检查配置是否成功
        config_success = _check_config_success(agent_response)

        if config_success:
            logger.debug(f"Node {node_short_name} configured successfully")
            return {
                "node": node_short_name,
                "success": True,
                "message": "Configured successfully",
                "logs": agent_response
            }
        else:
            logger.warning(f"Node {node_short_name} has configuration issues")
            return {
                "node": node_short_name,
                "success": False,
                "message": "Configuration issues detected",
                "logs": agent_response
            }

    except Exception as e:
        log_error(logger, e, f"Failed to configure node {node_short_name}")
        return {
            "node": node_short_name,
            "success": False,
            "message": f"Exception: {str(e)}",
            "logs": str(e)
        }


def _extract_agent_response(result: Dict) -> str:
    """从 agent 结果中提取响应文本。

    Args:
        result: agent.invoke() 的返回值

    Returns:
        提取的响应文本
    """
    try:
        messages = result.get("messages", [])

        # 查找最后一个 AIMessage
        last_ai_message = None
        for msg in reversed(messages):
            if hasattr(msg, 'type') and msg.type == 'ai':
                last_ai_message = msg
                break

        if last_ai_message and hasattr(last_ai_message, 'text'):
            return last_ai_message.text
        elif last_ai_message and hasattr(last_ai_message, 'content'):
            content = last_ai_message.content
            return str(content) if not isinstance(content, str) else content
        else:
            return ""

    except Exception as e:
        get_logger("node.configure").warning(f"Failed to extract agent response: {e}")
        return ""


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



