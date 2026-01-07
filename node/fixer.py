"""Fixer 节点：错误诊断和修复

分析部署错误日志，智能修复网络拓扑设计问题。
"""
from typing import Dict, Any

from langchain.chat_models import init_chat_model
from langchain.agents import create_agent

from state import GraphState
from .utils import NetworkBlueprint
from config import config, MAX_RETRIES
from tools.containerlab_tools import clab_lifecycle_tool, node_config_tool
from logger import get_logger, set_log_context, log_error, log_step


def fixer(state: GraphState) -> Dict[str, Any]:
    """
    Fixer Node: 分析错误日志并修复 NetworkBlueprint。

    工作流程:
    1. 检查重试次数（熔断机制）
    2. 提取上下文信息（user_request, error_logs, blueprint）
    3. 使用 LLM 分析错误并生成修复方案
    4. 返回更新后的 blueprint

    Args:
        state: 当前工作流状态

    Returns:
        更新后的状态字典

    Raises:
        RuntimeError: 当达到最大重试次数时
    """
    logger = get_logger("node.fixer")
    set_log_context(stage="fixer")

    # 1. 熔断机制：检查重试次数
    current_retries = state.get("retry_count", 0)
    max_retries = config.max_retries

    log_step(
        logger,
        f"Fixer activated (Attempt {current_retries + 1}/{max_retries})",
        status="start",
        retry_count=current_retries + 1
    )

    if current_retries >= max_retries:
        error_msg = (
            f"Max retries ({max_retries}) reached. "
            f"Unable to fix the topology. Last error: {state.get('error_logs', 'Unknown')}"
        )
        logger.error(f"❌ {error_msg}")
        logger.error("Please review the error logs and consider:")
        logger.error("  1. Checking if Docker images are available")
        logger.error("  2. Verifying network complexity is appropriate")
        logger.error("  3. Reviewing the user request for conflicts")
        raise RuntimeError(error_msg)

    # 2. 获取上下文
    try:
        user_request = state.get("user_request", "")
        error_logs = state.get("error_logs", "Unknown Error")
        current_bp = state.get("blueprint")

        # 转换 blueprint 为 JSON 字符串
        if current_bp is not None and hasattr(current_bp, "model_dump_json"):
            current_bp_json = current_bp.model_dump_json()
        else:
            current_bp_json = str(current_bp) if current_bp else "No blueprint available"

        logger.debug(f"User request: {user_request[:100]}...")
        logger.debug(f"Error logs: {error_logs[:500]}...")

    except Exception as e:
        log_error(logger, e, "Failed to extract context from state")
        return {
            "retry_count": current_retries + 1,
            "error_logs": f"Fixer Context Error: {str(e)}"
        }

    # 3. 初始化 LLM Agent
    try:
        model = init_chat_model(
            model_provider="openai",
            model=config.llm_model,
            temperature=0.6,  # 稍高的温度以获得创造性修复方案
            base_url=config.base_url,
            api_key=config.api_key
        )

        system_prompt = _build_fixer_prompt(
            user_request, current_bp_json, error_logs, current_retries, max_retries
        )

        fixer_agent = create_agent(
            model=model,
            system_prompt=system_prompt,
            tools=[clab_lifecycle_tool, node_config_tool],
            response_format=NetworkBlueprint
        )

        logger.debug("Fixer agent initialized successfully")

    except Exception as e:
        log_error(logger, e, "Failed to initialize fixer agent")
        return {
            "retry_count": current_retries + 1,
            "error_logs": f"Fixer Initialization Error: {str(e)}"
        }

    # 4. 调用 Agent 生成修复方案
    try:
        logger.info("🔧 Analyzing errors and generating fix...")

        result = fixer_agent.invoke({
            "messages": [{
                "role": "user",
                "content": "Fix the broken network topology design based on deployment error logs."
            }]
        })

        # 提取 structured response
        if "structured_response" in result:
            new_blueprint = result["structured_response"]
        else:
            raise ValueError(
                f"Fixer agent did not return a valid blueprint. "
                f"Available keys: {list(result.keys())}"
            )

        log_step(
            logger,
            "Fixer completed",
            status="success",
            nodes_count=len(new_blueprint.nodes) if hasattr(new_blueprint, 'nodes') else 0
        )

        # 5. 返回更新后的状态
        return {
            "blueprint": new_blueprint,      # 更新蓝图
            "error_logs": "",                # 清空错误日志（关键！）
            "retry_count": current_retries + 1,  # 增加重试计数
        }

    except ValueError as e:
        # 结构化输出错误
        log_error(logger, e, "Fixer agent response validation failed")
        return {
            "retry_count": current_retries + 1,
            "error_logs": f"Fixer Response Error: {str(e)}"
        }

    except Exception as e:
        # 其他未预期的错误
        log_error(logger, e, "Fixer agent crashed unexpectedly")
        logger.warning("Proceeding with retry, but this may fail again")
        return {
            "retry_count": current_retries + 1,
            "error_logs": f"Fixer Internal Error: {str(e)}"
        }


def _build_fixer_prompt(
    user_request: str,
    current_bp_json: str,
    error_logs: str,
    current_retries: int,
    max_retries: int
) -> str:
    """构建 Fixer 的系统提示词。

    Args:
        user_request: 用户原始请求
        current_bp_json: 当前蓝图 JSON
        error_logs: 错误日志
        current_retries: 当前重试次数
        max_retries: 最大重试次数

    Returns:
        系统提示词字符串
    """
    return f"""
You are an expert Network Reliability Engineer (NRE) specializing in Containerlab and Docker.
Your job is to fix a broken network topology design based on deployment error logs.

### INPUT CONTEXT
1. **User Goal**: {user_request}
2. **Current Design (JSON)**: {current_bp_json}
3. **Error Logs**: {error_logs}
4. **Retry Count**: {current_retries + 1}/{max_retries}

### DIAGNOSIS PLAYBOOK (Common Errors & Fixes)

- **Error: "manifest for ... not found" / "pull access denied" / "no matching manifest"**
  -> **Diagnosis**: The Docker image name is incorrect or does not exist.
  -> **Fix**: Change the `image_flavor` of the failing node to a standard one:
     - For vulnerability images: Try removing the tag or using a different version
     - Fallback options: 'alpine:latest', 'ubuntu:latest', 'kalilinux/kali-rolling:latest'
     - Example: Change 'vulfocus/log4j2-xxx:invalid-tag' to 'alpine:latest'

- **Error: "Duplicate endpoint" / "interface used multiple times"**
  -> **Diagnosis**: Two nodes are trying to connect to the same port on a router, or the physical wiring is impossible.
  -> **Fix**: Check the `connected_subnets`. If multiple nodes are in the same subnet (>2), ensure:
     - Don't define router as endpoint (role should be "router")
     - The Builder will auto-inject switches when needed

- **Error: "bridge ... does not exist" / "network not found"**
  -> **Diagnosis**: Issue with bridge or network creation.
  -> **Fix**:
     - Simplify the subnet structure
     - Verify logical node roles are correct
     - Reduce complexity if possible

- **Error: "IP address conflict" / "File exists"**
  -> **Diagnosis**: IPAM logic collision or file system issue.
  -> **Fix**:
     - Ensure nodes have distinct roles
     - Check for duplicate node names (must be unique)

- **Error: "permission denied" / "access denied"**
  -> **Diagnosis**: Docker permission issues.
  -> **Fix**:
     - This is usually a system issue, not a topology issue
     - Advise user to check Docker permissions
     - Consider using simpler images that don't require special permissions

### TASK
1. Analyze the error log carefully and identify the ROOT CAUSE.
2. Modify the `Current Design` JSON **minimally** to resolve the specific error.
3. Do NOT change parts of the design that are working fine.
4. If an image is unavailable, substitute with a standard alternative.
5. Ensure strict adherence to the output schema.

### IMPORTANT PRINCIPLES
- **Minimal Change**: Only change what's absolutely necessary
- **Fallback Strategy**: When in doubt, use standard images (alpine, ubuntu)
- **Preserve Intent**: Keep the user's original network structure intent
- **Realistic**: Don't try to fix system-level issues (permissions, disk space) via topology changes

Begin your analysis and fix now.
"""
