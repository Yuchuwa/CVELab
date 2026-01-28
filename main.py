"""ContainerLab Builder - 主入口

基于 LLM 和 LangGraph 的智能网络拓扑自动化构建工具。
"""
from typing import Dict, Any

from state import GraphState
from langgraph.graph import StateGraph, START, END
from node.generate import generate
from node.deploy import deploy
from node.configure import configure
from node.builder import builder_node
from node.validate import validator_node
from node.fixer import fixer
from session_utils import ensure_session_dir, set_current_session_id
from config import config
from logger import (
    setup_logger,
    get_logger,
    set_log_context,
    log_step
)


def create_workflow() -> StateGraph:
    """创建并编译 LangGraph 工作流。"""
    workflow = StateGraph(GraphState)

    # 添加节点
    workflow.add_node("generator", generate)
    workflow.add_node("builder", builder_node)
    workflow.add_node("validator", validator_node)
    workflow.add_node("deployer", deploy)
    workflow.add_node("configurator", configure)
    workflow.add_node("fixer", fixer)

    # 添加边
    workflow.add_edge(START, "generator")
    workflow.add_edge("generator", "builder")

    # 条件边：检查构建错误
    def check_build_errors(state: GraphState) -> str:
        error_logs = state.get("error_logs", "")
        if "[ERROR_TYPE:BUILD]" in error_logs:
            return "fixer"
        return "validator"

    # 条件边：检查验证错误
    def check_validation_errors(state: GraphState) -> str:
        error_logs = state.get("error_logs", "")
        if "[ERROR_TYPE:SYSTEM]" in error_logs:
            return END
        if "[ERROR_TYPE:VALIDATE]" in error_logs:
            return "fixer"
        return "deployer"

    # 条件边：检查部署错误
    def check_deploy_errors(state: GraphState) -> str:
        error_logs = state.get("error_logs", "")
        if "[ERROR_TYPE:DEPLOY]" in error_logs:
            return "fixer"
        return "configurator"

    # 条件边：检查配置错误
    def check_configuration_errors(state: GraphState) -> str:
        error_logs = state.get("error_logs", "")
        if "[ERROR_TYPE:CONFIGURE]" in error_logs:
            return "fixer"
        return END

    # 添加条件边
    workflow.add_conditional_edges("builder", check_build_errors)
    workflow.add_conditional_edges("validator", check_validation_errors)
    workflow.add_conditional_edges("deployer", check_deploy_errors)
    workflow.add_conditional_edges("configurator", check_configuration_errors)

    return workflow.compile()


def run(user_request: str) -> Dict[str, Any]:
    """运行工作流。

    Args:
        user_request: 用户的自然语言请求

    Returns:
        工作流最终状态
    """
    # 生成会话 ID 和目录
    session_id, session_dir = ensure_session_dir()

    # 设置会话级别的 logger
    setup_logger(
        name="containerlab_builder",
        level=getattr(__import__("logging"), config.log_level),
        session_id=session_id
    )

    logger = get_logger("main")
    set_log_context(stage="main")

    # 打印欢迎信息
    logger.info("=" * 60)
    logger.info("🚀 ContainerLab Builder")
    logger.info("=" * 60)
    logger.info(f"📁 Session ID: {session_id}")
    logger.info(f"📂 Output directory: {session_dir}")
    logger.info(f"⚙️  Config: model={config.llm_model}, max_retries={config.max_retries}")

    # 设置当前会话 ID（供其他模块使用）
    set_current_session_id(session_id)

    # 创建工作流
    app = create_workflow()

    # 初始状态
    initial_state: GraphState = {
        "user_request": user_request,
        "blueprint": None,
        "yaml_path": "",
        "json_path": "",
        "error_logs": "",
        "is_deployed": False,
        "inspect_data": {},
        "retry_count": 0,
        "is_complete": False,
    }

    # 运行工作流
    try:
        result = app.invoke(initial_state)

        # 输出最终结果
        logger.info("=" * 60)
        if result.get("is_complete"):
            log_step(logger, "Workflow completed successfully", status="success")
            if result.get("yaml_path"):
                logger.info(f"📄 YAML file: {result['yaml_path']}")
        else:
            log_step(logger, "Workflow did not complete as expected", status="fail")
            if result.get("error_logs"):
                logger.error(f"Error: {result['error_logs']}")

        logger.info("=" * 60)

        return result

    except KeyboardInterrupt:
        logger.warning("Workflow interrupted by user")
        raise
    except Exception as e:
        logger.error(f"Workflow crashed: {e}", exc_info=True)
        raise


if __name__ == "__main__":
    # Test with a simple example
    test_request = """
    Create a simple pentest lab with:
    - External zone: A Kali attacker machine
    - Internal zone: A Redis server
    - Connect them through a router
    """

    run(test_request)
