"""Builder 节点：YAML 文件生成

从 NetworkBlueprint 生成 ContainerLab YAML 配置文件。
"""
from typing import Dict, Any

from state import GraphState
from .utils import NetworkBuilder
from session_utils import get_current_session_id
from logger import get_logger, set_log_context, log_step, log_error


def builder_node(state: GraphState) -> Dict[str, Any]:
    """
    Builder 节点：从蓝图构建 YAML 配置。

    工作流程:
    1. 检查 blueprint 是否存在
    2. 获取 session_id 并更新 lab_name
    3. 调用 NetworkBuilder 生成 YAML
    4. 返回 yaml_path

    Args:
        state: 当前工作流状态

    Returns:
        更新后的状态字典
    """
    logger = get_logger("node.builder")
    set_log_context(stage="builder")

    blueprint = state.get('blueprint')

    if blueprint is None:
        error_msg = "No blueprint provided to builder"
        logger.error(error_msg)
        return {"error_logs": error_msg}

    try:
        log_step(logger, "Building YAML from blueprint", status="start")

        # 获取会话 ID
        session_id = get_current_session_id()

        if not session_id:
            logger.warning("No session ID found, using default output directory")
            output_dir = "./clab_out"
            final_blueprint = blueprint
        else:
            output_dir = f"./clab_out/{session_id}"
            # 修改 lab_name 以确保唯一性
            original_name = blueprint.lab_name
            unique_name = f"{original_name}-{session_id}"
            final_blueprint = blueprint.model_copy(update={"lab_name": unique_name})

            logger.debug(f"Session directory: {output_dir}")
            logger.debug(f"Lab name: {original_name} → {unique_name}")

        # 构建网络
        builder = NetworkBuilder(final_blueprint, output_dir=output_dir)
        yaml_path = builder.build()

        log_step(
            logger,
            "YAML built successfully",
            status="success",
            yaml_path=yaml_path
        )

        return {"yaml_path": yaml_path, "error_logs": ""}

    except Exception as e:
        log_error(logger, e, "Failed to build YAML")
        return {"error_logs": f"Builder Error: {str(e)}"}