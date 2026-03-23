"""会话管理工具模块

该模块提供会话ID生成和管理功能，用于隔离不同会话的文件。
"""
import os
import uuid
from datetime import datetime
from contextvars import ContextVar


# 使用 contextvars 来存储会话ID，这样可以在异步环境中安全使用
_session_id: ContextVar[str] = ContextVar('_session_id', default='')


def set_current_session_id(session_id: str) -> None:
    """设置当前会话的ID。

    Args:
        session_id: 会话ID
    """
    _session_id.set(session_id)


def get_current_session_id() -> str:
    """获取当前会话的ID。

    Returns:
        当前会话的ID，如果未设置则返回空字符串
    """
    return _session_id.get()


def generate_session_id() -> str:
    """生成唯一的会话ID。

    Returns:
        格式为 'YYYYMMDD-HHMMSS-<uuid>' 的会话ID字符串
        例如: '20250107-143022-a1b2c3d4e5f6'
    """
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    unique_id = str(uuid.uuid4())[:8]
    return f"{timestamp}-{unique_id}"


def get_session_output_dir(base_dir: str = "./clab_out", session_id: str = None) -> str:
    """获取会话专属的输出目录路径。

    Args:
        base_dir: 基础输出目录，默认为 './clab_out'
        session_id: 会话ID，如果为None则生成新的会话ID

    Returns:
        会话输出目录的绝对路径
    """
    if session_id is None:
        session_id = generate_session_id()

    session_dir = os.path.join(base_dir, session_id)
    return os.path.abspath(session_dir)


def ensure_session_dir(base_dir: str = "./clab_out", session_id: str = None) -> tuple[str, str]:
    """确保会话目录存在，并返回会话ID和目录路径。

    Args:
        base_dir: 基础输出目录，默认为 './clab_out'
        session_id: 会话ID，如果为None则生成新的会话ID

    Returns:
        (session_id, session_dir) 元组
    """
    if session_id is None:
        session_id = generate_session_id()

    session_dir = get_session_output_dir(base_dir, session_id)
    os.makedirs(session_dir, exist_ok=True)

    return session_id, session_dir
