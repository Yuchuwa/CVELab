"""日志配置模块

提供统一的日志管理，支持多会话并发、结构化日志和错误追踪。
"""
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
from contextvars import ContextVar
import traceback as tb

from clab_builder.session_utils import get_current_session_id, get_session_output_dir


# 日志上下文变量（线程安全）
_log_context: ContextVar[dict] = ContextVar('_log_context', default={})


def set_log_context(**kwargs) -> None:
    """设置日志上下文信息。

    Args:
        **kwargs: 上下文键值对，如 node_name="router-1", stage="deploy"
    """
    current = _log_context.get()
    current.update(kwargs)
    _log_context.set(current)


def get_log_context() -> dict:
    """获取当前日志上下文。

    Returns:
        上下文字典
    """
    return _log_context.get()


def clear_log_context() -> None:
    """清除日志上下文。"""
    _log_context.set({})


class SessionFormatter(logging.Formatter):
    """自定义日志格式化器，支持 session_id 和结构化字段。

    格式: [timestamp] [session_id] [level] [node/stage] message
    """

    def __init__(self):
        # 控制台格式：彩色输出（如果支持）
        console_fmt = (
            "\033[90m[%(asctime)s.%(msecs)03d]\033[0m "  # 灰色时间戳
            "\033[36m[%(session_id)s]\033[0m "  # 青色 session_id
            "\033[33m[%(levelname)s]\033[0m "  # 黄色日志级别
            "%(context)s "  # 上下文（节点名、阶段等）
            "%(message)s"  # 消息
        )
        super().__init__(fmt=console_fmt, datefmt="%Y-%m-%d %H:%M:%S")

    def format(self, record: logging.LogRecord) -> str:
        # 添加 session_id
        record.session_id = get_current_session_id() or "no-session"

        # 添加上下文信息
        context = get_log_context()
        context_parts = []
        if context.get("node"):
            context_parts.append(f"\033[35mnode={context['node']}\033[0m")
        if context.get("stage"):
            context_parts.append(f"\033[35mstage={context['stage']}\033[0m")
        record.context = " ".join(context_parts) if context_parts else ""

        # 格式化消息
        result = super().format(record)

        # 如果有异常，添加详细信息
        if record.exc_info:
            result += "\n" + "\n".join(
                "    " + line
                for line in self.formatException(record.exc_info).split("\n")
            )

        return result


class FileFormatter(logging.Formatter):
    """文件日志格式化器（无颜色代码）。

    格式: [timestamp] [session_id] [level] [node/stage] message [extra_fields]
    """

    def __init__(self):
        file_fmt = (
            "[%(asctime)s.%(msecs)03d] "
            "[%(session_id)s] "
            "[%(levelname)s] "
            "[%(context)s] "
            "%(message)s"
            " | %(name)s:%(funcName)s:%(lineno)d"
        )
        super().__init__(fmt=file_fmt, datefmt="%Y-%m-%d %H:%M:%S")

    def format(self, record: logging.LogRecord) -> str:
        # 添加 session_id
        record.session_id = get_current_session_id() or "no-session"

        # 添加上下文信息
        context = get_log_context()
        context_parts = []
        if context.get("node"):
            context_parts.append(f"node={context['node']}")
        if context.get("stage"):
            context_parts.append(f"stage={context['stage']}")
        record.context = " ".join(context_parts) if context_parts else "-"

        return super().format(record)


def setup_logger(
    name: str = "containerlab_builder",
    level: int = logging.INFO,
    log_file: Optional[str] = None,
    session_id: Optional[str] = None
) -> logging.Logger:
    """设置并返回一个配置好的 logger。

    同时配置根 logger，确保所有子 logger 都能输出到文件。

    Args:
        name: logger 名称
        level: 日志级别
        log_file: 日志文件路径（如果为 None，自动生成）
        session_id: 会话 ID（用于生成日志文件名）

    Returns:
        配置好的 logger 实例
    """
    # 确定日志文件路径
    if log_file is None and session_id:
        # 自动生成日志文件路径
        session_dir = get_session_output_dir(session_id=session_id)
        os.makedirs(session_dir, exist_ok=True)
        log_file = os.path.join(session_dir, f"{session_id}.log")

    # 配置根 logger（确保所有子 logger 都能输出）
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)  # 根 logger 设置为最低级别

    # 检查根 logger 是否已有控制台 handler
    root_has_console = any(
        isinstance(h, logging.StreamHandler) and h.stream == sys.stdout
        for h in root_logger.handlers
    )

    # 检查根 logger 是否已有文件 handler
    root_has_file = any(
        isinstance(h, logging.FileHandler)
        for h in root_logger.handlers
    )

    # 根 logger 的控制台处理器（只添加一次）
    if not root_has_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(SessionFormatter())
        root_logger.addHandler(console_handler)

    # 根 logger 的文件处理器（只添加一次）
    if log_file and not root_has_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)  # 文件记录更详细的日志
        file_handler.setFormatter(FileFormatter())
        root_logger.addHandler(file_handler)

    # 获取指定的 logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = True  # 允许传播到根 logger

    return logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """获取 logger 实例。

    Args:
        name: logger 名称，如果为 None 则使用调用者的模块名

    Returns:
        logger 实例
    """
    if name is None:
        # 自动获取调用者的模块名
        frame = sys._getframe(1)
        name = frame.f_globals.get("__name__", "containerlab_builder")

    return logging.getLogger(name)


def log_function_call(logger: Optional[logging.Logger] = None):
    """装饰器：记录函数调用和返回值。

    Args:
        logger: 使用的 logger，如果为 None 则自动获取

    Example:
        @log_function_call()
        def my_function(x, y):
            return x + y
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            nonlocal logger
            if logger is None:
                logger = get_logger()

            func_name = f"{func.__module__}.{func.__name__}"
            logger.debug(f"→ Calling {func_name} with args={args}, kwargs={kwargs}")

            try:
                result = func(*args, **kwargs)
                logger.debug(f"← {func_name} returned successfully")
                return result
            except Exception as e:
                logger.error(
                    f"✗ {func_name} raised {type(e).__name__}: {e}",
                    exc_info=True
                )
                raise

        return wrapper
    return decorator


def log_error(
    logger: logging.Logger,
    error: Exception,
    message: str = "An error occurred",
    **context
) -> None:
    """记录错误及其完整上下文。

    Args:
        logger: logger 实例
        error: 异常对象
        message: 错误消息
        **context: 额外的上下文信息
    """
    # 设置上下文
    if context:
        set_log_context(**context)

    logger.error(
        f"{message}: {type(error).__name__}: {str(error)}",
        exc_info=True
    )


def log_step(
    logger: logging.Logger,
    step_name: str,
    status: str = "start",
    **details
) -> None:
    """记录工作流步骤。

    Args:
        logger: logger 实例
        step_name: 步骤名称
        status: 状态 (start/success/fail/skip)
        **details: 额外的详细信息
    """
    status_icons = {
        "start": "▶",
        "success": "✓",
        "fail": "✗",
        "skip": "⊝"
    }

    icon = status_icons.get(status, "•")
    detail_str = " ".join(f"{k}={v}" for k, v in details.items())

    if status == "start":
        logger.info(f"{icon} {step_name} - {detail_str}")
    elif status == "success":
        logger.info(f"{icon} {step_name} completed successfully")
    elif status == "fail":
        logger.error(f"{icon} {step_name} failed - {detail_str}")
    else:
        logger.warning(f"{icon} {step_name} - {detail_str}")


# 初始化根 logger（在 main.py 中会重新配置）
_root_logger_initialized = False


def init_root_logger():
    """初始化根 logger（在程序启动时调用一次）。"""
    global _root_logger_initialized
    if _root_logger_initialized:
        return

    # 配置根 logger
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",  # 简单格式，由 handlers 处理详细格式
        handlers=[logging.StreamHandler(sys.stdout)]
    )

    _root_logger_initialized = True
