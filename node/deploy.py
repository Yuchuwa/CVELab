"""Deploy 节点：容器部署和健康检查

负责 ContainerLab 拓扑的部署、权限修复和容器健康检查。
"""
import subprocess
import json
import os
import time
from typing import Dict, Any, Tuple, Optional

from state import GraphState
from config import config, TIMEOUT_SECONDS
from logger import get_logger, set_log_context, log_step, log_error


# 检测是否需要 sudo（全局缓存一次）
_NEEDS_SUDO: Optional[bool] = None


def check_containerlab_needs_sudo() -> bool:
    """检查执行 containerlab 是否需要 sudo。

    Returns:
        True 如果需要 sudo，否则 False
    """
    global _NEEDS_SUDO

    if _NEEDS_SUDO is not None:
        return _NEEDS_SUDO

    logger = get_logger("node.deploy")
    logger.debug("Checking if containerlab requires sudo...")

    try:
        result = subprocess.run(
            ["containerlab", "version"],
            capture_output=True,
            timeout=5
        )
        _NEEDS_SUDO = False
        logger.debug("containerlab can run without sudo")
        return False
    except (subprocess.CalledProcessError, FileNotFoundError, Exception) as e:
        logger.debug(f"containerlab requires sudo: {e}")
        _NEEDS_SUDO = True
        return True


def get_sudo_prefix() -> str:
    """获取 sudo 前缀。

    Returns:
        "sudo " 如果需要 sudo，否则 ""
    """
    return "sudo " if check_containerlab_needs_sudo() else ""


def run_command_streaming(
    cmd: str,
    timeout: int = None,
    logger: Optional[Any] = None
) -> Tuple[int, str]:
    """
    执行命令并实时打印输出（Streaming Output）。

    防止长时间无响应被误判为卡死，提供实时进度反馈。

    Args:
        cmd: 要执行的命令
        timeout: 超时时间（秒），None 则使用配置默认值
        logger: logger 实例

    Returns:
        (return_code, full_output) 元组
    """
    if logger is None:
        logger = get_logger("node.deploy")

    if timeout is None:
        timeout = config.timeout_seconds

    logger.info(f"⚙️  Executing: {cmd}")

    try:
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # 将错误流合并到标准输出
            text=True,
            bufsize=1,  # 行缓冲
        )
    except Exception as e:
        log_error(logger, e, "Failed to start command process")
        return -1, f"Failed to start process: {str(e)}"

    full_output = []
    start_time = time.time()

    # 确保 stdout 可用
    if process.stdout is None:
        process.wait()
        return process.returncode, "Error: stdout is None"

    # 实时读取日志
    last_progress_time = start_time
    progress_interval = 30  # 每30秒输出一次进度提示

    try:
        while True:
            # 检查是否超时
            elapsed = time.time() - start_time
            if elapsed > timeout:
                process.kill()
                logger.warning(f"Command timeout after {elapsed:.1f}s")
                return -1, "".join(full_output) + f"\n[Timeout after {elapsed:.1f}s]"

            # 定期输出进度（避免长时间无输出时用户焦虑）
            if elapsed - (last_progress_time - start_time) > progress_interval:
                logger.debug(f"Command still running... ({elapsed:.1f}s elapsed)")
                last_progress_time = time.time()

            # 读取一行
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break

            if line:
                # 记录到文件日志（不打印到控制台，避免重复）
                logger.debug(f"   | {line.strip()}")
                full_output.append(line)

    except KeyboardInterrupt:
        logger.warning("Command interrupted by user")
        process.kill()
        return -1, "".join(full_output) + "\n[Interrupted by user]"

    return process.returncode, "".join(full_output)


def wait_for_lab_healthy(
    yaml_path: str,
    logger: Optional[Any] = None
) -> Tuple[bool, Optional[Dict]]:
    """
    异步轮询：主动检查 inspect 状态，直到所有容器都 Running。

    containerlab inspect 返回的 JSON 格式:
    {
      "lab-name": [
        { "name": "...", "state": "running", ... },
        ...
      ]
    }

    Args:
        yaml_path: YAML 文件路径
        logger: logger 实例

    Returns:
        (is_healthy, inspect_data) 元组
    """
    if logger is None:
        logger = get_logger("node.deploy")

    max_retries = config.container_health_check_max_retries
    interval = config.container_health_check_interval
    sudo_prefix = get_sudo_prefix()

    log_step(logger, "Waiting for containers to become healthy", status="start")

    for attempt in range(max_retries):
        cmd = f"{sudo_prefix}containerlab inspect -t {yaml_path} --format json"

        try:
            res = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
        except subprocess.TimeoutExpired:
            logger.warning(f"Inspect command timeout (attempt {attempt + 1}/{max_retries})")
            time.sleep(interval)
            continue

        if res.returncode == 0:
            try:
                data = json.loads(res.stdout)

                # 提取容器列表
                containers = []
                for value in data.values():
                    if isinstance(value, list):
                        containers = value
                        break

                # 1. 检查是否有容器
                if not containers:
                    logger.warning(
                        f"Inspect returned valid JSON but no containers found "
                        f"(attempt {attempt + 1}/{max_retries})"
                    )
                    if attempt == 0:
                        logger.debug(f"Raw output: {res.stdout[:200]}...")
                    time.sleep(interval)
                    continue

                # 2. 检查所有容器是否都是 'running'
                not_ready = [c['name'] for c in containers if c['state'].lower() != 'running']

                if not not_ready:
                    log_step(
                        logger,
                        "All containers healthy",
                        status="success",
                        total_containers=len(containers)
                    )
                    return True, data
                else:
                    logger.debug(
                        f"Waiting for {len(not_ready)}/{len(containers)} containers: "
                        f"{', '.join(not_ready[:3])}{'...' if len(not_ready) > 3 else ''}"
                    )
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error (attempt {attempt + 1}/{max_retries}): {e}")
                logger.debug(f"Raw output: {res.stdout[:200]}...")
        else:
            logger.warning(
                f"Inspect command failed (rc={res.returncode}, attempt {attempt + 1}/{max_retries})"
            )
            if res.stderr:
                logger.debug(f"stderr: {res.stderr[:200]}")

        time.sleep(interval)

    log_step(
        logger,
        "Container health check timeout",
        status="fail",
        max_retries=max_retries
    )
    return False, None


def fix_permissions(path: str, logger: Optional[Any] = None) -> bool:
    """
    递归修改指定路径的所有权。

    将文件从 root 改回当前 sudo 的调用用户，使 VSCode 等工具能读取状态文件。

    Args:
        path: 要修改权限的路径
        logger: logger 实例

    Returns:
        True 如果成功，否则 False
    """
    if logger is None:
        logger = get_logger("node.deploy")

    logger.debug(f"Fixing permissions for: {path}")

    try:
        sudo_prefix = get_sudo_prefix()
        # 使用 shell 逻辑动态判断用户
        cmd = (
            f"if [ -n \"$SUDO_USER\" ]; then "
            f"chown -R $SUDO_USER:$SUDO_USER {path}; "
            f"else "
            f"chown -R $(id -un):$(id -gn) {path}; "
            f"fi"
        )

        result = subprocess.run(
            f"{sudo_prefix}sh -c '{cmd}'",
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            logger.debug("Permissions fixed successfully")
            return True
        else:
            logger.warning(f"Failed to fix permissions: {result.stderr}")
            return False

    except Exception as e:
        log_error(logger, e, "Error fixing permissions")
        return False


def deploy(state: GraphState) -> Dict[str, Any]:
    """
    Deploy 节点：部署容器实验室并进行健康检查。

    工作流程:
    1. 预清理（destroy 已有的 lab）
    2. 流式部署（实时输出进度）
    3. 修复文件权限
    4. 健康检查（等待所有容器 running）

    Args:
        state: 当前工作流状态

    Returns:
        更新后的状态字典
    """
    logger = get_logger("node.deploy")
    set_log_context(stage="deploy")

    yaml_path = os.path.abspath(state['yaml_path'])
    sudo_prefix = get_sudo_prefix()

    log_step(logger, f"Deploying {yaml_path}", status="start")

    if check_containerlab_needs_sudo():
        logger.debug("Using sudo for containerlab commands")

    # 1. PRE-CLEAN（快速清理）
    logger.debug("Pre-cleaning existing deployment...")
    try:
        subprocess.run(
            f"{sudo_prefix}containerlab destroy -t {yaml_path} --cleanup",
            shell=True,
            capture_output=True,
            timeout=60
        )
    except Exception as e:
        logger.debug(f"Pre-clean warning (non-critical): {e}")

    # 2. STREAMING DEPLOY（实时输出）
    return_code, logs = run_command_streaming(
        f"{sudo_prefix}containerlab deploy -t {yaml_path} --reconfigure",
        timeout=config.timeout_seconds,
        logger=logger
    )

    if return_code != 0:
        # 只返回最后 2000 字符避免 Token 爆炸，但保留错误信息
        error_logs = logs[-2000:] if len(logs) > 2000 else logs
        log_step(
            logger,
            "Deployment failed",
            status="fail",
            return_code=return_code
        )
        return {
            "error_logs": error_logs,
            "is_deployed": False,
            "inspect_data": None
        }

    # 3. 修复文件权限
    output_dir = os.path.dirname(yaml_path)
    fix_permissions(output_dir, logger=logger)

    # 4. 健康检查
    is_healthy, inspect_data = wait_for_lab_healthy(yaml_path, logger=logger)

    if not is_healthy:
        error_msg = (
            "Timeout waiting for containers to become 'running'. "
            "Check the container logs for issues."
        )
        log_step(logger, "Health check failed", status="fail")
        return {
            "error_logs": error_msg,
            "is_deployed": False,
            "inspect_data": None
        }

    log_step(logger, "Deployment successful", status="success")

    return {
        "error_logs": "",
        "is_deployed": True,
        "inspect_data": inspect_data
    }