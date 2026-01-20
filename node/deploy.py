"""Deploy 节点：容器部署和健康检查

负责 ContainerLab 拓扑的部署、权限修复和容器健康检查。
"""
import subprocess
import os
import time
from typing import Dict, Any, Tuple, Optional

from state import GraphState
from config import config
from logger import get_logger, set_log_context, log_step, log_error
from .fixer import ERROR_TYPE_DEPLOY, ERROR_TYPE_SYSTEM
from .utils import ConfigApplier


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
        subprocess.run(
            ["containerlab", "version"],
            capture_output=True,
            timeout=5,
            check=True
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
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except Exception as e:
        log_error(logger, e, "Failed to start command process")
        return -1, f"Failed to start process: {str(e)}"

    full_output = []
    start_time = time.time()

    if process.stdout is None:
        process.wait()
        return process.returncode, "Error: stdout is None"

    last_progress_time = start_time
    progress_interval = 30

    try:
        while True:
            elapsed = time.time() - start_time
            if elapsed > timeout:
                process.kill()
                logger.warning(f"Command timeout after {elapsed:.1f}s")
                return -1, "".join(full_output) + f"\n[Timeout after {elapsed:.1f}s]"

            if elapsed - (last_progress_time - start_time) > progress_interval:
                logger.debug(f"Command still running... ({elapsed:.1f}s elapsed)")
                last_progress_time = time.time()

            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break

            if line:
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
                data = __import__("json").loads(res.stdout)

                # 提取容器列表
                containers = []
                for value in data.values():
                    if isinstance(value, list):
                        containers = value
                        break

                if not containers:
                    logger.warning(
                        f"Inspect returned valid JSON but no containers found "
                        f"(attempt {attempt + 1}/{max_retries})"
                    )
                    if attempt == 0:
                        logger.debug(f"Raw output: {res.stdout[:200]}...")
                    time.sleep(interval)
                    continue

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
            except __import__("json").JSONDecodeError as e:
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


def deploy(state: GraphState) -> Dict[str, Any]:
    """
    Deploy 节点：部署容器实验室并进行健康检查。

    工作流程:
    1. 预清理（destroy 已有的 lab）
    2. 流式部署（实时输出进度）
    3. 健康检查（等待所有容器 running）
    4. 应用网络配置（使用 JSON + ConfigApplier）

    Args:
        state: 当前工作流状态

    Returns:
        更新后的状态字典
    """
    logger = get_logger("node.deploy")
    set_log_context(stage="deploy")

    yaml_path = os.path.abspath(state['yaml_path'])
    json_path = state.get('json_path')
    sudo_prefix = get_sudo_prefix()

    log_step(logger, f"Deploying {yaml_path}", status="start")

    if check_containerlab_needs_sudo():
        logger.debug("Using sudo for containerlab commands")

    # =========================================
    # 步骤 1: 预清理（快速清理）
    # =========================================
    log_step(logger, "Pre-cleaning existing deployment", status="start")
    logger.debug("Pre-cleaning existing deployment...")
    try:
        subprocess.run(
            f"{sudo_prefix}containerlab destroy -t {yaml_path} --cleanup",
            shell=True,
            capture_output=True,
            timeout=60
        )
        log_step(logger, "Pre-clean completed", status="success")
    except Exception as e:
        logger.debug(f"Pre-clean warning (non-critical): {e}")
        log_step(logger, "Pre-clean skipped (no existing deployment)", status="success")

    # =========================================
    # 步骤 2: 流式部署
    # =========================================
    log_step(logger, "Deploying containers with containerlab", status="start")
    return_code, logs = run_command_streaming(
        f"{sudo_prefix}containerlab deploy -t {yaml_path} --reconfigure",
        timeout=config.timeout_seconds,
        logger=logger
    )

    if return_code != 0:
        # 判断是系统错误还是部署错误
        error_lower = logs.lower()
        if any(keyword in error_lower for keyword in [
            "permission denied", "access denied", "operation not permitted",
            "no space left", "disk full", "out of memory", "oom",
            "docker daemon", "docker not running"
        ]):
            error_type = ERROR_TYPE_SYSTEM
        else:
            error_type = ERROR_TYPE_DEPLOY

        # 截断日志（避免 token 过多）
        error_logs_short = logs[-2000:] if len(logs) > 2000 else logs

        logger.error(f"Error logs (will be sent to fixer):\n{error_logs_short}")

        log_step(
            logger,
            "Deployment failed",
            status="fail",
            return_code=return_code
        )

        return {
            "error_logs": f"{error_type} {error_logs_short}",
            "is_deployed": False,
            "inspect_data": None
        }

    log_step(logger, "Containers deployed successfully", status="success")

    # =========================================
    # 步骤 3: 健康检查
    # =========================================
    is_healthy, inspect_data = wait_for_lab_healthy(yaml_path, logger=logger)

    if not is_healthy:
        error_msg = (
            "Timeout waiting for containers to become 'running'. "
            "Check the container logs for issues."
        )
        log_step(logger, "Health check failed", status="fail")
        return {
            "error_logs": f"{ERROR_TYPE_DEPLOY} {error_msg}",
            "is_deployed": False,
            "inspect_data": None
        }

    # =========================================
    # 步骤 5: 应用网络配置
    # =========================================
    if json_path:
        log_step(logger, "Applying network configuration", status="start")

        try:
            # 提取 lab_name（去除 .clab.yml 后缀）
            lab_name = os.path.basename(yaml_path).replace('.clab.yml', '')
            config_dir = os.path.dirname(json_path)

            logger.debug(f"Applying network config for lab: {lab_name}")
            logger.debug(f"Config directory: {config_dir}")

            # 直接使用 ConfigApplier 类
            applier = ConfigApplier(lab_name, config_dir)
            stats = applier.apply_all()

            if stats["failed"] == 0:
                log_step(
                    logger,
                    "Network configuration applied successfully",
                    status="success",
                    configured=stats["success"]
                )
            else:
                log_step(
                    logger,
                    "Network configuration completed with warnings",
                    status="success",
                    configured=stats["success"],
                    failed=stats["failed"]
                )
                logger.warning(f"Failed nodes: {', '.join(stats['failed_nodes'])}")

        except FileNotFoundError as e:
            log_error(logger, e, "Config file not found (non-critical)")
        except Exception as e:
            log_error(logger, e, "Failed to apply network configuration (non-critical)")
            # 不中断部署流程，只记录错误

    log_step(logger, "Deployment completed successfully", status="success")

    return {
        "error_logs": "",
        "is_deployed": True,
        "inspect_data": inspect_data
    }
