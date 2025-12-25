import subprocess
import json
import os
import time
import select
from state import GraphState

def run_command_streaming(cmd: str, timeout: int = 600):
    """
    执行命令并实时打印输出 (Streaming Output)，防止长时间无响应被误判为卡死。
    """
    print(f"   ⚙️ Executing: {cmd}")
    process = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,  # 将错误流合并到标准输出
        text=True,
        bufsize=1,  # 行缓冲
    )

    full_output = []
    start_time = time.time()

    # 确保 stdout 可用
    if process.stdout is None:
        process.wait()
        return process.returncode, "Error: stdout is None"

    # 实时读取日志
    while True:
        # 检查是否超时
        if time.time() - start_time > timeout:
            process.kill()
            return -1, "".join(full_output) + "\n[Timeout Detected]"

        # 读取一行
        line = process.stdout.readline()
        if not line and process.poll() is not None:
            break

        if line:
            # 打印到控制台 (去掉换行符防止双重换行)
            print(f"      | {line.strip()}")
            full_output.append(line)

    return process.returncode, "".join(full_output)

def wait_for_lab_healthy(yaml_path: str, max_retries: int = 10, interval: int = 3):
    """
    异步轮询：主动检查 inspect 状态，直到所有容器都 Running。
    替代死板的 time.sleep()。

    containerlab inspect 返回的 JSON 格式:
    {
      "lab-name": [
        { "name": "...", "state": "running", ... },
        ...
      ]
    }
    """
    print("   ⏳ Polling for container readiness...")

    for attempt in range(max_retries):
        cmd = f"sudo containerlab inspect -t {yaml_path} --format json"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if res.returncode == 0:
            try:
                data = json.loads(res.stdout)

                # containerlab inspect 返回格式是 { "lab-name": [containers...] }
                # 需要找到第一个值（容器列表）
                containers = []
                for value in data.values():
                    if isinstance(value, list):
                        containers = value
                        break

                # 1. 检查是否有容器
                if not containers:
                    print(f"      [Attempt {attempt+1}] Inspect returned valid JSON but no containers found.")
                    if attempt == 0:
                        print(f"      [Debug Raw Output]: {res.stdout[:200]}...")
                    time.sleep(interval)
                    continue

                # 2. 检查所有容器是否都是 'running'
                not_ready = [c['name'] for c in containers if c['state'].lower() != 'running']

                if not not_ready:
                    print(f"      ✅ All {len(containers)} containers are RUNNING.")
                    return True, data
                else:
                    print(f"      [Attempt {attempt+1}] Waiting for: {not_ready}")
            except json.JSONDecodeError as e:
                print(f"      [Attempt {attempt+1}] JSON decode error: {e}")
        else:
            print(f"      [Attempt {attempt+1}] Inspect command failed (rc={res.returncode})")

        time.sleep(interval)

    return False, None

def fix_permissions(path):
    """
    递归修改指定路径的所有权，将其从 root 改回当前 sudo 的调用用户。
    这样 VSCode (普通用户) 才能读取状态文件。
    """
    print(f"   🔧 Fixing permissions for path: {path}")
    # 使用 shell 逻辑动态判断：如果有 SUDO_USER (通过 sudo 运行脚本)，就用它；否则用当前用户
    cmd = f"if [ -n \"$SUDO_USER\" ]; then chown -R $SUDO_USER:$SUDO_USER {path}; else chown -R $(id -un):$(id -gn) {path}; fi"
    subprocess.run(f"sudo sh -c '{cmd}'", shell=True)

def deploy(state: GraphState):
    yaml_path = os.path.abspath(state['yaml_path'])
    print(f"\n🚀 [Deployer] Async-style Deployment: {yaml_path}")
    
    # 1. PRE-CLEAN (快速清理)
    subprocess.run(f"sudo containerlab destroy -t {yaml_path} --cleanup", 
                   shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    
    # 2. STREAMING DEPLOY (实时输出)
    # 使用流式执行，你可以看到 apt-install 的每一行进度
    return_code, logs = run_command_streaming(
        f"sudo containerlab deploy -t {yaml_path} --reconfigure", 
        timeout=600 # 给足时间装软件
    )
    
    if return_code != 0:
        print("❌ Deploy command failed.")
        return {
            "error_logs": logs[-1000:], # 只返回最后1000字符避免 Token 爆炸
            "is_deployed": False,
            "inspect_data": None
        }

    output_dir = os.path.dirname(yaml_path) 
    fix_permissions(output_dir)
    # 3. ACTIVE POLLING (主动轮询健康检查)
    # 这里不再傻睡 5秒，而是智能等待直到就绪
    is_healthy, inspect_data = wait_for_lab_healthy(yaml_path)
    
    if not is_healthy:
        msg = "Timeout waiting for containers to become 'running'."
        print(f"❌ {msg}")
        return {
            "error_logs": msg,
            "is_deployed": False,
            "inspect_data": None
        }

    print("✅ Deployment & Health Check Passed.")
    return {
        "error_logs": "",
        "is_deployed": True,
        "inspect_data": inspect_data
    }