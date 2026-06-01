#!/usr/bin/env python3
"""
Agent容器启动和验证工具

用于测试和修复Agent容器启动问题
"""

import subprocess
import sys
from pathlib import Path


def check_docker():
    """检查Docker是否可用"""
    try:
        result = subprocess.run(
            ["docker", "--version"],
            capture_output=True,
            check=True
        )
        print("✅ Docker可用")
        return True
    except:
        print("❌ Docker不可用")
        return False


def check_agent_image():
    """检查Agent镜像是否存在"""
    try:
        result = subprocess.run(
            ["docker", "images", "security-researcher-agent:latest"],
            capture_output=True,
            text=True
        )
        if "security-researcher-agent" in result.stdout:
            print("✅ Agent镜像存在")
            return True
        else:
            print("❌ Agent镜像不存在")
            print("请运行: cd agent_container && ./build.sh")
            return False
    except:
        print("❌ 无法检查镜像")
        return False


def force_start_agent_container(container_name="security-researcher-agent",
                                network_name="cve-test-network"):
    """强制启动Agent容器"""
    print(f"🧹 清理旧容器（如果存在）")
    subprocess.run(
        ["docker", "rm", "-f", container_name],
        capture_output=True
    )

    print(f"🚀 启动新的Agent容器: {container_name}")

    cmd = [
        "docker", "run", "-d",
        f"--name={container_name}",
        f"--network={network_name}",
        "-v", "/tmp/agent_workspace:/workspace",
        "security-researcher-agent:latest",
        "tail", "-f", "/dev/null"
    ]

    print(f"执行: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"❌ 启动失败: {result.stderr}")
        return None

    container_id = result.stdout.strip()
    print(f"✅ Agent容器已启动: {container_id[:12]}...")

    # 验证容器状态
    import time
    time.sleep(2)

    status_result = subprocess.run(
        ["docker", "inspect", "-f", "'{{.State.Status}}'", container_name],
        capture_output=True,
        text=True
    )
    status = status_result.stdout.strip().strip("'").strip('"')
    print(f"   容器状态: {status}")

    return container_id


def verify_agent_tools(container_name="security-researcher-agent"):
    """验证Agent容器中的工具"""
    print(f"🔍 验证Agent容器中的工具:")

    tools = {
        "curl": ["curl", "--version"],
        "nc": ["which", "nc"],
        "python3": ["python3", "--version"],
        "nmap": ["which", "nmap"]
    }

    all_available = True
    for tool, cmd in tools.items():
        result = subprocess.run(
            ["docker", "exec", container_name] + cmd,
            capture_output=True,
            text=True
        )
        available = result.returncode == 0
        print(f"   {'✅' if available else '❌'} {tool}: {'可用' if available else '不可用'}")
        if not available and tool in ["curl", "nc", "python3"]:
            all_available = False

    return all_available


def test_agent_connectivity(container_name="security-researcher-agent",
                           cve_container="cve-cve202346604"):
    """测试Agent容器的网络连通性"""
    print(f"🔍 测试网络连通性:")

    # 获取CVE容器IP
    try:
        result = subprocess.run([
            "docker", "inspect", "-f",
            "'{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'",
            cve_container
        ], capture_output=True, text=True)

        cve_ip = result.stdout.strip().strip("'").strip('"')
        print(f"   CVE容器IP: {cve_ip}")

        if not cve_ip:
            print(f"   ❌ 无法获取CVE容器IP")
            return False

        # 测试HTTP连接
        result = subprocess.run([
            "docker", "exec", container_name,
            "curl", "-s", "-o", "/dev/null",
            "-w", "%{http_code}",
            f"http://{cve_ip}:8161"
        ], capture_output=True, text=True)

        http_code = result.stdout.strip()
        print(f"   HTTP连接: {'✅ ' + http_code if http_code == '200' else '❌ ' + http_code}")

        return http_code == "200"

    except Exception as e:
        print(f"   ❌ 连接测试失败: {e}")
        return False


def main():
    """主函数"""
    print("=" * 60)
    print("Agent容器启动和验证工具")
    print("=" * 60)

    # 检查Docker
    if not check_docker():
        return 1

    # 检查镜像
    if not check_agent_image():
        return 1

    # 启动容器
    container_id = force_start_agent_container()
    if not container_id:
        return 1

    # 验证工具
    if not verify_agent_tools():
        print("⚠️  部分核心工具不可用")

    # 测试连通性
    test_agent_connectivity()

    print("\n✅ Agent容器验证完成!")
    print(f"容器ID: {container_id}")
    print(f"\n💡 使用方法:")
    print(f"  docker exec security-researcher-agent <command>")
    print(f"  docker exec security-researcher-agent bash")

    return 0


if __name__ == "__main__":
    sys.exit(main())
