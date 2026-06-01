"""
CVE环境容器管理器

负责独立启动和管理CVE环境容器，提供网络隔离、IP获取等基础功能。
"""

import subprocess
import time
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ContainerInfo:
    """容器信息"""
    container_id: str
    container_name: str
    container_ip: str
    image_name: str
    ports: List[int]
    status: str
    created_time: str


class CVEEnvironmentManager:
    """CVE环境容器管理器"""

    def __init__(self, network_name: str = "cve-network"):
        self.network_name = network_name
        self.running_containers: Dict[str, ContainerInfo] = {}

        # 初始化网络
        self._ensure_network_exists()

    def _ensure_network_exists(self):
        """确保Docker网络存在"""
        try:
            result = subprocess.run(
                ["docker", "network", "inspect", self.network_name],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                print(f"🌐 创建Docker网络: {self.network_name}")
                subprocess.run(
                    ["docker", "network", "create", self.network_name],
                    capture_output=True
                )
            else:
                print(f"✅ Docker网络已存在: {self.network_name}")

        except Exception as e:
            print(f"❌ 创建网络失败: {e}")

    def start_cve_container(self, cve_id: str, docker_image: str,
                          ports: List[int]) -> ContainerInfo:
        """启动CVE环境容器"""

        container_name = f"cve-{cve_id.replace('-', '').lower()}"

        print(f"🚀 启动CVE环境容器: {container_name}")
        print(f"   镜像: {docker_image}")
        print(f"   端口: {ports}")

        # 准备端口映射
        port_mappings = []
        for port in ports:
            port_mappings.extend(["-p", f"{port}:{port}"])

        try:
            # 启动容器
            cmd = [
                "docker", "run", "-d",
                f"--name={container_name}",
                f"--network={self.network_name}",
                *port_mappings,
                docker_image
            ]

            print(f"   执行命令: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120  # 2分钟超时
            )

            if result.returncode != 0:
                print(f"❌ 容器启动失败:")
                print(f"   stdout: {result.stdout}")
                print(f"   stderr: {result.stderr}")
                raise RuntimeError(f"容器启动失败: {result.stderr}")

            container_id = result.stdout.strip()

            # 等待容器完全启动
            time.sleep(5)

            # 获取容器IP
            container_ip = self.get_container_ip(container_id)

            # 验证容器状态
            status = self._check_container_status(container_id)

            container_info = ContainerInfo(
                container_id=container_id,
                container_name=container_name,
                container_ip=container_ip,
                image_name=docker_image,
                ports=ports,
                status=status,
                created_time=time.strftime("%Y-%m-%d %H:%M:%S")
            )

            self.running_containers[cve_id] = container_info

            print(f"✅ CVE容器启动成功:")
            print(f"   ID: {container_id[:12]}...")
            print(f"   IP: {container_ip}")
            print(f"   状态: {status}")

            return container_info

        except subprocess.TimeoutExpired:
            raise TimeoutError("容器启动超时（>120秒）")
        except Exception as e:
            raise RuntimeError(f"启动CVE容器时出错: {e}")

    def get_container_ip(self, container_id: str) -> str:
        """获取容器IP地址"""
        try:
            # 使用docker inspect获取IP
            result = subprocess.run(
                ["docker", "inspect", container_id],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                raise RuntimeError(f"无法获取容器信息: {result.stderr}")

            inspect_data = json.loads(result.stdout)

            # 尝试获取IP地址
            ip_address = None

            # 方法1: 从NetworkSettings.Networks获取（推荐）
            networks = inspect_data[0].get("NetworkSettings", {}).get("Networks", {})
            if networks:
                for network_name, network_info in networks.items():
                    ip_address = network_info.get("IPAddress", "")
                    if ip_address and ip_address != "":
                        print(f"   找到IP {ip_address} (网络: {network_name})")
                        break

            # 方法2: 直接从IPAddress获取
            if not ip_address or ip_address == "":
                ip_address = inspect_data[0].get("NetworkSettings", {}).get("IPAddress", "")

            if not ip_address:
                # 方法3: 使用docker inspect命令格式
                result = subprocess.run(
                    ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}", container_id],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0 and result.stdout.strip():
                    ip_address = result.stdout.strip()

            if not ip_address:
                raise RuntimeError("无法获取容器IP地址")

            return ip_address

        except json.JSONDecodeError as e:
            raise RuntimeError(f"解析docker inspect输出失败: {e}")
        except Exception as e:
            raise RuntimeError(f"获取容器IP时出错: {e}")

    def _check_container_status(self, container_id: str) -> str:
        """检查容器状态"""
        try:
            result = subprocess.run(
                ["docker", "inspect", "-f", "'{{.State.Status}}'", container_id],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                status = result.stdout.strip()
                if status and status != "":
                    return status
                else:
                    return "running"
            else:
                return "error"

        except Exception as e:
            print(f"⚠️  检查容器状态时出错: {e}")
            return "unknown"

    def stop_cve_container(self, cve_id: str) -> bool:
        """停止CVE容器"""
        if cve_id not in self.running_containers:
            print(f"⚠️  CVE容器不存在: {cve_id}")
            return False

        container_info = self.running_containers[cve_id]

        print(f"🛑 停止CVE容器: {container_info.container_name}")

        try:
            # 停止容器
            result = subprocess.run(
                ["docker", "stop", container_info.container_id],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                print(f"✅ 容器已停止: {container_info.container_name}")
                del self.running_containers[cve_id]
                return True
            else:
                print(f"❌ 停止容器失败: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            print("❌ 停止容器超时")
            return False
        except Exception as e:
            print(f"❌ 停止容器时出错: {e}")
            return False

    def cleanup_cve_container(self, cve_id: str) -> bool:
        """清理CVE容器（停止并删除）"""
        if cve_id not in self.running_containers:
            print(f"⚠️  CVE容器不存在: {cve_id}")
            return False

        container_info = self.running_containers[cve_id]

        print(f"🧹 清理CVE容器: {container_info.container_name}")

        try:
            # 先停止
            self.stop_cve_container(cve_id)

            # 再删除
            result = subprocess.run(
                ["docker", "rm", container_info.container_id],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                print(f"✅ 容器已清理: {container_info.container_name}")
                return True
            else:
                print(f"⚠️  删除容器失败: {result.stderr}")
                return False

        except Exception as e:
            print(f"❌ 清理容器时出错: {e}")
            return False

    def get_container_info(self, cve_id: str) -> Optional[ContainerInfo]:
        """获取容器信息"""
        return self.running_containers.get(cve_id)

    def list_running_containers(self) -> Dict[str, ContainerInfo]:
        """列出所有运行的CVE容器"""
        return self.running_containers.copy()

    def cleanup_all_containers(self) -> Tuple[int, int]:
        """清理所有CVE容器"""
        print("🧹 清理所有CVE容器...")

        container_ids = list(self.running_containers.keys())
        success_count = 0

        for cve_id in container_ids:
            if self.cleanup_cve_container(cve_id):
                success_count += 1

        print(f"✅ 清理完成: {success_count}/{len(container_ids)} 个容器")
        return success_count, len(container_ids)

    def get_network_name(self) -> str:
        """获取网络名称"""
        return self.network_name


class NetworkManager:
    """网络管理器 - 负责网络隔离和配置"""

    def __init__(self, network_name: str = "cve-network"):
        self.network_name = network_name
        self.network_subnets = {}

    def create_isolated_network(self, subnet_name: str = "isolated") -> str:
        """创建隔离网络子网"""
        subnet_cidr = "172.{}.0.0/16".format(hash(subnet_name) % 256)

        try:
            result = subprocess.run([
                "docker", "network", "create",
                "--driver", "bridge",
                "--subnet", subnet_cidr,
                f"{self.network_name}-{subnet_name}"
            ], capture_output=True, text=True)

            if result.returncode == 0:
                network_full_name = f"{self.network_name}-{subnet_name}"
                self.network_subnets[subnet_name] = network_full_name
                print(f"✅ 创建隔离网络: {network_full_name} ({subnet_cidr})")
                return network_full_name
            else:
                print(f"❌ 创建网络失败: {result.stderr}")
                raise RuntimeError(f"网络创建失败: {result.stderr}")

        except Exception as e:
            raise RuntimeError(f"创建隔离网络时出错: {e}")

    def get_network_info(self, network_name: str = None) -> Dict:
        """获取网络信息"""
        target_network = network_name or self.network_name

        try:
            result = subprocess.run([
                "docker", "network", "inspect", target_network
            ], capture_output=True, text=True)

            if result.returncode == 0:
                network_data = json.loads(result.stdout)
                return network_data[0] if network_data else {}
            else:
                return {}

        except Exception as e:
            print(f"⚠️  获取网络信息时出错: {e}")
            return {}

    def cleanup_network(self):
        """清理所有相关网络"""
        print(f"🧹 清理网络: {self.network_name}")

        try:
            # 删除所有子网络
            for subnet_name, network_full_name in list(self.network_subnets.items()):
                subprocess.run([
                    "docker", "network", "rm", network_full_name
                ], capture_output=True)
                print(f"   删除子网络: {network_full_name}")

            # 删除主网络
            result = subprocess.run([
                "docker", "network", "rm", self.network_name
            ], capture_output=True)

            if result.returncode == 0:
                print(f"✅ 网络清理完成")

        except Exception as e:
            print(f"⚠️  网络清理时出错: {e}")