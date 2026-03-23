"""配置应用器

负责使用 nsenter 为容器应用网络配置，并收集诊断数据。
"""
import os
import subprocess
import json
from typing import Dict, Any, Optional

from clab_builder.logger import get_logger


class ConfigApplier:
    """网络配置应用器

    使用 nsenter 在容器的网络命名空间中执行命令来应用网络配置。
    支持诊断数据收集以验证配置状态。
    """

    def __init__(self, lab_name: str, config_dir: str = "./clab_out"):
        """初始化配置应用器

        Args:
            lab_name: 实验名称
            config_dir: 配置文件目录
        """
        self.lab_name = lab_name
        self.config_dir = config_dir
        self.config_file = os.path.join(config_dir, f"{lab_name}.config.json")
        self.logger = get_logger("node.apply_config")

    def load_config(self) -> Dict[str, Any]:
        """加载配置 JSON 文件

        Returns:
            配置字典

        Raises:
            FileNotFoundError: 配置文件不存在
        """
        if not os.path.exists(self.config_file):
            raise FileNotFoundError(f"Config file not found: {self.config_file}")

        with open(self.config_file, 'r') as f:
            return json.load(f)

    def get_container_pid(self, node_name: str) -> Optional[int]:
        """获取运行中容器的 PID

        Args:
            node_name: 节点名称

        Returns:
            容器 PID，如果容器未找到或未运行则返回 None
        """
        container_name = f"clab-{self.lab_name}-{node_name}"
        try:
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Pid}}", container_name],
                capture_output=True,
                text=True,
                check=True,
                timeout=10
            )
            return int(result.stdout.strip())
        except subprocess.CalledProcessError:
            self.logger.warning(f"Container {container_name} not found or not running")
            return None
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Timeout getting PID for {container_name}")
            return None
        except ValueError:
            self.logger.error(f"Invalid PID returned for {container_name}")
            return None

    def nsenter_exec(self, pid: int, command: str) -> bool:
        """使用 nsenter 在容器网络命名空间中执行命令

        Args:
            pid: 容器 PID
            command: 要执行的命令

        Returns:
            命令是否成功执行
        """
        if not pid:
            return False

        try:
            full_cmd = f"sudo nsenter -n -t {pid} -- {command}"
            subprocess.run(full_cmd, shell=True, check=True, capture_output=True, timeout=30)
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command failed: {command}")
            self.logger.error(f"Error: {e.stderr.decode() if e.stderr else str(e)}")
            return False
        except subprocess.TimeoutExpired:
            self.logger.error(f"Command timeout: {command}")
            return False

    def _nsenter_capture(self, pid: int, command: str) -> str:
        """使用 nsenter 执行命令并返回输出

        Args:
            pid: 容器 PID
            command: 要执行的命令

        Returns:
            命令输出，失败时返回空字符串或错误信息
        """
        if not pid:
            return ""

        try:
            full_cmd = f"sudo nsenter -n -t {pid} -- {command}"
            result = subprocess.run(
                full_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            self.logger.warning(f"Command failed: {command}")
            return e.stderr or ""
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Command timeout: {command}")
            return ""

    def apply_node_config(self, node_name: str, node_config: Dict[str, Any]) -> bool:
        """为单个节点应用网络配置

        Args:
            node_name: 节点名称
            node_config: 节点配置字典

        Returns:
            配置是否成功应用
        """
        self.logger.debug(f"Configuring {node_name}...")

        role = node_config.get("role")

        # 获取容器 PID
        pid = self.get_container_pid(node_name)
        if not pid:
            self.logger.warning(f"  Container not found for {node_name}, skipping")
            return False

        success = True

        # 路由器：跳过 IP 配置（FRR 处理），但需重启 FRR
        if role == "router":
            self.logger.debug(f"  Router {node_name} - skipping IP config (FRR managed)")
            # 重启 FRR 以应用 bind mount 的配置
            if "frr" in node_config:
                self.logger.debug(f"  Restarting FRR for {node_name}...")
                if not self.nsenter_exec(pid, "killall -HUP zebra ospfd"):
                    self.logger.warning(f"  Failed to restart FRR")
                    success = False
            return success

        # 非路由器：应用 IP 地址和路由
        # 应用 IP 地址
        if "interfaces" in node_config:
            for iface in node_config["interfaces"]:
                iface_name = iface["name"]
                address = iface["address"]

                self.logger.debug(f"  Setting {iface_name}: {address}")

                if not self.nsenter_exec(pid, f"ip addr add {address} dev {iface_name}"):
                    self.logger.warning(f"  Failed to add address to {iface_name}")
                    success = False

                if not self.nsenter_exec(pid, f"ip link set dev {iface_name} up"):
                    self.logger.warning(f"  Failed to bring up {iface_name}")
                    success = False

        # 应用默认路由
        if "default_route" in node_config:
            route = node_config["default_route"]
            gateway = route.get("gateway")

            if gateway:
                self.logger.debug(f"  Setting default route via {gateway}")
                if not self.nsenter_exec(pid, f"ip route replace default via {gateway}"):
                    self.logger.warning(f"  Failed to set default route")
                    success = False

        # 注意：FRR 配置通过 bind mounts 应用
        if "frr" in node_config:
            self.logger.debug(f"  Restarting FRR for {node_name}...")
            self.nsenter_exec(pid, "killall -HUP zebra ospfd")

        return success

    def apply_all(self) -> Dict[str, Any]:
        """为所有节点应用配置

        Returns:
            包含统计信息的字典
        """
        import time

        self.logger.info(f"Loading configuration from {self.config_file}")
        config = self.load_config()

        self.logger.info(f"Applying network configuration for lab: {config['lab_name']}")
        self.logger.debug(f"Subnets: {config['subnets']}")

        success_count = 0
        failed_nodes = []
        skipped_count = 0

        for node_name, node_config in config["nodes"].items():
            # 跳过网桥节点（它们不需要网络配置）
            role = node_config.get("role", "")
            if role == "switch":
                self.logger.debug(f"  Skipping {node_name} (role: {role}, no network config needed)")
                skipped_count += 1
                continue

            if self.apply_node_config(node_name, node_config):
                success_count += 1
            else:
                failed_nodes.append(node_name)

        total = len(config["nodes"]) - skipped_count  # 只统计需要配置的节点
        self.logger.info(f"Configuration complete: {success_count}/{total} nodes configured (skipped {skipped_count} bridge nodes)")

        if failed_nodes:
            self.logger.warning(f"Failed nodes: {', '.join(failed_nodes)}")

        # 等待配置真正应用（给内核时间配置 IP）
        self.logger.info("Waiting for network configuration to take effect...")
        time.sleep(2)

        # 验证关键节点的 IP 是否配置成功
        verify_count = 0
        for node_name, node_config in config["nodes"].items():
            role = node_config.get("role")
            # 只验证端点和漏洞目标节点的 IP 配置
            if role in ["endpoint", "vul-target"] and "interfaces" in node_config:
                if self._verify_ip_config(node_name, node_config):
                    verify_count += 1
                else:
                    self.logger.warning(f"  IP verification failed for {node_name}")

        self.logger.info(f"IP verification: {verify_count}/{total} nodes verified")

        return {
            "total": total,
            "success": success_count,
            "failed": len(failed_nodes),
            "failed_nodes": failed_nodes
        }

    def _verify_ip_config(self, node_name: str, node_config: Dict[str, Any]) -> bool:
        """验证节点的 IP 配置是否已应用

        Args:
            node_name: 节点名称
            node_config: 节点配置字典

        Returns:
            IP 配置是否正确
        """
        pid = self.get_container_pid(node_name)
        if not pid:
            return False

        for iface in node_config.get("interfaces", []):
            expected_ip = iface.get("address", "").split("/")[0]  # 去掉 /24
            iface_name = iface.get("name")

            if not expected_ip or not iface_name:
                continue

            # 检查 IP 是否已配置
            ip_output = self._nsenter_capture(pid, f"ip addr show {iface_name}")
            if expected_ip not in ip_output:
                return False

        return True

    def collect_diagnostics(self, yaml_path: str = None) -> Dict[str, Any]:
        """收集所有节点的原始诊断数据（不做判断，由 LLM 分析）

        注意：所有配置信息均从 JSON 读取（唯一真源），不再依赖 YAML。
        yaml_path 参数已废弃，保留仅为向后兼容。

        Args:
            yaml_path: 已废弃，不再使用（保留仅为向后兼容）

        Returns:
            包含所有节点原始诊断数据的字典
        """
        self.logger.info(f"Loading configuration from {self.config_file}")
        config = self.load_config()

        # 不再需要加载 YAML - 所有配置（包括 ports）都在 JSON 中

        self.logger.info(f"Collecting diagnostics for lab: {config['lab_name']}")

        diagnostics = {
            "lab_name": config['lab_name'],
            "nodes": {}
        }

        # Sort nodes to ensure consistent ordering in diagnostics and LLM analysis
        # This helps maintain predictable output order in configure node logs
        for node_name in sorted(config["nodes"].keys()):
            node_config = config["nodes"][node_name]
            node_diagnostics = self._collect_node_diagnostics(node_name, node_config)
            diagnostics["nodes"][node_name] = node_diagnostics

        self.logger.info(f"Diagnostics collected for {len(diagnostics['nodes'])} nodes")

        return diagnostics

    def _collect_node_diagnostics(
        self,
        node_name: str,
        node_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """收集单个节点的原始诊断数据（不做判断）

        所有配置信息（包括 ports）均从 node_config（JSON）读取。

        Args:
            node_name: 节点名称
            node_config: 节点配置字典（从 JSON 加载，包含 container_config）

        Returns:
            节点诊断数据字典
        """
        self.logger.debug(f"Collecting diagnostics from: {node_name}")

        diagnostics = {
            "node": node_name,
            "checks": {}
        }

        # 1. 检查容器是否存在
        pid = self.get_container_pid(node_name)
        if not pid:
            diagnostics["checks"]["container"] = {
                "status": "not_found",
                "message": "Container not found or not running",
                "pid": None
            }
            return diagnostics

        diagnostics["checks"]["container"] = {
            "status": "running",
            "message": f"Container running (PID: {pid})",
            "pid": pid
        }

        # 2. 收集 IP 地址配置
        ip_output = self._nsenter_capture(pid, "ip addr show")
        diagnostics["checks"]["ip_config"] = {
            "raw_output": ip_output,
            "expected": node_config.get("interfaces", [])
        }

        # 3. 收集接口状态
        iface_output = self._nsenter_capture(pid, "ip link show")
        diagnostics["checks"]["interfaces"] = {
            "raw_output": iface_output,
            "expected": node_config.get("interfaces", [])
        }

        # 4. 收集路由配置
        route_output = self._nsenter_capture(pid, "ip route show")
        diagnostics["checks"]["routes"] = {
            "raw_output": route_output,
            "expected": node_config.get("default_route", None)
        }

        # 5. 收集端口监听状态
        port_output = self._nsenter_capture(pid, "ss -tlnp")
        if not port_output:
            port_output = self._nsenter_capture(pid, "netstat -tlnp")
        # 从 JSON 的 container_config 读取 ports（唯一真源）
        expected_ports = node_config.get("container_config", {}).get("ports", [])
        diagnostics["checks"]["ports"] = {
            "raw_output": port_output,
            "expected": expected_ports
        }

        # 6. 收集进程状态
        process_output = self._nsenter_capture(pid, "ps aux")
        diagnostics["checks"]["processes"] = {
            "raw_output": process_output,
            "expected_image": node_config.get("image", "")
        }

        return diagnostics
