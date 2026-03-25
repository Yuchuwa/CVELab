"""网络构建器

负责根据 NetworkBlueprint 生成 containerlab 配置文件。
"""
import os
import yaml
import json
import ipaddress
import shutil
import secrets
import string
from collections import defaultdict
from typing import Dict, Any, List

from .models import (
    NetworkBlueprint, LogicalNode,
    LabConfig, NodeConfig, ContainerConfig,
    InterfaceConfig, DefaultRoute, FRRConfig,
    TopologyLink, LinkEndpoint, ClabYAML, ClabTopology
)


class NetworkBuilder:
    """网络拓扑构建器

    将逻辑网络蓝图转换为 containerlab 可用的 YAML 和 JSON 配置文件。
    处理子网分配、IP 地址管理、节点创建和 FRR 路由配置生成。
    """

    @staticmethod
    def generate_flag(length: int = 32) -> str:
        """生成随机化的FLAG

        Args:
            length: FLAG随机字符串长度，默认32位

        Returns:
            格式为 FLAG{随机字符串} 的FLAG
        """
        alphabet = string.ascii_letters + string.digits
        random_str = ''.join(secrets.choice(alphabet) for _ in range(length))
        return f"FLAG{{{random_str}}}"

    def __init__(self, blueprint: NetworkBlueprint, output_dir: str = "./clab_out"):
        """初始化网络构建器

        Args:
            blueprint: 网络蓝图，包含拓扑设计
            output_dir: 输出目录，用于存放生成的配置文件
        """
        self.bp = blueprint
        self.output_dir = output_dir

        # Output structures
        self.clab_nodes: Dict[str, Any] = {}
        self.clab_links: List[Dict[str, Any]] = []

        # IPAM State
        self.supernet = ipaddress.IPv4Network("10.0.0.0/8")
        self.subnet_iterator = self.supernet.subnets(new_prefix=24)
        self.subnet_map: Dict[str, ipaddress.IPv4Network] = {}
        self.node_ip_map: Dict[str, Dict[str, str]] = defaultdict(dict) # {node: {subnet: ip}}

        # Interface mapping tracker (NEW: 修复接口编号问题)
        self.link_interface_map: Dict[str, Dict[str, str]] = defaultdict(dict)  # {node: {subnet: "eth1"}}

        # Vul-target compose file cache
        self.vul_target_compose: Dict[str, Dict[str, Any]] = {}  # {node_name: compose_data}

        # Initialize workspace
        os.makedirs(self.output_dir, exist_ok=True)

        # Only remove files if the same lab name already exists
        yaml_filename = f"{self.bp.lab_name}.clab.yml"
        yaml_path = os.path.join(self.output_dir, yaml_filename)
        lab_dir = os.path.join(self.output_dir, f"clab-{self.bp.lab_name}")

        if os.path.exists(yaml_path):
            os.remove(yaml_path)
        if os.path.exists(lab_dir):
            shutil.rmtree(lab_dir)

    def build(self) -> tuple[str, str]:
        """主构建流程（使用 Pydantic 模型）

        生成 containerlab YAML 和配置 JSON 文件。

        Returns:
            (yaml_path, json_path): 生成的文件路径元组
        """
        # 1) 内部计算：分配子网、处理拓扑、生成 FRR 配置
        self._allocate_subnets()
        self._process_topology()
        self._apply_scenario_policies()  # 应用场景特定的安全策略
        self._generate_frr_configs()

        # 2) 生成 LabConfig（Pydantic 模型，单一数据源）
        lab_config = self._generate_config_json()

        # 3) 写入 JSON（使用 model_dump）
        json_path = f"{self.output_dir}/{self.bp.lab_name}.config.json"
        with open(json_path, "w") as f:
            json.dump(lab_config.model_dump(exclude_none=True), f, indent=2)

        # 4) 直接从 self.clab_nodes 生成 YAML（包含网桥和背板容器）
        clab_yaml = self._generate_yaml_direct()
        yaml_path = f"{self.output_dir}/{self.bp.lab_name}.clab.yml"
        with open(yaml_path, "w") as f:
            yaml.dump(clab_yaml.to_yaml_dict(), f, sort_keys=False)

        # 5) 返回值保持兼容
        return yaml_path, json_path

    def _allocate_subnets(self):
        """为逻辑子网名称分配实际 CIDR 地址块（确定性排序）

        使用字母序排序确保：
        1. 即使 LLM 生成的子网顺序不同，IP 分配仍然一致
        2. 用户手动调整蓝图中的子网顺序不会影响 IP 分配
        3. 重新生成配置时保持幂等性
        """
        # 对子网名称按字母序排序，确保确定性分配
        sorted_subnets = sorted(self.bp.subnets)

        for name in sorted_subnets:
            self.subnet_map[name] = next(self.subnet_iterator)

    def _determine_image(self, flavor: str, role: str) -> str:
        """将抽象的镜像类型映射为实际的 Docker 镜像

        Args:
            flavor: 镜像类型标识符
            role: 节点角色（router/endpoint/vul-target）

        Returns:
            Docker 镜像名称
        """
        flavor = flavor.lower()

        # All routers use FRR
        if role == "router":
            return "frrouting/frr:v8.4.1"

        # Endpoint mapping
        if flavor == "kali":
            return "kalilinux/kali-rolling:latest"
        elif flavor == "ubuntu":
            return "ubuntu:latest"
        elif flavor == "alpine":
            return "alpine:latest"
        else:
            # For redis, nginx, etc.
            return f"{flavor}:latest"

    def _parse_compose_file(self, compose_path: str) -> Dict[str, Any]:
        """解析 Vulhub 路径中的 docker-compose.yml 文件

        Args:
            compose_path: Vulhub 漏洞目录路径

        Returns:
            包含 compose 文件数据的字典（image、ports 等）
        """
        compose_file = os.path.join(compose_path, "docker-compose.yml")

        if not os.path.exists(compose_file):
            return {}

        try:
            with open(compose_file, 'r') as f:
                compose_data = yaml.safe_load(f)

            # Extract the first service's configuration
            if 'services' in compose_data and compose_data['services']:
                first_service = list(compose_data['services'].values())[0]
                return {
                    'image': first_service.get('image', ''),
                    'ports': first_service.get('ports', []),
                    'volumes': first_service.get('volumes', []),
                    'env': first_service.get('environment', {}),  # docker-compose uses 'environment'
                    'command': first_service.get('command', ''),
                    'service_name': list(compose_data['services'].keys())[0]
                }
        except Exception as e:
            print(f"Warning: Failed to parse compose file {compose_file}: {e}")

        return {}

    def _process_topology(self):
        """处理网络拓扑：创建节点、连接线和 IP 分配"""
        # Group nodes by subnet to detect where switches are needed
        subnet_members = defaultdict(list)
        for node in self.bp.nodes:
            for sub in node.connected_subnets:
                subnet_members[sub].append(node)

        # 1. Create Nodes
        for node in self.bp.nodes:
            self._create_clab_node(node)

        # 2. Handle Connectivity (Switches & Links & IPs)
        for sub_name, members in subnet_members.items():
            self._wire_subnet(sub_name, members)

        # 3. Configure vul-target ports (bind to eth1 IP)
        self._configure_vul_target_ports()

    def _apply_scenario_policies(self):
        """应用场景特定的安全策略（防火墙规则、ACL、NAT等）

        场景B：
        1. 在 core-router 上添加 ACL，阻止 External 直接访问 Internal
        2. 在 edge-router 上添加 NAT 规则，允许内网访问外网

        ACL规则：
        - External (10.0.1.0/24) → Internal (10.0.2.0/24): DENY
        - DMZ (10.0.0.0/24) → Internal (10.0.2.0/24): ALLOW

        NAT规则：
        - 内网→外网: MASQUERADE on eth0
        """
        # 识别子网（支持多种命名方式）
        external_subnet = None
        dmz_subnet = None
        internal_subnet = None

        for subnet in self.bp.subnets:
            if subnet == "external":
                external_subnet = subnet
            elif subnet == "dmz":
                dmz_subnet = subnet
            elif subnet == "internal":
                internal_subnet = subnet

        # 如果没有标准名称，按字母序备用逻辑
        if not all([external_subnet, dmz_subnet, internal_subnet]):
            sorted_subnets = sorted(self.bp.subnets)
            if len(sorted_subnets) >= 3:
                # 字母序：dmz, external, internal
                dmz_subnet = sorted_subnets[0]  # dmz
                external_subnet = sorted_subnets[1]  # external
                internal_subnet = sorted_subnets[2]  # internal

        # 添加 NAT 规则到 edge-router（所有场景）
        if external_subnet:
            edge_router_name = None
            for node in self.bp.nodes:
                if node.role == "router" and external_subnet in node.connected_subnets:
                    edge_router_name = node.name
                    break

            if edge_router_name and edge_router_name in self.clab_nodes:
                router_def = self.clab_nodes[edge_router_name]
                if "exec" not in router_def:
                    router_def["exec"] = []

                # 添加 NAT MASQUERADE 规则
                nat_rule = "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"
                router_def["exec"].append(nat_rule)
                print(f"[DEBUG] Applied NAT rule to {edge_router_name}: {nat_rule}")

        # 只在场景B应用 ACL 规则
        if self.bp.scenario != "B":
            return

        # 检查是否有三段子网（场景B特征）
        if len(self.bp.subnets) < 3:
            return

        if not all([external_subnet, dmz_subnet, internal_subnet]):
            return

        # 获取子网 CIDR
        external_cidr = str(self.subnet_map.get(external_subnet))
        internal_cidr = str(self.subnet_map.get(internal_subnet))
        dmz_cidr = str(self.subnet_map.get(dmz_subnet))

        # 提取网络地址（/24）
        external_network = external_cidr[:external_cidr.rfind('.') + 1] + '0/24'
        internal_network = internal_cidr[:internal_cidr.rfind('.') + 1] + '0/24'
        dmz_network = dmz_cidr[:dmz_cidr.rfind('.') + 1] + '0/24'

        # 找到 core-router（连接 DMZ 和 Internal 的路由器）
        core_router_name = None
        for node in self.bp.nodes:
            if node.role == "router":
                # 检查是否连接 dmz 和 internal
                connected = set(node.connected_subnets)
                if dmz_subnet in connected and internal_subnet in connected:
                    core_router_name = node.name
                    # 排除 edge-router（如果同时连接 external）
                    if external_subnet in connected:
                        core_router_name = None
                    break

        if not core_router_name:
            return

        # 添加 iptables 规则到 core-router
        if core_router_name in self.clab_nodes:
            router_def = self.clab_nodes[core_router_name]

            # 确保 exec 字段存在
            if "exec" not in router_def:
                router_def["exec"] = []

            # 添加 ACL 规则
            acl_rules = [
                # 1. 阻止 External (10.0.1.0/24) 直接访问 Internal (10.0.2.0/24)
                f"iptables -A FORWARD -s {external_network} -d {internal_network} -j DROP",
                # 2. 允许 DMZ (10.0.0.0/24) 访问 Internal (10.0.2.0/24)
                f"iptables -A FORWARD -s {dmz_network} -d {internal_network} -j ACCEPT",
                # 3. 允许已建立的连接返回流量
                f"iptables -A FORWARD -s {internal_network} -d {dmz_network} -m state --state ESTABLISHED,RELATED -j ACCEPT",
                # 4. 允许 Internal → DMZ 的新连接
                f"iptables -A FORWARD -s {internal_network} -d {dmz_network} -j ACCEPT",
            ]

            # 将规则添加到 exec 列表
            router_def["exec"].extend(acl_rules)
            print(f"[DEBUG] Applied ACL rules to {core_router_name}:")
            for rule in acl_rules:
                print(f"  - {rule}")

    def _create_clab_node(self, node: LogicalNode):
        """创建 containerlab 节点定义（不包含 exec 命令）

        Args:
            node: 逻辑节点对象
        """
        # Handle vul-target role - parse docker-compose.yml from container_path
        if node.role == "vul-target" and node.container_path:
            # Parse compose file to get image and configuration
            compose_data = self._parse_compose_file(node.container_path)
            self.vul_target_compose[node.name] = compose_data

            image = compose_data.get('image', '')

            # Generate random FLAG and create bind mount to /flag
            flag = self.generate_flag()
            flag_dir = os.path.join(self.output_dir, f"flag-{node.name}")
            flag_file = os.path.join(flag_dir, "flag")
            os.makedirs(flag_dir, exist_ok=True)
            with open(flag_file, 'w') as f:
                f.write(flag)
            # Use absolute path for bind mount (containerlab requires absolute paths)
            flag_bind = f"{os.path.abspath(flag_file)}:/flag/flag"

            node_def = {
                "kind": "linux",
                "image": image,
                "exec": [],  # No exec commands - container handles its own startup
                "binds": [flag_bind],  # Bind mount FLAG to /flag
                "ports": compose_data.get('ports', []),
                "env": compose_data.get('env', {}),
                "cmd": compose_data.get('command', '')
            }
            self.clab_nodes[node.name] = node_def

            # Track node metadata for config JSON
            if not hasattr(self, '_node_metadata'):
                self._node_metadata = {}
            self._node_metadata[node.name] = {
                "role": node.role,
                "image": image,
                "image_flavor": node.image_flavor,
                "container_path": node.container_path,
                "compose_data": compose_data,
                "flag": flag
            }
            return

        image = self._determine_image(node.image_flavor, node.role)

        node_def = {
            "kind": "linux",
            "image": image,
            "exec": [],  # Empty - all config via nsenter/FRR
            "binds": [],
            "sysctls": {}
        }

        # Enable forwarding for routers
        if node.role == "router":
            node_def['sysctls'] = {"net.ipv4.ip_forward": "1"}

        self.clab_nodes[node.name] = node_def

        # Track node metadata for config JSON
        if not hasattr(self, '_node_metadata'):
            self._node_metadata = {}
        self._node_metadata[node.name] = {
            "role": node.role,
            "image": image,
            "image_flavor": node.image_flavor,
            "container_path": node.container_path
        }

    def _wire_subnet(self, subnet_name: str, members: List[LogicalNode]):
        """连接子网：创建网桥/链路并分配 IP（不包含 exec 命令）

        IP 分配策略（/24 子网）：
        - .1       : 第一个路由器
        - .2-.63   : 额外的路由器
        - .64-.254 : 端点设备

        Args:
            subnet_name: 子网名称
            members: 连接到该子网的节点列表
        """
        cidr_obj = self.subnet_map[subnet_name]

        # Step 1: Create Physical Links (L2 Topology)
        if len(members) > 2:
            # Use containerlab namespace bridge
            # 返回完整节点名（如 sw-dmz|backplane）
            bridge_full_name = self._inject_bridge_node(f"sw-{subnet_name}")

            # Connect everyone to bridge（使用完整节点名）
            for member in members:
                self._create_link(member.name, bridge_full_name, subnet_name)

        elif len(members) == 2:
            # Point-to-Point connection
            self._create_link(members[0].name, members[1].name, subnet_name)

        # Step 2: Allocate IPs (stored in node_ip_map only)
        router_ip_offset = 1  # .1 for first router
        user_lan_offset = 64  # .64 for endpoints

        routers = [m for m in members if m.role == "router"]
        endpoints = [m for m in members if m.role in ["endpoint", "vul-target"]]

        # Assign IPs to routers
        for router in routers:
            ip_str = str(cidr_obj[router_ip_offset])
            router_ip_offset += 1
            self.node_ip_map[router.name][subnet_name] = ip_str

        # Assign IPs to endpoints
        for endpoint in endpoints:
            ip_str = str(cidr_obj[user_lan_offset])
            user_lan_offset += 1
            self.node_ip_map[endpoint.name][subnet_name] = ip_str

    def _inject_bridge_node(self, name: str) -> str:
        """注入 namespace bridge 类型的交换机节点

        使用 containerlab 的 namespace bridge（在容器命名空间内创建），
        不需要宿主机特权。每个网桥都有独立的 backplane 容器。

        网桥节点命名格式：{bridge_name}|{backplane_name}（如 sw-dmz|backplane-dmz）

        Args:
            name: 网桥/交换机节点名称（如 sw-dmz, sw-internal）

        Returns:
            完整节点名（如 sw-dmz|backplane-dmz），用于创建 links
        """
        # 确保元数据字典存在
        if not hasattr(self, '_node_metadata'):
            self._node_metadata = {}

        # 从网桥名称提取 subnet 名称（如 sw-dmz -> dmz）
        subnet_name = name.replace("sw-", "", 1)
        backplane_name = f"backplane-{subnet_name}"
        bridge_full_name = f"{name}|{backplane_name}"

        # 创建 backplane 容器（作为网络命名空间载体）
        if backplane_name not in self.clab_nodes:
            self.clab_nodes[backplane_name] = {
                "kind": "linux",
                "image": "alpine:latest",
                "cmd": "sleep infinity"  # 保持容器运行，确保 namespace bridge 稳定
            }

        # backplane 容器元数据
        if backplane_name not in self._node_metadata:
            self._node_metadata[backplane_name] = {
                "role": "switch",
                "image": "alpine:latest",
                "image_flavor": "alpine",
                "container_path": None
            }

        # 创建网桥节点（namespace bridge，附加到 backplane 容器）
        if bridge_full_name not in self.clab_nodes:
            self.clab_nodes[bridge_full_name] = {
                "kind": "bridge",
                "network-mode": f"container:{backplane_name}"
            }

        # 网桥节点元数据
        if bridge_full_name not in self._node_metadata:
            self._node_metadata[bridge_full_name] = {
                "role": "switch",
                "image": None,
                "image_flavor": None,
                "container_path": None
            }

        return bridge_full_name  # 返回完整节点名供调用者使用

    def _create_link(self, node_a: str, node_b: str, subnet_name: str = None):
        """在两个节点之间创建链路（不包含 exec 命令）

        Args:
            node_a: 第一个节点名称（如果是网桥，格式如 sw-dmz）
            node_b: 第二个节点名称（如果是网桥，格式如 sw-dmz）
            subnet_name: 子网名称（用于记录接口映射）
        """
        eth_a = self._inc_interface(node_a)
        eth_b = self._inc_interface(node_b)

        # 使用节点名创建链接
        self.clab_links.append({
            "endpoints": [
                f"{node_a}:eth{eth_a}",
                f"{node_b}:eth{eth_b}"
            ]
        })

        # 记录接口映射
        if subnet_name:
            self.link_interface_map[node_a][subnet_name] = f"eth{eth_a}"
            self.link_interface_map[node_b][subnet_name] = f"eth{eth_b}"

    def _interface_tracker(self) -> defaultdict:
        """获取接口计数器"""
        if not hasattr(self, '_iface_counts'):
            self._iface_counts = defaultdict(int)
        return self._iface_counts

    def _inc_interface(self, node: str) -> int:
        """增加节点接口计数并返回新值

        Args:
            node: 节点名称

        Returns:
            新的接口编号
        """
        t = self._interface_tracker()
        t[node] += 1
        return t[node]

    def _get_interface_count(self, node: str) -> int:
        """获取节点的接口数量

        Args:
            node: 节点名称

        Returns:
            接口数量
        """
        return self._interface_tracker()[node]

    def _configure_vul_target_ports(self):
        """移除 vul-target 节点的端口映射

        Vul-target 服务应仅通过内部容器网络访问，
        不暴露给主机。这避免了端口冲突并改善网络隔离。
        """
        for node in self.bp.nodes:
            if node.role != "vul-target" or not node.container_path:
                continue

            # Remove port mappings - services only listen on container internal network
            if node.name in self.clab_nodes:
                self.clab_nodes[node.name]['ports'] = []

    def _generate_frr_configs(self):
        """为所有路由器生成 FRR 配置（不仅限于复杂模式）"""
        router_idx = 0

        for name, node_def in self.clab_nodes.items():
            # Check if this is a router
            bp_node = next((n for n in self.bp.nodes if n.name == name), None)
            if bp_node and bp_node.role == "router":

                config_path = os.path.join(self.output_dir, name)
                os.makedirs(config_path, exist_ok=True)

                # Generate unique router-id and loopback
                router_idx += 1
                unique_loopback = f"10.10.{router_idx}.1"
                router_id = unique_loopback

                # 1. Generate daemons
                with open(os.path.join(config_path, "daemons"), "w") as f:
                    f.write("zebra=yes\nospfd=yes\n")

                # 2. Generate frr.conf
                lines = [
                    "frr version 8.5",
                    "frr defaults traditional",
                    f"hostname {name}",
                    "no ipv6 forwarding",
                    "!"
                ]

                # Loopback
                lines.extend([
                    "interface lo",
                    f" ip address {unique_loopback}/32",
                    "!"
                ])

                # Physical interfaces
                current_eth = 1
                connected_subs = self.node_ip_map[name]
                ospf_networks = []

                for subnet_name, ip_addr in connected_subs.items():
                    lines.extend([
                        f"interface eth{current_eth}",
                        f" ip address {ip_addr}/24",
                        "!"
                    ])

                    # Add to OSPF (exclude management network)
                    subnet_cidr = str(self.subnet_map[subnet_name])
                    if not subnet_cidr.startswith("172.20.20"):
                        ospf_networks.append(subnet_cidr)

                    current_eth += 1

                # OSPF configuration
                lines.extend([
                    "router ospf",
                    f" ospf router-id {router_id}",
                    " passive-interface eth0",
                ])

                for network in ospf_networks:
                    lines.append(f" network {network} area 0")

                lines.append("!")

                with open(os.path.join(config_path, "frr.conf"), "w") as f:
                    f.write("\n".join(lines))

                # Add binds to node definition
                abs_path = os.path.abspath(config_path)
                node_def['binds'] = [
                    f"{abs_path}/daemons:/etc/frr/daemons",
                    f"{abs_path}/frr.conf:/etc/frr/frr.conf"
                ]

                # Store FRR config for JSON output
                if not hasattr(self, '_frr_configs'):
                    self._frr_configs = {}
                self._frr_configs[name] = {
                    "router_id": router_id,
                    "loopback": unique_loopback,
                    "ospf_networks": ospf_networks
                }

    def _generate_config_json(self) -> LabConfig:
        """生成外部配置应用器使用的配置 JSON（使用 Pydantic 模型）

        Returns:
            LabConfig: 完整的实验配置对象
        """
        # 构建 links（转换为 Pydantic 模型）
        topology_links = []
        for link in self.clab_links:
            endpoints_str = link["endpoints"]  # ["node1:eth1", "node2:eth2"]
            endpoints = []
            for ep_str in endpoints_str:
                node, iface = ep_str.split(":")
                endpoints.append(LinkEndpoint(node=node, interface=iface))
            topology_links.append(TopologyLink(endpoints=endpoints))

        # 构建 nodes
        nodes_config = {}
        for node_name in self.clab_nodes.keys():
            # Get metadata
            metadata = self._node_metadata.get(node_name, {})
            role = metadata.get("role", "endpoint")

            # 跳过 namespace bridge 节点（格式: sw-dmz|backplane-dmz）
            # 这些是附加到 backplane 容器的虚拟网桥，不是真正的容器
            if "|" in node_name:
                continue

            container_path = metadata.get("container_path")

            # 构建 interfaces（使用 link_interface_map 确保顺序正确）
            interfaces = []
            if node_name in self.node_ip_map:
                for subnet_name, ip_addr in self.node_ip_map[node_name].items():
                    # 使用 link_interface_map 获取确定性的接口名
                    iface_name = self.link_interface_map[node_name].get(subnet_name, f"eth{len(interfaces)+1}")
                    interfaces.append(InterfaceConfig(
                        name=iface_name,
                        subnet=subnet_name,
                        address=f"{ip_addr}/24"
                    ))

            # 构建 default_route（仅 endpoint/vul-target）
            default_route = None
            if role in ["endpoint", "vul-target"] and node_name in self.node_ip_map:
                # Find first router in the same subnet
                for subnet_name in self.node_ip_map[node_name].keys():
                    # Find routers in this subnet
                    for other_node, other_ips in self.node_ip_map.items():
                        if subnet_name in other_ips:
                            other_metadata = self._node_metadata.get(other_node, {})
                            if other_metadata.get("role") == "router":
                                # Get router's IP in the current subnet
                                gateway_ip = other_ips[subnet_name]
                                default_route = DefaultRoute(
                                    destination="0.0.0.0/0",
                                    gateway=gateway_ip
                                )
                                break
                    if default_route:
                        break

            # 构建 frr（仅 router）
            frr_config = None
            if role == "router" and hasattr(self, '_frr_configs') and node_name in self._frr_configs:
                frr_data = self._frr_configs[node_name]
                frr_config = FRRConfig(
                    router_id=frr_data["router_id"],
                    loopback=frr_data["loopback"],
                    ospf_networks=frr_data["ospf_networks"]
                )

            # 构建 container_config（从 self.clab_nodes 提取）
            clab_node = self.clab_nodes[node_name]
            container_config = ContainerConfig(
                kind=clab_node.get("kind", "linux"),
                image=metadata.get("image") or clab_node.get("image", ""),
                network_mode=clab_node.get("network-mode"),
                binds=clab_node.get("binds", []),
                env=clab_node.get("env", {}),
                sysctls=clab_node.get("sysctls", {}),
                cmd=clab_node.get("cmd", ""),
                ports=clab_node.get("ports", []),
                exec=clab_node.get("exec", [])
            )

            # 组装 NodeConfig
            if role == "switch":
                # Switches 是 L2 设备，不需要 IP 配置
                # 接口信息从 YAML links 中推导（因为 switch 没有 subnet 维度的接口映射）
                nodes_config[node_name] = NodeConfig(
                    role=role,
                    image=metadata.get("image", ""),
                    interfaces=[],  # Switch 接口通过 links 隐式定义
                    container_config=container_config
                )
            else:
                nodes_config[node_name] = NodeConfig(
                    role=role,
                    image=metadata.get("image", ""),
                    interfaces=interfaces,
                    default_route=default_route,
                    frr=frr_config,
                    container_config=container_config,
                    container_path=container_path,
                    flag=metadata.get("flag")
                )

        # 返回 LabConfig 对象
        return LabConfig(
            lab_name=self.bp.lab_name,
            subnets={name: str(cidr) for name, cidr in self.subnet_map.items()},
            links=topology_links,
            nodes=nodes_config
        )

    def _generate_yaml_direct(self) -> ClabYAML:
        """直接从内部状态生成 YAML（包含所有节点，包括网桥）

        Returns:
            ClabYAML: containerlab YAML 对象
        """
        # 直接使用 self.clab_nodes 构建节点配置
        clab_nodes = {}
        for node_name, node_def in self.clab_nodes.items():
            # 转换为 ContainerConfig
            container_config = ContainerConfig(
                kind=node_def.get("kind", "linux"),
                image=node_def.get("image"),
                network_mode=node_def.get("network-mode"),
                binds=node_def.get("binds", []),
                env=node_def.get("env", {}),
                sysctls=node_def.get("sysctls", {}),
                cmd=node_def.get("cmd", ""),
                ports=node_def.get("ports", []),
                exec=node_def.get("exec", [])
            )
            clab_nodes[node_name] = container_config

        # 直接使用 self.clab_links 构建链路配置
        clab_links = self.clab_links

        # 返回 ClabYAML 对象
        return ClabYAML(
            name=self.bp.lab_name,
            topology=ClabTopology(
                nodes=clab_nodes,
                links=clab_links
            )
        )

    def _generate_yaml_from_config(self, lab_config: LabConfig) -> ClabYAML:
        """从 LabConfig 生成 containerlab YAML（不依赖内部状态）

        Args:
            lab_config: 完整的实验配置对象

        Returns:
            ClabYAML: containerlab YAML 对象
        """
        # 构建 nodes（直接使用 container_config）
        clab_nodes = {}
        for node_name, node_config in lab_config.nodes.items():
            clab_nodes[node_name] = node_config.container_config

        # 构建 links（转换为 containerlab 格式）
        clab_links = [link.to_clab_format() for link in lab_config.links]

        # 返回 ClabYAML 对象
        return ClabYAML(
            name=lab_config.lab_name,
            topology=ClabTopology(
                nodes=clab_nodes,
                links=clab_links
            )
        )


# ============================================
# 独立函数：从JSON重新生成YAML
# ============================================

def regenerate_yaml_from_json(
    json_path: str,
    yaml_path: str = None
) -> str:
    """
    从JSON配置文件重新生成YAML（独立函数，不依赖NetworkBuilder实例）

    用于Fixer修改JSON后快速更新YAML，无需重新构建整个拓扑。

    Args:
        json_path: JSON配置文件路径
        yaml_path: 输出的YAML文件路径（可选，默认与json同目录）

    Returns:
        生成的YAML文件路径

    Raises:
        FileNotFoundError: JSON文件不存在
        ValueError: JSON格式错误
        ValidationError: JSON不符合LabConfig schema
    """
    import yaml
    from logger import get_logger

    logger = get_logger("node.builder")
    logger.info(f"Regenerating YAML from JSON: {json_path}")

    # 1. 确定输出路径
    if yaml_path is None:
        import os
        lab_name = os.path.basename(json_path).replace('.config.json', '')
        output_dir = os.path.dirname(json_path)
        yaml_path = os.path.join(output_dir, f"{lab_name}.clab.yml")

    # 2. 加载JSON文件
    try:
        with open(json_path, 'r') as f:
            config_data = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"JSON file not found: {json_path}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format: {e}")

    # 3. 解析为LabConfig模型（验证格式）
    try:
        lab_config = LabConfig(**config_data)
    except Exception as e:
        logger.error(f"JSON validation failed: {e}")
        raise ValueError(f"JSON does not match LabConfig schema: {e}")

    # 4. 从LabConfig生成YAML（复用现有逻辑）
    try:
        clab_yaml = _generate_yaml_from_lab_config(lab_config)
    except Exception as e:
        logger.error(f"YAML generation failed: {e}")
        raise RuntimeError(f"Failed to generate YAML: {e}")

    # 5. 写入YAML文件
    try:
        with open(yaml_path, 'w') as f:
            yaml.dump(clab_yaml.to_yaml_dict(), f, sort_keys=False)
        logger.info(f"✓ YAML regenerated successfully: {yaml_path}")
    except Exception as e:
        logger.error(f"Failed to write YAML: {e}")
        raise IOError(f"Failed to write YAML file: {e}")

    return yaml_path


def _generate_yaml_from_lab_config(lab_config: LabConfig) -> ClabYAML:
    """
    从LabConfig生成ClabYAML（独立静态方法）

    这是NetworkBuilder._generate_yaml_from_config()的无状态版本，
    可以独立调用，不依赖NetworkBuilder实例。

    Args:
        lab_config: 完整的实验配置对象

    Returns:
        ClabYAML: containerlab YAML对象
    """
    # Step 1: 从 links 中提取所有网桥节点名（以 sw- 开头）
    bridge_nodes = set()
    for link in lab_config.links:
        for endpoint in link.endpoints:
            node_name = endpoint.node
            if node_name.startswith("sw-"):
                bridge_nodes.add(node_name)

    # Step 2: 构建 nodes（从 JSON 中获取）
    clab_nodes = {}
    for node_name, node_config in lab_config.nodes.items():
        clab_nodes[node_name] = node_config.container_config

    # Step 3: 添加 namespace bridge 节点（格式: sw-dmz|backplane-dmz）
    for bridge_full_name in sorted(bridge_nodes):
        if bridge_full_name not in clab_nodes:
            # Namespace bridge: 提取 backplane 名称并设置 network-mode
            bridge_name, backplane_name = bridge_full_name.split("|", 1)

            # 确保 backplane 容器存在
            if backplane_name not in clab_nodes:
                # 从 JSON 中查找 backplane 配置
                backplane_config = None
                for node_name, node_config in lab_config.nodes.items():
                    if node_name == backplane_name:
                        backplane_config = node_config.container_config
                        break

                if backplane_config:
                    clab_nodes[backplane_name] = backplane_config

            # 创建 namespace bridge 节点
            clab_nodes[bridge_full_name] = ContainerConfig(
                kind="bridge",
                network_mode=f"container:{backplane_name}"
            )

    # Step 4: 构建 links（转换为 containerlab 格式）
    clab_links = [link.to_clab_format() for link in lab_config.links]

    # 返回 ClabYAML 对象
    return ClabYAML(
        name=lab_config.lab_name,
        topology=ClabTopology(
            nodes=clab_nodes,
            links=clab_links
        )
    )
