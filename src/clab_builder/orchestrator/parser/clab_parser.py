"""ContainerLab标准格式解析器

支持ContainerLab原生YAML格式，从labels中提取元数据
"""
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional
from clab_builder.shared.models import (
    ContainerLabTopology, NetworkNode, NetworkLink,
    TopologySpecification, IsolationPolicy, SecurityZone,
)


class ContainerLabParser:
    """ContainerLab标准格式解析器"""

    def __init__(self, yaml_file: str):
        self.yaml_file = Path(yaml_file)
        self.raw_data = self._load_yaml()
        self.clab_topology = self._parse_clab_format()

    def _load_yaml(self) -> Dict[str, Any]:
        """加载YAML文件"""
        with open(self.yaml_file, 'r') as f:
            return yaml.safe_load(f)

    def _parse_clab_format(self) -> ContainerLabTopology:
        """解析ContainerLab格式"""
        return ContainerLabTopology(**self.raw_data)

    def extract_topology_specification(self) -> TopologySpecification:
        """转换为拓扑规格"""
        nodes = []
        links = []

        # 解析节点
        topology_nodes = self.raw_data.get('topology', {}).get('nodes', {})
        for node_name, node_config in topology_nodes.items():
            if not isinstance(node_config, dict):
                raise ValueError(f"Invalid node config for {node_name}: expected mapping")
            if not any(k in node_config for k in ("kind", "image", "labels")):
                raise ValueError(
                    f"Invalid node config for {node_name}: missing kind/image/labels"
                )

            # 从labels提取元数据
            labels = node_config.get('labels', {})
            role = labels.get('role', 'endpoint')

            # 支持多种CVE字段格式
            cve_id = labels.get('cve') or labels.get('cve_id')

            # 构建网络节点
            network_node = NetworkNode(
                name=node_name,
                type=self._map_node_type(role),
                image=node_config.get('image', 'alpine:latest'),
                networks=self._extract_networks(node_config),
                role=role,
                ports=node_config.get('ports', []),
                cve_injection=self._extract_cve_info(cve_id, labels),
                routing=self._extract_routing_info(labels),
                vars={
                    'kind': node_config.get('kind', 'linux'),
                    **{k: v for k, v in labels.items() if k not in ['role', 'cve', 'cve_id', 'cve_name', 'cvss_score']}
                }
            )
            nodes.append(network_node)

        # 解析链路
        topology_links = self.raw_data.get('topology', {}).get('links', [])
        for link_config in topology_links:
            endpoints = link_config.get('endpoints', [])
            if len(endpoints) == 2:
                source, destination = endpoints
                source_node, source_iface = source.split(':')
                dest_node, dest_iface = destination.split(':')

                network_link = NetworkLink(
                    source=source_node,
                    source_interface=source_iface,
                    destination=dest_node,
                    destination_interface=dest_iface
                )
                links.append(network_link)

        # 解析网络隔离策略
        isolation_policies = self._parse_isolation_policies()

        # 解析安全区域
        security_zones = self._parse_security_zones(nodes, isolation_policies)

        return TopologySpecification(
            lab_name=self.raw_data.get('name', 'lab'),
            description=self.raw_data.get('description', ''),
            nodes=nodes,
            links=links,
            isolation_policies=isolation_policies,
            security_zones=security_zones,
            topology_data=self.raw_data
        )

    def _map_node_type(self, role: str) -> str:
        """映射角色到节点类型"""
        role_mapping = {
            'attacker': 'attacker',
            'router': 'router',
            'vuln-target': 'vuln-target',
            'dns': 'dns',
            'dhcp': 'dhcp',
            'decoy': 'decoy'
        }
        return role_mapping.get(role, 'endpoint')

    def _extract_networks(self, node_config: Dict[str, Any]) -> List[str]:
        """从节点配置提取网络信息"""
        # ContainerLab中网络通过links隐式定义
        # 这里暂时返回空列表，后续从links推断
        return []

    def _extract_cve_info(self, cve_id: Optional[str], labels: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """提取CVE注入信息"""
        if not cve_id:
            return None

        return {
            'cve_id': cve_id,
            'name': labels.get('cve_name', ''),  # 修复字段名
            'cvss_score': labels.get('cvss_score', ''),
            'auto_inject': True
        }

    def _extract_routing_info(self, labels: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """提取路由配置"""
        routing_protocol = labels.get('routing')
        if not routing_protocol:
            return None

        return {
            'protocol': routing_protocol,
            'enabled': True
        }

    def _parse_isolation_policies(self) -> List[IsolationPolicy]:
        """解析网络隔离策略"""
        policies = []

        # 从YAML中获取isolation_policies配置
        isolation_config = self.raw_data.get('isolation_policies', [])

        for policy_dict in isolation_config:
            try:
                policy = IsolationPolicy(
                    source=policy_dict.get('source', ''),
                    destination=policy_dict.get('destination', ''),
                    action=policy_dict.get('action', 'DROP'),
                    allowed_ports=policy_dict.get('allowed_ports', []),
                    allowed_protocols=policy_dict.get('allowed_protocols', []),
                    log=policy_dict.get('log', True),
                    description=policy_dict.get('description', '')
                )
                policies.append(policy)
            except Exception as e:
                print(f"⚠️  解析隔离策略失败: {e}, 策略: {policy_dict}")

        return policies

    def _parse_security_zones(self, nodes: List[NetworkNode], policies: List[IsolationPolicy]) -> Dict[str, SecurityZone]:
        """解析安全区域配置"""
        zones = {}

        # 从节点labels中提取安全区域信息
        for node in nodes:
            zone_name = node.vars.get('security_zone', 'default')
            zone_type = self._infer_zone_type(node.role, zone_name)

            if zone_name not in zones:
                # 为每个区域分配子网
                zone_index = len(zones)
                subnet = self._generate_zone_subnet(zone_type, zone_index)

                zones[zone_name] = SecurityZone(
                    name=zone_name,
                    subnet=subnet,
                    containers=[],
                    zone_type=zone_type
                )

            # 将容器添加到对应区域
            zones[zone_name].containers.append(node.name)

        return zones

    def _infer_zone_type(self, node_role: str, zone_name: str) -> str:
        """根据节点角色和区域名称推断区域类型"""
        # 如果区域名称已经明确类型
        if 'dmz' in zone_name.lower():
            return 'dmz'
        elif 'attacker' in zone_name.lower():
            return 'attacker'
        elif 'isolated' in zone_name.lower():
            return 'isolated'

        # 根据节点角色推断
        role_mapping = {
            'attacker': 'attacker',
            'primary_attacker': 'attacker',
            'vulnerability': 'dmz',
            'primary_vulnerability': 'dmz',
            'web_server': 'dmz',
            'router': 'internal',
            'database': 'internal',
            'internal_router': 'internal'
        }

        return role_mapping.get(node_role, 'internal')

    def _generate_zone_subnet(self, zone_type: str, index: int) -> str:
        """为安全区域生成子网"""
        # 为不同区域类型使用不同的子网范围
        subnet_ranges = {
            'attacker': f"10.100.{index}.0/24",
            'dmz': f"10.101.{index}.0/24",
            'internal': f"10.102.{index}.0/24",
            'isolated': f"10.103.{index}.0/24",
            'management': f"10.104.{index}.0/24",
            'default': f"10.105.{index}.0/24"
        }

        return subnet_ranges.get(zone_type, f"10.105.{index}.0/24")

    def get_clab_topology(self) -> ContainerLabTopology:
        """获取ContainerLab拓扑对象"""
        return self.clab_topology

    def get_raw_yaml(self) -> Dict[str, Any]:
        """获取原始YAML数据"""
        return self.raw_data


def main():
    """测试解析器"""
    parser = ContainerLabParser('examples/simple_clab.yaml')
    spec = parser.extract_topology_specification()

    print(f"实验室: {spec.lab_name}")
    print(f"节点数: {len(spec.nodes)}")
    print(f"链路数: {len(spec.links)}")

    for node in spec.nodes:
        print(f"  - {node.name}: {node.type} ({node.image})")


if __name__ == "__main__":
    main()
