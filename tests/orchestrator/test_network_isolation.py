"""网络隔离功能单元测试"""

import pytest
from pathlib import Path
from clab_builder.core.parser import ContainerLabParser
from clab_builder.models.models import IsolationPolicy, SecurityZone, TopologySpecification


@pytest.mark.unit
@pytest.mark.isolation
class TestNetworkIsolationParsing:
    """网络隔离解析测试"""

    def test_parse_isolation_policies(self, sample_topology_file: str):
        """测试隔离策略解析"""
        parser = ContainerLabParser(sample_topology_file)
        spec = parser.extract_topology_specification()

        # 验证隔离策略数量
        assert len(spec.isolation_policies) == 2
        assert isinstance(spec.isolation_policies, list)

        # 验证第一个策略
        policy1 = spec.isolation_policies[0]
        assert policy1.source == "attacker_zone"
        assert policy1.destination == "dmz_zone"
        assert policy1.action == "ACCEPT"
        assert policy1.allowed_ports == [80, 443]
        assert policy1.log is True

    def test_parse_security_zones(self, sample_topology_file: str):
        """测试安全区域解析"""
        parser = ContainerLabParser(sample_topology_file)
        spec = parser.extract_topology_specification()

        # 验证安全区域数量
        assert len(spec.security_zones) == 3

        # 验证attacker_zone
        attacker_zone = spec.security_zones.get("attacker_zone")
        assert attacker_zone is not None
        assert attacker_zone.zone_type == "attacker"
        assert "attacker" in attacker_zone.containers
        assert attacker_zone.subnet.startswith("10.100.")

        # 验证dmz_zone
        dmz_zone = spec.security_zones.get("dmz_zone")
        assert dmz_zone is not None
        assert dmz_zone.zone_type == "dmz"
        assert "router" in dmz_zone.containers
        assert "web-server" in dmz_zone.containers

        # 验证internal_zone
        internal_zone = spec.security_zones.get("internal_zone")
        assert internal_zone is not None
        assert internal_zone.zone_type == "internal"
        assert "database" in internal_zone.containers

    def test_zone_subnet_allocation(self, sample_topology_file: str):
        """测试区域子网分配"""
        parser = ContainerLabParser(sample_topology_file)
        spec = parser.extract_topology_specification()

        # 验证子网分配规则
        expected_subnets = {
            'attacker_zone': '10.100.',
            'dmz_zone': '10.101.',
            'internal_zone': '10.102.'
        }

        for zone_name, prefix in expected_subnets.items():
            zone = spec.security_zones.get(zone_name)
            assert zone is not None
            assert zone.subnet.startswith(prefix)

    def test_isolation_policy_validation(self):
        """测试隔离策略模型验证"""
        # 有效策略
        valid_policy = IsolationPolicy(
            source="attacker_zone",
            destination="dmz_zone",
            action="ACCEPT",
            allowed_ports=[80, 443],
            log=True
        )
        assert valid_policy.source == "attacker_zone"
        assert valid_policy.action == "ACCEPT"

        # 测试不同的有效动作
        valid_actions = ["ACCEPT", "DROP", "REJECT"]
        for action in valid_actions:
            policy = IsolationPolicy(
                source="attacker_zone",
                destination="dmz_zone",
                action=action
            )
            assert policy.action == action

        # 测试默认值
        default_policy = IsolationPolicy(
            source="attacker_zone",
            destination="dmz_zone"
        )
        assert default_policy.action == "DROP"
        assert default_policy.log is True

    def test_security_zone_model(self):
        """测试安全区域模型"""
        zone = SecurityZone(
            name="test_zone",
            subnet="10.100.0.0/24",
            zone_type="attacker",
            containers=["container1", "container2"]
        )

        assert zone.name == "test_zone"
        assert zone.subnet == "10.100.0.0/24"
        assert zone.zone_type == "attacker"
        assert len(zone.containers) == 2


@pytest.mark.unit
@pytest.mark.isolation
class TestNetworkIsolationGeneration:
    """网络隔离生成测试"""

    def test_generate_isolation_playbook(self, sample_topology_file: str):
        """测试隔离playbook生成"""
        from clab_builder.core.generator import TopologyGenerator

        generator = TopologyGenerator(sample_topology_file)
        clab_config, ansible_config = generator.generate()

        # 验证生成了网络隔离playbook
        assert 'playbooks' in ansible_config
        assert 'configure_network_isolation' in ansible_config['playbooks']

        isolation_playbook = ansible_config['playbooks']['configure_network_isolation']
        assert isinstance(isolation_playbook, str)
        assert len(isolation_playbook) > 0

        # 验证playbook内容包含关键元素
        assert "iptables" in isolation_playbook.lower()
        assert "forward" in isolation_playbook.lower()

    def test_subnet_resolution(self, sample_topology_file: str):
        """测试子网解析"""
        from clab_builder.core.generator import TopologyGenerator

        generator = TopologyGenerator(sample_topology_file)
        generator.specification = generator._parse_input_format()

        # 测试子网解析
        attacker_subnet = generator._get_zone_subnet("attacker_zone")
        assert attacker_subnet.startswith("10.100.")

        dmz_subnet = generator._get_zone_subnet("dmz_zone")
        assert dmz_subnet.startswith("10.101.")

        # 测试不存在的区域
        unknown_subnet = generator._get_zone_subnet("unknown_zone")
        assert unknown_subnet == "10.105.0.0/24"


@pytest.mark.unit
@pytest.mark.isolation
class TestIsolationPolicyLogic:
    """隔离策略逻辑测试"""

    def test_policy_action_interpretation(self):
        """测试策略动作解释"""
        # ACCEPT策略
        accept_policy = IsolationPolicy(
            source="attacker_zone",
            destination="dmz_zone",
            action="ACCEPT",
            allowed_ports=[80, 443]
        )
        assert accept_policy.action == "ACCEPT"
        assert len(accept_policy.allowed_ports) == 2

        # DROP策略
        drop_policy = IsolationPolicy(
            source="attacker_zone",
            destination="internal_zone",
            action="DROP",
            log=True
        )
        assert drop_policy.action == "DROP"
        assert drop_policy.log is True

    def test_protocol_filtering(self):
        """测试协议过滤"""
        policy = IsolationPolicy(
            source="attacker_zone",
            destination="dmz_zone",
            action="ACCEPT",
            allowed_protocols=["tcp", "udp"],
            allowed_ports=[80, 443, 53]
        )

        assert "tcp" in policy.allowed_protocols
        assert "udp" in policy.allowed_protocols
        assert len(policy.allowed_ports) == 3

    def test_port_specific_vs_wildcard(self):
        """测试端口特定与通配符"""
        # 端口特定策略
        specific_policy = IsolationPolicy(
            source="attacker_zone",
            destination="dmz_zone",
            action="ACCEPT",
            allowed_ports=[80, 443]
        )
        assert len(specific_policy.allowed_ports) == 2

        # 通配符策略
        wildcard_policy = IsolationPolicy(
            source="internal_zone",
            destination="internal_zone",
            action="ACCEPT"
        )
        assert len(wildcard_policy.allowed_ports) == 0


@pytest.mark.unit
@pytest.mark.isolation
class TestZoneAssignment:
    """区域分配测试"""

    def test_role_based_zone_assignment(self, sample_topology_file: str):
        """测试基于角色的区域分配"""
        parser = ContainerLabParser(sample_topology_file)
        spec = parser.extract_topology_specification()

        # 验证角色到区域的映射
        for node in spec.nodes:
            if node.role == "attacker":
                assert "attacker_zone" in spec.security_zones
                assert node.name in spec.security_zones["attacker_zone"].containers
            elif node.role in ["router", "web_server"]:
                assert "dmz_zone" in spec.security_zones
                assert node.name in spec.security_zones["dmz_zone"].containers
            elif node.role == "database":
                assert "internal_zone" in spec.security_zones
                assert node.name in spec.security_zones["internal_zone"].containers

    def test_explicit_zone_override(self):
        """测试显式区域覆盖"""
        # 创建带有显式区域定义的拓扑数据
        topology_data = {
            'name': 'explicit-zone-test',
            'topology': {
                'nodes': {
                    'custom-server': {
                        'kind': 'linux',
                        'image': 'nginx:latest',
                        'labels': {
                            'role': 'web_server',
                            'security_zone': 'custom_zone'  # 显式指定
                        }
                    }
                },
                'links': []
            }
        }

        # 保存到临时文件
        import tempfile
        import yaml

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(topology_data, f)
            temp_file = f.name

        try:
            parser = ContainerLabParser(temp_file)
            spec = parser.extract_topology_specification()

            # 验证创建了自定义区域
            assert "custom_zone" in spec.security_zones
            assert "custom-server" in spec.security_zones["custom_zone"].containers

        finally:
            import os
            os.unlink(temp_file)


@pytest.mark.unit
@pytest.mark.isolation
class TestIsolationValidation:
    """隔离验证测试"""

    def test_policy_consistency_check(self, sample_topology_file: str):
        """测试策略一致性检查"""
        parser = ContainerLabParser(sample_topology_file)
        spec = parser.extract_topology_specification()

        # 检查策略引用的区域是否存在
        for policy in spec.isolation_policies:
            assert policy.source in spec.security_zones, \
                f"源区域 {policy.source} 在安全区域中不存在"
            assert policy.destination in spec.security_zones, \
                f"目标区域 {policy.destination} 在安全区域中不存在"

    def test_container_zone_assignment(self, sample_topology_file: str):
        """测试容器区域分配"""
        parser = ContainerLabParser(sample_topology_file)
        spec = parser.extract_topology_specification()

        # 验证每个容器都被分配到一个区域
        all_zone_containers = []
        for zone in spec.security_zones.values():
            all_zone_containers.extend(zone.containers)

        # 检查是否所有节点都在某个区域中
        node_names = [node.name for node in spec.nodes]
        assert len(node_names) == len(all_zone_containers)
        assert set(node_names) == set(all_zone_containers)