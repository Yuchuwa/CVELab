"""集成测试 - 完整的工作流程测试"""

import pytest
import yaml
import tempfile
import os
from pathlib import Path
from clab_builder.core.parser import ContainerLabParser
from clab_builder.core.generator import TopologyGenerator
from clab_builder.models.models import IsolationPolicy, SecurityZone


@pytest.mark.integration
class TestTopologyWorkflow:
    """拓扑工作流程集成测试"""

    def test_end_to_end_topology_generation(self, sample_topology_file: str):
        """测试端到端拓扑生成流程"""
        # 1. 解析拓扑
        parser = ContainerLabParser(sample_topology_file)
        spec = parser.extract_topology_specification()

        assert spec.lab_name == "test-lab"
        assert len(spec.nodes) == 4
        assert len(spec.links) == 3

        # 2. 生成配置
        generator = TopologyGenerator(sample_topology_file)
        clab_config, ansible_config = generator.generate()

        # 3. 验证ContainerLab配置
        assert clab_config is not None
        assert isinstance(clab_config, str)

        clab_data = yaml.safe_load(clab_config)
        assert 'name' in clab_data
        assert 'topology' in clab_data
        assert 'nodes' in clab_data['topology']

        # 4. 验证Ansible配置
        assert ansible_config is not None
        assert 'inventory' in ansible_config
        assert 'playbooks' in ansible_config

    def test_network_isolation_workflow(self, sample_topology_file: str):
        """测试网络隔离工作流程"""
        # 解析包含隔离策略的拓扑
        parser = ContainerLabParser(sample_topology_file)
        spec = parser.extract_topology_specification()

        # 验证隔离策略解析
        assert len(spec.isolation_policies) > 0

        # 验证安全区域创建
        assert len(spec.security_zones) > 0

        # 生成隔离配置
        generator = TopologyGenerator(sample_topology_file)
        clab_config, ansible_config = generator.generate()

        # 验证生成了隔离playbook
        assert 'configure_network_isolation' in ansible_config['playbooks']

        isolation_playbook = ansible_config['playbooks']['configure_network_isolation']
        assert len(isolation_playbook) > 0

        # 验证playbook可以解析为YAML
        playbook_data = yaml.safe_load(isolation_playbook)
        assert playbook_data is not None
        assert 'hosts' in playbook_data
        assert 'tasks' in playbook_data


@pytest.mark.integration
class TestParserGeneratorIntegration:
    """解析器和生成器集成测试"""

    def test_parser_to_generator_data_flow(self, sample_topology_file: str):
        """测试从解析器到生成器的数据流"""
        # 解析阶段
        parser = ContainerLabParser(sample_topology_file)
        spec = parser.extract_topology_specification()

        # 记录关键数据
        lab_name = spec.lab_name
        node_count = len(spec.nodes)
        isolation_policy_count = len(spec.isolation_policies)
        zone_count = len(spec.security_zones)

        # 生成阶段
        generator = TopologyGenerator(sample_topology_file)
        clab_config, ansible_config = generator.generate()

        # 验证数据传递正确
        assert lab_name in clab_config  # 实验室名称传递到ContainerLab配置

        # 验证inventory包含正确的节点
        inventory = ansible_config['inventory']
        total_inventory_hosts = sum(len(hosts) for hosts in inventory.values() if isinstance(hosts, dict) and 'hosts' in hosts)
        assert total_inventory_hosts >= node_count  # 至少包含原始节点数

    def test_isolation_policy_consistency(self, sample_topology_file: str):
        """测试隔离策略一致性"""
        parser = ContainerLabParser(sample_topology_file)
        spec = parser.extract_topology_specification()

        # 获取所有区域名称
        zone_names = set(spec.security_zones.keys())

        # 验证所有策略引用的区域都存在
        for policy in spec.isolation_policies:
            assert policy.source in zone_names, f"策略源区域 {policy.source} 不存在"
            assert policy.destination in zone_names, f"策略目标区域 {policy.destination} 不存在"

    def test_container_zone_assignment_consistency(self, sample_topology_file: str):
        """测试容器区域分配一致性"""
        parser = ContainerLabParser(sample_topology_file)
        spec = parser.extract_topology_specification()

        # 获取所有节点名称
        node_names = {node.name for node in spec.nodes}

        # 获取所有区域中的容器
        zone_containers = set()
        for zone in spec.security_zones.values():
            zone_containers.update(zone.containers)

        # 验证所有节点都被分配到区域
        assert node_names == zone_containers, "节点和区域容器分配不一致"


@pytest.mark.integration
class TestYAMLConfigurationGeneration:
    """YAML配置生成集成测试"""

    def test_containerlab_yaml_validity(self, sample_topology_file: str):
        """测试ContainerLab YAML有效性"""
        generator = TopologyGenerator(sample_topology_file)
        clab_config, _ = generator.generate()

        # 验证可以解析为有效的YAML
        assert yaml.safe_load(clab_config) is not None

        # 验证包含必需字段
        clab_data = yaml.safe_load(clab_config)
        assert 'name' in clab_data
        assert 'topology' in clab_data
        assert 'nodes' in clab_data['topology']

    def test_ansible_playbook_generation(self, sample_topology_file: str):
        """测试Ansible playbook生成"""
        generator = TopologyGenerator(sample_topology_file)
        _, ansible_config = generator.generate()

        # 验证生成了预期的playbooks
        playbooks = ansible_config['playbooks']
        assert 'deploy' in playbooks
        assert 'configure_routing' in playbooks
        assert 'configure_dns' in playbooks
        assert 'configure_network_isolation' in playbooks

        # 验证每个playbook都是有效的YAML
        for playbook_name, playbook_content in playbooks.items():
            if isinstance(playbook_content, str):
                playbook_data = yaml.safe_load(playbook_content)
                assert playbook_data is not None, f"{playbook_name} playbook 解析失败"

    def test_inventory_generation(self, sample_topology_file: str):
        """测试inventory生成"""
        generator = TopologyGenerator(sample_topology_file)
        _, ansible_config = generator.generate()

        inventory = ansible_config['inventory']

        # 验证inventory结构
        assert 'all' in inventory
        assert 'routers' in inventory
        assert 'attackers' in inventory
        assert 'vuln_targets' in inventory

        # 验证all组包含vars
        assert 'vars' in inventory['all']


@pytest.mark.integration
class TestComplexTopologyScenarios:
    """复杂拓扑场景集成测试"""

    def test_multi_zone_topology(self):
        """测试多区域拓扑"""
        topology_data = {
            'name': 'multi-zone-test',
            'topology': {
                'nodes': {
                    'attacker': {
                        'kind': 'linux',
                        'image': 'kali:latest',
                        'labels': {'role': 'attacker', 'security_zone': 'attacker_zone'}
                    },
                    'dmz_server': {
                        'kind': 'linux',
                        'image': 'nginx:latest',
                        'labels': {'role': 'web_server', 'security_zone': 'dmz_zone'}
                    },
                    'internal_db': {
                        'kind': 'linux',
                        'image': 'mysql:latest',
                        'labels': {'role': 'database', 'security_zone': 'internal_zone'}
                    },
                    'isolated_service': {
                        'kind': 'linux',
                        'image': 'redis:latest',
                        'labels': {'role': 'cache', 'security_zone': 'isolated_zone'}
                    }
                },
                'links': [
                    {'endpoints': ['attacker:eth1', 'dmz_server:eth1']},
                    {'endpoints': ['dmz_server:eth2', 'internal_db:eth1']},
                    {'endpoints': ['internal_db:eth2', 'isolated_service:eth1']}
                ]
            },
            'isolation_policies': [
                {'source': 'attacker_zone', 'destination': 'dmz_zone', 'action': 'ACCEPT'},
                {'source': 'attacker_zone', 'destination': 'internal_zone', 'action': 'DROP'},
                {'source': 'attacker_zone', 'destination': 'isolated_zone', 'action': 'DROP'},
                {'source': 'dmz_zone', 'destination': 'internal_zone', 'action': 'DROP'},
                {'source': 'dmz_zone', 'destination': 'isolated_zone', 'action': 'DROP'},
                {'source': 'internal_zone', 'destination': 'isolated_zone', 'action': 'DROP'}
            ]
        }

        # 创建临时文件
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(topology_data, f)
            temp_file = f.name

        try:
            # 解析和生成
            parser = ContainerLabParser(temp_file)
            spec = parser.extract_topology_specification()

            # 验证4个区域都创建了
            assert len(spec.security_zones) == 4

            # 验证所有节点都分配到正确区域
            assert 'attacker' in spec.security_zones['attacker_zone'].containers
            assert 'dmz_server' in spec.security_zones['dmz_zone'].containers
            assert 'internal_db' in spec.security_zones['internal_zone'].containers
            assert 'isolated_service' in spec.security_zones['isolated_zone'].containers

            # 验证6条隔离策略
            assert len(spec.isolation_policies) == 6

        finally:
            os.unlink(temp_file)

    def test_port_specific_isolation(self):
        """测试端口特定隔离"""
        topology_data = {
            'name': 'port-specific-test',
            'topology': {
                'nodes': {
                    'client': {
                        'kind': 'linux',
                        'image': 'alpine:latest',
                        'labels': {'role': 'client', 'security_zone': 'client_zone'}
                    },
                    'server': {
                        'kind': 'linux',
                        'image': 'nginx:latest',
                        'labels': {'role': 'server', 'security_zone': 'server_zone'},
                        'ports': ['80/tcp', '443/tcp', '22/tcp', '3306/tcp']
                    }
                },
                'links': [
                    {'endpoints': ['client:eth1', 'server:eth1']}
                ]
            },
            'isolation_policies': [
                {
                    'source': 'client_zone',
                    'destination': 'server_zone',
                    'action': 'ACCEPT',
                    'allowed_ports': [80, 443],  # 只允许HTTP/HTTPS
                    'allowed_protocols': ['tcp']
                }
            ]
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(topology_data, f)
            temp_file = f.name

        try:
            parser = ContainerLabParser(temp_file)
            spec = parser.extract_topology_specification()

            # 验证端口特定策略
            policy = spec.isolation_policies[0]
            assert policy.allowed_ports == [80, 443]
            assert policy.allowed_protocols == ['tcp']

            # 生成配置并验证
            generator = TopologyGenerator(temp_file)
            _, ansible_config = generator.generate()

            isolation_playbook = ansible_config['playbooks']['configure_network_isolation']
            assert '80' in isolation_playbook
            assert '443' in isolation_playbook

        finally:
            os.unlink(temp_file)


@pytest.mark.integration
class TestErrorHandling:
    """错误处理集成测试"""

    def test_invalid_yaml_handling(self):
        """测试无效YAML处理"""
        invalid_yaml = """
        name: test
        topology:
          nodes:
            invalid_node: {invalid}
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(invalid_yaml)
            temp_file = f.name

        try:
            # 应该能够捕获YAML错误
            with pytest.raises(Exception):
                parser = ContainerLabParser(temp_file)
                parser.extract_topology_specification()

        finally:
            os.unlink(temp_file)

    def test_missing_required_fields(self):
        """测试缺少必需字段"""
        incomplete_yaml = """
        name: test
        topology:
          nodes: {}
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(incomplete_yaml)
            temp_file = f.name

        try:
            parser = ContainerLabParser(temp_file)
            spec = parser.extract_topology_specification()

            # 应该能够处理空节点列表
            assert len(spec.nodes) == 0

        finally:
            os.unlink(temp_file)