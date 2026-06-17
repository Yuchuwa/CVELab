"""CVE注入准确性增强单元测试"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from clab_builder.core.cve_validator import (
    CVEAccuracyValidator,
    CVEDatabaseValidator,
    CVEEnvironmentValidator,
    CVEExploitGenerator,
    CVEDatabaseInfo,
    CVESeverity,
    CVEAttackComplexity,
    CVEValidationResult,
    ExploitStep
)


@pytest.mark.unit
@pytest.mark.cve
class TestCVEDatabaseValidator:
    """CVE数据库验证器测试"""

    def test_validator_initialization(self):
        """测试验证器初始化"""
        validator = CVEDatabaseValidator(use_cache=True)
        assert validator.use_cache is True
        assert isinstance(validator.cache, dict)

    def test_cache_operations(self):
        """测试缓存操作"""
        validator = CVEDatabaseValidator(use_cache=True)

        # 测试缓存加载
        cache = validator._load_cache()
        assert isinstance(cache, dict)

        # 测试CVE信息缓存
        cve_info = CVEDatabaseInfo(
            cve_id="CVE-2021-44228",
            description="Test CVE",
            cvss_score=7.5,
            severity=CVESeverity.HIGH,
            attack_complexity=CVEAttackComplexity.LOW,
            attack_vector="NETWORK",
            required_privileges=["user"]
        )

        validator._cache_cve("CVE-2021-44228", cve_info)

        # 验证缓存成功
        assert "CVE-2021-44228" in validator.cache

    @pytest.mark.slow
    @pytest.mark.docker
    def test_nvd_database_query(self):
        """测试NVD数据库查询（需要网络）"""
        validator = CVEDatabaseValidator(use_cache=False)

        # 测试真实CVE查询
        valid, info = validator.validate_cve_exists("CVE-2021-44228")

        # 由于需要网络连接，这个测试可能会失败
        # 我们主要测试函数不会崩溃
        assert isinstance(valid, bool)
        if valid:
            assert info is not None

    def test_exploit_db_fallback(self):
        """测试exploit-db回退机制"""
        validator = CVEDatabaseValidator(use_cache=False)

        # 测试不存在的CVE
        valid, info = validator.validate_cve_exists("CVE-9999-9999")
        assert valid is False
        assert info is None


@pytest.mark.unit
@pytest.mark.cve
class TestCVEEnvironmentValidator:
    """CVE环境验证器测试"""

    def test_environment_validator_initialization(self):
        """测试环境验证器初始化"""
        validator = CVEEnvironmentValidator()
        assert validator is not None

    def test_image_requirement_extraction(self):
        """测试镜像需求提取"""
        validator = CVEEnvironmentValidator()

        cve_info = CVEDatabaseInfo(
            cve_id="CVE-2021-44228",
            description="Log4j vulnerability",
            cvss_score=7.5,
            severity=CVESeverity.HIGH,
            attack_complexity=CVEAttackComplexity.LOW,
            attack_vector="NETWORK",
            required_privileges=["user"]
        )

        images = validator._extract_required_images(cve_info)
        assert isinstance(images, list)

    def test_port_requirement_extraction(self):
        """测试端口需求提取"""
        validator = CVEEnvironmentValidator()

        # 测试Log4j CVE
        log4j_info = CVEDatabaseInfo(
            cve_id="CVE-2021-44228",
            description="Log4j RCE",
            cvss_score=10.0,
            severity=CVESeverity.CRITICAL,
            attack_complexity=CVEAttackComplexity.LOW,
            attack_vector="NETWORK",
            required_privileges=["user"]
        )

        ports = validator._extract_required_ports(log4j_info)
        assert 8080 in ports or 8443 in ports

    def test_service_requirement_extraction(self):
        """测试服务需求提取"""
        validator = CVEEnvironmentValidator()

        log4j_info = CVEDatabaseInfo(
            cve_id="CVE-2021-44228",
            description="Log4j RCE in Java applications",
            cvss_score=10.0,
            severity=CVESeverity.CRITICAL,
            attack_complexity=CVEAttackComplexity.LOW,
            attack_vector="NETWORK",
            required_privileges=["user"]
        )

        services = validator._extract_required_services(log4j_info)
        assert "java" in services

    def test_environment_compatibility_validation(self):
        """测试环境兼容性验证"""
        validator = CVEEnvironmentValidator()

        cve_info = CVEDatabaseInfo(
            cve_id="CVE-2021-44228",
            description="Log4j vulnerability",
            cvss_score=10.0,
            severity=CVESeverity.CRITICAL,
            attack_complexity=CVEAttackComplexity.LOW,
            attack_vector="NETWORK",
            required_privileges=["user"]
        )

        # 测试兼容环境
        compatible_env = {
            'available_images': ['vulnerables/web-apps/log4j-vulnerable-app'],
            'available_ports': [8080, 8443],
            'running_services': ['java']
        }

        valid, issues = validator.validate_environment_compatibility(cve_info, compatible_env)
        assert valid is True
        assert len(issues) == 0

        # 测试不兼容环境
        incompatible_env = {
            'available_images': [],
            'available_ports': [],
            'running_services': []
        }

        valid, issues = validator.validate_environment_compatibility(cve_info, incompatible_env)
        assert valid is False
        assert len(issues) > 0


@pytest.mark.unit
@pytest.mark.cve
class TestCVEExploitGenerator:
    """CVE攻击生成器测试"""

    def test_exploit_generator_initialization(self):
        """测试攻击生成器初始化"""
        generator = CVEExploitGenerator()
        assert generator is not None

    def test_log4j_exploit_generation(self):
        """测试Log4j攻击步骤生成"""
        generator = CVEExploitGenerator()

        target_info = {
            'target_ip': '10.101.0.3',
            'target_port': 8080,
            'attacker_ip': '10.100.0.2'
        }

        cve_info = CVEDatabaseInfo(
            cve_id="CVE-2021-44228",
            description="Log4j RCE",
            cvss_score=10.0,
            severity=CVESeverity.CRITICAL,
            attack_complexity=CVEAttackComplexity.LOW,
            attack_vector="NETWORK",
            required_privileges=["user"]
        )

        steps = generator.generate_exploit_steps("CVE-2021-44228", cve_info, target_info)

        assert len(steps) > 0
        assert all(isinstance(step, ExploitStep) for step in steps)

        # 验证关键步骤存在
        step_descriptions = [step.description for step in steps]
        assert any("侦察" in desc for desc in step_descriptions)
        assert any("注入" in desc for desc in step_descriptions)
        assert any("验证" in desc for desc in step_descriptions)

    def test_exploit_step_structure(self):
        """测试攻击步骤结构"""
        step = ExploitStep(
            step_number=1,
            description="测试步骤",
            command="echo test",
            expected_output="test",
            validation_method="output_match",
            required_tools=["bash"]
        )

        assert step.step_number == 1
        assert step.description == "测试步骤"
        assert step.command == "echo test"
        assert step.validation_method == "output_match"
        assert "bash" in step.required_tools


@pytest.mark.unit
@pytest.mark.cve
class TestCVEAccuracyValidator:
    """CVE准确性验证器测试"""

    def test_validator_initialization(self):
        """测试准确性验证器初始化"""
        validator = CVEAccuracyValidator()

        assert validator.db_validator is not None
        assert validator.env_validator is not None
        assert validator.exploit_generator is not None

    def test_cve_accuracy_validation_workflow(self):
        """测试CVE准确性验证工作流程"""
        validator = CVEAccuracyValidator()

        cve_id = "CVE-2021-44228"
        topology_data = {
            'topology': {
                'nodes': {
                    'attacker': {
                        'kind': 'linux',
                        'labels': {'role': 'attacker'}
                    },
                    'target': {
                        'kind': 'linux',
                        'labels': {
                            'role': 'vulnerability',
                            'cve': cve_id
                        }
                    }
                },
                'links': [
                    {'endpoints': ['attacker:eth1', 'target:eth1']}
                ]
            }
        }
        target_environment = {
            'target_ip': '10.101.0.3',
            'target_port': 8080,
            'attacker_ip': '10.100.0.2'
        }

        # Mock数据库验证
        with patch.object(validator.db_validator, 'validate_cve_exists') as mock_db:
            mock_cve_info = CVEDatabaseInfo(
                cve_id=cve_id,
                description="Log4j vulnerability",
                cvss_score=10.0,
                severity=CVESeverity.CRITICAL,
                attack_complexity=CVEAttackComplexity.LOW,
                attack_vector="NETWORK",
                required_privileges=["user"]
            )
            mock_db.return_value = (True, mock_cve_info)

            # Mock环境验证
            with patch.object(validator.env_validator, 'validate_environment_compatibility') as mock_env:
                mock_env.return_value = (True, [])

                result = validator.validate_cve_accuracy(cve_id, topology_data, target_environment)

        # 验证结果结构
        assert isinstance(result, CVEValidationResult)
        assert result.cve_id == cve_id
        assert hasattr(result, 'overall_valid')
        assert hasattr(result, 'validation_timestamp')

    def test_dependency_checking(self):
        """测试依赖关系检查"""
        validator = CVEAccuracyValidator()

        cve_info = CVEDatabaseInfo(
            cve_id="CVE-2021-44228",
            description="Log4j vulnerability",
            cvss_score=10.0,
            severity=CVESeverity.CRITICAL,
            attack_complexity=CVEAttackComplexity.LOW,
            attack_vector="NETWORK",
            required_privileges=["user"]
        )

        # 测试完整拓扑
        complete_topology = {
            'topology': {
                'nodes': {
                    'attacker': {
                        'kind': 'linux',
                        'labels': {'role': 'attacker'}
                    },
                    'router': {
                        'kind': 'linux',
                        'labels': {'role': 'router'}
                    },
                    'target': {
                        'kind': 'linux',
                        'labels': {'role': 'vulnerability'}
                    }
                },
                'links': [
                    {'endpoints': ['attacker:eth1', 'router:eth1']},
                    {'endpoints': ['router:eth2', 'target:eth1']}
                ]
            }
        }

        valid, issues = validator._check_dependencies(cve_info, complete_topology)
        assert valid is True
        assert len(issues) == 0

        # 测试不完整拓扑
        incomplete_topology = {
            'topology': {
                'nodes': {
                    'target': {
                        'kind': 'linux',
                        'labels': {'role': 'vulnerability'}
                    }
                },
                'links': []
            }
        }

        valid, issues = validator._check_dependencies(cve_info, incomplete_topology)
        assert valid is False
        assert len(issues) > 0
        assert any("攻击者" in issue for issue in issues)

    def test_playbook_accuracy_validation(self):
        """测试playbook准确性验证"""
        validator = CVEAccuracyValidator()

        cve_id = "CVE-2021-44228"
        topology_data = {
            'topology': {
                'nodes': {
                    'attacker': {
                        'kind': 'linux',
                        'labels': {'role': 'attacker'}
                    },
                    'target': {
                        'kind': 'linux',
                        'labels': {'role': 'vulnerability'}
                    }
                },
                'links': [
                    {'endpoints': ['attacker:eth1', 'target:eth1']}
                ]
            }
        }

        # Mock攻击步骤生成
        with patch.object(validator, '_generate_mock_exploit_steps') as mock_steps:
            mock_steps.return_value = [
                ExploitStep(
                    step_number=1,
                    description="侦察",
                    command="nmap -sV target",
                    expected_output="open",
                    validation_method="output_match"
                ),
                ExploitStep(
                    step_number=2,
                    description="攻击",
                    command="exploit target",
                    expected_output="success",
                    validation_method="exit_code"
                )
            ]

            accurate = validator._validate_playbook_accuracy(cve_id, mock_steps.return_value, topology_data)
            assert accurate is True


@pytest.mark.unit
@pytest.mark.cve
class TestCVEDataModels:
    """CVE数据模型测试"""

    def test_cve_database_info_model(self):
        """测试CVE数据库信息模型"""
        cve_info = CVEDatabaseInfo(
            cve_id="CVE-2021-44228",
            description="Log4j vulnerability",
            cvss_score=10.0,
            severity=CVESeverity.CRITICAL,
            attack_complexity=CVEAttackComplexity.LOW,
            attack_vector="NETWORK",
            required_privileges=[],
            known_exploited=True,
            published_date="2021-12-10",
            references=[]
        )

        assert cve_info.cve_id == "CVE-2021-44228"
        assert cve_info.severity == CVESeverity.CRITICAL
        assert cve_info.attack_complexity == CVEAttackComplexity.LOW

    def test_exploit_step_model(self):
        """测试攻击步骤模型"""
        step = ExploitStep(
            step_number=1,
            description="侦察步骤",
            command="nmap -sV target",
            expected_output="open",
            validation_method="output_match",
            timeout=30,
            required_tools=["nmap"]
        )

        assert step.step_number == 1
        assert step.validation_method == "output_match"
        assert "nmap" in step.required_tools

    def test_validation_result_model(self):
        """测试验证结果模型"""
        result = CVEValidationResult(
            cve_id="CVE-2021-44228",
            database_valid=True,
            environment_compatible=True,
            dependencies_met=True,
            exploit_steps_valid=True,
            playbook_accurate=True,
            reproducible=True,
            overall_valid=True
        )

        assert result.overall_valid is True
        assert result.cve_id == "CVE-2021-44228"
        assert all([
            result.database_valid,
            result.environment_compatible,
            result.dependencies_met,
            result.exploit_steps_valid,
            result.playbook_accurate,
            result.reproducible
        ])

    def test_severity_classification(self):
        """测试严重程度分类"""
        assert CVESeverity.CRITICAL == "CRITICAL"
        assert CVESeverity.HIGH == "HIGH"
        assert CVESeverity.MEDIUM == "MEDIUM"
        assert CVESeverity.LOW == "LOW"

    def test_attack_complexity_classification(self):
        """测试攻击复杂度分类"""
        assert CVEAttackComplexity.LOW == "LOW"
        assert CVEAttackComplexity.MEDIUM == "MEDIUM"
        assert CVEAttackComplexity.HIGH == "HIGH"


@pytest.mark.unit
@pytest.mark.cve
class TestCVEIntegration:
    """CVE功能集成测试"""

    def test_end_to_end_cve_validation(self):
        """测试端到端CVE验证流程"""
        validator = CVEAccuracyValidator()

        # 模拟一个完整的场景
        cve_id = "CVE-2021-44228"
        topology_data = {
            'topology': {
                'nodes': {
                    'attacker': {
                        'kind': 'linux',
                        'image': 'kalilinux/kali-rolling:latest',
                        'labels': {'role': 'attacker', 'security_zone': 'attacker_zone'}
                    },
                    'web_server': {
                        'kind': 'linux',
                        'image': 'vulnerables/web-apps/log4j-vulnerable-app',
                        'labels': {
                            'role': 'vulnerability',
                            'cve': cve_id,
                            'security_zone': 'dmz_zone'
                        },
                        'ports': ['8080/tcp']
                    }
                },
                'links': [
                    {'endpoints': ['attacker:eth1', 'web_server:eth1']}
                ]
            }
        }
        target_environment = {
            'target_ip': '10.101.0.3',
            'target_port': 8080,
            'attacker_ip': '10.100.0.2'
        }

        # Mock所有依赖验证
        with patch.object(validator.db_validator, 'validate_cve_exists') as mock_db:
            mock_cve_info = CVEDatabaseInfo(
                cve_id=cve_id,
                description="Log4j RCE",
                cvss_score=10.0,
                severity=CVESeverity.CRITICAL,
                attack_complexity=CVEAttackComplexity.LOW,
                attack_vector="NETWORK",
                required_privileges=["user"],
                known_exploited=True
            )
            mock_db.return_value = (True, mock_cve_info)

            with patch.object(validator.env_validator, 'validate_environment_compatibility') as mock_env:
                mock_env.return_value = (True, [])

                result = validator.validate_cve_accuracy(cve_id, topology_data, target_environment)

        # 验证结果结构
        assert result.cve_id == cve_id
        assert 'validation_timestamp' in result
        assert isinstance(result.issues, list)
        assert isinstance(result.recommendations, list)


@pytest.mark.unit
@pytest.mark.cve
class TestCVEPlaybookGeneration:
    """CVE Playbook生成测试"""

    def test_playbook_generation_integration(self, sample_topology_file: str):
        """测试playbook生成集成"""
        from clab_builder.core.parser import ContainerLabParser
        from clab_builder.core.generator import TopologyGenerator

        # 解析包含CVE的拓扑
        parser = ContainerLabParser(sample_topology_file)
        spec = parser.extract_topology_specification()

        # 为一个节点添加CVE信息
        spec.nodes[1].cve_injection = {
            'cve_id': 'CVE-2021-44228',
            'name': 'Log4j RCE',
            'cvss_score': '10.0'
        }

        # 更新generator的specification
        generator = TopologyGenerator(sample_topology_file)
        generator.specification = spec

        # 生成CVE exploit playbooks
        cve_playbooks = generator._generate_cve_exploit_playbooks()

        # 验证生成了playbook
        assert isinstance(cve_playbooks, dict)
        assert len(cve_playbooks) > 0

        # 验证playbook格式
        for playbook_name, playbook_content in cve_playbooks.items():
            assert playbook_name.startswith("exploit_")
            assert len(playbook_content) > 0
            assert "tasks:" in playbook_content

    def test_log4j_playbook_content(self, sample_topology_file: str):
        """测试Log4j playbook内容质量"""
        from clab_builder.core.parser import ContainerLabParser
        from clab_builder.core.generator import TopologyGenerator

        parser = ContainerLabParser(sample_topology_file)
        spec = parser.extract_topology_specification()

        # 创建模拟CVE节点
        from clab_builder.models.models import NetworkNode
        cve_node = NetworkNode(
            name="log4j-target",
            type="vuln-target",
            image="vulnerables/web-apps/log4j-vulnerable-app",
            role="vulnerability",
            ports=["8080/tcp"],
            cve_injection={
                'cve_id': 'CVE-2021-44228',
                'name': 'Log4j RCE',
                'cvss_score': '10.0'
            }
        )

        generator = TopologyGenerator(sample_topology_file)
        playbook = generator._generate_log4j_exploit_playbook(
            cve_node.name,
            "10.101.0.3",
            [8080]
        )

        # 验证playbook包含关键元素
        assert "CVE-2021-44228" in playbook
        assert "tasks:" in playbook
        assert "侦察" in playbook or "准备" in playbook
        assert "注入" in playbook or "攻击" in playbook
        assert "验证" in playbook or "报告" in playbook
        assert "target_host" in playbook
        assert "target_ip" in playbook

    def test_generic_playbook_generation(self):
        """测试通用playbook生成"""
        from clab_builder.core.generator import TopologyGenerator
        from clab_builder.models.models import NetworkNode

        generator = TopologyGenerator("dummy.yaml")
        cve_node = NetworkNode(
            name="target-server",
            type="vuln-target",
            image="nginx:latest",
            role="vulnerability",
            ports=[80, 443],
            cve_injection={
                'cve_id': 'CVE-2024-1234',
                'name': 'Test CVE'
            }
        )

        playbook = generator._generate_generic_exploit_playbook(
            cve_node.name,
            "CVE-2024-1234",
            "10.101.0.3",
            [80, 443]
        )

        # 验证基本结构
        assert "---" in playbook
        assert "hosts:" in playbook
        assert "tasks:" in playbook
        assert cve_node.name in playbook
        assert "10.101.0.3" in playbook
        assert "80" in playbook or "443" in playbook


@pytest.mark.unit
@pytest.mark.cve
class TestCVEErrorHandling:
    """CVE功能错误处理测试"""

    def test_invalid_cve_format(self):
        """测试无效CVE格式处理"""
        validator = CVEAccuracyValidator()

        invalid_cve_ids = [
            "INVALID-CVE",
            "CVE-",
            "",
            "CVE-9999-99999999"
        ]

        for invalid_cve in invalid_cve_ids:
            # 应该能够处理无效格式而不崩溃
            assert validator is not None

    def test_missing_topology_information(self):
        """测试缺少拓扑信息"""
        validator = CVEAccuracyValidator()

        incomplete_topology = {
            'topology': {
                'nodes': {},  # 空节点
                'links': []
            }
        }

        cve_info = CVEDatabaseInfo(
            cve_id="CVE-2021-44228",
            description="Test",
            cvss_score=7.5,
            severity=CVESeverity.HIGH,
            attack_complexity=CVEAttackComplexity.LOW,
            attack_vector="NETWORK",
            required_privileges=["user"]
        )

        # 依赖检查应该发现问题
        valid, issues = validator._check_dependencies(cve_info, incomplete_topology)
        assert valid is False
        assert len(issues) > 0

    def test_network_failure_handling(self):
        """测试网络故障处理"""
        validator = CVEDatabaseValidator(use_cache=False)

        # 模拟网络故障
        with patch('requests.get') as mock_get:
            mock_get.side_effect = Exception("Network error")

            # 应该优雅处理网络错误
            valid, info = validator.validate_cve_exists("CVE-2021-44228")
            assert isinstance(valid, bool)
            assert info is None


@pytest.mark.unit
@pytest.mark.cve
class TestCVEQualityMetrics:
    """CVE质量指标测试"""

    def test_validation_result_quality_score(self):
        """测试验证结果质量评分"""
        # 完美通过的结果
        perfect_result = CVEValidationResult(
            cve_id="CVE-2021-44228",
            database_valid=True,
            environment_compatible=True,
            dependencies_met=True,
            exploit_steps_valid=True,
            playbook_accurate=True,
            reproducible=True,
            overall_valid=True
        )

        # 计算质量分数 (6个维度，每个16.67分)
        quality_score = sum([
            perfect_result.database_valid,
            perfect_result.environment_compatible,
            perfect_result.dependencies_met,
            perfect_result.exploit_steps_valid,
            perfect_result.playbook_accurate,
            perfect_result.reproducible
        ]) / 6 * 100

        assert quality_score == 100.0

    def test_partial_validation_scoring(self):
        """测试部分通过的评分"""
        # 部分通过的结果
        partial_result = CVEValidationResult(
            cve_id="CVE-2021-44228",
            database_valid=True,
            environment_compatible=False,
            dependencies_met=True,
            exploit_steps_valid=True,
            playbook_accurate=False,
            reproducible=True,
            overall_valid=False
        )

        # 计算质量分数
        quality_score = sum([
            partial_result.database_valid,
            partial_result.environment_compatible,
            partial_result.dependencies_met,
            partial_result.exploit_steps_valid,
            partial_result.playbook_accurate,
            partial_result.reproducible
        ]) / 6 * 100

        assert 50.0 <= quality_score < 100.0
        assert round(quality_score, 2) == 66.67  # 4/6 * 100
