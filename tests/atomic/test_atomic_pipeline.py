"""
CVE原子化模块测试套件

验证整个CVE atomic pipeline的功能
"""

import pytest
import os
import yaml
import tempfile
from pathlib import Path

from clab_builder.atomic.processor import CVEProcessor
from clab_builder.atomic.enricher import CVEEnricher
from clab_builder.atomic.validator import CVEAtomicValidator, CVEQualityScorer
from clab_builder.atomic.mapper import AttackStageMapper
from clab_builder.atomic.catalog import CVECatalogLoader


@pytest.mark.unit
class TestCVEProcessor:
    """CVE处理器测试"""

    def test_processor_initialization(self):
        """测试处理器初始化"""
        processor = CVEProcessor()
        assert processor.output_dir == "data/processing/partial"
        assert os.path.exists(processor.output_dir)

    def test_extract_cve_id_from_content(self):
        """测试CVE ID提取"""
        processor = CVEProcessor()

        test_content = """
        # CVE-2021-44228 Apache Log4j RCE
        This is a test content with CVE-2021-44228 mentioned.
        """
        cve_id = processor._extract_cve_id(test_content)
        assert cve_id == "CVE-2021-44228"

    def test_extract_environment_info(self):
        """测试环境信息提取"""
        processor = CVEProcessor()

        test_readme = """
        Docker image: vulhub/log4j:latest
        Ports: 8080, 8443
        """
        env_info = processor._extract_environment_info(test_readme)

        assert env_info["docker_image"] == "vulhub/log4j:latest"
        assert 8080 in env_info["required_ports"]
        assert 8443 in env_info["required_ports"]


@pytest.mark.unit
class TestAttackStageMapper:
    """ATT&CK阶段映射器测试"""

    def test_mapper_initialization(self):
        """测试映射器初始化"""
        mapper = AttackStageMapper()
        assert len(mapper.stage_keywords) > 0
        assert len(mapper.heuristics) > 0

    def test_map_from_rce_description(self):
        """测试RCE类CVE的ATT&CK映射"""
        mapper = AttackStageMapper()

        rce_description = "Apache Log4j remote code execution via JNDI injection"
        cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"

        attack_chain = mapper.map_from_description(rce_description, cvss_vector)

        # RCE漏洞应该对多个ATT&CK阶段都有高分（不只是initial_access）
        assert attack_chain.stage_scores.get("initial_access", 0) >= 0.5, f"initial_access score too low: {attack_chain.stage_scores.get('initial_access', 0)}"
        assert attack_chain.stage_scores.get("execution", 0) > 0.7, f"execution score too low: {attack_chain.stage_scores.get('execution', 0)}"
        # RCE的主要阶段应该是initial_access或execution之一
        assert attack_chain.primary_stage.value in ["initial_access", "execution"], f"Unexpected primary stage: {attack_chain.primary_stage.value}"


@pytest.mark.unit
class TestCVEEnricher:
    """CVE信息丰富器测试"""

    def test_enricher_initialization(self):
        """测试丰富器初始化"""
        enricher = CVEEnricher()
        assert enricher.data_sources is not None

    def test_enrich_attack_chain_analysis(self):
        """测试攻击链分析丰富化"""
        enricher = CVEEnricher()

        basic_catalog = {
            "basic_info": {
                "cve_id": "CVE-2021-44228",
                "name": "Test CVE",
                "cvss_score": 10.0,
                "description": "Remote code execution",
                "attack_vector": "NETWORK"
            },
            "environment": {
                "docker_image": "vulhub/test:latest",
                "required_ports": [8080]
            },
            "attack_info": {
                "exploit_method": "Test",
                "complexity": "low"
            }
        }

        enriched = enricher.enrich_attack_chain_analysis("CVE-2021-44228", basic_catalog)

        assert "attack_chain" in enriched
        assert "primary_stage" in enriched["attack_chain"]
        assert "stage_scores" in enriched["attack_chain"]

    def test_enrich_topology_analysis(self):
        """测试拓扑适配分析"""
        enricher = CVEEnricher()

        basic_catalog = {
            "environment": {
                "docker_image": "vulhub/test:latest",
                "required_ports": [80, 443]
            },
            "attack_info": {
                "exploit_method": "Test"
            }
        }

        enriched = enricher.enrich_topology_analysis("CVE-TEST", basic_catalog)

        assert "topology_fit" in enriched
        assert "network_layer" in enriched["topology_fit"]
        assert "suitable_roles" in enriched["topology_fit"]


@pytest.mark.unit
class TestCVEAtomicValidator:
    """CVE原子化验证器测试"""

    def test_validator_initialization(self):
        """测试验证器初始化"""
        validator = CVEAtomicValidator()
        assert validator is not None

    def test_validate_complete_catalog(self):
        """测试完整catalog验证"""
        validator = CVEAtomicValidator()

        # 创建完整的测试catalog
        complete_catalog = {
            "basic_info": {
                "cve_id": "CVE-2021-TEST",
                "name": "Test CVE",
                "cvss_score": 7.5,
                "description": "Test description"
            },
            "environment": {
                "docker_image": "test:latest",
                "required_ports": [8080]
            },
            "attack_info": {
                "exploit_method": "Test",
                "complexity": "low"
            },
            "attack_chain": {
                "primary_stage": "initial_access",
                "stage_scores": {"initial_access": 0.8},
                "reasoning": "Test reasoning",
                "confidence": 0.8
            },
            "topology_fit": {
                "network_layer": "dmz",
                "suitable_roles": ["web_server"],
                "requires_attacker": True,
                "internet_accessible": True
            },
            "verification": {
                "tested": False,
                "success_rate": 0.0
            }
        }

        syntax_valid, issues = validator.validate_catalog_syntax(complete_catalog)
        assert syntax_valid, f"语法验证失败: {issues}"

        logic_valid, issues = validator.validate_logic_consistency(complete_catalog)
        assert logic_valid, f"逻辑验证失败: {issues}"

    def test_validate_incomplete_catalog(self):
        """测试不完整catalog验证"""
        validator = CVEAtomicValidator()

        incomplete_catalog = {
            "basic_info": {
                "name": "Test"
                # 缺少必需字段
            }
        }

        syntax_valid, issues = validator.validate_catalog_syntax(incomplete_catalog)
        assert not syntax_valid, "应该检测到语法错误"


@pytest.mark.unit
class TestCVEQualityScorer:
    """CVE质量评分器测试"""

    def test_scorer_initialization(self):
        """测试评分器初始化"""
        scorer = CVEQualityScorer()
        assert scorer.score_weights == {
            'completeness': 0.3,
            'accuracy': 0.4,
            'exploitability': 0.3
        }

    def test_score_complete_catalog(self):
        """测试完整catalog评分"""
        scorer = CVEQualityScorer()

        complete_catalog = {
            "basic_info": {
                "cve_id": "CVE-2021-TEST",
                "name": "Test",
                "cvss_score": 8.5,
                "description": "Test"
            },
            "environment": {
                "docker_image": "test:latest",
                "required_ports": [8080]
            },
            "attack_info": {
                "exploit_method": "Test",
                "complexity": "low"
            },
            "attack_chain": {
                "primary_stage": "initial_access",
                "stage_scores": {"initial_access": 0.8}
            },
            "topology_fit": {
                "network_layer": "dmz",
                "suitable_roles": ["web_server"]
            },
            "verification": {
                "tested": False,
                "success_rate": 0.0
            }
        }

        quality_score = scorer.score_catalog(complete_catalog)

        assert 0 <= quality_score['completeness'] <= 1.0
        assert 0 <= quality_score['accuracy'] <= 1.0
        assert 0 <= quality_score['exploitability'] <= 1.0
        assert 0 <= quality_score['total_score'] <= 1.0


@pytest.mark.integration
class TestCVECatalogLoader:
    """CVE Catalog加载器集成测试"""

    def test_catalog_loader_initialization(self):
        """测试catalog加载器初始化"""
        loader = CVECatalogLoader()
        assert loader.catalog_dir == "data/catalogs/verified"

    def test_load_single_catalog(self):
        """测试单个catalog加载"""
        loader = CVECatalogLoader("data/catalogs/verified")

        catalog = loader.load_catalog("CVE-2021-44228")
        assert catalog is not None
        assert catalog.basic_info.cve_id == "CVE-2021-44228"

    def test_load_all_catalogs(self):
        """测试批量catalog加载"""
        loader = CVECatalogLoader("data/catalogs/verified")

        catalogs = loader.load_all_catalogs()
        assert isinstance(catalogs, dict)
        assert len(catalogs) > 0

    def test_get_cves_by_stage(self):
        """测试按攻击阶段查询CVE"""
        loader = CVECatalogLoader("data/catalogs/verified")

        loader.load_all_catalogs()

        # 查询适合initial_access的CVE
        initial_access_cves = loader.get_cves_by_stage("initial_access", 0.5)
        assert isinstance(initial_access_cves, list)

        # 验证结果包含适合initial_access的CVE
        for catalog in initial_access_cves:
            assert catalog.is_suitable_for_stage("initial_access", 0.5)

    def test_get_cves_by_complexity(self):
        """测试按复杂度查询CVE"""
        loader = CVECatalogLoader("data/catalogs/verified")

        loader.load_all_catalogs()

        # 查询低复杂度CVE
        simple_cves = loader.get_cves_by_complexity("medium")
        assert isinstance(simple_cves, list)

        # 验证结果包含低复杂度CVE
        for catalog in simple_cves:
            complexity = catalog.get_complexity_level()
            assert complexity in ["low", "medium"]


@pytest.mark.integration
class TestAtomicPipeline:
    """完整原子化pipeline集成测试"""

    def test_full_pipeline_simulation(self):
        """测试完整pipeline流程"""
        # 1. 创建测试catalog数据
        test_catalog = {
            "basic_info": {
                "cve_id": "CVE-2021-PIPELINE",
                "name": "Pipeline Test CVE",
                "cvss_score": 8.0,
                "description": "Test CVE for pipeline validation"
            },
            "environment": {
                "docker_image": "test:latest",
                "required_ports": [8080]
            },
            "attack_info": {
                "exploit_method": "Pipeline Test",
                "complexity": "medium"
            },
            "attack_chain": {
                "primary_stage": "initial_access",
                "stage_scores": {"initial_access": 0.8},
                "reasoning": "Test pipeline",
                "confidence": 0.8
            },
            "topology_fit": {
                "network_layer": "dmz",
                "suitable_roles": ["web_server"],
                "requires_attacker": True,
                "internet_accessible": True
            },
            "verification": {
                "tested": False,
                "success_rate": 0.0
            }
        }

        # 2. 验证catalog数据
        validator = CVEAtomicValidator()
        syntax_valid, syntax_issues = validator.validate_catalog_syntax(test_catalog)
        logic_valid, logic_issues = validator.validate_logic_consistency(test_catalog)

        assert syntax_valid, f"语法验证失败: {syntax_issues}"
        assert logic_valid, f"逻辑验证失败: {logic_issues}"

        # 3. 质量评分
        scorer = CVEQualityScorer()
        quality_score = scorer.score_catalog(test_catalog)

        assert quality_score['total_score'] > 0.5, "质量分数太低"

        # 4. 保存catalog到staging
        import tempfile
        import yaml

        staging_dir = "data/processing/staging"
        os.makedirs(staging_dir, exist_ok=True)

        staging_file = os.path.join(staging_dir, "CVE-2021-PIPELINE.yaml")
        with open(staging_file, 'w') as f:
            yaml.dump(test_catalog, f, default_flow_style=False)

        assert os.path.exists(staging_file)

        # 5. 验证文件内容
        with open(staging_file, 'r') as f:
            loaded_data = yaml.safe_load(f)
            assert loaded_data == test_catalog