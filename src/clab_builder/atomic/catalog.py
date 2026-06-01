"""
CVE Catalog 定义 - 实用且可操作的CVE原子化信息

只包含容易获取和验证的信息，避免过度复杂的主观评估。
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum


class MITREAttackStage(Enum):
    """MITRE ATT&CK 攻击阶段"""
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class ExploitComplexity(Enum):
    """利用复杂度"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    EXPERT = "expert"


class NetworkLayer(Enum):
    """网络层级"""
    ATTACKER = "attacker"        # 攻击者区域
    DMZ = "dmz"                # 非军事化区
    INTERNAL = "internal"        # 内网
    ISOLATED = "isolated"       # 隔离区域


@dataclass
class AttackChainFit:
    """ATT&CK攻击链适配度"""
    primary_stage: MITREAttackStage          # 主要适合的阶段
    stage_scores: Dict[str, float]           # 各阶段的适配分数
    reasoning: str                            # 适配理由
    confidence: float = 0.0                  # 置信度 (0-1)

    def get_stages_above_threshold(self, threshold: float = 0.7) -> List[str]:
        """获取高于阈值的阶段"""
        return [stage for stage, score in self.stage_scores.items() if score >= threshold]


@dataclass
class BasicInfo:
    """CVE基础信息 (可从NVD自动获取)"""
    cve_id: str
    name: str
    cvss_score: float
    description: str
    publish_date: str
    cwe_id: Optional[str] = None
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None


@dataclass
class EnvironmentInfo:
    """环境信息 (可从VulnHub自动获取)"""
    docker_image: str
    image_source: str
    required_ports: List[int]
    estimated_memory: int                    # MB
    startup_time: int                        # seconds to be ready
    os_type: str = "linux"


@dataclass
class AttackInfo:
    """攻击信息 (可从writeups分析)"""
    exploit_method: str
    attack_surface: str                     # HTTP/SSH/SMB etc
    access_required: str                    # network/local
    complexity: ExploitComplexity
    popular: bool                           # 是否是热门漏洞
    exploit_available: bool                 # 是否有公开exploit


@dataclass
class TopologyFit:
    """拓扑适配信息"""
    suitable_roles: List[str]               # web_server/database/server等
    network_layer: NetworkLayer
    requires_attacker: bool                 # 是否需要攻击者节点
    internet_accessible: bool              # 是否可从外网访问
    dependencies: List[str] = field(default_factory=list)  # 依赖的服务


@dataclass
class VerificationStatus:
    """验证状态"""
    tested: bool                            # 是否经过实际测试
    success_rate: float                     # 测试成功率 (0-1)
    last_tested: str                        # 最后测试日期
    test_count: int = 0                     # 测试次数
    notes: List[str] = field(default_factory=list)  # 测试笔记


@dataclass
class CVECatalog:
    """
    CVE原子化Catalog - 实用且可操作的CVE信息

    设计原则:
    - 只包含容易获取和验证的信息
    - 支持自动化收集和处理
    - 面向训练场景设计
    """
    # 基础信息
    basic_info: BasicInfo

    # 环境信息
    environment: EnvironmentInfo

    # 攻击信息
    attack_info: AttackInfo

    # ATT&CK阶段适配
    attack_chain: AttackChainFit

    # 拓扑适配
    topology_fit: TopologyFit

    # 验证状态
    verification: VerificationStatus

    # 元数据
    catalog_version: str = "1.0"
    last_updated: str = ""
    source_reliability: str = "medium"      # high/medium/low

    def get_primary_attack_stage(self) -> str:
        """获取主要攻击阶段"""
        return self.attack_chain.primary_stage.value

    def is_suitable_for_stage(self, stage: str, threshold: float = 0.7) -> bool:
        """检查是否适合指定攻击阶段"""
        stage_score = self.attack_chain.stage_scores.get(stage, 0.0)
        return stage_score >= threshold

    def get_memory_requirement(self) -> int:
        """获取内存需求"""
        return self.environment.estimated_memory

    def requires_external_network(self) -> bool:
        """是否需要外部网络"""
        return self.topology_fit.internet_accessible

    def get_complexity_level(self) -> str:
        """获取利用复杂度"""
        return self.attack_info.complexity.value

    def is_verified(self) -> bool:
        """是否已验证"""
        return self.verification.tested and self.verification.success_rate > 0.8

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "cve_id": self.basic_info.cve_id,
            "name": self.basic_info.name,
            "cvss_score": self.basic_info.cvss_score,
            "docker_image": self.environment.docker_image,
            "attack_method": self.attack_info.exploit_method,
            "primary_stage": self.attack_chain.primary_stage.value,
            "network_layer": self.topology_fit.network_layer.value,
            "verified": self.is_verified(),
            "complexity": self.get_complexity_level()
        }


class CVECatalogLoader:
    """CVE Catalog加载器"""

    def __init__(self, catalog_dir: str = "data/catalogs/verified"):
        self.catalog_dir = catalog_dir
        self._catalogs: Dict[str, CVECatalog] = {}

    def load_catalog(self, cve_id: str) -> Optional[CVECatalog]:
        """加载指定CVE的catalog"""
        import os
        import yaml

        catalog_path = os.path.join(self.catalog_dir, f"{cve_id}.yaml")
        if not os.path.exists(catalog_path):
            return None

        try:
            with open(catalog_path, 'r') as f:
                data = yaml.safe_load(f)

            return self._dict_to_catalog(data)
        except Exception as e:
            print(f"Error loading catalog for {cve_id}: {e}")
            return None

    def load_all_catalogs(self) -> Dict[str, CVECatalog]:
        """加载所有验证过的catalog"""
        import os
        import glob

        catalog_files = glob.glob(os.path.join(self.catalog_dir, "*.yaml"))

        for catalog_file in catalog_files:
            cve_id = os.path.basename(catalog_file).replace('.yaml', '')
            catalog = self.load_catalog(cve_id)
            if catalog:
                self._catalogs[cve_id] = catalog

        return self._catalogs

    def _dict_to_catalog(self, data: Dict) -> CVECatalog:
        """从字典构建catalog对象"""
        # 转换字符串枚举为枚举对象
        basic_info_dict = data.get('basic_info', {})
        environment_dict = data.get('environment', {})
        attack_info_dict = data.get('attack_info', {})
        attack_chain_dict = data.get('attack_chain', {})
        topology_fit_dict = data.get('topology_fit', {})
        verification_dict = data.get('verification', {})

        # 转换complexity字符串为枚举
        if 'complexity' in attack_info_dict:
            complexity_str = attack_info_dict['complexity']
            attack_info_dict['complexity'] = ExploitComplexity(complexity_str)

        # 转换network_layer字符串为枚举
        if 'network_layer' in topology_fit_dict:
            layer_str = topology_fit_dict['network_layer']
            topology_fit_dict['network_layer'] = NetworkLayer(layer_str)

        # 转换primary_stage字符串为枚举
        if 'primary_stage' in attack_chain_dict:
            stage_str = attack_chain_dict['primary_stage']
            attack_chain_dict['primary_stage'] = MITREAttackStage(stage_str)

        return CVECatalog(
            basic_info=BasicInfo(**basic_info_dict),
            environment=EnvironmentInfo(**environment_dict),
            attack_info=AttackInfo(**attack_info_dict),
            attack_chain=AttackChainFit(**attack_chain_dict),
            topology_fit=TopologyFit(**topology_fit_dict),
            verification=VerificationStatus(**verification_dict),
            last_updated=data.get('last_updated', ''),
            source_reliability=data.get('source_reliability', 'medium')
        )

    def get_cves_by_stage(self, stage: str, min_score: float = 0.7) -> List[CVECatalog]:
        """按攻击阶段获取CVE"""
        result = []

        if not self._catalogs:
            self.load_all_catalogs()

        for catalog in self._catalogs.values():
            if catalog.is_suitable_for_stage(stage, min_score):
                result.append(catalog)

        return result

    def get_cves_by_complexity(self, max_complexity: str = "medium") -> List[CVECatalog]:
        """按复杂度获取CVE"""
        complexity_order = {"low": 1, "medium": 2, "high": 3, "expert": 4}
        max_level = complexity_order.get(max_complexity, 2)

        result = []
        for catalog in self._catalogs.values():
            current_level = complexity_order.get(catalog.get_complexity_level(), 99)
            if current_level <= max_level:
                result.append(catalog)

        return result