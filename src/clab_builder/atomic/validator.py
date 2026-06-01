"""
CVE原子化验证器 - 验证catalog的准确性和可用性

验证流程: 语法检查 → 逻辑验证 → 实际测试 → 质量评分
"""

import os
import yaml
import subprocess
from typing import Dict, List, Tuple, Optional
from datetime import datetime
from .catalog import CVECatalog, VerificationStatus


class CVEAtomicValidator:
    """CVE原子化验证器"""

    def __init__(self):
        self.validation_results = []

    def validate_catalog_syntax(self, catalog_data: Dict) -> Tuple[bool, List[str]]:
        """验证catalog语法"""
        issues = []

        # 检查必需字段
        required_sections = ['basic_info', 'environment', 'attack_info', 'attack_chain', 'topology_fit', 'verification']
        for section in required_sections:
            if section not in catalog_data:
                issues.append(f"缺少必需部分: {section}")

        # 检查basic_info字段
        if 'basic_info' in catalog_data:
            basic_fields = ['cve_id', 'name', 'cvss_score', 'description']
            for field in basic_fields:
                if field not in catalog_data['basic_info'] or not catalog_data['basic_info'][field]:
                    issues.append(f"basic_info.{field} 为空")

        # 检查environment字段
        if 'environment' in catalog_data:
            if 'docker_image' not in catalog_data['environment'] or not catalog_data['environment']['docker_image']:
                issues.append("environment.docker_image 为空")

        return len(issues) == 0, issues

    def validate_logic_consistency(self, catalog_data: Dict) -> Tuple[bool, List[str]]:
        """验证逻辑一致性"""
        issues = []

        # 检查CVSS分数范围
        cvss_score = catalog_data.get('basic_info', {}).get('cvss_score', 0)
        if not 0 <= cvss_score <= 10:
            issues.append(f"CVSS分数超出范围: {cvss_score}")

        # 检查端口合理性
        ports = catalog_data.get('environment', {}).get('required_ports', [])
        invalid_ports = [p for p in ports if not 1 <= p <= 65535]
        if invalid_ports:
            issues.append(f"无效的端口号: {invalid_ports}")

        # 检查attack_chain分数范围
        stage_scores = catalog_data.get('attack_chain', {}).get('stage_scores', {})
        for stage, score in stage_scores.items():
            if not 0 <= score <= 1:
                issues.append(f"attack_chain.{stage} 分数超出范围: {score}")

        return len(issues) == 0, issues

    def validate_docker_image(self, docker_image: str) -> Tuple[bool, str]:
        """验证Docker镜像可用性"""
        try:
            # 检查镜像是否可以拉取
            result = subprocess.run(
                ["docker", "pull", docker_image],
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0:
                return True, "镜像拉取成功"
            else:
                return False, f"镜像拉取失败: {result.stderr}"

        except subprocess.TimeoutExpired:
            return False, "镜像拉取超时"
        except Exception as e:
            return False, f"检查镜像时出错: {str(e)}"

    def validate_exploit_possibility(self, catalog_data: Dict) -> Tuple[bool, List[str]]:
        """验证利用可能性"""
        issues = []

        # 检查是否有明确的利用方法
        exploit_method = catalog_data.get('attack_info', {}).get('exploit_method', '')
        if not exploit_method or exploit_method == "unknown":
            issues.append("缺少明确的利用方法")

        # 检查复杂度是否合理
        complexity = catalog_data.get('attack_info', {}).get('complexity', '')
        if complexity not in ['low', 'medium', 'high', 'expert']:
            issues.append(f"无效的复杂度: {complexity}")

        # 检查是否有可用的端口
        ports = catalog_data.get('environment', {}).get('required_ports', [])
        if not ports:
            issues.append("没有定义端口，无法进行利用")

        return len(issues) == 0, issues

    def validate_catalog_file(self, catalog_path: str) -> Tuple[bool, Dict]:
        """验证catalog文件"""
        if not os.path.exists(catalog_path):
            return False, {"error": "文件不存在"}

        try:
            with open(catalog_path, 'r') as f:
                catalog_data = yaml.safe_load(f)

            # 执行各种验证
            syntax_valid, syntax_issues = self.validate_catalog_syntax(catalog_data)
            logic_valid, logic_issues = self.validate_logic_consistency(catalog_data)
            exploit_valid, exploit_issues = self.validate_exploit_possibility(catalog_data)

            all_issues = syntax_issues + logic_issues + exploit_issues

            validation_result = {
                "syntax_valid": syntax_valid,
                "logic_valid": logic_valid,
                "exploit_valid": exploit_valid,
                "overall_valid": syntax_valid and logic_valid and exploit_valid,
                "issues": all_issues,
                "validation_timestamp": datetime.now().isoformat()
            }

            return validation_result["overall_valid"], validation_result

        except Exception as e:
            return False, {"error": f"验证过程中出错: {str(e)}"}

    def move_to_verified(self, catalog_path: str) -> bool:
        """将验证通过的catalog移到verified目录"""
        try:
            import shutil
            verified_dir = "data/catalogs/verified"
            os.makedirs(verified_dir, exist_ok=True)

            filename = os.path.basename(catalog_path)
            destination = os.path.join(verified_dir, filename)

            shutil.copy(catalog_path, destination)
            print(f"✅ Catalog已验证并移至: {destination}")
            return True

        except Exception as e:
            print(f"❌ 移动文件失败: {e}")
            return False

    def move_to_failed(self, catalog_path: str, issues: List[str]) -> bool:
        """将验证失败的catalog移到failed目录"""
        try:
            import shutil
            failed_dir = "data/catalogs/failed"
            os.makedirs(failed_dir, exist_ok=True)

            filename = os.path.basename(catalog_path)
            destination = os.path.join(failed_dir, filename)

            shutil.copy(catalog_path, destination)

            # 保存失败原因
            error_file = destination.replace('.yaml', '_errors.txt')
            with open(error_file, 'w') as f:
                f.write("验证失败原因:\n")
                for issue in issues:
                    f.write(f"  - {issue}\n")

            print(f"❌ Catalog验证失败，已移至: {destination}")
            return True

        except Exception as e:
            print(f"❌ 移动失败文件失败: {e}")
            return False

    def verify_and_move(self, catalog_path: str) -> bool:
        """验证并移动catalog的完整流程"""
        is_valid, result = self.validate_catalog_file(catalog_path)

        if is_valid:
            return self.move_to_verified(catalog_path)
        else:
            issues = result.get('issues', [])
            return self.move_to_failed(catalog_path, issues)


class CVEQualityScorer:
    """CVE质量评分器"""

    def __init__(self):
        self.score_weights = {
            'completeness': 0.3,     # 信息完整度
            'accuracy': 0.4,         # 信息准确性
            'exploitability': 0.3    # 可利用性
        }

    def score_catalog(self, catalog_data: Dict) -> Dict[str, float]:
        """对catalog进行质量评分"""
        completeness = self._score_completeness(catalog_data)
        accuracy = self._score_accuracy(catalog_data)
        exploitability = self._score_exploitability(catalog_data)

        total_score = (
            completeness * self.score_weights['completeness'] +
            accuracy * self.score_weights['accuracy'] +
            exploitability * self.score_weights['exploitability']
        )

        return {
            'completeness': completeness,
            'accuracy': accuracy,
            'exploitability': exploitability,
            'total_score': total_score
        }

    def _score_completeness(self, catalog_data: Dict) -> float:
        """评分信息完整度"""
        required_fields = {
            'basic_info': ['cve_id', 'name', 'cvss_score', 'description'],
            'environment': ['docker_image', 'required_ports'],
            'attack_info': ['exploit_method', 'complexity'],
            'attack_chain': ['primary_stage', 'stage_scores'],
            'topology_fit': ['suitable_roles', 'network_layer']
        }

        total_fields = sum(len(fields) for fields in required_fields.values())
        filled_fields = 0

        for section, fields in required_fields.items():
            section_data = catalog_data.get(section, {})
            for field in fields:
                if section_data.get(field):
                    filled_fields += 1

        return filled_fields / total_fields if total_fields > 0 else 0.0

    def _score_accuracy(self, catalog_data: Dict) -> float:
        """评分信息准确性"""
        score = 0.0

        # 检查CVE ID格式
        cve_id = catalog_data.get('basic_info', {}).get('cve_id', '')
        if cve_id and cve_id.startswith('CVE-'):
            score += 0.3

        # 检查CVSS分数合理性
        cvss = catalog_data.get('basic_info', {}).get('cvss_score', 0)
        if 0 <= cvss <= 10:
            score += 0.3

        # 检查attack_chain分数范围
        stage_scores = catalog_data.get('attack_chain', {}).get('stage_scores', {})
        valid_scores = all(0 <= score <= 1 for score in stage_scores.values())
        if valid_scores:
            score += 0.4

        return min(score, 1.0)

    def _score_exploitability(self, catalog_data: Dict) -> float:
        """评分可利用性"""
        score = 0.0

        # 检查是否有明确的利用方法
        exploit_method = catalog_data.get('attack_info', {}).get('exploit_method', '')
        if exploit_method and exploit_method != 'unknown':
            score += 0.4

        # 检查复杂度
        complexity = catalog_data.get('attack_info', {}).get('complexity', 'high')
        if complexity == 'low':
            score += 0.4
        elif complexity == 'medium':
            score += 0.2

        # 检查exploit可用性
        if catalog_data.get('attack_info', {}).get('exploit_available', False):
            score += 0.2

        return min(score, 1.0)


# 使用示例
if __name__ == "__main__":
    validator = CVEAtomicValidator()
    scorer = CVEQualityScorer()

    # 测试验证
    test_catalog = {
        "basic_info": {
            "cve_id": "CVE-2021-44228",
            "name": "Test CVE",
            "cvss_score": 10.0,
            "description": "Test description"
        },
        "environment": {
            "docker_image": "vulhub/log4j:latest",
            "required_ports": [8080]
        },
        "attack_info": {
            "exploit_method": "JNDI Injection",
            "complexity": "low",
            "exploit_available": True
        },
        "attack_chain": {
            "primary_stage": "initial_access",
            "stage_scores": {"initial_access": 0.9, "execution": 0.8}
        },
        "topology_fit": {
            "suitable_roles": ["web_server"],
            "network_layer": "dmz"
        },
        "verification": {
            "tested": False,
            "success_rate": 0.0
        }
    }

    # 验证语法
    syntax_valid, issues = validator.validate_catalog_syntax(test_catalog)
    print(f"语法验证: {'✅ 通过' if syntax_valid else '❌ 失败'}")
    if issues:
        for issue in issues:
            print(f"  - {issue}")

    # 质量评分
    quality_score = scorer.score_catalog(test_catalog)
    print(f"\n📊 质量评分:")
    print(f"  完整度: {quality_score['completeness']:.2f}")
    print(f"  准确性: {quality_score['accuracy']:.2f}")
    print(f"  可利用性: {quality_score['exploitability']:.2f}")
    print(f"  总分: {quality_score['total_score']:.2f}")