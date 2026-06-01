"""
ATT&CK攻击阶段映射器 - 将CVE映射到MITRE ATT&CK阶段

支持自动推断和手动映射
"""

import re
from typing import Dict, List, Tuple
from .catalog import MITREAttackStage, AttackChainFit


class AttackStageMapper:
    """ATT&CK阶段映射器"""

    def __init__(self):
        # 阶段关键词映射
        self.stage_keywords = {
            MITREAttackStage.INITIAL_ACCESS: [
                "entry point", "initial access", "gain foothold", "remote exploit",
                "remote", "网络入口", "初始访问", "远程利用", "边界突破"
            ],
            MITREAttackStage.EXECUTION: [
                "code execution", "rce", "remote code execution", "run command",
                "execute", "command execution", "代码执行", "远程执行"
            ],
            MITREAttackStage.PERSISTENCE: [
                "backdoor", "persistence", "maintain access", "survive",
                "持久化", "后门", "维持访问", "生存"
            ],
            MITREAttackStage.PRIVILEGE_ESCALATION: [
                "privilege escalation", "escalate", "privilege", "root", "admin",
                "权限提升", "提权", "获得更高权限"
            ],
            MITREAttackStage.DEFENSE_EVASION: [
                "defense evasion", "bypass", "avoid detection", "stealth",
                "防御规避", "绕过检测", "隐蔽", "规避"
            ],
            MITREAttackStage.CREDENTIAL_ACCESS: [
                "credential", "password", "hash", "token", "authentication",
                "凭证", "密码", "凭据", "认证信息"
            ],
            MITREAttackStage.DISCOVERY: [
                "reconnaissance", "scan", "discover", "enumerate", "gather info",
                "侦察", "扫描", "信息收集", "发现"
            ],
            MITREAttackStage.LATERAL_MOVEMENT: [
                "lateral", "spread", "pivot", "internal", "movement",
                "横向移动", "内网渗透", "扩展攻击范围", "跳板"
            ],
            MITREAttackStage.COLLECTION: [
                "data collection", "gather", "exfiltrate", "steal",
                "数据收集", "窃取", "收集数据"
            ],
            MITREAttackStage.COMMAND_AND_CONTROL: [
                "c2", "command and control", "callback", "communication",
                "命令控制", "C2", "通信", "建立连接"
            ],
            MITREAttackStage.EXFILTRATION: [
                "exfiltration", "data theft", "export data", "steal data",
                "数据窃取", "数据外传", "导出数据"
            ],
            MITREAttackStage.IMPACT: [
                "impact", "damage", "disrupt", "destroy", "ransomware",
                "造成影响", "破坏", "影响", "勒索软件"
            ]
        }

        # CVE特征到阶段的启发式规则
        # Pattern支持多种表达方式，包括带空格的完整描述
        self.heuristics = {
            "remote code execution": [
                MITREAttackStage.INITIAL_ACCESS,
                MITREAttackStage.EXECUTION,
                MITREAttackStage.LATERAL_MOVEMENT
            ],
            "rce": [
                MITREAttackStage.INITIAL_ACCESS,
                MITREAttackStage.EXECUTION,
                MITREAttackStage.LATERAL_MOVEMENT
            ],
            "sql_injection": [
                MITREAttackStage.INITIAL_ACCESS,
                MITREAttackStage.EXECUTION
            ],
            "authentication_bypass": [
                MITREAttackStage.CREDENTIAL_ACCESS,
                MITREAttackStage.INITIAL_ACCESS
            ],
            "privilege_escalation": [
                MITREAttackStage.PRIVILEGE_ESCALATION
            ],
            "file_inclusion": [
                MITREAttackStage.INITIAL_ACCESS,
                MITREAttackStage.LATERAL_MOVEMENT
            ]
        }

    def map_from_description(self, cve_description: str, cvss_vector: str = "") -> AttackChainFit:
        """从CVE描述推断ATT&CK阶段适配"""

        stage_scores = {stage.value: 0.0 for stage in MITREAttackStage}

        # 1. 从描述中提取关键词
        combined_text = (cve_description + " " + cvss_vector).lower()

        for stage, keywords in self.stage_keywords.items():
            for keyword in keywords:
                if keyword.lower() in combined_text:
                    stage_scores[stage.value] += 0.3

        # 2. 应用启发式规则
        for pattern, applicable_stages in self.heuristics.items():
            if pattern in cve_description.lower():
                for stage in applicable_stages:
                    stage_scores[stage.value] += 0.4

        # 3. 基于CVSS向量调整
        # CVSS向量格式: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
        if "AV:N" in cvss_vector:  # Network attack vector
            stage_scores[MITREAttackStage.INITIAL_ACCESS.value] += 0.2

        if "AV:L" in cvss_vector or "AV:A" in cvss_vector:  # Local or Adjacent attack vector
            stage_scores[MITREAttackStage.LATERAL_MOVEMENT.value] += 0.2
            stage_scores[MITREAttackStage.PRIVILEGE_ESCALATION.value] += 0.2

        if "S:C" in cvss_vector:  # Scope Changed
            stage_scores[MITREAttackStage.LATERAL_MOVEMENT.value] += 0.1

        # 4. 标准化到0-1范围
        for stage in stage_scores:
            stage_scores[stage] = min(stage_scores[stage], 1.0)

        # 5. 确定主要阶段
        primary_stage = self._determine_primary_stage(stage_scores)

        # 6. 生成适配理由
        reasoning = self._generate_reasoning(stage_scores, cve_description)

        return AttackChainFit(
            primary_stage=primary_stage,
            stage_scores=stage_scores,
            reasoning=reasoning,
            confidence=max(stage_scores.values())
        )

    def _determine_primary_stage(self, stage_scores: Dict[str, float]) -> MITREAttackStage:
        """确定主要攻击阶段"""
        max_score = 0.0
        primary_stage = MITREAttackStage.INITIAL_ACCESS  # 默认值

        for stage_name, score in stage_scores.items():
            if score > max_score:
                max_score = score
                try:
                    primary_stage = MITREAttackStage(stage_name)
                except ValueError:
                    continue

        return primary_stage

    def _generate_reasoning(self, stage_scores: Dict[str, float], description: str) -> str:
        """生成适配理由"""
        top_stages = sorted(stage_scores.items(), key=lambda x: x[1], reverse=True)[:3]

        reasons = []
        for stage_name, score in top_stages:
            if score > 0.5:
                stage_obj = MITREAttackStage(stage_name)
                reasons.append(f"适合{stage_obj.value.replace('_', ' ')} (适配度: {score:.1f})")

        return "；".join(reasons) if reasons else "基于描述关键词分析"

    def map_from_writeup(self, writeup_content: str) -> AttackChainFit:
        """从writeup内容推断ATT&CK阶段"""
        # 与从描述映射类似，但可以分析更详细的writeup内容
        return self.map_from_description(writeup_content)

    def map_from_exploit_code(self, exploit_code: str) -> AttackChainFit:
        """从exploit代码推断ATT&CK阶段"""
        # 分析exploit代码的特征
        if "socket" in exploit_code.lower() and "connect" in exploit_code.lower():
            # 网络连接，可能用于初始访问或横向移动
            pass

        # 这里可以添加更复杂的代码分析逻辑
        return self.map_from_description(exploit_code)


class AttackChainAnalyzer:
    """攻击链分析器 - 验证CVE组合的攻击链逻辑"""

    def __init__(self):
        self.mapper = AttackStageMapper()

    def validate_attack_chain(self, cve_chain: List[str]) -> Tuple[bool, List[str]]:
        """验证CVE攻击链的逻辑性"""
        issues = []

        # 简化的验证逻辑
        # 1. 检查阶段覆盖
        stages_covered = set()
        for cve_id in cve_chain:
            # 这里应该加载每个CVE的catalog并检查其适配阶段
            # 暂时跳过实际加载
            pass

        # 2. 检查阶段顺序
        stage_order = [
            MITREAttackStage.INITIAL_ACCESS,
            MITREAttackStage.EXECUTION,
            MITREAttackStage.LATERAL_MOVEMENT,
            MITREAttackStage.PRIVILEGE_ESCALATION,
            MITREAttackStage.PERSISTENCE
        ]

        # 3. 检查逻辑合理性
        # 例如：不能在没有获得初始访问的情况下进行横向移动

        return len(issues) == 0, issues

    def recommend_attack_chain(self, target_stages: List[str]) -> List[str]:
        """推荐符合目标攻击链的CVE"""
        # 这里应该根据ATT&CK阶段查找适配的CVE
        # 暂时返回空列表
        return []


# 使用示例
if __name__ == "__main__":
    mapper = AttackStageMapper()

    # 测试映射
    test_description = "Apache Log4j remote code execution via JNDI injection"
    test_cvss = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"

    attack_chain = mapper.map_from_description(test_description, test_cvss)

    print("🎯 ATT&CK阶段映射结果:")
    print(f"  主要阶段: {attack_chain.primary_stage.value}")
    print(f"  置信度: {attack_chain.confidence:.2f}")
    print(f"  理由: {attack_chain.reasoning}")
    print(f"  各阶段评分:")
    for stage, score in attack_chain.stage_scores.items():
        if score > 0:
            print(f"    {stage}: {score:.2f}")