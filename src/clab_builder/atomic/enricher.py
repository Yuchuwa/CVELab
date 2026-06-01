"""
CVE信息丰富器 - 从多个数据源丰富catalog信息

支持从writeups、exploits、CVE数据库等来源获取详细信息
"""

import requests
import re
from typing import Dict, List, Optional
from .catalog import CVECatalog


class CVEEnricher:
    """CVE信息丰富器"""

    def __init__(self):
        self.data_sources = {
            'github_exploits': 'https://api.github.com/search/repositories',
            'exploitdb': 'https://www.exploit-db.com/',
            'nvd': 'https://nvd.nist.gov/vuln/detail/'
        }

    def enrich_from_writeups(self, cve_id: str, catalog_data: Dict) -> Dict:
        """从writeups丰富信息"""
        enriched_data = catalog_data.copy()

        # 这里应该实现实际的writeup收集逻辑
        # 1. 搜索GitHub相关writeups
        # 2. 搜索Medium/Blog文章
        # 3. 提取攻击细节和技巧

        # 简化版本：添加模拟的writeup信息
        enriched_data['writeups'] = [
            {
                'source': 'github',
                'url': 'https://github.com/example/log4j-writeup',
                'reliability': 'high'
            }
        ]

        return enriched_data

    def enrich_from_exploits(self, cve_id: str, catalog_data: Dict) -> Dict:
        """从exploit代码丰富信息"""
        enriched_data = catalog_data.copy()

        # 这里应该实现实际的exploit收集逻辑
        # 1. 查询exploit-db
        # 2. 搜索GitHub POC代码
        # 3. 分析Metasploit模块

        enriched_data['exploits'] = [
            {
                'source': 'exploitdb',
                'url': 'https://www.exploit-db.com/exploits/50574',
                'language': 'python',
                'verified': True
            }
        ]

        return enriched_data

    def enrich_attack_chain_analysis(self, cve_id: str, catalog_data: Dict) -> Dict:
        """丰富攻击链分析"""
        from .mapper import AttackStageMapper

        mapper = AttackStageMapper()

        # 基于CVE描述映射ATT&CK阶段
        attack_chain = mapper.map_from_description(
            catalog_data['basic_info']['description'],
            catalog_data['basic_info'].get('attack_vector', '')
        )

        enriched_data = catalog_data.copy()
        enriched_data['attack_chain'] = {
            'primary_stage': attack_chain.primary_stage.value,
            'stage_scores': attack_chain.stage_scores,
            'reasoning': attack_chain.reasoning,
            'confidence': attack_chain.confidence
        }

        return enriched_data

    def enrich_topology_analysis(self, cve_id: str, catalog_data: Dict) -> Dict:
        """丰富拓扑适配分析"""
        enriched_data = catalog_data.copy()

        # 分析环境信息推断拓扑适配
        ports = catalog_data['environment'].get('required_ports', [])

        # 基于端口推断适合的角色和网络层
        if 80 in ports or 443 in ports or 8080 in ports:
            suitable_roles = ['web_server', 'api_server', 'reverse_proxy']
            network_layer = 'dmz'
        elif 3306 in ports or 5432 in ports:
            suitable_roles = ['database']
            network_layer = 'internal'
        elif 22 in ports or 3389 in ports:
            suitable_roles = ['server', 'workstation']
            network_layer = 'internal'
        else:
            suitable_roles = ['server']
            network_layer = 'internal'

        enriched_data['topology_fit'] = {
            'suitable_roles': suitable_roles,
            'network_layer': network_layer,
            'requires_attacker': True,
            'internet_accessible': network_layer == 'dmz',
            'dependencies': []
        }

        return enriched_data

    def full_enrichment_pipeline(self, cve_id: str, basic_catalog: Dict) -> Dict:
        """完整的丰富化流程"""
        enriched = basic_catalog.copy()

        # 按顺序丰富各个部分
        enriched = self.enrich_from_writeups(cve_id, enriched)
        enriched = self.enrich_from_exploits(cve_id, enriched)
        enriched = self.enrich_attack_chain_analysis(cve_id, enriched)
        enriched = self.enrich_topology_analysis(cve_id, enriched)

        # 添加时间戳
        from datetime import datetime
        enriched['last_updated'] = datetime.now().isoformat()

        return enriched


class WriteupAnalyzer:
    """Writeup分析器 - 从writeups中提取有用信息"""

    def __init__(self):
        self.useful_patterns = {
            'exploit_steps': r'(step|phase|stage).{0,10}?\d*[:\s]*(exploit|attack|payload)',
            'success_indicators': r'(success|working|gained|access|shell)',
            'failure_indicators': r'(failed|error|denied|blocked)',
            'tools_used': r'(tool|script|exploit|framework)[:\s]*[\w\-]+',
            'mitigation': r'(mitigate|patch|fix|protect)'
        }

    def analyze_writeup(self, writeup_content: str) -> Dict:
        """分析writeup内容提取关键信息"""
        analysis = {
            'exploit_steps': [],
            'success_indicators': [],
            'tools_used': [],
            'mitigation_techniques': []
        }

        for pattern_name, pattern in self.useful_patterns.items():
            matches = re.findall(pattern, writeup_content, re.IGNORECASE)
            if matches:
                if pattern_name == 'exploit_steps':
                    analysis['exploit_steps'].extend(matches)
                elif pattern_name == 'success_indicators':
                    analysis['success_indicators'].extend(matches)
                elif pattern_name == 'tools_used':
                    analysis['tools_used'].extend(matches)
                elif pattern_name == 'mitigation':
                    analysis['mitigation_techniques'].extend(matches)

        return analysis

    def extract_attack_timeline(self, writeup_content: str) -> List[Dict]:
        """提取攻击时间线"""
        timeline = []

        # 查找时间相关的表达式
        time_patterns = [
            r'(first|then|next|after|before).{0,20}?(step|stage|phase)',
            r'\d+[:\.]\d+\s*(am|pm|A\.M\.|P\.M\.)',
            r'step\s*\d+',
            r'phase\s*\d+'
        ]

        for pattern in time_patterns:
            matches = re.finditer(pattern, writeup_content, re.IGNORECASE)
            for match in matches:
                timeline.append({
                    'timestamp': match.group(),
                    'context': writeup_content[max(0, match.start()-50):match.start()+50]
                })

        return timeline


# 使用示例
if __name__ == "__main__":
    enricher = CVEEnricher()
    analyzer = WriteupAnalyzer()

    # 测试丰富化流程
    basic_catalog = {
        "basic_info": {
            "cve_id": "CVE-2021-44228",
            "name": "Apache Log4j RCE",
            "cvss_score": 10.0,
            "description": "Apache Log4j remote code execution via JNDI injection",
            "attack_vector": "NETWORK"
        },
        "environment": {
            "docker_image": "vulhub/log4j:latest",
            "required_ports": [8080, 8443]
        },
        "attack_info": {
            "exploit_method": "JNDI Injection",
            "complexity": "low"
        }
    }

    # 执行完整丰富化
    enriched_catalog = enricher.full_enrichment_pipeline("CVE-2021-44228", basic_catalog)

    print("🎯 丰富化后的catalog:")
    print(f"  主要攻击阶段: {enriched_catalog.get('attack_chain', {}).get('primary_stage', 'unknown')}")
    print(f"  拓扑适配: {enriched_catalog.get('topology_fit', {}).get('network_layer', 'unknown')}")

    # 测试writeup分析
    sample_writeup = """
    Step 1: Setup the vulnerable Log4j environment.
    Step 2: Prepare the LDAP listener to receive connections.
    Step 3: Send the JNDI injection payload to exploit the vulnerability.
    Success: We received a callback connection on port 1389.
    Tools used: curl, netcat, docker
    """

    analysis = analyzer.analyze_writeup(sample_writeup)
    print(f"\n📋 Writeup分析:")
    print(f"  利用步骤: {analysis['exploit_steps']}")
    print(f"  成功指标: {analysis['success_indicators']}")
    print(f"  使用工具: {analysis['tools_used']}")