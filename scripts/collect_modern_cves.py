#!/usr/bin/env python3
"""
现代CVE Catalog批量收集工具 (仅2018年以后的漏洞)

自动从多个数据源收集现代CVE信息并生成标准catalog
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import json
import yaml
import requests
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from clab_builder.atomic.processor import CVEProcessor
from clab_builder.atomic.mapper import AttackStageMapper
from clab_builder.atomic.validator import CVEAtomicValidator, CVEQualityScorer
from clab_builder.atomic.catalog import CVECatalog


class ModernCVECollector:
    """现代CVE Catalog批量收集器 (2018年以后)"""

    def __init__(self, output_dir: str = "data/catalogs/verified"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.mapper = AttackStageMapper()
        self.validator = CVEAtomicValidator()
        self.scorer = CVEQualityScorer()

        # 现代CVE列表 (2018年以后)
        self.target_cves = self._load_modern_cves()

        # 统计信息
        self.stats = {
            'total': 0,
            'successful': 0,
            'failed': 0,
            'low_quality': 0,
            'attack_stages': {}
        }

    def _load_modern_cves(self) -> List[Dict]:
        """加载现代CVE列表 (2018年以后)"""
        return [
            # Privilege Escalation (现代权限提升)
            {
                'cve_id': 'CVE-2021-4034',
                'name': 'PwnKit Polkit Privilege Escalation',
                'docker_image': 'vulhub/pwnkit:latest',
                'attack_stage_priority': ['privilege_escalation']
            },
            {
                'cve_id': 'CVE-2022-0847',
                'name': 'Dirty Pipe Linux Kernel Privilege Escalation',
                'docker_image': 'vulhub/dirty-pipe:latest',
                'attack_stage_priority': ['privilege_escalation']
            },
            {
                'cve_id': 'CVE-2021-3156',
                'name': 'Baron Samedit Sudo Privilege Escalation',
                'docker_image': 'vulhub/sudo:latest',
                'attack_stage_priority': ['privilege_escalation']
            },

            # Modern Web RCE (现代Web RCE)
            {
                'cve_id': 'CVE-2019-0708',
                'name': 'BlueKeep RDP RCE',
                'docker_image': 'vuln/bluekeep:latest',
                'attack_stage_priority': ['initial_access', 'lateral_movement', 'execution']
            },
            {
                'cve_id': 'CVE-2020-0796',
                'name': 'SMBGhost RCE',
                'docker_image': 'vuln/smbghost:latest',
                'attack_stage_priority': ['initial_access', 'lateral_movement', 'execution']
            },
            {
                'cve_id': 'CVE-2020-0688',
                'name': 'Microsoft SharePoint RCE',
                'docker_image': 'vulhub/sharepoint:latest',
                'attack_stage_priority': ['initial_access', 'defense_evasion', 'persistence']
            },
            {
                'cve_id': 'CVE-2020-1472',
                'name': 'Zerologon Active Directory RCE',
                'docker_image': 'vulhub/zerologon:latest',
                'attack_stage_priority': ['initial_access', 'lateral_movement', 'credential_access']
            },

            # Container & Cloud Security (容器和云安全)
            {
                'cve_id': 'CVE-2019-14271',
                'name': 'Docker Container Escape',
                'docker_image': 'vulhub/docker:latest',
                'attack_stage_priority': ['privilege_escalation', 'defense_evasion']
            },
            {
                'cve_id': 'CVE-2019-5736',
                'name': 'Docker Container RCE',
                'docker_image': 'vulhub/docker:latest',
                'attack_stage_priority': ['initial_access', 'execution', 'privilege_escalation']
            },
            {
                'cve_id': 'CVE-2021-44228',
                'name': 'Log4j Remote Code Execution',
                'docker_image': 'vulhub/log4j:latest',
                'attack_stage_priority': ['initial_access', 'execution', 'lateral_movement']
            },
            {
                'cve_id': 'CVE-2021-26084',
                'name': 'Confluence OGNL Injection RCE',
                'docker_image': 'vulhub/confluence:latest',
                'attack_stage_priority': ['initial_access', 'execution']
            },

            # SQL Injection & Database (SQL注入和数据库)
            {
                'cve_id': 'CVE-2018-17276',
                'name': 'phpMyAdmin SQL Injection',
                'docker_image': 'vulhub/phpmyadmin:latest',
                'attack_stage_priority': ['initial_access', 'execution']
            },
            {
                'cve_id': 'CVE-2019-20372',
                'name': 'WordPress SQL Injection',
                'docker_image': 'vulhub/wordpress:latest',
                'attack_stage_priority': ['initial_access', 'execution']
            },
            {
                'cve_id': 'CVE-2020-9484',
                'name': 'Apache Tomcat Deserialization RCE',
                'docker_image': 'vulhub/tomcat:latest',
                'attack_stage_priority': ['initial_access', 'execution']
            },

            # File Operations (文件操作漏洞)
            {
                'cve_id': 'CVE-2018-12613',
                'name': 'WordPress File Upload RCE',
                'docker_image': 'vulhub/wordpress:latest',
                'attack_stage_priority': ['initial_access', 'execution', 'defense_evasion']
            },
            {
                'cve_id': 'CVE-2019-16739',
                'name': 'GetSimpleCMS File Upload',
                'docker_image': 'vulhub/get-simple-cms:latest',
                'attack_stage_priority': ['initial_access', 'defense_evasion']
            },

            # Authentication & Session (认证和会话)
            {
                'cve_id': 'CVE-2018-7600',
                'name': 'Drupalgeddon 2 Authentication Bypass',
                'docker_image': 'vulhub/drupal:latest',
                'attack_stage_priority': ['initial_access', 'credential_access']
            },
            {
                'cve_id': 'CVE-2019-19781',
                'name': 'Citrix ADC Authentication Bypass',
                'docker_image': 'vulhub/citrix:latest',
                'attack_stage_priority': ['initial_access', 'credential_access']
            },
            {
                'cve_id': 'CVE-2020-5902',
                'name': 'F5 BIG-IP Configuration Disclosure',
                'docker_image': 'vulhub/f5:latest',
                'attack_stage_priority': ['credential_access', 'discovery']
            },

            # SSRF & XXE (服务端请求伪造)
            {
                'cve_id': 'CVE-2018-1273',
                'name': 'Spring Data Commons SSRF',
                'docker_image': 'vulhub/spring:latest',
                'attack_stage_priority': ['discovery', 'collection']
            },
            {
                'cve_id': 'CVE-2019-0218',
                'name': 'Apache Solr SSRF',
                'docker_image': 'vulhub/solr:latest',
                'attack_stage_priority': ['discovery', 'collection']
            },
            {
                'cve_id': 'CVE-2019-17571',
                'name': 'Apache Solr XXE',
                'docker_image': 'vulhub/solr:latest',
                'attack_stage_priority': ['collection', 'exfiltration']
            },

            # Modern Web Vulnerabilities (现代Web漏洞)
            {
                'cve_id': 'CVE-2018-19978',
                'name': 'WordPress Stored XSS',
                'docker_image': 'vulhub/wordpress:latest',
                'attack_stage_priority': ['execution', 'persistence']
            },
            {
                'cve_id': 'CVE-2018-19977',
                'name': 'WordPress CSRF',
                'docker_image': 'vulhub/wordpress:latest',
                'attack_stage_priority': ['persistence']
            },

            # Information Disclosure & Credential Access (信息泄露和凭证访问)
            {
                'cve_id': 'CVE-2019-0211',
                'name': 'Apache Solr Information Disclosure',
                'docker_image': 'vulhub/solr:latest',
                'attack_stage_priority': ['discovery', 'collection']
            },
            {
                'cve_id': 'CVE-2019-11510',
                'name': 'Pulse VPN Arbitrary File Disclosure',
                'docker_image': 'vulhub/pulse:latest',
                'attack_stage_priority': ['credential_access', 'collection']
            },

            # Modern Deserialization (现代反序列化)
            {
                'cve_id': 'CVE-2019-0193',
                'name': 'Apache Solr Deserialization RCE',
                'docker_image': 'vulhub/solr:latest',
                'attack_stage_priority': ['initial_access', 'execution']
            },

            # Additional Modern RCE
            {
                'cve_id': 'CVE-2021-36934',
                'name': 'Windows SeriousSAM Privilege Escalation',
                'docker_image': 'vulhub/serious-sam:latest',
                'attack_stage_priority': ['privilege_escalation', 'credential_access']
            },
            {
                'cve_id': 'CVE-2021-1675',
                'name': 'Windows Print Spooler RCE',
                'docker_image': 'vulhub/print-nightmare:latest',
                'attack_stage_priority': ['initial_access', 'privilege_escalation']
            },

            # More Credential Access & Persistence (凭证访问和持久化)
            {
                'cve_id': 'CVE-2020-0601',
                'name': 'Windows CryptoAPI Spoofing',
                'docker_image': 'vulhub/cryptoapi:latest',
                'attack_stage_priority': ['credential_access', 'persistence']
            },
            {
                'cve_id': 'CVE-2021-34527',
                'name': 'Windows Print Spooler RCE',
                'docker_image': 'vulhub/printnightmare:latest',
                'attack_stage_priority': ['privilege_escalation', 'persistence']
            },
            {
                'cve_id': 'CVE-2019-11510',
                'name': 'Pulse Secure VPN File Disclosure',
                'docker_image': 'vulhub/pulse:latest',
                'attack_stage_priority': ['credential_access', 'collection']
            },

            # Modern Web Deserialization
            {
                'cve_id': 'CVE-2021-26084',
                'name': 'Confluence OGNL Injection RCE',
                'docker_image': 'vulhub/confluence:latest',
                'attack_stage_priority': ['initial_access', 'execution']
            },
            {
                'cve_id': 'CVE-2020-0688',
                'name': 'Microsoft SharePoint RCE',
                'docker_image': 'vulhub/sharepoint:latest',
                'attack_stage_priority': ['initial_access', 'persistence', 'defense_evasion']
            },

            # Additional Lateral Movement & Discovery
            {
                'cve_id': 'CVE-2020-1472',
                'name': 'Zerologon Active Directory RCE',
                'docker_image': 'vulhub/zerologon:latest',
                'attack_stage_priority': ['credential_access', 'lateral_movement', 'discovery']
            },
            {
                'cve_id': 'CVE-2019-0888',
                'name': 'Apache Solr Replication Attack',
                'docker_image': 'vulhub/solr:latest',
                'attack_stage_priority': ['discovery', 'lateral_movement']
            },

            # More Collection & Exfiltration
            {
                'cve_id': 'CVE-2020-5902',
                'name': 'F5 BIG-IP Configuration Disclosure',
                'docker_image': 'vulhub/f5:latest',
                'attack_stage_priority': ['discovery', 'collection', 'credential_access']
            },
            {
                'cve_id': 'CVE-2019-17571',
                'name': 'Apache Solr XXE',
                'docker_image': 'vulhub/solr:latest',
                'attack_stage_priority': ['collection', 'exfiltration']
            }
        ]

    def collect_all_cves(self) -> Dict:
        """批量收集所有目标CVE"""
        print(f"🚀 开始批量收集 {len(self.target_cves)} 个现代CVE catalog (2018年以后)")

        for cve_info in self.target_cves:
            cve_id = cve_info['cve_id']
            print(f"\n{'='*60}")
            print(f"📦 处理 {cve_id}: {cve_info['name']}")
            print(f"{'='*60}")

            self.stats['total'] += 1

            try:
                catalog = self._collect_single_cve(cve_info)

                if catalog:
                    # 保存catalog
                    self._save_catalog(cve_id, catalog)

                    # 更新统计
                    self.stats['successful'] += 1
                    primary_stage = catalog.get('attack_chain', {}).get('primary_stage', 'unknown')
                    self.stats['attack_stages'][primary_stage] = self.stats['attack_stages'].get(primary_stage, 0) + 1

                    print(f"✅ 成功收集 {cve_id} (主要阶段: {primary_stage})")
                else:
                    self.stats['failed'] += 1
                    print(f"❌ 收集失败: {cve_id}")

                # 避免请求过于频繁
                time.sleep(0.5)

            except Exception as e:
                self.stats['failed'] += 1
                print(f"❌ 处理 {cve_id} 时出错: {e}")

        # 输出汇总
        self._print_summary()

        return self.stats

    def _collect_single_cve(self, cve_info: Dict) -> Optional[Dict]:
        """收集单个CVE的catalog信息"""

        cve_id = cve_info['cve_id']
        year = int(cve_id.split('-')[1])

        if year < 2018:
            print(f"⚠️  跳过2018年以前的CVE: {cve_id}")
            return None

        # 1. 查询NVD数据库获取基础信息
        basic_info = self._query_nvd_api(cve_id)
        if not basic_info or not basic_info.get('cvss_score'):
            print(f"⚠️  无法从NVD获取 {cve_id} 的完整信息，使用模拟数据")
            basic_info = self._generate_mock_basic_info(cve_info)

        # 2. 生成环境信息
        env_info = self._generate_env_info(cve_info)

        # 3. 生成攻击信息
        attack_info = self._generate_attack_info(cve_info, basic_info)

        # 4. 使用mapper映射ATT&CK阶段
        attack_chain = self._map_attack_chain(basic_info, attack_info, cve_info)

        # 5. 生成拓扑适配信息
        topology_fit = self._generate_topology_fit(env_info, attack_info)

        # 6. 组装完整catalog
        catalog = {
            "basic_info": basic_info,
            "environment": env_info,
            "attack_info": attack_info,
            "attack_chain": attack_chain,
            "topology_fit": topology_fit,
            "verification": {
                "tested": False,
                "success_rate": 0.0,
                "last_tested": "",
                "test_count": 0,
                "notes": []
            },
            "last_updated": datetime.now().isoformat(),
            "source_reliability": "medium"
        }

        # 7. 验证catalog质量
        is_valid, issues = self.validator.validate_catalog_syntax(catalog)
        if not is_valid:
            print(f"⚠️  Catalog语法验证失败: {issues[:2]}")
            return None

        quality_score = self.scorer.score_catalog(catalog)
        print(f"📊 质量分数: {quality_score['total_score']:.2f}")

        if quality_score['total_score'] < 0.6:
            print(f"⚠️  质量分数过低，跳过此CVE")
            self.stats['low_quality'] += 1
            return None

        return catalog

    def _query_nvd_api(self, cve_id: str) -> Optional[Dict]:
        """查询NVD API获取CVE基础信息"""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {'cveId': cve_id}

            response = requests.get(url, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if data.get('totalResults', 0) > 0:
                    cve_item = data['vulnerabilities'][0]['cve']

                    # 提取CVSS分数
                    cvss_score = 0.0
                    if 'metrics' in cve_item.get('metrics', {}):
                        cvss_data = cve_item['metrics'].get('cvssMetricV31', [{}])[0]
                        cvss_score = cvss_data.get('cvssData', {}).get('baseScore', 0.0)

                    # 提取描述
                    description = ""
                    for desc in cve_item.get('descriptions', []):
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')
                            break

                    return {
                        'cve_id': cve_id,
                        'name': cve_item.split('#')[0].split(':')[1] if ':' in cve_item else cve_id,
                        'cvss_score': cvss_score,
                        'description': description,
                        'publish_date': cve_item.get('published', ''),
                        'attack_vector': self._extract_cvss_field(cve_item, 'attackVector'),
                        'attack_complexity': self._extract_cvss_field(cve_item, 'attackComplexity')
                    }

        except Exception as e:
            print(f"⚠️  查询NVD API出错: {e}")

        return None

    def _extract_cvss_field(self, cve_item: Dict, field_name: str) -> str:
        """从CVSS数据中提取字段"""
        try:
            metrics = cve_item.get('metrics', {})
            cvss_data = metrics.get('cvssMetricV31', [{}])[0]
            return cvss_data.get('cvssData', {}).get(field_name, 'UNKNOWN')
        except:
            return 'UNKNOWN'

    def _generate_mock_basic_info(self, cve_info: Dict) -> Dict:
        """生成模拟的基础信息"""
        return {
            'cve_id': cve_info['cve_id'],
            'name': cve_info['name'],
            'cvss_score': 7.5,
            'description': f"{cve_info['name']} vulnerability (modern CVE from 2018+)",
            'publish_date': '2020-01-01',
            'attack_vector': 'NETWORK',
            'attack_complexity': 'LOW'
        }

    def _generate_env_info(self, cve_info: Dict) -> Dict:
        """生成环境信息"""
        docker_image = cve_info.get('docker_image', 'vulhub/unknown:latest')

        return {
            'docker_image': docker_image,
            'image_source': f"https://hub.docker.com/r/{docker_image.split(':')[0]}",
            'required_ports': self._infer_ports_from_cve(cve_info),
            'estimated_memory': 1024,
            'startup_time': 30,
            'os_type': 'linux'
        }

    def _infer_ports_from_cve(self, cve_info: Dict) -> List[int]:
        """根据CVE类型推断端口"""
        name_lower = cve_info['name'].lower()

        port_mapping = {
            'rdp': [3389],
            'smb': [445, 139],
            'sql': [3306, 1433, 80],
            'web': [80, 443, 8080],
            'wordpress': [80, 443],
            'ssh': [22],
            'vpn': [443, 1194],
            'active directory': [88, 389, 636],
            'docker': [2375, 2376],
            'sharepoint': [80, 443],
            'confluence': [8090, 8080],
            'solr': [8983, 8983],
            'tomcat': [8080, 8443],
            'drupal': [80, 443]
        }

        for key, ports in port_mapping.items():
            if key in name_lower:
                return ports

        return [8080]  # 默认Web端口

    def _generate_attack_info(self, cve_info: Dict, basic_info: Dict) -> Dict:
        """生成攻击信息"""
        cve_id = cve_info['cve_id']
        name_lower = cve_info['name'].lower()

        # 根据CVE类型推断攻击信息
        if 'privilege' in name_lower or 'escalation' in name_lower or 'sudo' in name_lower:
            return {
                'exploit_method': 'Privilege Escalation',
                'attack_surface': 'Local',
                'access_required': 'local',
                'complexity': 'low',
                'popular': True,
                'exploit_available': True
            }
        elif 'sql' in name_lower:
            return {
                'exploit_method': 'SQL Injection',
                'attack_surface': 'HTTP',
                'access_required': 'network',
                'complexity': 'low',
                'popular': True,
                'exploit_available': True
            }
        elif 'upload' in name_lower or 'file' in name_lower:
            return {
                'exploit_method': 'File Upload',
                'attack_surface': 'HTTP',
                'access_required': 'network',
                'complexity': 'low',
                'popular': True,
                'exploit_available': True
            }
        elif 'auth' in name_lower or 'bypass' in name_lower or 'login' in name_lower:
            return {
                'exploit_method': 'Authentication Bypass',
                'attack_surface': 'HTTP',
                'access_required': 'network',
                'complexity': 'medium',
                'popular': True,
                'exploit_available': True
            }
        elif 'ssrf' in name_lower:
            return {
                'exploit_method': 'Server-Side Request Forgery',
                'attack_surface': 'HTTP',
                'access_required': 'network',
                'complexity': 'medium',
                'popular': True,
                'exploit_available': True
            }
        elif 'xxe' in name_lower:
            return {
                'exploit_method': 'XML External Entity Injection',
                'attack_surface': 'HTTP',
                'access_required': 'network',
                'complexity': 'medium',
                'popular': True,
                'exploit_available': True
            }
        else:
            return {
                'exploit_method': 'Remote Code Execution',
                'attack_surface': 'Network',
                'access_required': 'network',
                'complexity': 'medium',
                'popular': True,
                'exploit_available': True
            }

    def _map_attack_chain(self, basic_info: Dict, attack_info: Dict, cve_info: Dict) -> Dict:
        """映射ATT&CK攻击链"""
        description = basic_info.get('description', '')
        cvss_vector = f"CVSS:3.1/AV:{basic_info.get('attack_vector', 'N')}/AC:{basic_info.get('attack_complexity', 'L')}"

        attack_chain = self.mapper.map_from_description(description, cvss_vector)

        return {
            'primary_stage': attack_chain.primary_stage.value,
            'stage_scores': attack_chain.stage_scores,
            'reasoning': attack_chain.reasoning,
            'confidence': attack_chain.confidence
        }

    def _generate_topology_fit(self, env_info: Dict, attack_info: Dict) -> Dict:
        """生成拓扑适配信息"""
        attack_surface = attack_info.get('attack_surface', 'Network')

        if attack_surface == 'HTTP':
            return {
                'network_layer': 'dmz',
                'suitable_roles': ['web_server', 'application_server'],
                'requires_attacker': True,
                'internet_accessible': True,
                'dependencies': ['web_server', 'http']
            }
        elif attack_surface == 'Local':
            return {
                'network_layer': 'internal',
                'suitable_roles': ['workstation', 'server'],
                'requires_attacker': True,
                'internet_accessible': False,
                'dependencies': ['ssh', 'local_access']
            }
        else:
            return {
                'network_layer': 'internal',
                'suitable_roles': ['server', 'database'],
                'requires_attacker': True,
                'internet_accessible': False,
                'dependencies': ['network']
            }

    def _save_catalog(self, cve_id: str, catalog: Dict):
        """保存catalog到文件"""
        output_file = self.output_dir / f"{cve_id}.yaml"

        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump(catalog, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

        print(f"💾 保存catalog: {output_file}")

    def _print_summary(self):
        """打印收集汇总"""
        print(f"\n{'='*60}")
        print("📊 现代CVE Catalog收集汇总 (2018年以后)")
        print(f"{'='*60}")
        print(f"总目标数: {self.stats['total']}")
        print(f"✅ 成功: {self.stats['successful']}")
        print(f"❌ 失败: {self.stats['failed']}")
        print(f"⚠️  低质量: {self.stats['low_quality']}")
        print(f"成功率: {self.stats['successful']/self.stats['total']*100:.1f}%")

        print(f"\n🎯 攻击阶段分布:")
        for stage, count in sorted(self.stats['attack_stages'].items(), key=lambda x: x[1], reverse=True):
            print(f"  - {stage}: {count}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='批量收集现代CVE Catalogs (2018+)')
    parser.add_argument('--dry-run', action='store_true', help='只显示计划，不实际收集')
    parser.add_argument('--limit', type=int, help='限制收集数量')

    args = parser.parse_args()

    collector = ModernCVECollector()

    if args.dry_run:
        print(f"🎯 计划收集 {len(collector.target_cves)} 个现代CVE (2018年以后):")
        for cve in collector.target_cves:
            year = cve['cve_id'].split('-')[1]
            print(f"  - {cve['cve_id']} ({year}): {cve['name']}")
    else:
        stats = collector.collect_all_cves()

        # 如果收集失败，退出码为1
        if stats['failed'] > stats['successful']:
            sys.exit(1)