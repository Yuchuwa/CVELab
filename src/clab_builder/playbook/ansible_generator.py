"""
Ansible配置生成器

为CVE环境生成标准的Ansible部署配置。
"""

import yaml
from pathlib import Path
from typing import Dict, List, Any


class AnsibleConfigGenerator:
    """Ansible配置生成器"""

    def generate(self,
                 cve_id: str,
                 docker_image: str,
                 ports: List[int],
                 network_name: str = "cve-network",
                 **kwargs) -> str:
        """
        生成Ansible配置

        Args:
            cve_id: CVE编号
            docker_image: Docker镜像
            ports: 端口列表
            network_name: Docker网络名称
            **kwargs: 其他配置参数

        Returns:
            YAML格式的Ansible配置
        """
        container_name = f"cve-{cve_id.replace('-', '').lower()}"

        config = {
            'cve_environment': {
                'cve_id': cve_id,
                'container_name': container_name,
                'docker_image': docker_image,
                'ports': ports,
                'network': network_name
            },
            'deployment': {
                'method': 'docker',
                'restart_policy': kwargs.get('restart_policy', 'unless-stopped'),
                'network_mode': 'bridge',
                'environment_vars': kwargs.get('environment', {})
            },
            'ports': {
                'publish': [
                    {'host': port, 'container': port, 'protocol': 'tcp'}
                    for port in ports
                ]
            },
            'volumes': kwargs.get('volumes', []),
            'security': {
                'privileged': kwargs.get('privileged', False),
                'capabilities': kwargs.get('capabilities', [])
            }
        }

        return yaml.dump(config, allow_unicode=True, sort_keys=False, default_flow_style=False)

    def save_config(self, config: str, output_path: Path):
        """保存配置到文件"""
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("# Ansible Configuration for CVE Environment\n")
            f.write(f"# Generated: {self._get_timestamp()}\n\n")
            f.write(config)

        print(f"✅ Ansible配置已保存: {output_path}")

    def _get_timestamp(self) -> str:
        """获取时间戳"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
