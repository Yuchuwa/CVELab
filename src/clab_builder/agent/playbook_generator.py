"""
Playbook生成器

为SecurityResearcherAgent提供标准化的Ansible配置和exploit playbook生成功能。

这是Agent调用的唯一自定义工具，因为Ansible YAML格式需要严格的结构化生成。
"""

import yaml
from typing import Dict, List, Any, Tuple
from datetime import datetime


class PlaybookGenerator:
    """
    Playbook生成器

    生成两种输出：
    1. Ansible启动配置 - 用于部署CVE环境
    2. Exploit playbook - 用于执行攻击验证
    """

    def generate(self,
                 cve_id: str,
                 docker_image: str,
                 ports: List[int],
                 attack_path: Dict[str, Any],
                 mitre_mapping: Dict[str, List[str]],
                 exploit_info: Dict[str, Any],
                 verification: Dict[str, Any]) -> Tuple[str, str]:
        """
        生成Ansible配置和exploit playbook

        Returns:
            (ansible_config_yaml, exploit_playbook_yaml)
        """
        ansible_config = self._generate_ansible_config(
            cve_id, docker_image, ports
        )

        exploit_playbook = self._generate_exploit_playbook(
            cve_id, attack_path, mitre_mapping, exploit_info, verification
        )

        return ansible_config, exploit_playbook

    def _generate_ansible_config(self, cve_id: str,
                                  docker_image: str,
                                  ports: List[int]) -> str:
        """生成Ansible启动配置（用于部署CVE环境）"""
        config = {
            'cve_environment': {
                'cve_id': cve_id,
                'docker_image': docker_image,
                'ports': ports,
                'network': 'cve-network',
                'container_name': f'cve-{cve_id.replace("-", "").lower()}'
            },
            'deployment': {
                'method': 'docker',
                'restart_policy': 'unless-stopped',
                'network_mode': 'bridge',
                'publish_ports': [
                    {'host': port, 'container': port}
                    for port in ports
                ]
            },
            'metadata': {
                'generated_by': 'SecurityResearcherAgent',
                'generated_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'version': '1.0'
            }
        }

        return yaml.dump(config, allow_unicode=True, sort_keys=False, default_flow_style=False)

    def _generate_exploit_playbook(self,
                                   cve_id: str,
                                   attack_path: Dict[str, Any],
                                   mitre_mapping: Dict[str, List[str]],
                                   exploit_info: Dict[str, Any],
                                   verification: Dict[str, Any]) -> str:
        """生成Exploit Playbook（用于执行攻击验证）"""
        playbook = {
            'name': f'CVE {cve_id} Exploit Playbook',
            'hosts': 'cve_targets',
            'gather_facts': True,
            'vars': {
                'cve_id': cve_id,
                'exploit_type': exploit_info.get('type', 'unknown'),
                'target': exploit_info.get('target', 'target:port'),
                'confidence': verification.get('confidence', 0.0)
            },
            'tasks': []
        }

        # 添加MITRE ATT&CK阶段任务
        tasks = playbook['tasks']

        # Initial Access
        if 'initial_access' in attack_path:
            stage = attack_path['initial_access']
            tasks.append({
                'name': f"Initial Access - {stage.get('technique_name', 'Unknown')}",
                'mitre_technique_id': stage.get('technique_id', ''),
                'debug': {
                    'msg': f"Stage: {stage.get('description', '')}"
                }
            })

        # Execution
        if 'execution' in attack_path:
            stage = attack_path['execution']
            tasks.append({
                'name': f"Execution - {stage.get('technique_name', 'Unknown')}",
                'mitre_technique_id': stage.get('technique_id', ''),
                'debug': {
                    'msg': f"Stage: {stage.get('description', '')}"
                }
            })

        # Privilege Escalation
        if 'privilege_escalation' in attack_path:
            stage = attack_path['privilege_escalation']
            tasks.append({
                'name': f"Privilege Escalation - {stage.get('technique_name', 'Unknown')}",
                'mitre_technique_id': stage.get('technique_id', ''),
                'debug': {
                    'msg': f"Stage: {stage.get('description', '')}"
                }
            })

        # 漏洞特定阶段
        if 'vulnerability_specific' in attack_path:
            vuln_stage = attack_path['vulnerability_specific']
            for i, step in enumerate(vuln_stage.get('stages', []), 1):
                tasks.append({
                    'name': f"Vulnerability Specific - Step {i}",
                    'debug': {
                        'msg': f"Step: {step}"
                    }
                })

        # 验证任务
        if verification.get('success'):
            tasks.append({
                'name': 'Verification',
                'debug': {
                    'msg': 'Exploit verification successful'
                }
            })

        # 添加元数据
        playbook['metadata'] = {
            'mitre_mapping': mitre_mapping,
            'verification': verification,
            'generated_by': 'SecurityResearcherAgent',
            'generated_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        return yaml.dump(playbook, allow_unicode=True, sort_keys=False, default_flow_style=False)


# 便捷函数：从Agent结果生成完整playbook文件
def generate_complete_playbook(agent_output, output_dir: str):
    """
    生成完整的playbook文件

    Args:
        agent_output: SecurityResearcherAgent的输出
        output_dir: 输出目录
    """
    from pathlib import Path

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    cve_id = agent_output.cve_id

    # 保存Ansible配置
    config_file = output_path / f"{cve_id}_ansible_config.yml"
    with open(config_file, 'w', encoding='utf-8') as f:
        f.write("# Ansible Configuration for CVE Environment\n")
        f.write(agent_output.ansible_config)

    # 保存Exploit Playbook
    playbook_file = output_path / f"{cve_id}_exploit_playbook.yml"
    with open(playbook_file, 'w', encoding='utf-8') as f:
        f.write(f"# Exploit Playbook for {cve_id}\n")
        f.write(agent_output.exploit_playbook)

    # 保存执行日志
    log_file = output_path / f"{cve_id}_execution.log"
    with open(log_file, 'w', encoding='utf-8') as f:
        f.write(f"# Execution Log for {cve_id}\n")
        for log_entry in agent_output.execution_log:
            f.write(f"{log_entry}\n")

    print(f"✅ Playbook文件已生成到: {output_dir}")
    return config_file, playbook_file, log_file
