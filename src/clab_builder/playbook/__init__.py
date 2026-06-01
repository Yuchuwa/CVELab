"""
Playbook生成模块

从Agent验证的攻击路径生成标准的Ansible配置和exploit playbook。
"""

from .ansible_generator import AnsibleConfigGenerator
from .exploit_playbook_generator import ExploitPlaybookGenerator

__all__ = ['AnsibleConfigGenerator', 'ExploitPlaybookGenerator']
