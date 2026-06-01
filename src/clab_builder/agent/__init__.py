"""
Agent系统模块

Agent驱动的CVE复现和验证系统，使用Claude Code SDK实现自主分析、执行和生成。

架构：
- SecurityResearcherAgent: 主Agent，使用Claude Code SDK的Bash/Read/Write工具
- PlaybookGenerator: 生成标准Ansible格式的配置和playbook
"""

from .security_researcher import SecurityResearcherAgent, CVEInput, AgentOutput
from .playbook_generator import PlaybookGenerator, generate_complete_playbook

__all__ = [
    'SecurityResearcherAgent',
    'CVEInput',
    'AgentOutput',
    'PlaybookGenerator',
    'generate_complete_playbook'
]
