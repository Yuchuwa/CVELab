"""Clab Builder - ContainerLab拓扑生成和验证工具

基于ContainerLab的CVE训练数据批量生成系统的核心工具包。
直接从ContainerLab YAML拓扑文件生成、部署和验证网络环境。

主要组件:
- ContainerLabParser: ContainerLab YAML解析器
- TopologyGenerator: 拓扑生成器
- EnvironmentValidator: 环境验证器
- SubnetManager: 子网管理器
"""

__version__ = "2.1.0"

# 核心组件
from .core import ContainerLabParser, TopologyGenerator, EnvironmentValidator
from .utils import SubnetManager, setup_logger, get_logger
from .config import config, AppConfig

__all__ = [
    # 核心组件
    'ContainerLabParser',
    'TopologyGenerator',
    'EnvironmentValidator',
    'SubnetManager',

    # 配置和日志
    'config',
    'AppConfig',
    'setup_logger',
    'get_logger',
    '__version__'
]