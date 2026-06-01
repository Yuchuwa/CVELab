"""
CVE原子化模块

负责CVE的原子化处理、验证和catalog生成，提供清晰的pipeline流程。

Pipeline:
    收集 → 处理 → 验证 → Catalog → 使用
"""

from .catalog import CVECatalog, AttackChainFit
from .processor import CVEProcessor
from .validator import CVEAtomicValidator
from .mapper import AttackStageMapper
from .enricher import CVEEnricher

__all__ = [
    'CVECatalog',
    'AttackChainFit',
    'CVEProcessor',
    'CVEAtomicValidator',
    'AttackStageMapper',
    'CVEEnricher'
]