"""拓扑模板数据模型

定义 template.yaml 的结构，供 Template Loader 解析和 Scenario Assembler 消费。
"""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class TransitDef(BaseModel):
    """transit link 定义（router 间或 attacker↔router）"""
    subnet: str
    endpoints: List[str]  # 恰好 2 个节点名


class ZoneDef(BaseModel):
    """zone 定义"""
    subnet: str
    type: str = "internal"  # dmz | internal | isolated | restricted
    router: str = ""  # 连接到哪个 router


class RouterDef(BaseModel):
    """router 定义"""
    image: str = "frrouting/frr:latest"
    connects: Optional[List[str]] = None  # 文档用途，路由由 transits + zone.router 决定


class IsolationRule(BaseModel):
    """隔离规则"""
    from_zone: str = Field(alias="from")
    to_zone: str = Field(alias="to")
    action: str = "accept"  # accept | drop | reject

    model_config = {"populate_by_name": True}


class InjectionPoint(BaseModel):
    """漏洞注入点"""
    id: str
    zone: str
    position: str = ""  # entry | intermediate | final; empty means infer from order
    require_toolbox_compatible: bool = False
    role_description: str = ""
    required_mitre: List[str]
    required_vuln_category: List[str]
    required_service_role: Optional[List[str]] = None
    count: int = 1


class NoiseService(BaseModel):
    """噪音服务"""
    name: str
    zone: str
    image: str


class TopologyTemplate(BaseModel):
    """template.yaml 完整模型"""
    name: str
    description: str = ""
    difficulty: str = "easy"

    transits: List[TransitDef] = Field(default_factory=list)

    zones: Dict[str, ZoneDef]
    routers: Dict[str, RouterDef]
    isolation_rules: List[IsolationRule] = Field(default_factory=list)

    noise_levels: Dict[str, List[NoiseService]] = Field(default_factory=dict)
    injection_points: List[InjectionPoint] = Field(default_factory=list)
