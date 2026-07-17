"""拓扑模板数据模型

定义 template.yaml 的结构，供 Template Loader 解析和 Scenario Assembler 消费。
"""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field

from clab_builder.shared.models.atom import CapabilityType


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


class ObjectiveDef(BaseModel):
    """最终业务目标及其私有 reference assertion。

    ``goal``/``evidence_field`` are safe to expose to a Guided Agent.  The
    reference command and success pattern remain verifier-side data and must
    never be copied into the agent input.
    """
    id: str = ""
    asset: str
    validation: str
    goal: str = ""
    evidence_field: str = "evidence"
    verification_mode: str = "agent_evidence"
    actor_ref: str = ""
    reference_command: Optional[str] = None
    success_pattern: Optional[str] = None


class ScenarioAsset(BaseModel):
    """An asset that can be acquired by a reference attack path."""
    id: str
    location: Dict[str, str] = Field(default_factory=dict)
    readable_by: List[str] = Field(default_factory=list)
    metadata: Dict[str, str] = Field(default_factory=dict)
    owner: str = ""
    access_requires: List[str] = Field(default_factory=list)
    grants: List[str] = Field(default_factory=list)
    # Optional service contract used when setup/verify commands target a
    # protocol-specific service (for example PostgreSQL).  This prevents a
    # generic ``database`` role from being paired with a non-database Atom.
    required_service_access: Dict[str, object] = Field(default_factory=dict)


class BaselineAsset(BaseModel):
    """A normal enterprise service already present in the template."""
    id: str
    role: str = ""
    zone: str = ""
    node_ref: str = ""


class InjectionPoint(BaseModel):
    """漏洞注入点"""
    id: str
    zone: str
    role_description: str = ""
    required_mitre: List[str] = Field(default_factory=list)
    required_vuln_category: List[str] = Field(default_factory=list)
    required_service_role: Optional[List[str]] = None
    required_capabilities: List[CapabilityType] = Field(default_factory=list)
    required_service_access: Dict[str, object] = Field(default_factory=dict)
    required_assets: List[str] = Field(default_factory=list)
    kill_chain_phase: str = ""
    depends_on: List[str] = Field(default_factory=list)
    asset_host_refs: List[str] = Field(default_factory=list)
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
    objectives: List[ObjectiveDef] = Field(default_factory=list)
    assets: List[ScenarioAsset] = Field(default_factory=list)
    baseline_assets: List[BaselineAsset] = Field(default_factory=list)
    injection_points: List[InjectionPoint] = Field(default_factory=list)
