"""ContainerLab拓扑数据模型

定义ContainerLab YAML解析和使用的数据结构
"""
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class NetworkNode(BaseModel):
    """网络节点模型"""
    name: str = Field(..., description="节点名称")
    type: str = Field(default="linux", description="节点类型")
    image: str = Field(..., description="Docker镜像")
    networks: List[str] = Field(default_factory=list, description="连接的网络")
    role: str = Field(default="endpoint", description="节点角色")
    ports: List[Any] = Field(default_factory=list, description="端口列表")
    cve_injection: Optional[Dict[str, Any]] = Field(None, description="CVE注入信息")
    routing: Optional[Dict[str, Any]] = Field(None, description="路由信息")
    vars: Dict[str, Any] = Field(default_factory=dict, description="其他变量")


class NetworkLink(BaseModel):
    """网络链接模型"""
    source: str = Field(..., description="源节点")
    source_interface: str = Field(..., description="源节点接口")
    destination: str = Field(..., description="目标节点")
    destination_interface: str = Field(..., description="目标节点接口")
    link_name: Optional[str] = Field(None, description="链接名称")


class ContainerLabTopology(BaseModel):
    """ContainerLab拓扑模型"""
    name: str = Field(..., description="实验室名称")
    nodes: Dict[str, Any] = Field(default_factory=dict, description="节点定义")
    links: List[Dict[str, Any]] = Field(default_factory=list, description="链接定义")
    topology: Dict[str, Any] = Field(default_factory=dict, description="原始拓扑数据")

    def __init__(self, **data):
        """初始化拓扑"""
        super().__init__(**data)
        # 从原始数据中提取拓扑信息
        if 'topology' in data:
            self.topology = data['topology']
            self.nodes = self.topology.get('nodes', {})
            self.links = self.topology.get('links', [])


class IsolationPolicy(BaseModel):
    """网络隔离策略模型"""
    source: str = Field(..., description="源安全区域")
    destination: str = Field(..., description="目标安全区域")
    action: str = Field(default="DROP", description="动作: ACCEPT/DROP/REJECT")
    allowed_ports: List[int] = Field(default_factory=list, description="允许的端口列表")
    allowed_protocols: List[str] = Field(default_factory=list, description="允许的协议列表")
    log: bool = Field(default=True, description="是否记录日志")
    description: str = Field(default="", description="策略描述")


class SecurityZone(BaseModel):
    """安全区域模型"""
    name: str = Field(..., description="区域名称")
    subnet: str = Field(..., description="子网CIDR")
    containers: List[str] = Field(default_factory=list, description="区域内的容器列表")
    zone_type: str = Field(default="internal", description="区域类型: dmz/internal/attacker/isolated")


class TopologySpecification(BaseModel):
    """拓扑规格模型"""
    lab_name: str = Field(..., description="实验室名称")
    description: str = Field(default="", description="实验室描述")
    nodes: List[NetworkNode] = Field(default_factory=list, description="节点列表")
    links: List[NetworkLink] = Field(default_factory=list, description="链接列表")
    isolation_policies: List[IsolationPolicy] = Field(default_factory=list, description="网络隔离策略列表")
    security_zones: Dict[str, SecurityZone] = Field(default_factory=dict, description="安全区域映射")
    topology_data: Dict[str, Any] = Field(default_factory=dict, description="原始拓扑数据")
