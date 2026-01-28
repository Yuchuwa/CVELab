"""数据模型定义

定义网络拓扑和节点的数据结构。
"""
from typing import List, Literal, Union, Dict, Optional, Any
from pydantic import BaseModel, Field


# ============================================
# 蓝图模型（LLM 生成）
# ============================================

class LogicalNode(BaseModel):
    """逻辑节点模型

    表示网络拓扑中的一个节点，定义其基本属性和连接关系。
    """
    name: str = Field(..., description="Unique hostname. MUST be lowercase, kebab-case (e.g., 'edge-router'). NO spaces, underscores, or special characters.")
    role: Literal["router", "endpoint", "vul-target"] = Field(..., description="The functional role of the node. 'vul-target' is for vulnerability target nodes from Vulhub.")
    image_flavor: str = Field(default="", description="Abstract flavor for standard images: 'kali', 'alpine', 'redis', etc. Empty for vul-target nodes.")
    container_path: Union[str, None] = Field(None, description="For 'vul-target' role: Path to Vulhub vulnerability directory (e.g., '/path/to/vulhub/activemq/CVE-2023-46604'). The builder will parse docker-compose.yml from this path.")
    connected_subnets: List[str] = Field(..., description="List of subnet names this node connects to. e.g. ['dmz', 'internal'].")


class NetworkBlueprint(BaseModel):
    """网络蓝图模型

    表示由 LLM 生成的逻辑网络拓扑设计。
    """
    lab_name: str = Field(..., description="Name of the lab. MUST use kebab-case (e.g., 'mvp-pentest-lab'). STRICTLY NO SPACES.")
    scenario: Literal["A", "B", "C"] = Field(..., description="Scenario type: A=single-layer with 1 vul-target + N endpoints, B=three-layer enterprise network, C=A/B + firewall (reserved)")
    subnets: List[str] = Field(..., description="List of unique logical subnet names defined in the topology.")
    nodes: List[LogicalNode] = Field(..., description="List of logical nodes.")


# ============================================
# Containerlab YAML 相关模型
# ============================================

class ContainerConfig(BaseModel):
    """容器配置（用于生成 containerlab YAML）"""
    kind: Literal["linux"] = Field(default="linux", description="Node kind in containerlab")
    image: str = Field(..., description="Docker image name with tag")
    binds: List[str] = Field(default_factory=list, description="Volume bind mounts (host:container)")
    env: Dict[str, str] = Field(default_factory=dict, description="Environment variables")
    sysctls: Dict[str, str] = Field(default_factory=dict, description="Kernel parameters (e.g., net.ipv4.ip_forward)")
    cmd: str = Field(default="", description="Override container command")
    ports: List[str] = Field(default_factory=list, description="Port mappings (host:container)")
    exec: List[str] = Field(default_factory=list, description="Commands to execute after startup (deprecated)")


class LinkEndpoint(BaseModel):
    """链路端点"""
    node: str = Field(..., description="Node name")
    interface: str = Field(..., description="Interface name (e.g., eth1)")

    def to_string(self) -> str:
        """转换为 containerlab 格式：node:eth1"""
        return f"{self.node}:{self.interface}"


class TopologyLink(BaseModel):
    """拓扑链路"""
    endpoints: List[LinkEndpoint] = Field(..., description="Two endpoints forming a link")

    def to_clab_format(self) -> Dict[str, List[str]]:
        """转换为 containerlab YAML 格式"""
        return {"endpoints": [ep.to_string() for ep in self.endpoints]}


class ClabTopology(BaseModel):
    """Containerlab 拓扑定义"""
    nodes: Dict[str, ContainerConfig] = Field(..., description="Node definitions")
    links: List[Dict[str, List[str]]] = Field(..., description="Link definitions")


class ClabYAML(BaseModel):
    """Containerlab YAML 根对象"""
    name: str = Field(..., description="Lab name")
    topology: ClabTopology = Field(..., description="Topology definition")

    def to_yaml_dict(self) -> Dict[str, Any]:
        """转换为 YAML 友好的字典（移除空值）"""
        data = self.model_dump(exclude_none=True, exclude_unset=True)
        return self._prune_empty(data)

    @staticmethod
    def _prune_empty(data):
        """递归清除空值"""
        if isinstance(data, dict):
            return {k: ClabYAML._prune_empty(v) for k, v in data.items()
                   if v not in (None, [], {}, "")}
        elif isinstance(data, list):
            return [ClabYAML._prune_empty(item) for item in data]
        return data


# ============================================
# 配置 JSON 相关模型
# ============================================

class InterfaceConfig(BaseModel):
    """接口配置"""
    name: str = Field(..., description="Interface name (e.g., eth1)")
    subnet: str = Field(..., description="Logical subnet name")
    address: str = Field(..., description="IP address with CIDR (e.g., 10.0.0.1/24)")


class DefaultRoute(BaseModel):
    """默认路由"""
    destination: str = Field(default="0.0.0.0/0", description="Route destination")
    gateway: str = Field(..., description="Gateway IP address")


class FRRConfig(BaseModel):
    """FRR 路由配置"""
    router_id: str = Field(..., description="OSPF router ID")
    loopback: str = Field(..., description="Loopback IP address")
    ospf_networks: List[str] = Field(default_factory=list, description="OSPF advertised networks")


class NodeConfig(BaseModel):
    """节点完整配置（用于 config.json）"""
    # 部署配置（configure.py 使用）
    role: Literal["router", "endpoint", "vul-target", "switch"] = Field(..., description="Node role")
    image: str = Field(..., description="Docker image")
    interfaces: List[InterfaceConfig] = Field(default_factory=list, description="Network interfaces")
    default_route: Optional[DefaultRoute] = Field(None, description="Default route (for endpoints/vul-targets)")
    frr: Optional[FRRConfig] = Field(None, description="FRR routing configuration (for routers)")

    # 容器配置（YAML 生成使用）
    container_config: ContainerConfig = Field(..., description="Containerlab container configuration")

    # 可选元数据
    container_path: Optional[str] = Field(None, description="Vulhub container path (for vul-targets)")


class LabConfig(BaseModel):
    """完整实验配置（config.json 根对象）"""
    lab_name: str = Field(..., description="Laboratory name")
    subnets: Dict[str, str] = Field(..., description="Subnet name to CIDR mapping")
    links: List[TopologyLink] = Field(..., description="Network topology links")
    nodes: Dict[str, NodeConfig] = Field(..., description="Node configurations")
