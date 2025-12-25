from typing import TypedDict, List, Dict, Any, Union
from node.utils import NetworkBlueprint

class NodeConfigSpec(TypedDict):
    node_name: str
    image: str
    interfaces: Dict[str, str]  # e.g., {"eth1": "10.0.0.2/24"}
    gateway: str                # e.g., "10.0.0.1"
    routes: List[str]           # e.g., ["192.168.10.0/24 via 10.0.0.1"]
    services: List[str]         # e.g., ["redis-server", "java"]
    install_tools: bool         # True if likely needs iproute2

class GraphState(TypedDict):
    user_request: str
    yaml_path: str  # 生成的 YAML 文件路径
    blueprint: Union[NetworkBlueprint, None]  #中间状态
    error_logs: str  # validate 的错误信息
    is_deployed:bool
    inspect_data: Dict[str, Any]     # containerlab inspect 返回的 JSON 数据
    retry_count: int
    is_complete: bool  #是否configure完成

