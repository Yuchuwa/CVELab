import re
import ipaddress
import yaml
from typing import Dict, List, Any, Set, Tuple
from state import GraphState

# 定义返回结构
class ValidationResult:
    def __init__(self):
        self.valid = True
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def add_error(self, msg: str):
        self.valid = False
        self.errors.append(msg)

    def add_warning(self, msg: str):
        self.warnings.append(msg)

def validate_topology(topology_data: Dict[str, Any]) -> ValidationResult:
    """
    对 Containerlab 的拓扑字典进行深度静态分析。
    传入参数应该是 yaml.safe_load() 后的字典。
    """
    res = ValidationResult()
    
    # 提取核心数据
    topo = topology_data.get('topology', {})
    nodes = topo.get('nodes', {})
    links = topo.get('links', [])

    # --- 辅助数据结构构建 ---
    
    # 1. 物理链路映射: 记录每个节点的物理接口占用情况
    # 格式: { "node_name": {"eth1", "eth2"} }
    node_interfaces: Dict[str, Set[str]] = {name: set() for name in nodes}
    
    # 2. 全局 IP 记录: 用于查重
    # 格式: "192.168.1.1": "node_name"
    global_ips: Dict[str, str] = {}
    
    # 3. 节点 IP 配置记录: 用于检查网关可达性
    # 格式: { "node_name": [IPv4Interface_obj | IPv6Interface_obj, ...] }
    node_ip_objs: Dict[str, List] = {name: [] for name in nodes}
    
    # 4. 邻居关系图: 用于检查下一跳是否直连
    # 格式: { "node_name": {"neighbor_name"} }
    adjacency: Dict[str, Set[str]] = {name: set() for name in nodes}

    # =========================================
    # Check 1: L1 物理接口排他性 & 链路构建
    # =========================================
    used_endpoints = set()
    
    for link in links:
        eps = link.get('endpoints', [])
        if len(eps) != 2:
            res.add_error(f"[L1 Error] Link definition invalid (must have 2 endpoints): {eps}")
            continue
            
        # 记录邻居关系
        try:
            node_a, iface_a = eps[0].split(':')
            node_b, iface_b = eps[1].split(':')
            
            # 检查节点是否存在
            if node_a not in nodes: res.add_error(f"[Topology Error] Link references undefined node '{node_a}'")
            if node_b not in nodes: res.add_error(f"[Topology Error] Link references undefined node '{node_b}'")
            
            # 检查接口重复使用
            if eps[0] in used_endpoints:
                res.add_error(f"[L1 Error] Interface '{eps[0]}' is used in multiple links. Physical ports cannot be split. Use a bridge.")
            if eps[1] in used_endpoints:
                res.add_error(f"[L1 Error] Interface '{eps[1]}' is used in multiple links. Physical ports cannot be split. Use a bridge.")
            
            used_endpoints.add(eps[0])
            used_endpoints.add(eps[1])
            
            # 记录接口索引
            if node_a in node_interfaces: node_interfaces[node_a].add(iface_a)
            if node_b in node_interfaces: node_interfaces[node_b].add(iface_b)
            
            # 记录邻接关系
            if node_a in adjacency: adjacency[node_a].add(node_b)
            if node_b in adjacency: adjacency[node_b].add(node_a)
            
        except ValueError:
            res.add_error(f"[Syntax Error] Invalid endpoint format (expected 'node:ethX'): {eps}")

    # =========================================
    # Check 2 - 8: 节点内部配置检查
    # =========================================
    
    # 正则表达式预编译
    regex_ip_add = re.compile(r"ip\s+addr(?:ess)?\s+add\s+([0-9./]+)\s+dev\s+([a-z0-9]+)")
    regex_ip_route = re.compile(r"ip\s+route\s+add\s+.*via\s+([0-9.]+)")
    regex_install = re.compile(r"(apt-get|apk)\s+(?:.*)\s+install")
    
    # 默认管理网段 (Containerlab default)
    mgmt_network = ipaddress.ip_network("172.20.20.0/24", strict=False)

    for node_name, node_cfg in nodes.items():
        image = node_cfg.get('image', '')
        cmds = node_cfg.get('exec', [])
        kind = node_cfg.get('kind', 'linux')
        
        # --- Check 5: 操作系统能力 (工具缺失) ---
        is_alpine = "alpine" in image or kind == "bridge"
        has_install_cmd = False
        uses_ip_cmd = False
        first_ip_cmd_index = 9999
        install_cmd_index = -1
        
        # 收集该节点配置的所有 IP 和 路由
        configured_subnets: List = []
        
        for idx, cmd in enumerate(cmds):
            # 检查安装命令
            if regex_install.search(cmd) and "iproute2" in cmd:
                has_install_cmd = True
                install_cmd_index = idx
            
            # 检查 IP 配置
            ip_match = regex_ip_add.search(cmd)
            if ip_match:
                uses_ip_cmd = True
                first_ip_cmd_index = min(first_ip_cmd_index, idx)
                
                ip_str, iface_str = ip_match.groups()
                
                try:
                    ip_obj = ipaddress.ip_interface(ip_str)
                    node_ip_objs[node_name].append(ip_obj)
                    
                    # --- Check 7: 全局 IP 唯一性 ---
                    ip_addr_str = str(ip_obj.ip)
                    if ip_addr_str in global_ips:
                        res.add_error(f"[L3 Error] Duplicate IP {ip_addr_str} found on '{node_name}' and '{global_ips[ip_addr_str]}'.")
                    else:
                        global_ips[ip_addr_str] = node_name
                        
                    # --- Check 3: 管理网段冲突 ---
                    if ip_obj.ip in mgmt_network:
                        res.add_warning(f"[Routing Warning] Node '{node_name}' IP {ip_str} overlaps with default Management Network {mgmt_network}. This may cause routing issues.")
                    
                    # --- Check 2: 路由器接口隔离 (同网段检查) ---
                    # 检查该节点是否已经在另一个接口配置了同一个网段
                    for existing_net in configured_subnets:
                        if ip_obj.network == existing_net and kind != "bridge":
                            res.add_error(f"[L3 Error] Node '{node_name}' has multiple interfaces in the same subnet {existing_net}. This causes ARP flux. Use a bridge instead.")
                    configured_subnets.append(ip_obj.network)
                    
                    # --- Check 8: 链路状态依赖 (空接口配置) ---
                    # 检查配置 IP 的接口 (如 eth2) 是否真的连了线
                    if iface_str != "lo" and iface_str not in node_interfaces[node_name]:
                        # 特殊处理：bridge 类型的 br0 是虚拟的，不算错
                        if not (kind == "bridge" or iface_str.startswith("br")):
                             res.add_error(f"[Config Error] Node '{node_name}' tries to configure IP on '{iface_str}', but this interface has NO physical link defined.")
                    
                except ValueError:
                    res.add_error(f"[Syntax Error] Invalid IP format in node '{node_name}': {ip_str}")

        # 续 Check 5: 验证安装命令顺序
        if not is_alpine and uses_ip_cmd:
            if not has_install_cmd:
                res.add_error(f"[Sys Error] Node '{node_name}' ({image}) uses 'ip addr' but does not install 'iproute2'.")
            elif install_cmd_index > first_ip_cmd_index:
                res.add_error(f"[Sys Error] Node '{node_name}' installs 'iproute2' at step {install_cmd_index}, but tries to use it at step {first_ip_cmd_index}. Installation must come FIRST.")

    # =========================================
    # Check 4: 网关可达性 (下一跳检查)
    # =========================================
    for node_name, node_cfg in nodes.items():
        cmds = node_cfg.get('exec', [])
        for cmd in cmds:
            route_match = regex_ip_route.search(cmd)
            if route_match:
                gw_ip_str = route_match.group(1)
                try:
                    gw_ip = ipaddress.ip_address(gw_ip_str)
                    
                    # 检查1: 网关IP是否存在于整个网络中
                    if str(gw_ip) not in global_ips:
                        res.add_error(f"[Routing Error] Node '{node_name}' sets gateway via {gw_ip}, but no node in the topology has this IP.")
                        continue
                    
                    target_node = global_ips[str(gw_ip)]
                    
                    # 检查2: 网关节点是否是直连邻居 (L2 Reachability)
                    # 注意：如果中间有 switch (bridge)，邻居关系需要递归查找，这里做 simplified 检查
                    # 如果目标节点在邻居列表中，或者 目标节点就是邻居的邻居 (通过 switch)
                    # 为了简化，我们检查：是否有任何一个本地接口 IP 和 网关 IP 在同一个子网
                    
                    is_reachable = False
                    for local_iface in node_ip_objs[node_name]:
                        if gw_ip in local_iface.network:
                            is_reachable = True
                            break
                    
                    if not is_reachable:
                         res.add_error(f"[Routing Error] Node '{node_name}' sets gateway {gw_ip}, but it has no interface in that subnet to reach it.")

                except ValueError:
                    pass

    return res

def validator_node(state: GraphState):
    print("\n🔍 [Validator] Checking configuration...")

    # 读取 YAML 文件内容
    yaml_path = state.get('yaml_path')
    if not yaml_path:
        print("   -> Validation Failed: No YAML file path provided.")
        return {"error_logs": "No YAML file path provided"}

    try:
        with open(yaml_path, 'r', encoding='utf-8') as f:
            topology_data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"   -> Validation Failed: Invalid YAML syntax: {e}")
        return {"error_logs": f"Invalid YAML syntax: {e}"}
    except Exception as e:
        print(f"   -> Validation Failed: Error reading file: {e}")
        return {"error_logs": f"Error reading file: {e}"}

    result = validate_topology(topology_data)
    if result.valid:
        print("   -> Validation Passed.")
        return {"error_logs": ""}
    else:
        print(f"   -> Validation Failed: {result.errors}")
        return {"error_logs": "\n".join(result.errors)}