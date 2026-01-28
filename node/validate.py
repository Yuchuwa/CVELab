import ipaddress
import json
import yaml
import subprocess
from typing import Dict, List, Any, Set
from collections import Counter
from state import GraphState
from .fixer import ERROR_TYPE_VALIDATE
from logger import get_logger, set_log_context, log_step


# ============================================
# 验证结果类
# ============================================
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


# ============================================
# A. YAML 文件验证（containerlab 可解析性）
# ============================================
def validate_yaml_with_containerlab(yaml_path: str) -> ValidationResult:
    """
    使用 containerlab 验证 YAML 文件是否可解析

    使用 containerlab graph 命令验证 YAML 语法。
    graph 命令在没有容器运行时会自动降级到离线模式，只解析拓扑文件，
    因此可以在首次部署前验证 YAML 语法是否正确。

    Args:
        yaml_path: YAML 文件路径

    Returns:
        ValidationResult 对象
    """
    res = ValidationResult()
    logger = get_logger("node.validate")

    try:
        # 使用 containerlab graph 验证（离线模式，无需容器）
        # graph 命令在容器不存在时会自动降级到离线模式，只解析拓扑文件
        result = subprocess.run(
            ["containerlab", "graph", "-t", yaml_path, "--dot"],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            # containerlab 无法解析
            error_output = result.stderr or result.stdout
            res.add_error(
                f"[YAML Containerlab] containerlab cannot parse this YAML file:\n"
                f"{error_output[:500]}\n\n"
                f"This indicates a bug in NetworkBuilder._generate_yaml_from_config()."
            )
            logger.error(f"containerlab graph validation failed: {error_output[:200]}")
        else:
            logger.debug("✓ YAML validated by containerlab graph (offline mode)")

    except subprocess.TimeoutExpired:
        res.add_warning("[YAML Containerlab] Validation timeout (30s)")
        logger.warning("containerlab graph timeout")
    except FileNotFoundError:
        res.add_warning("[YAML Containerlab] containerlab command not found, skipping validation")
        logger.debug("containerlab not found in PATH")
    except Exception as e:
        res.add_warning(f"[YAML Containerlab] Validation skipped: {str(e)}")
        logger.debug(f"containerlab graph validation error: {e}")

    return res


# ============================================
# B. YAML 拓扑验证（纯拓扑结构）
# ============================================
def validate_yaml_topology(topology_data: Dict[str, Any]) -> ValidationResult:
    """
    验证 YAML 拓扑结构的正确性（Builder 正确性检查）

    在新架构下，YAML 由 JSON 派生，本函数用于验证：
    1. YAML 正确反映了 JSON 的拓扑结构
    2. Builder 的 YAML 生成逻辑没有 bug

    检查项：
    - 节点名称唯一性
    - 链路格式正确性
    - 链路节点存在性
    - 接口排他性

    注意：如果发现 YAML 拓扑错误，说明 NetworkBuilder 有 bug。
    """
    res = ValidationResult()

    # 提取核心数据
    topo = topology_data.get('topology', {})
    nodes = topo.get('nodes', {})
    links = topo.get('links', [])

    # =========================================
    # A1: 节点名称唯一性
    # =========================================
    node_names = list(nodes.keys())
    if len(node_names) != len(set(node_names)):
        # 统计重复节点
        from collections import Counter
        counter = Counter(node_names)
        duplicates = [name for name, count in counter.items() if count > 1]
        res.add_error(f"[YAML Error] Duplicate node names found: {duplicates}")

    # =========================================
    # A2-A4: 链路验证
    # =========================================
    # 辅助数据结构
    node_interfaces: Dict[str, Set[str]] = {name: set() for name in nodes}
    used_endpoints = set()

    for link_idx, link in enumerate(links):
        eps = link.get('endpoints', [])

        # A2: 链路格式正确性
        if len(eps) != 2:
            res.add_error(f"[YAML Error] Link #{link_idx} must have exactly 2 endpoints, got {len(eps)}: {eps}")
            continue

        # 解析 endpoints
        try:
            node_a, iface_a = eps[0].split(':')
            node_b, iface_b = eps[1].split(':')

            # A3: 链路节点存在性
            if node_a not in nodes:
                res.add_error(f"[YAML Error] Link #{link_idx} references undefined node '{node_a}'")
            if node_b not in nodes:
                res.add_error(f"[YAML Error] Link #{link_idx} references undefined node '{node_b}'")

            # A4: 接口排他性
            if eps[0] in used_endpoints:
                res.add_error(f"[YAML Error] Interface '{eps[0]}' is used in multiple links. Physical ports cannot be split.")
            if eps[1] in used_endpoints:
                res.add_error(f"[YAML Error] Interface '{eps[1]}' is used in multiple links. Physical ports cannot be split.")

            used_endpoints.add(eps[0])
            used_endpoints.add(eps[1])

            # 记录接口占用
            if node_a in node_interfaces:
                node_interfaces[node_a].add(iface_a)
            if node_b in node_interfaces:
                node_interfaces[node_b].add(iface_b)

        except ValueError:
            res.add_error(f"[YAML Error] Link #{link_idx} has invalid endpoint format (expected 'node:ethX'): {eps}")

    # =========================================
    # A5: Bridge 节点检查（仅供参考）
    # =========================================
    bridge_count = sum(1 for n in nodes.values() if n.get('kind') == 'bridge')
    if bridge_count > 0:
        res.add_warning(f"[YAML Info] Found {bridge_count} bridge node(s) in topology")

    return res


# ============================================
# B. JSON 配置验证（网络配置）
# ============================================
def validate_json_config(config_data: Dict[str, Any]) -> ValidationResult:
    """
    验证 JSON 配置文件的正确性。

    检查项:
    - B1: 网关可达性（核心）
    - B2: IP 地址格式
    - B3: IP 全局唯一性
    - B4: 子网引用有效性
    - B5: 节点配置完整性
    - B6: 路由器配置完整性
    - B7: CIDR 掩码一致性
    """
    res = ValidationResult()

    # 提取数据
    nodes_config = config_data.get('nodes', {})
    subnets = config_data.get('subnets', {})

    # =========================================
    # B2: IP 地址格式 + B3: IP 全局唯一性
    # =========================================
    global_ips: Dict[str, str] = {}  # {ip: node_name}
    subnet_interfaces: Dict[str, List[Dict]] = {}  # {subnet: [interfaces]}

    for node_name, node_cfg in nodes_config.items():
        for iface in node_cfg.get('interfaces', []):
            address = iface.get('address', '')
            subnet_name = iface.get('subnet', '')

            # B2: IP 地址格式
            try:
                ip_iface = ipaddress.ip_interface(address)
                ip_addr = str(ip_iface.ip)

                # B3: IP 全局唯一性
                if ip_addr in global_ips:
                    res.add_error(f"[JSON Error] Duplicate IP {ip_addr} found on '{node_name}' and '{global_ips[ip_addr]}'")
                else:
                    global_ips[ip_addr] = node_name

                # 按子网分组接口（用于 B7: CIDR 掩码一致性）
                if subnet_name:
                    if subnet_name not in subnet_interfaces:
                        subnet_interfaces[subnet_name] = []
                    subnet_interfaces[subnet_name].append({
                        'node': node_name,
                        'address': address,
                        'iface_obj': ip_iface
                    })

            except ValueError:
                res.add_error(f"[JSON Error] Node '{node_name}' has invalid IP address format: {address}")

    # =========================================
    # B1: 网关可达性（核心验证）
    # =========================================
    for node_name, node_cfg in nodes_config.items():
        role = node_cfg.get('role', '')
        default_route = node_cfg.get('default_route')

        if role in ['endpoint', 'vul-target'] and default_route:
            gateway_ip = default_route.get('gateway')

            if not gateway_ip:
                res.add_error(f"[JSON Error] Node '{node_name}' has default_route but missing 'gateway'")
                continue

            try:
                gw_addr = ipaddress.ip_address(gateway_ip)

                # 检查1: 网关 IP 必须存在于某个节点的接口上
                if gateway_ip not in global_ips:
                    res.add_error(f"[JSON Error] Node '{node_name}' gateway {gateway_ip} does not exist in any node's interfaces")
                    continue

                # 检查2: 网关必须在本节点的某个接口的同子网内（关键检查）
                gateway_reachable = False
                reachable_subnet = None

                for iface in node_cfg.get('interfaces', []):
                    try:
                        iface_addr = ipaddress.ip_interface(iface['address'])
                        iface_subnet_name = iface.get('subnet')

                        # 检查网关是否在接口的子网内
                        if gw_addr in iface_addr.network:
                            gateway_reachable = True
                            reachable_subnet = iface_subnet_name
                            break
                    except (ValueError, KeyError):
                        pass

                if not gateway_reachable:
                    # 获取本地子网信息用于错误提示
                    local_subnets = []
                    for iface in node_cfg.get('interfaces', []):
                        try:
                            iface_net = ipaddress.ip_interface(iface['address']).network
                            local_subnets.append(str(iface_net))
                        except ValueError:
                            pass

                    res.add_error(
                        f"[JSON Error] Node '{node_name}' gateway {gateway_ip} is not reachable. "
                        f"Gateway is not in any local subnet ({', '.join(local_subnets)}). "
                        f"Gateway must be in the same subnet as one of the node's interfaces."
                    )

            except ValueError:
                res.add_error(f"[JSON Error] Node '{node_name}' has invalid gateway IP format: {gateway_ip}")

    # =========================================
    # B4: 子网引用有效性
    # =========================================
    for node_name, node_cfg in nodes_config.items():
        for iface in node_cfg.get('interfaces', []):
            subnet_name = iface.get('subnet')

            if subnet_name and subnet_name not in subnets:
                res.add_error(f"[JSON Error] Node '{node_name}' interface '{iface.get('name')}' references undefined subnet '{subnet_name}'")

    # =========================================
    # B5: 节点配置完整性
    # =========================================
    for node_name, node_cfg in nodes_config.items():
        role = node_cfg.get('role', '')

        # 检查必需字段
        if 'image' not in node_cfg or not node_cfg['image']:
            res.add_error(f"[JSON Error] Node '{node_name}' is missing 'image' field")

        # endpoint/vul-target 必须有接口配置
        if role in ['endpoint', 'vul-target']:
            if 'interfaces' not in node_cfg or not node_cfg['interfaces']:
                res.add_error(f"[JSON Error] Node '{node_name}' ({role}) must have 'interfaces' configured")
            else:
                # 检查接口字段完整性
                for idx, iface in enumerate(node_cfg['interfaces']):
                    if 'name' not in iface:
                        res.add_error(f"[JSON Error] Node '{node_name}' interface #{idx} is missing 'name'")
                    if 'address' not in iface:
                        res.add_error(f"[JSON Error] Node '{node_name}' interface #{idx} is missing 'address'")
                    if 'subnet' not in iface:
                        res.add_error(f"[JSON Error] Node '{node_name}' interface #{idx} is missing 'subnet'")

            # 必须有默认路由
            if 'default_route' not in node_cfg or not node_cfg['default_route']:
                res.add_warning(f"[JSON Warning] Node '{node_name}' ({role}) should have 'default_route' configured")

    # =========================================
    # B6: 路由器配置完整性
    # =========================================
    for node_name, node_cfg in nodes_config.items():
        if node_cfg.get('role') == 'router':
            frr_config = node_cfg.get('frr')

            if not frr_config:
                res.add_warning(f"[JSON Warning] Router '{node_name}' is missing FRR configuration")
            else:
                # 检查 router_id 格式
                router_id = frr_config.get('router_id')
                if router_id:
                    try:
                        ipaddress.ip_address(router_id)
                    except ValueError:
                        res.add_error(f"[JSON Error] Router '{node_name}' has invalid router_id format: {router_id}")

                # 检查 loopback 格式
                loopback = frr_config.get('loopback')
                if loopback:
                    try:
                        ipaddress.ip_address(loopback)
                    except ValueError:
                        res.add_error(f"[JSON Error] Router '{node_name}' has invalid loopback format: {loopback}")

                # 检查 OSPF 网络格式
                ospf_networks = frr_config.get('ospf_networks', [])
                if not ospf_networks:
                    res.add_warning(f"[JSON Warning] Router '{node_name}' has no OSPF networks configured")
                else:
                    for network in ospf_networks:
                        try:
                            ipaddress.ip_network(network)
                        except ValueError:
                            res.add_error(f"[JSON Error] Router '{node_name}' has invalid OSPF network format: {network}")

    # =========================================
    # B7: CIDR 掩码一致性
    # =========================================
    for subnet_name, interfaces in subnet_interfaces.items():
        if len(interfaces) > 1:
            # 获取第一个接口的掩码
            first_prefixlen = interfaces[0]['iface_obj'].network.prefixlen

            # 检查所有接口的掩码是否一致
            for iface_info in interfaces[1:]:
                if iface_info['iface_obj'].network.prefixlen != first_prefixlen:
                    res.add_error(
                        f"[JSON Error] Subnet '{subnet_name}' has inconsistent CIDR masks. "
                        f"Interface '{interfaces[0]['node']}' uses /{first_prefixlen}, "
                        f"but '{iface_info['node']}' uses /{iface_info['iface_obj'].network.prefixlen}"
                    )

    return res


# ============================================
# C. YAML-JSON 一致性验证（Builder 正确性检查）
# ============================================
def validate_consistency(
    topology_data: Dict[str, Any],
    config_data: Dict[str, Any]
) -> ValidationResult:
    """
    验证 YAML 是否正确从 JSON 派生（Builder 正确性检查）

    在新架构下，YAML 应由 JSON 生成（NetworkBuilder._generate_yaml_from_config），
    如果出现不一致，说明 Builder 的 YAML 生成逻辑存在 bug。

    注意：这是 Builder 的 bug，不应触发 Fixer，而是直接报错。
    """
    res = ValidationResult()

    # 提取数据
    topo = topology_data.get('topology', {})
    yaml_nodes = topo.get('nodes', {})
    json_nodes = config_data.get('nodes', {})

    # 排除 switch 节点（通过节点名称前缀 sw- 或 JSON 中的 role 字段判断）
    # Switches are now linux containers with role "switch" in JSON, but may have any kind in YAML
    yaml_nodes_no_switch = {n: cfg for n, cfg in yaml_nodes.items()
                            if not n.startswith('sw-') and cfg.get('kind') != 'bridge'}
    json_nodes_no_switch = {n: cfg for n, cfg in json_nodes.items()
                            if cfg.get('role') != 'switch'}

    # =========================================
    # C1: 节点数量一致性
    # =========================================
    yaml_count = len(yaml_nodes_no_switch)
    json_count = len(json_nodes_no_switch)

    if yaml_count != json_count:
        res.add_error(
            f"[Consistency Error] Node count mismatch: YAML has {yaml_count} nodes, "
            f"JSON has {json_count} nodes (excluding switches)"
        )

    # =========================================
    # C2: 节点名称一致性
    # =========================================
    yaml_node_names = set(yaml_nodes_no_switch.keys())
    json_node_names = set(json_nodes_no_switch.keys())

    missing_in_json = yaml_node_names - json_node_names
    if missing_in_json:
        res.add_error(f"[Consistency Error] Nodes in YAML but not in JSON: {missing_in_json}")

    missing_in_yaml = json_node_names - yaml_node_names
    if missing_in_yaml:
        res.add_error(f"[Consistency Error] Nodes in JSON but not in YAML: {missing_in_yaml}")

    # =========================================
    # C3: 接口数量一致性
    # =========================================
    # 统计 YAML 中每个节点的接口数量
    yaml_iface_count = {}
    for link in topo.get('links', []):
        eps = link.get('endpoints', [])
        for ep in eps:
            try:
                node, iface = ep.split(':')
                yaml_iface_count[node] = yaml_iface_count.get(node, 0) + 1
            except ValueError:
                pass

    # 对比 JSON 中的接口数量
    for node_name in json_node_names & yaml_node_names:
        json_iface_count = len(json_nodes[node_name].get('interfaces', []))
        yaml_count = yaml_iface_count.get(node_name, 0)

        if json_iface_count < yaml_count:
            res.add_warning(
                f"[Consistency Warning] Node '{node_name}': JSON defines {json_iface_count} interface(s), "
                f"but YAML links use {yaml_count} interface(s)"
            )

    # =========================================
    # C4: 镜像一致性
    # =========================================
    for node_name in json_node_names & yaml_node_names:
        yaml_image = yaml_nodes[node_name].get('image', '')
        json_image = json_nodes[node_name].get('image', '')

        if yaml_image and json_image and yaml_image != json_image:
            res.add_warning(
                f"[Consistency Warning] Node '{node_name}' has different images: "
                f"YAML='{yaml_image}', JSON='{json_image}'"
            )

    return res


# ============================================
# 主验证节点
# ============================================
def validator_node(state: GraphState):
    """
    Validate 节点：验证配置文件正确性

    新架构下的验证逻辑：
    1. JSON 是唯一真源 - 进行完整验证（核心）
    2. YAML 是派生产物 - 验证其正确反映 JSON（Builder 正确性）
    3. YAML-JSON 一致性 - 捕获 Builder 的 bug

    工作流程:
    1. 读取 JSON 文件（唯一真源）
    2. 读取 YAML 文件（派生产物）
    3. 验证 JSON 配置（网关、IP、路由器等）
    4. 验证 YAML 拓扑（语法和结构）+ containerlab 验证
    5. 验证 YAML 是否正确派生自 JSON
    6. 合并验证结果

    注意：
    - JSON 错误会触发 Fixer 修复
    - YAML 错误说明 Builder 有 bug，直接报错中断
    """
    logger = get_logger("node.validate")
    set_log_context(stage="validate")
    log_step(logger, "Validating topology configuration", status="start")

    # =========================================
    # 步骤 1: 读取 YAML 文件
    # =========================================
    yaml_path = state.get('yaml_path')
    if not yaml_path:
        log_step(logger, "Validation failed - No YAML file path provided", status="fail")
        return {"error_logs": f"{ERROR_TYPE_VALIDATE} No YAML file path provided"}

    try:
        with open(yaml_path, 'r', encoding='utf-8') as f:
            topology_data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        log_step(logger, f"Validation failed - Invalid YAML syntax: {e}", status="fail")
        return {"error_logs": f"{ERROR_TYPE_VALIDATE} Invalid YAML syntax: {e}"}
    except Exception as e:
        log_step(logger, f"Validation failed - Error reading YAML: {e}", status="fail")
        return {"error_logs": f"{ERROR_TYPE_VALIDATE} Error reading YAML file: {e}"}

    # =========================================
    # 步骤 2: 读取 JSON 文件
    # =========================================
    json_path = state.get('json_path')
    if not json_path:
        log_step(logger, "Validation failed - No JSON file path provided", status="fail")
        return {"error_logs": f"{ERROR_TYPE_VALIDATE} No JSON file path provided"}

    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            config_data = json.load(f)
    except json.JSONDecodeError as e:
        log_step(logger, f"Validation failed - Invalid JSON syntax: {e}", status="fail")
        return {"error_logs": f"{ERROR_TYPE_VALIDATE} Invalid JSON syntax: {e}"}
    except Exception as e:
        log_step(logger, f"Validation failed - Error reading JSON: {e}", status="fail")
        return {"error_logs": f"{ERROR_TYPE_VALIDATE} Error reading JSON file: {e}"}

    # =========================================
    # 步骤 3: 验证 YAML 拓扑
    # =========================================
    log_step(logger, "Validating YAML topology", status="start")
    yaml_result = validate_yaml_topology(topology_data)
    if yaml_result.valid:
        log_step(logger, "YAML topology validation", status="success")
    else:
        log_step(logger, "YAML topology validation", status="fail", errors=len(yaml_result.errors))

    # =========================================
    # 步骤 3.5: 使用 containerlab 验证 YAML
    # =========================================
    log_step(logger, "Validating YAML with containerlab", status="start")
    containerlab_result = validate_yaml_with_containerlab(yaml_path)
    if containerlab_result.valid:
        log_step(logger, "containerlab validation", status="success")
    else:
        log_step(logger, "containerlab validation", status="fail", errors=len(containerlab_result.errors))
        # containerlab验证失败是致命错误，说明Builder有bug
        if containerlab_result.errors:
            error_msg = "\n".join(containerlab_result.errors)
            return {"error_logs": f"[ERROR_TYPE:SYSTEM] {error_msg}"}

    # 合并containerlab的警告
    yaml_result.warnings.extend(containerlab_result.warnings)

    # =========================================
    # 步骤 4: 验证 JSON 配置
    # =========================================
    log_step(logger, "Validating JSON configuration", status="start")
    json_result = validate_json_config(config_data)
    if json_result.valid:
        log_step(logger, "JSON configuration validation", status="success")
    else:
        log_step(logger, "JSON configuration validation", status="fail", errors=len(json_result.errors))

    # =========================================
    # 步骤 5: 验证 YAML-JSON 一致性
    # =========================================
    log_step(logger, "Validating YAML-JSON consistency", status="start")
    consistency_result = validate_consistency(topology_data, config_data)
    if consistency_result.valid:
        log_step(logger, "YAML-JSON consistency validation", status="success")
    else:
        log_step(logger, "YAML-JSON consistency validation", status="fail", errors=len(consistency_result.errors))

    # =========================================
    # 步骤 6: 合并验证结果
    # =========================================
    # 合并所有错误和警告
    all_errors = yaml_result.errors + json_result.errors + consistency_result.errors
    all_warnings = yaml_result.warnings + json_result.warnings + consistency_result.warnings

    # 判断总体是否通过
    overall_valid = yaml_result.valid and json_result.valid and consistency_result.valid

    if overall_valid:
        log_step(
            logger,
            "Topology validation completed successfully",
            status="success",
            warnings=len(all_warnings)
        )
        if all_warnings:
            logger.warning(f"Validation passed with {len(all_warnings)} warning(s)")
            for warning in all_warnings:
                logger.warning(f"  ⚠️  {warning}")
        return {"error_logs": ""}
    else:
        log_step(
            logger,
            f"Validation failed - {len(all_errors)} error(s), {len(all_warnings)} warning(s) found",
            status="fail",
            errors=len(all_errors),
            warnings=len(all_warnings)
        )

        # 记录所有错误和警告
        for error in all_errors:
            logger.error(f"  ❌ {error}")
        for warning in all_warnings:
            logger.warning(f"  ⚠️  {warning}")

        # 特殊处理：如果只有一致性错误（YAML与JSON不一致），说明是Builder bug
        if consistency_result.errors and not yaml_result.errors and not json_result.errors:
            error_details = []
            for error in consistency_result.errors:
                error_details.append(f"  ❌ {error}")

            error_msg = (
                "YAML derivation error detected (Builder bug):\n"
                "The YAML file does not match the JSON configuration.\n"
                "This indicates a bug in NetworkBuilder._generate_yaml_from_config().\n\n"
                "Inconsistencies found:\n" +
                "\n".join(error_details) +
                "\n\nPlease report this bug to the developer."
            )
            return {"error_logs": f"[ERROR_TYPE:SYSTEM] {error_msg}"}

        # 其他验证错误（JSON或YAML格式问题），触发Fixer修复
        error_msg = "\n".join(all_errors)
        return {"error_logs": f"{ERROR_TYPE_VALIDATE} Validation failed:\n{error_msg}"}
