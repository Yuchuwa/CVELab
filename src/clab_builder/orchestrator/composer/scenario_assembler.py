"""Scenario Assembler — 将 template + CVE atoms 组装为完整场景

支持多 transit link、多 router、显式 zone→router 映射。
自动分配数据面 IP，生成含 IP 配置的 ansible base.yaml。
"""

import copy
import hashlib
import ipaddress
import re
import secrets
from pathlib import Path
from collections import defaultdict, deque
from typing import Optional

import yaml

from clab_builder.shared.models.atom import AtomConfig
from clab_builder.shared.models.template import TopologyTemplate, InjectionPoint
from clab_builder.orchestrator.composer.template_loader import TemplateLoader


def _generate_flag() -> str:
    """生成唯一 FLAG"""
    return f"flag{{{secrets.token_hex(16)}}}"


def _generate_scenario_hash(scenario_name: str, cve_ids: list[str]) -> str:
    """场景去重 hash"""
    payload = f"{scenario_name}:{','.join(sorted(cve_ids))}"
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _parse_interface_map(clab: dict) -> dict[str, dict[str, str]]:
    """从 clab.yaml links 构建接口映射: {node: {ethX: peer_node}}"""
    iface_map: dict[str, dict[str, str]] = defaultdict(dict)
    for link in clab.get("topology", {}).get("links", []):
        endpoints = link.get("endpoints", [])
        if len(endpoints) != 2:
            continue
        # "node:ethX"
        node_a, iface_a = endpoints[0].rsplit(":", 1)
        node_b, iface_b = endpoints[1].rsplit(":", 1)
        iface_map[node_a][iface_a] = node_b
        iface_map[node_b][iface_b] = node_a
    return dict(iface_map)


def _next_eth(iface_map: dict[str, str]) -> str:
    """给定某节点的 {ethX: peer}，返回下一个可用的 eth 编号"""
    used = {int(e.replace("eth", "")) for e in iface_map if e.startswith("eth")}
    return f"eth{max(used, default=0) + 1}"


class ScenarioAssembler:
    """将 topology template + CVE atoms 组装为完整可部署场景"""

    def __init__(self, template_loader: TemplateLoader):
        self.template_loader = template_loader

    def assemble(
        self,
        template_name: str,
        atoms: list[AtomConfig],
        scenario_name: Optional[str] = None,
        atoms_dir: str = "data/atoms",
        toolbox_dir: str = "assets/toolbox",
    ) -> dict:
        """组装完整场景

        Returns:
            {
                "name", "hash", "template", "clab", "ansible_base",
                "cve_setup", "injections", "ground_truth", "flag_files",
                "ip_allocations",
            }
        """
        template = self.template_loader.load(template_name)
        clab_base = self.template_loader.load_clab_base(template_name)

        if not scenario_name:
            cve_tag = "-".join(a.cve_id.lower().replace("cve-", "") for a in atoms)
            scenario_name = f"{template_name}-{cve_tag}"

        # Deep copy to avoid mutating base
        clab = copy.deepcopy(clab_base)
        clab["name"] = scenario_name

        # 解析 base clab 的接口映射
        iface_map = _parse_interface_map(clab)

        injections = []
        cve_setup_tasks = []
        used_cves = []
        flag_files = []

        # 按 zone 分组 targets（用于 IP 分配）
        zone_targets: dict[str, list[str]] = defaultdict(list)

        for i, (ip, atom) in enumerate(zip(template.injection_points, atoms)):
            flag = _generate_flag()
            node_name = f"target-{i+1}"
            flag_file_name = f"flag-{node_name}.txt"

            # CVE 容器节点
            node_def = {
                "kind": "linux",
                "image": atom.docker_image,
            }
            node_def["env"] = {atom.flag_injection.env_var_name: flag}

            # CLab binds: init files (absolute path) + FLAG file + static toolbox
            binds = []
            atoms_path = Path(atoms_dir).resolve()
            for init_file in atom.service_startup.init_files:
                abs_path = atoms_path / atom.cve_id / "init" / init_file.filename
                binds.append(f"{abs_path}:{init_file.container_path}")
            binds.append(f"{flag_file_name}:/flag.txt")
            binds.append(f"{Path(toolbox_dir).resolve()}:/opt/toolbox:ro")
            node_def["binds"] = binds
            clab["topology"]["nodes"][node_name] = node_def

            # 找到该 zone 对应的 router
            zone_router = template.zones[ip.zone].router
            if not zone_router:
                zone_router = next(iter(template.routers), "edge-router")

            # Link target → zone router
            router_eth = _next_eth(iface_map.get(zone_router, {}))
            clab["topology"]["links"].append(
                {"endpoints": [f"{node_name}:eth1", f"{zone_router}:{router_eth}"]}
            )
            iface_map.setdefault(zone_router, {})[router_eth] = node_name
            iface_map.setdefault(node_name, {})["eth1"] = zone_router

            # CVE setup: wait for service
            cve_setup_tasks.append({
                "name": f"Wait for {atom.cve_id} on {node_name}",
                "hosts": "localhost",
                "gather_facts": False,
                "tasks": [
                    {
                        "name": f"Wait {atom.service_startup.wait_seconds}s for service",
                        "ansible.builtin.pause": {
                            "seconds": atom.service_startup.wait_seconds
                        },
                    },
                ],
            })

            injections.append({
                "ip_id": ip.id,
                "cve_id": atom.cve_id,
                "flag": flag,
                "node_name": node_name,
                "zone": ip.zone,
                "flag_file": flag_file_name,
            })
            flag_files.append((node_name, flag, flag_file_name))
            used_cves.append(atom.cve_id)
            zone_targets[ip.zone].append(node_name)

        # ── IP 分配 ──────────────────────────────────────
        ip_alloc = self._allocate_ips(template, iface_map, zone_targets)

        # 生成 base.yaml（含 IP 配置、路由、管理网络禁用）
        ansible_base = self._generate_base_yaml(template, ip_alloc, scenario_name)

        # Ground truth: 含数据面 IP
        ground_truth = {
            "scenario": scenario_name,
            "template": template_name,
            "attack_path": [],
        }
        for inj in injections:
            node_ip = ip_alloc.get(inj["node_name"], {})
            ground_truth["attack_path"].append({
                "step": len(ground_truth["attack_path"]) + 1,
                "injection_point": inj["ip_id"],
                "target_node": inj["node_name"],
                "cve_id": inj["cve_id"],
                "zone": inj["zone"],
                "flag": inj["flag"],
                "flag_hint": "file:/flag.txt",
                "target_ip": node_ip.get("eth1", "").split("/")[0],
            })

        return {
            "name": scenario_name,
            "hash": _generate_scenario_hash(scenario_name, used_cves),
            "template": template_name,
            "clab": clab,
            "ansible_base": ansible_base,
            "cve_setup": cve_setup_tasks,
            "injections": injections,
            "ground_truth": ground_truth,
            "flag_files": flag_files,
            "ip_allocations": ip_alloc,
        }

    def _allocate_ips(
        self,
        template: TopologyTemplate,
        iface_map: dict[str, dict[str, str]],
        zone_targets: dict[str, list[str]],
    ) -> dict:
        """自动分配数据面 IP（多 transit + 多 zone）

        Returns:
            {
                "attacker": {"eth1": "10.255.255.2/30", "gateway": "10.255.255.1"},
                "edge-router": {"eth1": "10.255.255.1/30", "eth3": "192.168.100.1/24"},
                "target-1": {"eth1": "192.168.100.2/24", "gateway": "192.168.100.1"},
            }
        """
        ip_alloc: dict[str, dict] = {}

        # 1. Transit IP 分配: 匹配 transits 到 clab links
        # 构建 peer→节点名查找表用于匹配
        for transit in template.transits:
            transit_net = ipaddress.ip_network(transit.subnet, strict=False)
            hosts = list(transit_net.hosts())
            ep0, ep1 = transit.endpoints[0], transit.endpoints[1]

            # 找到两端节点互连的接口
            ep0_iface = self._find_link_iface(iface_map, ep0, ep1)
            ep1_iface = self._find_link_iface(iface_map, ep1, ep0)

            if ep0_iface and ep1_iface:
                ip_alloc.setdefault(ep0, {})[ep0_iface] = f"{hosts[0]}/{transit_net.prefixlen}"
                ip_alloc.setdefault(ep1, {})[ep1_iface] = f"{hosts[1]}/{transit_net.prefixlen}"

        # 2. Zone IP 分配: router .1, targets .2, .3, ...
        for zone_name, node_names in zone_targets.items():
            zone_def = template.zones[zone_name]
            zone_router = zone_def.router
            zone_net = ipaddress.ip_network(zone_def.subnet, strict=False)
            zone_hosts = list(zone_net.hosts())

            # 找 router 在该 zone 的接口
            for i, tgt_name in enumerate(node_names):
                router_iface = self._find_link_iface(iface_map, zone_router, tgt_name)
                if router_iface:
                    ip_alloc.setdefault(zone_router, {})[router_iface] = (
                        f"{zone_hosts[0]}/{zone_net.prefixlen}"
                    )
                    break  # 同 zone 共享 router IP，只需设置一次

            # Targets
            for i, tgt_name in enumerate(node_names):
                tgt_ip = str(zone_hosts[i + 1])
                ip_alloc[tgt_name] = {
                    "eth1": f"{tgt_ip}/{zone_net.prefixlen}",
                    "gateway": str(zone_hosts[0]),
                }

        # 3. Attacker gateway: 指向直接相连的 router 的 transit IP
        attacker_alloc = ip_alloc.get("attacker", {})
        if attacker_alloc:
            for iface, peer in iface_map.get("attacker", {}).items():
                peer_iface = self._find_link_iface(iface_map, peer, "attacker")
                if peer_iface:
                    peer_ip = ip_alloc.get(peer, {}).get(peer_iface, "")
                    if peer_ip:
                        attacker_alloc["gateway"] = peer_ip.split("/")[0]

        # 4. Router static routes: 通过 BFS 计算到非直连网段的下一跳
        router_routes = self._compute_routes(template, ip_alloc, iface_map)
        for router_name, routes in router_routes.items():
            ip_alloc.setdefault(router_name, {})["routes"] = routes

        return ip_alloc

    def _find_link_iface(self, iface_map: dict, node: str, peer: str) -> str | None:
        """找到 node 连接 peer 的接口名"""
        for iface, connected in iface_map.get(node, {}).items():
            if connected == peer:
                return iface
        return None

    def _compute_routes(
        self,
        template: TopologyTemplate,
        ip_alloc: dict,
        iface_map: dict,
    ) -> dict[str, list[dict]]:
        """计算每个 router 到非直连 zone 网段的路由

        使用 BFS 从 transit graph 中计算最短路径。
        """
        # 构建 transit 邻接图
        adj: dict[str, list[str]] = defaultdict(list)
        for transit in template.transits:
            a, b = transit.endpoints
            adj[a].append(b)
            adj[b].append(a)

        # 每个 router 直接连接的 zone 网段
        router_local_zones: dict[str, list[str]] = defaultdict(list)
        for zone_name, zone_def in template.zones.items():
            if zone_def.router:
                router_local_zones[zone_def.router].append(zone_def.subnet)

        # BFS: 从每个 router 出发，找到到达其他 router 的最短路径下一跳
        router_routes: dict[str, list[dict]] = defaultdict(list)

        for router_name in template.routers:
            if router_name not in adj:
                continue

            # 直连网段（transit subnet + zone subnet）
            local_subnets = set()
            for transit in template.transits:
                if router_name in transit.endpoints:
                    local_subnets.add(transit.subnet)
            for subnet in router_local_zones.get(router_name, []):
                local_subnets.add(subnet)

            # BFS 找下一跳
            visited = {router_name}
            queue = deque()
            # 初始邻居就是下一跳
            for nb in adj[router_name]:
                visited.add(nb)
                queue.append((nb, nb))  # (current, first_hop)

            while queue:
                current, first_hop = queue.popleft()

                # current 连接的 zone 网段 → 通过 first_hop 到达
                for subnet in router_local_zones.get(current, []):
                    net = ipaddress.ip_network(subnet, strict=False)
                    if not any(
                        net.overlaps(ipaddress.ip_network(s, strict=False))
                        for s in local_subnets
                    ):
                        # 需要找到 first_hop 在 transit link 上的 IP（对端 IP）
                        hop_iface = self._find_link_iface(iface_map, router_name, first_hop)
                        if hop_iface:
                            peer_iface = self._find_link_iface(iface_map, first_hop, router_name)
                            hop_ip = ip_alloc.get(first_hop, {}).get(peer_iface, "") if peer_iface else ""
                            if hop_ip:
                                router_routes[router_name].append({
                                    "dst": subnet,
                                    "via": hop_ip.split("/")[0],
                                })

                for nb in adj[current]:
                    if nb not in visited:
                        visited.add(nb)
                        queue.append((nb, first_hop))

        return dict(router_routes)

    def _generate_base_yaml(
        self,
        template: TopologyTemplate,
        ip_alloc: dict,
        scenario_name: str = "",
    ) -> str:
        """生成完整的 base.yaml：用 nsenter 配置所有节点（不依赖容器内工具）"""
        tasks = []

        def nsenter_cmd(node: str, cmd: str, as_root: bool = False) -> dict:
            """用 docker exec 在容器内执行网络配置命令

            无需 sudo 权限（只要用户在 docker 组）。
            as_root=True 时用 --user root 执行（attacker 容器默认非 root）。
            """
            container = f"clab-{scenario_name}-{node}"
            user_flag = " --user root" if as_root else ""
            shell_cmd = f"docker exec{user_flag} {container} sh -c '{cmd}'"
            return {
                "name": f"Configure {node}: {cmd[:60]}",
                "ansible.builtin.shell": "{% raw %}" + shell_cmd + "{% endraw %}",
                "changed_when": False,
            }

        # 找 attacker 直连的 router（只有它需要 NAT）
        attacker_router = ""
        for transit in template.transits:
            if "attacker" in transit.endpoints:
                attacker_router = transit.endpoints[0] if transit.endpoints[1] == "attacker" else transit.endpoints[1]
                break

        # 1. Routers: 接口 IP + ip_forward + iptables + static routes
        # Build zone→subnet map for isolation rules
        zone_subnets = {name: z.subnet for name, z in template.zones.items()}
        # Attacker subnet: from transit connecting attacker
        for transit in template.transits:
            if "attacker" in transit.endpoints:
                zone_subnets["attacker"] = transit.subnet
                break

        for router_name in template.routers:
            router_config = ip_alloc.get(router_name, {})
            routes = router_config.get("routes", [])

            for iface, addr in router_config.items():
                if iface in ("gateway", "routes"):
                    continue
                tasks.append(nsenter_cmd(
                    router_name,
                    f"ip addr replace {addr} dev {iface} 2>/dev/null; ip link set {iface} up"
                ))

            tasks.append(nsenter_cmd(router_name, "sysctl -w net.ipv4.ip_forward=1"))

            # iptables: default DROP, then apply isolation_rules
            tasks.append(nsenter_cmd(router_name, "iptables -P FORWARD DROP"))
            tasks.append(nsenter_cmd(router_name, "iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT"))
            for rule in template.isolation_rules:
                src = zone_subnets.get(rule.from_zone, "")
                dst = zone_subnets.get(rule.to_zone, "")
                if not src or not dst:
                    continue
                action = "ACCEPT" if rule.action == "accept" else "DROP"
                tasks.append(nsenter_cmd(
                    router_name,
                    f"iptables -A FORWARD -s {src} -d {dst} -j {action}"
                ))

            if router_name == attacker_router:
                tasks.append(nsenter_cmd(router_name, "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"))

            for route in routes:
                tasks.append(nsenter_cmd(
                    router_name,
                    f"ip route replace {route['dst']} via {route['via']}"
                ))

        # 2. Targets: IP + default route + flush eth0 (禁用管理网)
        for node_name, config in ip_alloc.items():
            if not node_name.startswith("target-"):
                continue
            tasks.append(nsenter_cmd(
                node_name,
                f"ip addr replace {config['eth1']} dev eth1 2>/dev/null; ip link set eth1 up"
            ))
            tasks.append(nsenter_cmd(
                node_name,
                f"ip route replace default via {config['gateway']}"
            ))
            tasks.append(nsenter_cmd(node_name, "ip addr flush dev eth0"))

        # 3. Attacker: IP + route + flush eth0
        attacker_config = ip_alloc.get("attacker", {})
        if attacker_config:
            tasks.append(nsenter_cmd(
                "attacker",
                f"ip addr replace {attacker_config['eth1']} dev eth1 2>/dev/null; ip link set eth1 up",
                as_root=True,
            ))
            tasks.append(nsenter_cmd(
                "attacker",
                f"ip route replace default via {attacker_config['gateway']}",
                as_root=True,
            ))
            tasks.append(nsenter_cmd("attacker", "ip addr flush dev eth0", as_root=True))

        playbook = [{
            "name": "Configure data plane network",
            "hosts": "localhost",
            "gather_facts": False,
            "tasks": tasks,
        }]

        return yaml.dump(playbook, default_flow_style=False, sort_keys=False, allow_unicode=True)

    def write_output(self, scenario: dict, output_dir: str) -> str:
        """将场景写入输出目录"""
        from pathlib import Path

        out = Path(output_dir) / scenario["name"]
        out.mkdir(parents=True, exist_ok=True)
        (out / "ansible").mkdir(exist_ok=True)

        # FLAG files
        for node_name, flag, flag_file_name in scenario.get("flag_files", []):
            (out / flag_file_name).write_text(flag)

        # CLab YAML
        (out / "clab.yaml").write_text(
            yaml.dump(scenario["clab"], default_flow_style=False, sort_keys=False)
        )

        # Ansible base.yaml (生成的含 IP 配置)
        if scenario["ansible_base"]:
            (out / "ansible" / "base.yaml").write_text(scenario["ansible_base"])

        # CVE setup playbook
        if scenario["cve_setup"]:
            (out / "ansible" / "cve-setup.yaml").write_text(
                yaml.dump(scenario["cve_setup"], default_flow_style=False, sort_keys=False)
            )

        # Ground truth
        (out / "ground_truth.json").write_text(
            __import__("json").dumps(scenario["ground_truth"], indent=2, ensure_ascii=False)
        )

        # Scenario metadata
        meta = {
            "name": scenario["name"],
            "hash": scenario["hash"],
            "template": scenario["template"],
            "injections": scenario["injections"],
            "ip_allocations": scenario.get("ip_allocations", {}),
        }
        (out / "scenario.yaml").write_text(
            yaml.dump(meta, default_flow_style=False, sort_keys=False)
        )

        return str(out)
