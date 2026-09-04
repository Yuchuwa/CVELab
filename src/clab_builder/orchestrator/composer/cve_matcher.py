"""CVE Matcher — 将 injection_points 与 atom library 匹配"""

import random
from typing import Optional

from clab_builder.shared.models.atom import (
    AtomConfig,
    AttackMethod,
    ExploitComplexity,
    PivotCapability,
    ServiceRole,
    VulnCategory,
)
from clab_builder.shared.models.template import InjectionPoint
from clab_builder.shared.service_resolver import resolve_service_family, service_role_for_family


def effective_service_family(atom: AtomConfig) -> str:
    """Return persisted runtime family or safely derive it for legacy atoms."""
    runtime = getattr(atom, "runtime_spec", None)
    family = str(getattr(runtime, "service_family", "") or "").strip().lower()
    if family and family != "unknown":
        return family
    return resolve_service_family(
        getattr(runtime, "source_image", "") or getattr(atom, "docker_image", ""),
        "",
        getattr(runtime, "ports", None) or getattr(atom, "ports", []),
    )


def effective_service_role(atom: AtomConfig) -> str:
    """Use deterministic runtime classification when it has a known role."""
    return service_role_for_family(effective_service_family(atom)) or atom.service_role.value


def service_access_matches(required: dict, actual: dict) -> bool:
    """Return whether an Atom service declaration satisfies a slot contract.

    Both the matcher and asset preflight use this helper so a service protocol
    cannot be accepted during selection and rejected later during setup.
    An empty/absent Atom declaration is not sufficient for a non-empty
    contract: the Range must be able to prove that its setup commands target
    the service exposed by the selected Atom.
    """
    required = required or {}
    actual = actual or {}
    if not required:
        return True

    protocols = required.get("protocols", [])
    if required.get("protocol"):
        protocols = [required["protocol"]]
    ports = required.get("ports", [])
    if required.get("port") is not None:
        ports = [required["port"]]

    actual_protocol = str(actual.get("protocol", "")).lower()
    actual_port = actual.get("port")
    if protocols and actual_protocol not in {str(item).lower() for item in protocols}:
        return False
    if ports and actual_port not in ports:
        return False
    return bool(actual_protocol or actual_port) if (protocols or ports) else True


def match(
    injection_point: InjectionPoint,
    atoms: list[AtomConfig],
    exclude: Optional[list[str]] = None,
    *,
    ignore_mitre: bool = False,
) -> list[AtomConfig]:
    """匹配 injection_point 与可用 atom

    匹配规则:
        1. primary_mitre_phase in required_mitre
        2. vuln_category in required_vuln_category
        3. service_role in required_service_role (如果 injection_point 指定了)
        4. 已验证 + 单服务 (应该由调用方已过滤)

    Args:
        injection_point: 模板中的注入点
        atoms: 可用 atom 列表 (通常已过滤为 verified + single-service)
        exclude: 要排除的 CVE ID 列表

    Returns:
        匹配的 AtomConfig 列表
    """
    exclude_set = set(exclude or [])
    matched = []

    for atom in atoms:
        if atom.cve_id in exclude_set:
            continue

        # 规则 1: mitre phase 或 capability 匹配（按槽位声明逐步替代）
        # 如果槽位声明了 required_capabilities，用能力匹配（不再强制 required_mitre）；
        # 否则沿用现有 required_mitre 规则（空列表时跳过，不筛选）。
        if injection_point.required_capabilities:
            # AtomConfig exposes explicit verified grants and the legacy
            # pivot_capability compatibility view through this property.  A
            # matcher must use the same view as capability closure; otherwise
            # migrated atoms silently lose their usable capabilities.
            atom_caps = atom.verified_capability_types
            if not set(injection_point.required_capabilities).issubset(atom_caps):
                continue
        elif injection_point.required_mitre and not ignore_mitre:
            if atom.primary_mitre_phase.value not in injection_point.required_mitre:
                continue

        # 规则 2: vuln category 匹配（空列表时跳过，不筛选）
        if injection_point.required_vuln_category:
            if atom.vuln_category.value not in injection_point.required_vuln_category:
                continue

        # 规则 3: service role 匹配 (可选，空时跳过)
        if injection_point.required_service_role:
            if effective_service_role(atom) not in injection_point.required_service_role:
                continue

        if not service_access_matches(
            injection_point.required_service_access,
            atom.exploit_access.required_service,
        ):
            continue

        matched.append(atom)

    return matched


def pick_random(matched: list[AtomConfig], count: int = 1) -> list[AtomConfig]:
    """从匹配列表中随机选择

    Args:
        matched: 已匹配的 atom 列表
        count: 需要的数量

    Returns:
        随机选择的 atom 列表 (不超过 len(matched))
    """
    if len(matched) <= count:
        return matched
    return random.sample(matched, count)


def match_kill_chain(
    injection_point: InjectionPoint,
    atoms: list[AtomConfig],
    *,
    exclude: Optional[list[str]] = None,
    resolved_upstream: Optional[dict[str, AtomConfig]] = None,
    available_assets: Optional[set[str]] = None,
) -> list[AtomConfig]:
    """Match a slot while respecting dependencies and acquired assets."""
    available_assets = available_assets or set()
    if injection_point.required_assets and not set(injection_point.required_assets).issubset(available_assets):
        return []
    resolved_upstream = resolved_upstream or {}
    if any(dep not in resolved_upstream for dep in injection_point.depends_on):
        return []
    # kill_chain_phase is a topology/attack-role annotation, not a CVE phase
    # gate.  Once a template declares it, required_mitre remains a soft hint;
    # hard reachability is handled by depends_on, capabilities and isolation.
    candidates = match(
        injection_point,
        atoms,
        exclude=exclude,
        ignore_mitre=bool(injection_point.kill_chain_phase),
    )
    return candidates

def score_for_chain_position(
    atom: AtomConfig,
    injection_point: InjectionPoint,
    index: int,
    total: int,
) -> int:
    """Score an atom for a concrete attack-chain position.

    The template filter decides whether an atom is allowed. This score decides
    which allowed atom is operationally useful at this hop.
    """
    is_first = index == 0
    is_last = index == total - 1
    is_intermediate = not is_last
    score = 0

    # Prefer CVEs that actually produce command execution on hops that must
    # launch the next exploit from the compromised node.
    if atom.vuln_category in {
        VulnCategory.RCE,
        VulnCategory.DESERIALIZATION,
        VulnCategory.INJECTION,
    }:
        score += 30
    elif atom.vuln_category in {VulnCategory.LFI, VulnCategory.INFO_LEAK}:
        score += 8 if is_last else -25
    elif atom.vuln_category == VulnCategory.AUTH_BYPASS:
        score += 12

    if atom.attack_method in {
        AttackMethod.SINGLE_REQUEST,
        AttackMethod.MULTI_STEP_HTTP,
        AttackMethod.SERVICE_PROTOCOL,
    }:
        score += 18
    elif atom.attack_method == AttackMethod.REVERSE_CALLBACK:
        score += -20 if is_intermediate else -8
    elif atom.attack_method in {AttackMethod.FILE_UPLOAD, AttackMethod.DESERIALIZATION}:
        score += 10

    if atom.exploit_complexity == ExploitComplexity.SIMPLE:
        score += 18
    elif atom.exploit_complexity == ExploitComplexity.MEDIUM:
        score += 8 if is_first else 0
    elif atom.exploit_complexity == ExploitComplexity.COMPLEX:
        score += -8 if is_first else -30

    if atom.network_requirements.needs_callback:
        score += -25 if is_intermediate else -10
    if atom.network_requirements.needs_tool_download:
        score += -20 if is_intermediate else -8
    if atom.network_requirements.needs_ssh:
        score += -5

    if atom.post_exploit.pivot_capability in {
        PivotCapability.SHELL,
        PivotCapability.PORT_FORWARD,
        PivotCapability.FULL_TOOLBOX,
    }:
        score += 12

    tools = {
        str(tool).lower()
        for tool in atom.requirements.get("tools_needed", [])
        if isinstance(tool, str)
    }
    if tools:
        portable = {
            "sh",
            "bash",
            "busybox",
            "curl",
            "wget",
            "nc",
            "netcat",
            "telnet",
            "cat",
            "echo",
            "sed",
            "awk",
        }
        heavy_markers = (
            "python",
            "java",
            "jdk",
            "ysoserial",
            "nmap",
            "mysql",
            "gcc",
            "go",
            "maven",
            "impacket",
            "metasploit",
        )
        heavy = {
            tool
            for tool in tools
            if tool not in portable
            and any(marker in tool for marker in heavy_markers)
        }
        if heavy:
            score += -35 if is_intermediate else -10
        else:
            score += 8

    if is_first and atom.primary_mitre_phase.value == "initial_access":
        score += 10
    if is_last and atom.service_role in {
        ServiceRole.DATABASE,
        ServiceRole.FILE_SERVICE,
        ServiceRole.SYSTEM_SERVICE,
    }:
        score += 8
    if injection_point.zone in {"app", "data"} and atom.network_requirements.needs_callback:
        score -= 15

    return score


def pick_orchestrated(
    matched: list[AtomConfig],
    injection_point: InjectionPoint,
    index: int,
    total: int,
    count: int = 1,
) -> list[AtomConfig]:
    """Pick atoms using attack-chain suitability instead of pure randomness."""
    if len(matched) <= count:
        return matched
    ranked = sorted(
        matched,
        key=lambda atom: (
            score_for_chain_position(atom, injection_point, index, total),
            atom.verified,
            atom.cve_id,
        ),
        reverse=True,
    )
    return ranked[:count]
