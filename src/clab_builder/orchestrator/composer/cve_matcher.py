"""CVE Matcher — 将 injection_points 与 atom library 匹配"""

import random
from typing import Optional

from clab_builder.shared.models.atom import AtomConfig
from clab_builder.shared.models.template import InjectionPoint


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
            if atom.service_role.value not in injection_point.required_service_role:
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
