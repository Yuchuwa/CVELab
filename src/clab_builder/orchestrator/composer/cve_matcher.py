"""CVE Matcher — 将 injection_points 与 atom library 匹配"""

import random
from typing import Optional

from clab_builder.shared.models.atom import AtomConfig
from clab_builder.shared.models.template import InjectionPoint


def match(
    injection_point: InjectionPoint,
    atoms: list[AtomConfig],
    exclude: Optional[list[str]] = None,
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

        # 规则 1: mitre phase 匹配
        if atom.primary_mitre_phase.value not in injection_point.required_mitre:
            continue

        # 规则 2: vuln category 匹配
        if atom.vuln_category.value not in injection_point.required_vuln_category:
            continue

        # 规则 3: service role 匹配 (可选)
        if injection_point.required_service_role is not None:
            if atom.service_role.value not in injection_point.required_service_role:
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
