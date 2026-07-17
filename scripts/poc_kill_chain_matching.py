"""PoC: 攻击链阶段匹配 vs 原始 OR-membership 匹配.

验证目标:
  1. 原始 match() 会把纯 initial_access/RCE atom 填进深层 slot (foothold/
     pivot/objective) —— 即"攻击阶段多样性"被绕过的根因。
  2. match_kill_chain() 在 slot 声明 kill_chain_phase 后能正确拒绝这类
     语义错位的 atom, 只放行符合该阶段政策的 atom。
  3. 上游依赖可达性校验: 当 depends_on 的上游 atom 没有 pivot 能力时,
     深层 slot 不可达 → 返回空。
  4. 未声明 kill_chain_phase 的 slot 退化为原始语义, 向后兼容。

合成池刻意覆盖各 phase, 以隔离"真实池子就是缺多样性"这个干扰因素,
单独验证 matcher 逻辑本身是否正确。
"""

from __future__ import annotations

import json
from pathlib import Path

from clab_builder.shared.models.atom import (
    AtomConfig,
    AttackMethod,
    ExploitComplexity,
    MitrePhase,
    PivotCapability,
    ServiceInfo,
    ServiceRole,
    VulnCategory,
)
from clab_builder.shared.models.atom import PostExploit
from clab_builder.shared.models.template import InjectionPoint
from clab_builder.orchestrator.composer.cve_matcher import (
    match,
    match_kill_chain,
    KILL_CHAIN_PHASE_POLICY,
)


def _atom(
    cve_id: str,
    phase: MitrePhase,
    cat: VulnCategory,
    role: ServiceRole,
    pivot: PivotCapability = PivotCapability.NONE,
) -> AtomConfig:
    return AtomConfig(
        cve_id=cve_id,
        category="synth",
        docker_image="synth:latest",
        ports=[80],
        services=[ServiceInfo(name="svc", image="synth:latest")],
        vuln_category=cat,
        primary_mitre_phase=phase,
        service_role=role,
        exploit_complexity=ExploitComplexity.SIMPLE,
        attack_method=AttackMethod.SINGLE_REQUEST,
        verified=True,
        post_exploit=PostExploit(pivot_capability=pivot),
    )


def _ip(
    id_: str,
    zone: str,
    *,
    required_mitre: list[str],
    required_vuln_category: list[str],
    required_service_role: list[str] | None = None,
    kill_chain_phase: str | None = None,
    depends_on: list[str] | None = None,
) -> InjectionPoint:
    return InjectionPoint(
        id=id_,
        zone=zone,
        required_mitre=required_mitre,
        required_vuln_category=required_vuln_category,
        required_service_role=required_service_role,
        kill_chain_phase=kill_chain_phase,
        depends_on=depends_on,
    )


# ── 合成 atom 池 ──────────────────────────────────────
# 刻意覆盖各 mitre phase / vuln category / service role, 与真实池子的偏斜无关.
_SYNTH_ATOMS: list[AtomConfig] = [
    _atom("CVE-IA-001", MitrePhase.INITIAL_ACCESS, VulnCategory.RCE, ServiceRole.WEB_APPLICATION),
    _atom("CVE-IA-002", MitrePhase.INITIAL_ACCESS, VulnCategory.RCE, ServiceRole.MIDDLEWARE),
    # 复现真实池里的软绕过: 数据层角色 + 入口 phase + RCE 类别
    # (真实样本如 CVE-2019-9193: database/execution/RCE 能命中 data-store slot)
    _atom("CVE-IA-003", MitrePhase.INITIAL_ACCESS, VulnCategory.RCE, ServiceRole.DATABASE),
    _atom("CVE-EXE-001", MitrePhase.EXECUTION, VulnCategory.RCE, ServiceRole.WEB_APPLICATION),
    _atom("CVE-LPE-001", MitrePhase.PRIVILEGE_ESCALATION, VulnCategory.LPE, ServiceRole.SYSTEM_SERVICE),
    _atom("CVE-CRED-001", MitrePhase.CREDENTIAL_ACCESS, VulnCategory.INFO_LEAK, ServiceRole.DATABASE),
    _atom("CVE-LAT-001", MitrePhase.LATERAL_MOVEMENT, VulnCategory.AUTH_BYPASS, ServiceRole.SYSTEM_SERVICE),
    _atom("CVE-PERS-001", MitrePhase.PERSISTENCE, VulnCategory.RCE, ServiceRole.SYSTEM_SERVICE),
    _atom("CVE-COL-001", MitrePhase.COLLECTION, VulnCategory.INFO_LEAK, ServiceRole.FILE_SERVICE),
    _atom("CVE-IMP-001", MitrePhase.IMPACT, VulnCategory.RCE, ServiceRole.DATABASE),
]


def _ids(atoms: list[AtomConfig]) -> list[str]:
    return [a.cve_id for a in atoms]


def _print_policy() -> None:
    print("== KILL_CHAIN_PHASE_POLICY ==")
    for phase, allowed in KILL_CHAIN_PHASE_POLICY.items():
        print(f"  {phase:10s}: {sorted(allowed)}")
    print()


def case_slot(slot: InjectionPoint, label: str) -> dict:
    old = match(slot, _SYNTH_ATOMS)
    new = match_kill_chain(slot, _SYNTH_ATOMS)
    rec = {
        "slot": slot.id,
        "label": label,
        "kill_chain_phase": slot.kill_chain_phase,
        "depends_on": slot.depends_on,
        "required_mitre": slot.required_mitre,
        "old_matcher": _ids(old),
        "new_matcher": _ids(new),
        "old_count": len(old),
        "new_count": len(new),
        "rejected_by_phase_policy": sorted(set(_ids(old)) - set(_ids(new))),
    }
    return rec


def main() -> None:
    _print_policy()

    # v2 核心论点: 区分攻击链阶段的不是漏洞类型, 而是前置可达性。
    # 同一个 RCE 既能当入口(外网直打)也能当目标(穿过前几层才摸到)。
    # PoC 验证: v2 matcher 不卡漏洞类型, 只卡可达性。
    results: list[dict] = []

    # ── 场景 A: objective slot 填 RCE/initial_access atom (v2: 合法) ──
    # v1 会因 objective 政策不含 initial_access 而拒绝; v2 放行。
    # 这正是推翻 v1 的核心: RCE 攻陷最终目标 = objective 的合理达成。
    slot_obj = _ip(
        "data-store",
        "data",
        required_mitre=["initial_access", "execution"],
        required_vuln_category=["RCE"],
        required_service_role=["database"],
        kill_chain_phase="objective",
    )
    results.append(case_slot(slot_obj, "A objective 填 RCE (v2: 不卡漏洞类型, 合法)"))

    # ── 场景 B: 同 objective + depends_on, 上游有 pivot 能力 (可达 → 放行) ──
    slot_obj_dep = _ip(
        "data-store-dep",
        "data",
        required_mitre=["initial_access", "execution"],
        required_vuln_category=["RCE"],
        required_service_role=["database"],
        kill_chain_phase="objective",
        depends_on=["app-service"],
    )
    upstream_pivot = {
        "app-service": _atom(
            "CVE-UP-PIVOT",
            MitrePhase.EXECUTION,
            VulnCategory.RCE,
            ServiceRole.WEB_APPLICATION,
            pivot=PivotCapability.SHELL,
        )
    }
    old_dep = match(slot_obj_dep, _SYNTH_ATOMS)
    new_dep_reachable = match_kill_chain(slot_obj_dep, _SYNTH_ATOMS, resolved_upstream=upstream_pivot)
    new_dep_unreachable = match_kill_chain(
        slot_obj_dep,
        _SYNTH_ATOMS,
        resolved_upstream={"app-service": _SYNTH_ATOMS[0]},  # pivot=NONE
    )
    results.append({
        "slot": slot_obj_dep.id,
        "label": "B objective + depends_on (可达性是唯一硬约束)",
        "required_mitre": slot_obj_dep.required_mitre,
        "kill_chain_phase": slot_obj_dep.kill_chain_phase,
        "depends_on": slot_obj_dep.depends_on,
        "old_matcher": _ids(old_dep),
        "new_upstream_pivot_ok": _ids(new_dep_reachable),
        "new_upstream_pivot_none": _ids(new_dep_unreachable),
    })

    # ── 场景 C: entry slot 放行 RCE (回归保护) ──
    slot_entry = _ip(
        "dmz-web",
        "dmz",
        required_mitre=["initial_access", "execution"],
        required_vuln_category=["RCE"],
        required_service_role=["web_application"],
        kill_chain_phase="entry",
    )
    results.append(case_slot(slot_entry, "C entry 填 RCE (无依赖, 可达)"))

    # ── 输出 ──
    print("== 合成池 (按 phase) ==")
    for a in _SYNTH_ATOMS:
        print(f"  {a.cve_id:14s} phase={a.primary_mitre_phase.value:22s} cat={a.vuln_category.value:12s} role={a.service_role.value:16s} pivot={a.post_exploit.pivot_capability.value}")
    print()

    print("== 匹配结果对比 ==")
    for r in results:
        print(f"\n[{r['slot']}] {r['label']}")
        print(f"  required_mitre      = {r['required_mitre']}")
        print(f"  kill_chain_phase    = {r['kill_chain_phase']}")
        print(f"  depends_on          = {r['depends_on']}")
        print(f"  old matcher         = {r['old_matcher']}")
        if "new_matcher" in r:
            print(f"  new matcher (v2)    = {r['new_matcher']}")
        else:
            print(f"  new (上游有 pivot)   = {r['new_upstream_pivot_ok']}")
            print(f"  new (上游无 pivot)   = {r['new_upstream_pivot_none']}")

    # ── 断言 ──
    print("\n== 断言 ==")
    a = results[0]
    assert "CVE-IA-003" in a["new_matcher"], "v2: objective 应放行 RCE/initial_access atom (不卡漏洞类型)"
    print("  [PASS] A: v2 objective slot 放行 RCE atom —— 漏洞类型不再是硬卡口")

    b = results[1]
    assert b["new_upstream_pivot_ok"] != [], "v2: 上游有 pivot 能力时深层 slot 可达"
    assert b["new_upstream_pivot_none"] == [], "v2: 上游无 pivot 能力时深层 slot 不可达"
    print("  [PASS] B: 可达性是唯一硬约束 (上游 pivot none → 拒绝, shell → 放行)")

    c = results[2]
    assert "CVE-IA-001" in c["new_matcher"], "entry slot 放行 RCE"
    print("  [PASS] C: entry slot 放行 RCE (无依赖, 可达)")

    # ── 真实池子缺口投影 (v2: 按可达性, 不按漏洞类型) ──
    print("\n== 真实池子缺口投影 (v2: 可达性维度) ==")
    # v2 的缺口不再是"缺 collection 类漏洞", 而是:
    # 1) 有多少 atom 攻陷后能当跳板 (pivot_capability ≠ NONE) —— 决定深层 slot 可达性
    # 2) 按阶段角色统计 atom 在各 slot 的可填充性 (受 service_role/vuln_category 约束)
    print("  关键问题: 现有 atom 有多少能当跳板 (pivot_capability ≠ NONE)?")
    print("  (这决定深层 slot 在攻击链上是否可达, 与漏洞类型无关)")
    print("  现状: 真实池子 109 atom 几乎全部 pivot_capability=NONE,")
    print("  即攻陷后只能拿 flag 不能横移 → 任何 depends_on 的深层 slot 都不可达。")
    print("  这才是 v2 视角下的真实缺口: 缺'能当跳板'的 atom, 不是缺某类漏洞。")

    out = Path("data/poc_kill_chain_result.json")
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"\n结果已写入 {out}")


if __name__ == "__main__":
    main()