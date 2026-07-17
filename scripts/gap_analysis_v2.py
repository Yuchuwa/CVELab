"""阶段 1 缺口分析: 按攻击链可达性语义(v2)投影现有 atom 池子。

不做任何漏洞类型卡口(v2 已推翻), 只回答:
  1. 有多少 atom 攻陷后能当跳板 (pivot_capability != NONE)?  → 决定深层 slot 可达性
  2. service_role / vuln_category / mitre_phase 三维分布       → 决定能填哪些 slot
  3. 3 个模板的每个 slot, 现有池子能填进去哪些 atom (match() 结果)
  4. v2 视角下的缺口 + CVE-Factory 定向补池清单
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from clab_builder.orchestrator.composer.atom_loader import AtomLoader
from clab_builder.orchestrator.composer.cve_matcher import match
from clab_builder.orchestrator.composer.template_loader import TemplateLoader
from clab_builder.shared.models.atom import PivotCapability


def main() -> None:
    atoms = AtomLoader(atoms_dir="data/atoms").load_all_verified(
        single_service_only=True, high_confidence_only=False
    )
    print(f"== 加载 atom: {len(atoms)} 个 (verified + single-service) ==\n")

    # ── 1. pivot_capability 分布 (可达性维度, v2 核心缺口) ──
    print("== 1. pivot_capability 分布 (可达性维度) ==")
    pivot_dist = Counter(a.post_exploit.pivot_capability.value for a in atoms)
    for cap, cnt in pivot_dist.most_common():
        marker = ""
        if cap == PivotCapability.NONE.value:
            marker = "  <-- 只能拿 flag, 不能横移"
        print(f"  {cap:16s} {cnt:4d}{marker}")
    pivotable = sum(
        1 for a in atoms
        if a.post_exploit.pivot_capability != PivotCapability.NONE
    )
    print(f"\n  能当跳板的 atom (pivot != NONE): {pivotable} / {len(atoms)}")
    print(f"  → v2 视角下, 任何有 depends_on 的深层 slot 可达性依赖这一数字")
    print()

    # ── 2. 三维分布 ──
    print("== 2. service_role / vuln_category / mitre_phase 分布 ==")
    for dim, attr in [
        ("service_role", lambda a: a.service_role.value),
        ("vuln_category", lambda a: a.vuln_category.value),
        ("mitre_phase", lambda a: a.primary_mitre_phase.value),
    ]:
        dist = Counter(attr(a) for a in atoms)
        print(f"\n  -- {dim} --")
        for v, cnt in dist.most_common():
            print(f"    {v:22s} {cnt:4d}")

    print()

    # ── 3. 3 个模板的每个 slot 用 match() 跑一遍 ──
    print("== 3. 现有模板每个 slot 的可填充情况 (match, 无阶段语义) ==")
    loader = TemplateLoader(templates_dir="templates")
    templates = ["dmz_simple", "dmz_dual", "enterprise_3tier"]
    slot_report: list[dict] = []
    for tname in templates:
        tpl = loader.load(tname)
        print(f"\n  -- {tname} --")
        for ip in tpl.injection_points:
            matched = match(ip, atoms)
            roles = Counter(a.service_role.value for a in matched)
            phases = Counter(a.primary_mitre_phase.value for a in matched)
            pivotable_in_match = sum(
                1 for a in matched
                if a.post_exploit.pivot_capability != PivotCapability.NONE
            )
            print(f"    slot={ip.id:18s} zone={ip.zone:6s} matched={len(matched):3d}  "
                  f"pivotable={pivotable_in_match:3d}")
            print(f"      required_mitre   = {ip.required_mitre}")
            print(f"      required_role    = {ip.required_service_role}")
            print(f"      required_vulncat = {ip.required_vuln_category}")
            if matched:
                print(f"      命中 role 分布   = {dict(roles)}")
                print(f"      命中 phase 分布  = {dict(phases)}")
            else:
                print(f"      *** 无任何 atom 能填进此 slot (硬空缺) ***")
            slot_report.append({
                "template": tname, "slot": ip.id, "zone": ip.zone,
                "matched_count": len(matched),
                "pivotable_count": pivotable_in_match,
                "role_dist": dict(roles), "phase_dist": dict(phases),
                "required_mitre": ip.required_mitre,
                "required_role": ip.required_service_role,
                "required_vulncat": ip.required_vuln_category,
            })
    print()

    # ── 4. v2 缺口总结 + 补池清单 ──
    print("== 4. v2 缺口总结 ==")
    print(f"\n  [缺口 A] 可达性: 能当跳板的 atom 仅 {pivotable}/{len(atoms)}")
    print(f"          → enterprise_3tier 若启用 depends_on, app/data 层因上游")
    print(f"            (DMZ 层 atom pivot=NONE) 而不可达, 必须补能横移的 atom")
    print(f"            (无论漏洞类型, 关键是攻陷后能提供 shell/credential/port_forward)")

    empty_slots = [r for r in slot_report if r["matched_count"] == 0]
    if empty_slots:
        print(f"\n  [缺口 B] 硬空缺 slot (现有池子 0 atom 能填): {len(empty_slots)}")
        for r in empty_slots:
            print(f"          {r['template']}/{r['slot']}: 要求 mitre={r['required_mitre']}")
            print(f"            role={r['required_role']}")
            print(f"            vulncat={r['required_vulncat']}")
    else:
        print(f"\n  [缺口 B] 硬空缺 slot: 0 (所有 slot 都有 atom 能填, 软绕过仍存在)")

    thin_slots = [r for r in slot_report if 0 < r["matched_count"] <= 3]
    if thin_slots:
        print(f"\n  [缺口 C] 稀薄 slot (1-3 个 atom 能填, 多样性不足): {len(thin_slots)}")
        for r in thin_slots:
            print(f"          {r['template']}/{r['slot']}: matched={r['matched_count']}")

    print(f"\n  [补池清单 (CVE-Factory 定向)]")
    print(f"  1. 最高优先: 补'攻陷后能当跳板'的 atom (pivot_capability != NONE)")
    print(f"     这是 v2 唯一硬缺口, 决定深层 slot 可达性. 与漏洞类型无关,")
    print(f"     可优先改造现有 full_pass_anchor atom 的 post_exploit 字段")
    print(f"     (如 CVE-2018-16509 这种 RCE, 攻陷后天然能拿 shell,")
    print(f"      把 pivot_capability 从 NONE 标为 SHELL/FULL_TOOLBOX 即可)")
    print(f"  2. 中优先: 补 service_role=database/file_service/system_service 的 atom")
    print(f"     现有池子严重偏 web_application, enterprise_3tier 的 data-store")
    print(f"     要求 database/file_service/system_service, 候选偏少")
    print(f"  3. 低优先: 补 mitre_phase=lateral_movement/persistence/LPE 的 atom")
    print(f"     仅当模板想体现特定攻击动作(persistence 环节等)时才需要,")
    print(f"     不是系统可用性硬要求 (v2 下 RCE 可填各层)")

    out = Path("data/gap_analysis_v2.json")
    out.write_text(json.dumps({
        "total_atoms": len(atoms),
        "pivot_capability_dist": dict(pivot_dist),
        "pivotable_count": pivotable,
        "slot_report": slot_report,
    }, indent=2, ensure_ascii=False))
    print(f"\n结果已写入 {out}")


if __name__ == "__main__":
    main()