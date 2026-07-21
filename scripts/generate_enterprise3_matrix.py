#!/usr/bin/env python3
"""Generate a no-deploy manifest of compatible enterprise_3tier combinations."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from clab_builder.orchestrator.composer.capability_closure import (
    close_capabilities,
    seed_capabilities,
)
from clab_builder.orchestrator.composer.cve_matcher import match_kill_chain
from clab_builder.orchestrator.composer.cve_matcher import effective_service_family
from clab_builder.orchestrator.composer.scenario_assembler import _runtime_image_selection
from clab_builder.orchestrator.composer.scenario import ScenarioPipeline


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", default="enterprise_3tier")
    parser.add_argument("--templates-dir", default="templates")
    parser.add_argument("--atoms-dir", default="data/atoms")
    parser.add_argument(
        "--output",
        default="data/range_matrices/enterprise_3tier.json",
        help="Manifest path; this command never deploys a Range.",
    )
    parser.add_argument(
        "--max-cases",
        type=int,
        default=0,
        help="Optional coverage-first cap for the accepted case list (0 = all).",
    )
    return parser.parse_args()


def _coverage_features(case: dict) -> set[str]:
    """Return the reusable dimensions a bounded matrix should cover first."""
    features = {
        f"slot:{slot_id}:{cve_id}"
        for slot_id, cve_id in (case.get("slot_atoms") or {}).items()
    }
    features.update(
        f"asset-variant:{asset_id}:{variant_id}"
        for asset_id, variant_id in (case.get("asset_variants") or {}).items()
    )
    return features


def select_coverage_first(cases: list[dict], max_cases: int) -> list[dict]:
    """Greedily select distinct slot and asset-variant coverage, deterministically.

    Two-stage tie-breaking:
    1. Prefer cases that add the most uncovered slot/asset-variant features
       (the original coverage-first objective).
    2. On ties (including the common case where all features are already
       covered, so every remaining case adds zero), break by per-slot
       balance: pick the case whose entry-point slot (``dmz-web``) CVE has
       been selected the fewest times so far, then by total slot-CVE
       imbalance. This prevents the old behavior where, once coverage
       saturates, ``max`` keeps returning the alphabetically-first case ID
       and one entry CVE (historically CVE-2012-1823) ends up in ~70% of the
       selected cases purely because its case IDs sort earliest.

    Determinism is preserved: ties on the balance key fall back to the
    sorted case ID, so the result is reproducible regardless of dict order.
    """
    remaining = sorted(cases, key=lambda case: str(case["id"]))
    selected: list[dict] = []
    covered: set[str] = set()
    limit = max_cases or len(remaining)
    slot_cve_count: dict[str, dict[str, int]] = {}

    def _balance_key(case: dict) -> tuple:
        # We minimize this tuple with min(), so lower is better.
        # 1. Maximize new coverage first: -new_features (so more coverage =>
        #    smaller value, which min picks).
        # 2. Then balance the entry-point slot: the entry CVE's count so far
        #    (fewer = picked first, spreading entry CVEs).
        # 3. Then total slot-CVE imbalance (spreads across all slots too).
        slot_atoms = case.get("slot_atoms") or {}
        entry_slot = "dmz-web" if "dmz-web" in slot_atoms else next(
            iter(slot_atoms), ""
        )
        entry_cve = slot_atoms.get(entry_slot, "")
        entry_count = slot_cve_count.get(entry_slot, {}).get(entry_cve, 0)
        total = sum(
            slot_cve_count.get(slot, {}).get(cve, 0)
            for slot, cve in slot_atoms.items()
        )
        return (-len(_coverage_features(case) - covered), entry_count, total)

    while remaining and len(selected) < limit:
        best = min(remaining, key=_balance_key)
        # Record counts before removing so the chosen case is counted too.
        for slot, cve in (best.get("slot_atoms") or {}).items():
            slot_cve_count.setdefault(slot, {})
            slot_cve_count[slot][cve] = slot_cve_count[slot].get(cve, 0) + 1
        selected.append(best)
        covered.update(_coverage_features(best))
        remaining.remove(best)
    return selected


def _candidate_reason(pipeline, template, ip, atom, used_cves, upstream, assets) -> str:
    if atom.cve_id in used_cves:
        return "duplicate_cve"
    matched = match_kill_chain(
        ip, [atom], resolved_upstream=upstream, available_assets=assets
    )
    if not matched:
        return "slot_or_dependency_constraint"
    matched = pipeline._keep_chain_capable_atoms(ip, matched, template)
    if not matched:
        return "chain_capability_constraint"
    if not pipeline.assembler.slot_asset_compatible(template, ip, atom):
        return "asset_service_variant_incompatible"
    return ""


def runtime_ready_for_batch(atom) -> bool:
    """Return whether an Atom has a complete, verified runtime image contract.

    A generated batch is intended for bounded, reproducible experiments.  It
    must therefore avoid silently relying on the verifier's on-demand runtime
    rebuild fallback.  Direct scenario generation keeps that fallback for
    legacy compatibility; this stricter rule applies only to batch manifests.
    """
    return _runtime_image_selection(atom)["selection"] == "runtime_image"


def build_manifest(args: argparse.Namespace) -> dict:
    pipeline = ScenarioPipeline(
        templates_dir=args.templates_dir,
        atoms_dir=args.atoms_dir,
        default_validation_mode="guided_agent",
    )
    template = pipeline.template_loader.load(args.template)
    usable_atoms = sorted(
        [
            atom
            for atom in pipeline.atom_loader.load_all_verified(single_service_only=True)
            if pipeline._range_usable_atom(atom, validation_mode="guided_agent")
        ],
        key=lambda atom: atom.cve_id,
    )
    atoms = [atom for atom in usable_atoms if runtime_ready_for_batch(atom)]
    runtime_deferred = [
        {
            "cve_id": atom.cve_id,
            "reason": "runtime_contract_not_ready",
        }
        for atom in usable_atoms
        if not runtime_ready_for_batch(atom)
    ]
    accepted: list[dict] = []
    rejected: list[dict] = []

    def visit(index: int, selected: list, used_cves: list[str], upstream: dict, closures: dict, assets: set[str]) -> None:
        if index == len(template.injection_points):
            try:
                bindings = pipeline.assembler.resolve_asset_bindings(template, selected)
            except ValueError as exc:
                rejected.append({
                    "prefix": [atom.cve_id for atom in selected],
                    "injection_point": "resolved-assets",
                    "candidate": "",
                    "reason": str(exc),
                })
                return
            cves = [atom.cve_id for atom in selected]
            accepted.append({
                "id": "matrix-" + "-".join(cve.lower().replace("cve-", "") for cve in cves),
                "cves": cves,
                "purpose": "auto-compatible enterprise_3tier combination",
                "slot_atoms": {
                    ip.id: atom.cve_id
                    for ip, atom in zip(template.injection_points, selected)
                },
                "service_families": {
                    ip.id: effective_service_family(atom) or "unknown"
                    for ip, atom in zip(template.injection_points, selected)
                },
                "asset_variants": {
                    asset_id: binding.get("variant_id", "legacy")
                    for asset_id, binding in bindings.items()
                },
            })
            return

        ip = template.injection_points[index]
        for atom in atoms:
            reason = _candidate_reason(pipeline, template, ip, atom, used_cves, upstream, assets)
            if reason:
                rejected.append({
                    "prefix": [item.cve_id for item in selected],
                    "injection_point": ip.id,
                    "candidate": atom.cve_id,
                    "reason": reason,
                })
                continue
            closure = close_capabilities(
                seed_capabilities(atom, host_scope=ip.id), template.assets
            )
            visit(
                index + 1,
                [*selected, atom],
                [*used_cves, atom.cve_id],
                {**upstream, ip.id: atom},
                {**closures, ip.id: closure},
                set(assets).union(closure.assets),
            )

    visit(0, [], [], {}, {}, set())
    selected_cases = select_coverage_first(accepted, args.max_cases)
    return {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "template": args.template,
        "validation_mode": "guided_agent",
        "source": "no_deploy_matrix",
        "candidate_atom_count": len(atoms),
        "runtime_deferred_atoms": runtime_deferred,
        "selection_strategy": "coverage_first_slot_atom_and_asset_variant",
        "accepted_case_count": len(accepted),
        "cases": selected_cases,
        "rejections": rejected,
    }


def main() -> int:
    args = parse_args()
    if args.max_cases < 0:
        raise SystemExit("--max-cases must be zero or positive")
    output = ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = build_manifest(args)
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    print(
        f"Matrix saved to: {output}\n"
        f"accepted={payload['accepted_case_count']} selected={len(payload['cases'])} "
        f"rejected={len(payload['rejections'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
