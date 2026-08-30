#!/usr/bin/env python3
"""Score valid CVE/template combinations with frozen architecture-aware priors."""

from __future__ import annotations

import argparse
import itertools
import json
import math
from collections import Counter
from pathlib import Path

import yaml

from clab_builder.orchestrator.composer.atom_loader import AtomLoader
from clab_builder.orchestrator.composer.cve_matcher import match_kill_chain
from clab_builder.orchestrator.composer.template_loader import TemplateLoader


ROOT = Path(__file__).resolve().parents[1]

METHOD_SUCCESS = {
    "single_request": 0.90,
    "multi_step_http": 0.75,
    "file_upload": 0.60,
    "service_protocol": 0.65,
    "deserialization": 0.50,
    "reverse_callback": 0.40,
}
METHOD_COST = {
    "single_request": 0.15,
    "multi_step_http": 0.35,
    "file_upload": 0.50,
    "service_protocol": 0.40,
    "deserialization": 0.55,
    "reverse_callback": 0.65,
}
COMPLEXITY_MULTIPLIER = {"simple": 1.0, "medium": 0.85, "complex": 0.65}
COMPLEXITY_COST = {"simple": 0.0, "medium": 0.15, "complex": 0.30}
DEPTH_MULTIPLIER = {0: 1.0, 1: 0.82, 2: 0.72}
DEPTH_COST = {0: 0.0, 1: 0.10, 2: 0.15}

TARGET_COMPLETION_MULTIPLIER = 0.95
DEPENDENCY_EDGE_MULTIPLIER = 0.90
OBJECTIVE_MULTIPLIER = 0.82
PARALLEL_BRANCH_MULTIPLIER = 0.97

TARGET_COST = 0.08
DEPENDENCY_EDGE_COST = 0.08
OBJECTIVE_COST = 0.12
PARALLEL_BRANCH_COST = 0.05
DEPTH_ARCHITECTURE_COST = 0.05

TIER_CENTERS = {
    "easy": 12.5,
    "medium": 37.5,
    "hard": 62.5,
    "very_hard": 87.5,
}


def label_for_score(score: float) -> str:
    if score < 25:
        return "easy"
    if score < 50:
        return "medium"
    if score < 75:
        return "hard"
    return "very_hard"


def score_from_probability(success_probability: float, cost_factor: float) -> float:
    return round(80.0 * (1.0 - success_probability) + 20.0 * cost_factor, 2)


def dependency_depths(template: dict) -> dict[str, int]:
    """Return the longest dependency depth of every injection point."""
    slots = {item["id"]: item for item in template.get("injection_points", [])}
    depths: dict[str, int] = {}

    def visit(slot_id: str, visiting: set[str]) -> int:
        if slot_id in depths:
            return depths[slot_id]
        if slot_id in visiting:
            raise ValueError(f"cyclic injection-point dependency at {slot_id}")
        dependencies = slots[slot_id].get("depends_on") or []
        missing = [item for item in dependencies if item not in slots]
        if missing:
            raise ValueError(f"unknown dependencies for {slot_id}: {missing}")
        depth = 0 if not dependencies else 1 + max(
            visit(item, visiting | {slot_id}) for item in dependencies
        )
        depths[slot_id] = depth
        return depth

    for slot_id in slots:
        visit(slot_id, set())
    return depths


def guide_factors(guide: dict, *, depth: int) -> tuple[float, float, list[dict]]:
    """Quantify Guided-mode executability from declared guide structure."""
    steps = guide.get("steps") or []
    factors: list[dict] = []
    probability = 1.0
    cost = 0.0

    if steps:
        command_coverage = sum(bool(item.get("command_hint")) for item in steps) / len(steps)
        if command_coverage >= 0.8:
            probability *= 1.08
            cost -= 0.05
            factors.append({"name": "guided_command_coverage", "multiplier": 1.08})
        step_factor = max(0.75, 0.97 ** max(0, len(steps) - 1))
        probability *= step_factor
        cost += min(0.25, 0.04 * max(0, len(steps) - 1))
        factors.append({"name": f"guide_steps:{len(steps)}", "multiplier": round(step_factor, 4)})

    executions = [item.get("execution") or {} for item in steps]
    if any(item.get("external_download") for item in executions):
        probability *= 0.75
        cost += 0.20
        factors.append({"name": "external_download", "multiplier": 0.75})

    requirements = guide.get("requirements") or {}
    callback = str(requirements.get("callback") or "none").lower()
    if callback not in {"", "none", "false"}:
        probability *= 0.70
        cost += 0.20
        factors.append({"name": "guide_callback", "multiplier": 0.70})

    actor_transfers = sum(
        material.get("delivery") == "channel_transfer"
        for execution in executions
        for material in execution.get("materials") or []
    )
    if depth and actor_transfers:
        transfer_factor = 0.90 ** actor_transfers
        probability *= transfer_factor
        cost += min(0.20, 0.08 * actor_transfers)
        factors.append({
            "name": f"channel_transfers:{actor_transfers}",
            "multiplier": round(transfer_factor, 4),
        })

    return probability, cost, factors


def atom_slot_score(atom: dict, guide: dict, *, slot_id: str, depth: int) -> dict:
    method = atom["attack_method"]
    complexity = atom["exploit_complexity"]
    requirements = atom.get("network_requirements") or {}
    service = (atom.get("exploit_access") or {}).get("required_service") or {}
    credentials = atom.get("default_credentials") or {}

    probability = METHOD_SUCCESS[method]
    factors = [{"name": f"method:{method}", "multiplier": METHOD_SUCCESS[method]}]

    complexity_factor = COMPLEXITY_MULTIPLIER[complexity]
    probability *= complexity_factor
    factors.append({"name": f"complexity:{complexity}", "multiplier": complexity_factor})

    bounded_depth = min(depth, 2)
    probability *= DEPTH_MULTIPLIER[bounded_depth]
    factors.append({
        "name": f"dependency_depth:{depth}",
        "multiplier": DEPTH_MULTIPLIER[bounded_depth],
    })

    cost = METHOD_COST[method] + COMPLEXITY_COST[complexity] + DEPTH_COST[bounded_depth]

    if method == "file_upload" and depth:
        probability *= 0.70
        cost += 0.15
        factors.append({"name": "file_upload_relay", "multiplier": 0.70})

    if requirements.get("needs_callback"):
        probability *= 0.65
        cost += 0.20
        factors.append({"name": "callback_required", "multiplier": 0.65})

    if service.get("authentication"):
        if depth >= 2:
            auth_factor, auth_name = 0.95, "upstream_credential_asset"
        elif credentials.get("username") and credentials.get("password"):
            auth_factor, auth_name = 0.85, "declared_default_credentials"
        else:
            auth_factor, auth_name = 0.50, "authentication"
        probability *= auth_factor
        cost += 0.10
        factors.append({"name": auth_name, "multiplier": auth_factor})

    guide_probability, guide_cost, declared_guide_factors = guide_factors(
        guide, depth=depth
    )
    probability *= guide_probability
    cost += guide_cost
    factors.extend(declared_guide_factors)

    return {
        "cve_id": atom["cve_id"],
        "slot_id": slot_id,
        "dependency_depth": depth,
        "attack_method": method,
        "exploit_complexity": complexity,
        "success_probability": round(max(0.05, min(0.98, probability)), 4),
        "cost_factor": round(max(0.0, min(1.0, cost)), 3),
        "factors": factors,
    }


def architecture_profile(template: dict) -> dict:
    slots = template.get("injection_points") or []
    depths = dependency_depths(template)
    dependency_edges = sum(len(item.get("depends_on") or []) for item in slots)
    roots = sum(not (item.get("depends_on") or []) for item in slots)
    objectives = len(template.get("objectives") or [])
    max_depth = max(depths.values(), default=0)
    target_count = len(slots)

    factors = []
    probability = TARGET_COMPLETION_MULTIPLIER ** max(0, target_count - 1)
    factors.append({
        "name": f"required_targets:{target_count}",
        "multiplier": round(probability, 4),
    })
    if dependency_edges:
        value = DEPENDENCY_EDGE_MULTIPLIER ** dependency_edges
        probability *= value
        factors.append({
            "name": f"dependency_edges:{dependency_edges}",
            "multiplier": round(value, 4),
        })
    if objectives:
        value = OBJECTIVE_MULTIPLIER ** objectives
        probability *= value
        factors.append({
            "name": f"objectives:{objectives}",
            "multiplier": round(value, 4),
        })
    if roots > 1:
        value = PARALLEL_BRANCH_MULTIPLIER ** (roots - 1)
        probability *= value
        factors.append({
            "name": f"parallel_roots:{roots}",
            "multiplier": round(value, 4),
        })

    cost = (
        TARGET_COST * max(0, target_count - 1)
        + DEPENDENCY_EDGE_COST * dependency_edges
        + OBJECTIVE_COST * objectives
        + PARALLEL_BRANCH_COST * max(0, roots - 1)
        + DEPTH_ARCHITECTURE_COST * max_depth
    )
    return {
        "target_count": target_count,
        "dependency_edges": dependency_edges,
        "root_count": roots,
        "max_depth": max_depth,
        "objective_count": objectives,
        "success_multiplier": round(probability, 4),
        "cost_factor": round(min(1.0, cost), 3),
        "factors": factors,
        "depths": depths,
    }


def score_environment(
    template: dict,
    atom_profiles: list[dict],
    guides: dict[str, dict],
) -> dict:
    slots = template.get("injection_points") or []
    if len(slots) != len(atom_profiles):
        raise ValueError("one Atom is required for every injection point")
    architecture = architecture_profile(template)
    stages = [
        atom_slot_score(
            atom,
            guides.get(atom["cve_id"], {}),
            slot_id=slot["id"],
            depth=architecture["depths"][slot["id"]],
        )
        for slot, atom in zip(slots, atom_profiles, strict=True)
    ]
    success_probability = round(
        math.prod(item["success_probability"] for item in stages)
        * architecture["success_multiplier"],
        4,
    )
    stage_cost = sum(item["cost_factor"] for item in stages) / max(1, len(stages))
    cost_factor = round(min(1.0, stage_cost + architecture["cost_factor"]), 3)
    score = score_from_probability(success_probability, cost_factor)
    bottleneck = min(stages, key=lambda item: item["success_probability"])
    return {
        "template": template["name"],
        "cves": [item["cve_id"] for item in atom_profiles],
        "success_probability": success_probability,
        "cost_factor": cost_factor,
        "score": score,
        "label": label_for_score(score),
        "bottleneck": {
            "cve_id": bottleneck["cve_id"],
            "slot_id": bottleneck["slot_id"],
            "success_probability": bottleneck["success_probability"],
        },
        "architecture": architecture,
        "stages": stages,
    }


def load_atom_profile(atoms_dir: Path, cve_id: str) -> tuple[dict, dict]:
    atom_dir = atoms_dir / cve_id
    atom = yaml.safe_load((atom_dir / "atom.yaml").read_text(encoding="utf-8"))
    guide_path = atom_dir / ((atom.get("exploit_guide") or {}).get("path") or "exploit_guide.yaml")
    guide = yaml.safe_load(guide_path.read_text(encoding="utf-8")) if guide_path.is_file() else {}
    return atom, guide


def enumerate_candidates(
    templates_dir: Path,
    atoms_dir: Path,
    matrix_path: Path,
) -> list[dict]:
    loader = AtomLoader(str(atoms_dir))
    model_atoms = loader.load_all_completed()
    profiles = {}
    guides = {}
    for model in model_atoms:
        profiles[model.cve_id], guides[model.cve_id] = load_atom_profile(
            atoms_dir, model.cve_id
        )
    by_id = {item.cve_id: item for item in model_atoms}
    template_loader = TemplateLoader(str(templates_dir))
    candidates = []

    for template_name in ("dmz_simple", "dmz_dual"):
        model_template = template_loader.load(template_name)
        raw_template = yaml.safe_load(
            (templates_dir / template_name / "template.yaml").read_text(encoding="utf-8")
        )
        slot_candidates = [
            match_kill_chain(slot, model_atoms)
            for slot in model_template.injection_points
        ]
        for combination in itertools.product(*slot_candidates):
            ids = [item.cve_id for item in combination]
            if len(ids) != len(set(ids)):
                continue
            scored = score_environment(
                raw_template, [profiles[item] for item in ids], guides
            )
            scored["case_id"] = f"{template_name}-" + "-".join(
                item.removeprefix("CVE-") for item in ids
            )
            candidates.append(scored)

    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    raw_enterprise = yaml.safe_load(
        (templates_dir / "enterprise_3tier" / "template.yaml").read_text(encoding="utf-8")
    )
    for case in matrix["cases"]:
        ids = case["cves"]
        if not all(item in by_id for item in ids):
            continue
        scored = score_environment(
            raw_enterprise, [profiles[item] for item in ids], guides
        )
        scored["case_id"] = case["id"]
        candidates.append(scored)
    return candidates


def compact(item: dict) -> dict:
    return {
        "case_id": item["case_id"],
        "template": item["template"],
        "cves": item["cves"],
        "success_probability": item["success_probability"],
        "cost_factor": item["cost_factor"],
        "score": item["score"],
        "label": item["label"],
        "bottleneck": item["bottleneck"],
    }


def build_report(
    templates_dir: Path,
    atoms_dir: Path,
    matrix_path: Path,
    baseline_path: Path,
) -> dict:
    candidates = enumerate_candidates(templates_dir, atoms_dir, matrix_path)
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    canonical_ids = {item["cve_id"] for item in baseline["images"]}
    canonical = [
        item for item in candidates if set(item["cves"]).issubset(canonical_ids)
    ]
    distributions = {}
    for template in ("dmz_simple", "dmz_dual", "enterprise_3tier"):
        labels = Counter(
            item["label"] for item in candidates if item["template"] == template
        )
        distributions[template] = {
            "candidate_count": sum(labels.values()),
            "label_counts": dict(sorted(labels.items())),
        }
    anchors = {}
    for label, center in TIER_CENTERS.items():
        eligible = [item for item in canonical if item["label"] == label]
        anchors[label] = [
            compact(item)
            for item in sorted(
                eligible,
                key=lambda item: (abs(item["score"] - center), item["case_id"]),
            )[:8]
        ]
    return {
        "schema_version": 1,
        "method": "expert_prior_architecture_composition",
        "uses_historical_agent_results": False,
        "uses_difficulty_evaluator": False,
        "formula": "score = 80 * (1 - composed_success_probability) + 20 * composed_cost_factor",
        "components": {
            "atom": [
                "attack_method",
                "exploit_complexity",
                "authentication",
                "callback",
                "guided_step_count",
                "guided_command_coverage",
                "external_download",
                "material_transfer",
            ],
            "architecture": [
                "required_target_count",
                "dependency_edges",
                "maximum_dependency_depth",
                "parallel_roots",
                "business_objectives",
            ],
        },
        "candidate_distributions": distributions,
        "canonical_candidate_count": len(canonical),
        "canonical_tier_anchors": anchors,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--templates-dir", type=Path, default=ROOT / "templates")
    parser.add_argument("--atoms-dir", type=Path, default=ROOT / "data" / "atoms")
    parser.add_argument(
        "--matrix",
        type=Path,
        default=ROOT / "data" / "range_matrices" / "enterprise_3tier_hetero.json",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=ROOT / "data" / "runtime_baselines" / "canonical-runtime-2026-08-30.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "data" / "compositional_difficulty_analysis.json",
    )
    args = parser.parse_args()
    report = build_report(
        args.templates_dir, args.atoms_dir, args.matrix, args.baseline
    )
    args.output.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(args.output)


if __name__ == "__main__":
    main()
