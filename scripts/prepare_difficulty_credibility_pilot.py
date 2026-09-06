#!/usr/bin/env python3
"""Prepare an Atom-disjoint calibration/test manifest for difficulty research."""

from __future__ import annotations

import argparse
import importlib.util
import json
import random
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from clab_builder.evaluation.difficulty import sha256_file, write_report
from clab_builder.evaluation.kat import REQUIRED_KAT_CONTROLS
from clab_builder.evaluation.study import canonical_sha256, load_sealed_json

ROOT = Path(__file__).resolve().parents[1]
TIERS = ("easy", "medium", "hard", "very_hard")
TEMPLATE_NAMES = ("dmz_simple", "dmz_dual", "enterprise_3tier")

def _load_runtime_lock(
    root: Path, path: Path
) -> tuple[dict[str, str], dict[str, Any]]:
    resolved = path.resolve()
    relative = resolved.relative_to(root)
    payload, file_hash = load_sealed_json(
        resolved, seal_field="lock_sha256"
    )
    images = payload.get("images")
    if not isinstance(images, dict) or not images:
        raise ValueError("runtime image lock has no images")
    return {"path": relative.as_posix(), "sha256": file_hash}, payload


def _load_compositional_module(root: Path):
    path = root / "scripts" / "analyze_compositional_difficulty.py"
    spec = importlib.util.spec_from_file_location(
        "analyze_compositional_difficulty", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load compositional scorer: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _guide_steps(stage: dict[str, Any]) -> int:
    for factor in stage.get("factors") or []:
        name = str(factor.get("name") or "")
        if name.startswith("guide_steps:"):
            return int(name.split(":", 1)[1])
    return 0


def _case_baselines(candidate: dict[str, Any]) -> dict[str, Any]:
    architecture = candidate["architecture"]
    stages = candidate["stages"]
    stage_score_sum = sum(
        80.0 * (1.0 - float(stage["success_probability"]))
        + 20.0 * float(stage["cost_factor"])
        for stage in stages
    )
    return {
        "constant_success_probability": 0.5,
        "cve_count": len(candidate["cves"]),
        "target_count": int(architecture["target_count"]),
        "attack_path_depth": int(architecture["max_depth"]),
        "guide_step_count": sum(_guide_steps(stage) for stage in stages),
        "stage_score_sum": round(stage_score_sum, 3),
        # Current Atom artifacts do not contain a normalized CVSS field.
        # Keep the missing value explicit instead of silently inventing one.
        "mean_cvss": None,
    }


def _select_split(
    candidates: list[dict[str, Any]],
    *,
    quota_per_tier: int,
    rng: random.Random,
    max_atom_reuse: int,
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    selected_ids: set[str] = set()
    atom_counts: Counter[str] = Counter()
    template_counts: Counter[str] = Counter()
    for tier in reversed(TIERS):
        for _ in range(quota_per_tier):
            pool = [
                candidate
                for candidate in candidates
                if candidate["label"] == tier
                and candidate["case_id"] not in selected_ids
                and all(
                    atom_counts[atom] < max_atom_reuse
                    for atom in candidate["cves"]
                )
            ]
            if not pool:
                raise ValueError(f"cannot satisfy quota for tier {tier}")
            pool = sorted(pool, key=lambda item: item["case_id"])
            random_priority = {
                candidate["case_id"]: rng.random() for candidate in pool
            }
            candidate = min(
                pool,
                key=lambda item: (
                    template_counts[item["template"]],
                    sum(atom_counts[atom] for atom in item["cves"]),
                    -sum(atom_counts[atom] == 0 for atom in item["cves"]),
                    random_priority[item["case_id"]],
                    item["case_id"],
                ),
            )
            selected.append(candidate)
            selected_ids.add(candidate["case_id"])
            template_counts[candidate["template"]] += 1
            atom_counts.update(candidate["cves"])
    return sorted(
        selected,
        key=lambda item: (TIERS.index(item["label"]), item["case_id"]),
    )


def select_atom_disjoint_splits(
    candidates: list[dict[str, Any]],
    *,
    calibration_size: int,
    test_size: int,
    seed: int,
    max_atom_reuse: int = 2,
    max_partition_attempts: int = 10_000,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, list[str]]]:
    """Select tier-balanced splits whose Atom sets do not overlap."""
    if calibration_size % len(TIERS) or test_size % len(TIERS):
        raise ValueError("split sizes must be divisible by four tiers")
    atoms = sorted({atom for candidate in candidates for atom in candidate["cves"]})
    atom_sets = {
        candidate["case_id"]: frozenset(candidate["cves"])
        for candidate in candidates
    }
    if len(atoms) < 8:
        raise ValueError("too few distinct Atoms for an Atom-disjoint study")
    for attempt in range(max_partition_attempts):
        rng = random.Random(seed + attempt)
        shuffled = list(atoms)
        rng.shuffle(shuffled)
        midpoint = len(shuffled) // 2
        calibration_atoms = set(shuffled[:midpoint])
        test_atoms = set(shuffled[midpoint:])
        calibration_pool = [
            candidate
            for candidate in candidates
            if atom_sets[candidate["case_id"]].issubset(calibration_atoms)
        ]
        test_pool = [
            candidate
            for candidate in candidates
            if atom_sets[candidate["case_id"]].issubset(test_atoms)
        ]
        try:
            calibration = _select_split(
                calibration_pool,
                quota_per_tier=calibration_size // len(TIERS),
                rng=rng,
                max_atom_reuse=max_atom_reuse,
            )
            test = _select_split(
                test_pool,
                quota_per_tier=test_size // len(TIERS),
                rng=rng,
                max_atom_reuse=max_atom_reuse,
            )
        except ValueError:
            continue
        if (
            {item["template"] for item in calibration} == set(TEMPLATE_NAMES)
            and {item["template"] for item in test} == set(TEMPLATE_NAMES)
        ):
            return calibration, test, {
                "calibration": sorted(calibration_atoms),
                "test": sorted(test_atoms),
            }
    raise ValueError(
        "could not produce tier-balanced, template-covered, Atom-disjoint splits"
    )


def _split_summary(cases: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "case_count": len(cases),
        "tier_counts": dict(sorted(Counter(item["label"] for item in cases).items())),
        "template_counts": dict(
            sorted(Counter(item["template"] for item in cases).items())
        ),
        "distinct_atoms": len({atom for item in cases for atom in item["cves"]}),
        "atom_reuse": dict(
            sorted(Counter(atom for item in cases for atom in item["cves"]).items())
        ),
    }


def _compact_case(
    candidate: dict[str, Any],
    *,
    split: str,
    root: Path,
    hash_cache: dict[Path, str],
) -> dict[str, Any]:
    def cached_hash(path: Path) -> str:
        resolved = path.resolve()
        if resolved not in hash_cache:
            hash_cache[resolved] = sha256_file(resolved)
        return hash_cache[resolved]

    dependencies = {
        "template": {
            "path": f"templates/{candidate['template']}/template.yaml",
            "sha256": cached_hash(
                root / "templates" / candidate["template"] / "template.yaml"
            ),
        },
        "atoms": {},
    }
    for cve_id in candidate["cves"]:
        atom_dir = root / "data" / "atoms" / cve_id
        atom_path = atom_dir / "atom.yaml"
        guide_path = atom_dir / "exploit_guide.yaml"
        dependencies["atoms"][cve_id] = {
            "atom_yaml_sha256": cached_hash(atom_path),
            "guide_sha256": cached_hash(guide_path) if guide_path.is_file() else None,
        }
    return {
        "id": candidate["case_id"],
        "split": split,
        "template": candidate["template"],
        "cves": candidate["cves"],
        "predicted_success_probability": candidate["success_probability"],
        "predicted_cost_factor": candidate["cost_factor"],
        "predicted_score_v1": candidate["score"],
        "predicted_tier_v1": candidate["label"],
        "architecture": {
            key: candidate["architecture"][key]
            for key in (
                "target_count",
                "dependency_edges",
                "root_count",
                "max_depth",
                "objective_count",
            )
        },
        "baselines": _case_baselines(candidate),
        "eligibility": {
            "status": "pending_known_answer_tests",
            "required_controls": list(REQUIRED_KAT_CONTROLS),
        },
        "dependency_hashes": dependencies,
    }


def build_manifest(
    *,
    root: Path,
    matrix_path: Path,
    calibration_size: int,
    test_size: int,
    seed: int,
    max_atom_reuse: int,
    runtime_image_lock_path: Path | None = None,
) -> dict[str, Any]:
    scorer = _load_compositional_module(root)
    candidates = scorer.enumerate_candidates(
        root / "templates", root / "data" / "atoms", matrix_path
    )
    calibration, test, partitions = select_atom_disjoint_splits(
        candidates,
        calibration_size=calibration_size,
        test_size=test_size,
        seed=seed,
        max_atom_reuse=max_atom_reuse,
    )
    hash_cache: dict[Path, str] = {}
    cases = [
        *(
            _compact_case(
                candidate,
                split="calibration",
                root=root,
                hash_cache=hash_cache,
            )
            for candidate in calibration
        ),
        *(
            _compact_case(
                candidate, split="test", root=root, hash_cache=hash_cache
            )
            for candidate in test
        ),
    ]
    runtime_lock = None
    runtime_lock_payload = None
    if runtime_image_lock_path is not None:
        runtime_lock, runtime_lock_payload = _load_runtime_lock(
            root, runtime_image_lock_path
        )
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "status": "draft_prequalification",
        "claim": (
            "The frozen architecture-aware score predicts verifier-backed "
            "success probability on unseen Ranges and adds information beyond "
            "simple baselines under the registered protocol."
        ),
        "source": {
            "matrix": {
                "path": str(matrix_path.relative_to(root)).replace("\\", "/"),
                "sha256": sha256_file(matrix_path),
            },
            "scorer": {
                "path": "scripts/analyze_compositional_difficulty.py",
                "sha256": sha256_file(
                    root / "scripts" / "analyze_compositional_difficulty.py"
                ),
            },
            "uses_agent_results_for_selection": False,
            "uses_threshold_margin_for_selection": False,
            **({"runtime_image_lock": runtime_lock} if runtime_lock else {}),
        },
        "selection": {
            "strategy": "tier_stratified_random_atom_partition",
            "seed": seed,
            "calibration_size": calibration_size,
            "test_size": test_size,
            "max_atom_reuse_per_split": max_atom_reuse,
            "atom_disjoint": True,
            "template_coverage_required": list(TEMPLATE_NAMES),
            "tier_quota": {
                "calibration": {
                    tier: calibration_size // len(TIERS) for tier in TIERS
                },
                "test": {
                    tier: test_size // len(TIERS) for tier in TIERS
                },
            },
            "atom_partitions": partitions,
        },
        "protocol": {
            "primary_criterion": "verifier_backed_success_probability",
            "attempts_per_model": 3,
            "model_families": "to_be_frozen_before_execution",
            "agent_context": "guided",
            "max_turns": 30,
            "timeout_seconds": 1800,
            "test_outcomes_must_remain_unobserved_during_calibration": True,
            **(
                {
                    "prequalification_runtime_amendment": {
                        "lock_sha256": runtime_lock_payload.get("lock_sha256"),
                        "timing": "before_first_qualified_kat",
                        "agent_outcomes_observed": False,
                    }
                }
                if runtime_lock
                else {}
            ),
        },
        "baseline_availability": {
            "features_available": [
                "constant_success_probability",
                "cve_count",
                "target_count",
                "attack_path_depth",
                "guide_step_count",
                "stage_score_sum",
            ],
            "blocked": {
                "mean_cvss": (
                    "current completed Atom artifacts do not expose a normalized "
                    "CVSS field"
                )
            },
        },
        "split_summary": {
            "calibration": _split_summary(calibration),
            "test": _split_summary(test),
        },
        "cases": cases,
    }
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    return manifest


def _assert_recovery_matches_lock(
    *, cve_id: str, atom_path: Path, lock_record: dict[str, Any], lock: dict[str, Any]
) -> None:
    atom = yaml.safe_load(atom_path.read_text(encoding="utf-8-sig"))
    runtime = ((atom or {}).get("verification") or {}).get(
        "runtime_verification"
    ) or {}
    recovery = runtime.get("recovery") or {}
    expected = {
        "runtime_image_digest": lock_record.get("image_id"),
        "base_image_digest": lock_record.get("intermediate_image_id"),
        "recovery.lock_sha256": lock.get("lock_sha256"),
        "recovery.archive_file": lock_record.get("archive_file"),
        "recovery.archive_sha256": lock_record.get("archive_sha256"),
        "recovery.previous_base_image_digest": lock_record.get(
            "previous_base_image_digest"
        ),
        "recovery.previous_runtime_image_digest": lock_record.get(
            "previous_runtime_image_digest"
        ),
    }
    actual = {
        "runtime_image_digest": runtime.get("runtime_image_digest"),
        "base_image_digest": runtime.get("base_image_digest"),
        "recovery.lock_sha256": recovery.get("lock_sha256"),
        "recovery.archive_file": recovery.get("archive_file"),
        "recovery.archive_sha256": recovery.get("archive_sha256"),
        "recovery.previous_base_image_digest": recovery.get(
            "previous_base_image_digest"
        ),
        "recovery.previous_runtime_image_digest": recovery.get(
            "previous_runtime_image_digest"
        ),
    }
    mismatches = sorted(key for key, value in expected.items() if actual[key] != value)
    runtime_image = str(runtime.get("runtime_image") or "").removesuffix(":latest")
    lock_image = str(lock_record.get("image") or "").removesuffix(":latest")
    if runtime_image != lock_image:
        mismatches.append("runtime_image")
    if recovery.get("status") != "amended_prequalification":
        mismatches.append("recovery.status")
    if mismatches:
        raise ValueError(
            f"runtime recovery metadata mismatch for {cve_id}: "
            + ", ".join(mismatches)
        )


def amend_manifest_dependencies(
    manifest: dict[str, Any],
    *,
    root: Path,
    runtime_image_lock_path: Path,
) -> dict[str, Any]:
    """Reseal authorized runtime Atom changes without rerunning selection."""
    amended = json.loads(json.dumps(manifest))
    current_seal = str(amended.pop("manifest_sha256", ""))
    if not current_seal or canonical_sha256(amended) != current_seal:
        raise ValueError("existing manifest seal is invalid")
    existing_amendment = (
        (amended.get("protocol") or {}).get(
            "prequalification_runtime_amendment"
        )
        or {}
    )
    previous_seal = str(
        existing_amendment.get("amended_from_manifest_sha256") or current_seal
    )
    runtime_lock_record, runtime_lock = _load_runtime_lock(
        root, runtime_image_lock_path
    )
    authorized = runtime_lock["images"]
    source = amended.setdefault("source", {})
    source["runtime_image_lock"] = runtime_lock_record
    protocol = amended.setdefault("protocol", {})
    protocol["prequalification_runtime_amendment"] = {
        "lock_sha256": runtime_lock.get("lock_sha256"),
        "timing": "before_first_qualified_kat",
        "agent_outcomes_observed": False,
        "amended_from_manifest_sha256": previous_seal,
        "selection_preserved": True,
    }
    hash_cache: dict[Path, str] = {}

    def current_hash(path: Path) -> str:
        resolved = path.resolve()
        if resolved not in hash_cache:
            resolved.relative_to(root)
            hash_cache[resolved] = sha256_file(resolved)
        return hash_cache[resolved]

    for case in amended.get("cases") or []:
        dependencies = case.get("dependency_hashes") or {}
        template = dependencies.get("template") or {}
        template_path = root / str(template.get("path") or "")
        if current_hash(template_path) != template.get("sha256"):
            raise ValueError("unrelated template drift during runtime amendment")
        for cve_id, atom in (dependencies.get("atoms") or {}).items():
            atom_dir = root / "data" / "atoms" / cve_id
            atom_path = atom_dir / "atom.yaml"
            atom_hash = current_hash(atom_path)
            guide_path = atom_dir / "exploit_guide.yaml"
            guide_hash = current_hash(guide_path) if guide_path.is_file() else None
            if guide_hash != atom.get("guide_sha256"):
                raise ValueError(
                    f"unrelated guide drift during runtime amendment: {cve_id}"
                )
            if cve_id in authorized:
                _assert_recovery_matches_lock(
                    cve_id=cve_id,
                    atom_path=atom_path,
                    lock_record=authorized[cve_id],
                    lock=runtime_lock,
                )
                atom["atom_yaml_sha256"] = atom_hash
            elif atom_hash != atom.get("atom_yaml_sha256"):
                raise ValueError(
                    f"unrelated Atom drift during runtime amendment: {cve_id}"
                )
    amended["manifest_sha256"] = canonical_sha256(amended)
    return amended


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--matrix",
        type=Path,
        default=ROOT / "data" / "range_matrices" / "enterprise_3tier_hetero.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "data" / "difficulty_credibility_pilot_manifest.json",
    )
    parser.add_argument("--calibration-size", type=int, default=12)
    parser.add_argument("--test-size", type=int, default=12)
    parser.add_argument("--seed", type=int, default=20260903)
    parser.add_argument("--max-atom-reuse", type=int, default=2)
    parser.add_argument(
        "--runtime-image-lock",
        type=Path,
        default=ROOT / "data" / "difficulty_runtime_image_lock_2026-09-06.json",
    )
    parser.add_argument(
        "--amend-existing-manifest",
        type=Path,
        help="preserve frozen cases and refresh dependency hashes only",
    )
    args = parser.parse_args()
    if args.amend_existing_manifest:
        existing = json.loads(
            args.amend_existing_manifest.read_text(encoding="utf-8-sig")
        )
        manifest = amend_manifest_dependencies(
            existing,
            root=ROOT,
            runtime_image_lock_path=args.runtime_image_lock,
        )
    else:
        manifest = build_manifest(
            root=ROOT,
            matrix_path=args.matrix.resolve(),
            calibration_size=args.calibration_size,
            test_size=args.test_size,
            seed=args.seed,
            max_atom_reuse=args.max_atom_reuse,
            runtime_image_lock_path=args.runtime_image_lock,
        )
    write_report(args.output, manifest)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
