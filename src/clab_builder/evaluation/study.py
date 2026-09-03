"""Frozen study plans and evidence collection for difficulty experiments."""

from __future__ import annotations

import hashlib
import json
import random
import re
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from .difficulty import sha256_file, verifier_backed_success
from .kat import assess_case_kat


def _canonical_sha256(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def manifest_integrity(manifest: Mapping[str, Any], repo_root: str | Path) -> dict[str, Any]:
    """Verify the manifest seal and every dependency hash it freezes."""
    body = dict(manifest)
    claimed = str(body.pop("manifest_sha256", ""))
    failures: list[str] = []
    if not claimed or _canonical_sha256(body) != claimed:
        failures.append("manifest_sha256")

    root = Path(repo_root).resolve()

    def check(relative: Any, expected: Any, label: str) -> None:
        if not isinstance(relative, str) or not isinstance(expected, str):
            failures.append(label)
            return
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError:
            failures.append(label)
            return
        if not path.is_file() or sha256_file(path) != expected.lower():
            failures.append(label)

    source = manifest.get("source") or {}
    for name in ("matrix", "scorer"):
        record = source.get(name) or {}
        check(record.get("path"), record.get("sha256"), f"source.{name}")
    for case in manifest.get("cases") or []:
        case_id = str(case.get("id") or "")
        dependencies = case.get("dependency_hashes") or {}
        template = dependencies.get("template") or {}
        check(
            template.get("path"),
            template.get("sha256"),
            f"case.{case_id}.template",
        )
        for cve_id, atom in (dependencies.get("atoms") or {}).items():
            check(
                f"data/atoms/{cve_id}/atom.yaml",
                atom.get("atom_yaml_sha256"),
                f"case.{case_id}.atom.{cve_id}",
            )
            guide_hash = atom.get("guide_sha256")
            if guide_hash is not None:
                check(
                    f"data/atoms/{cve_id}/exploit_guide.yaml",
                    guide_hash,
                    f"case.{case_id}.guide.{cve_id}",
                )
    return {
        "valid": not failures,
        "failed_dependencies": sorted(failures),
    }


def assess_manifest_qualification(
    manifest: Mapping[str, Any],
    *,
    manifest_path: str | Path,
    evidence_dir: str | Path,
    repo_root: str | Path,
) -> dict[str, Any]:
    """Assess one evidence bundle per selected case without running controls."""
    manifest_file = Path(manifest_path).resolve()
    evidence_root = Path(evidence_dir).resolve()
    integrity = manifest_integrity(manifest, repo_root)
    assessments = []
    for case in manifest.get("cases") or []:
        case_id = str(case.get("id") or "")
        evidence_path = evidence_root / f"{case_id}.json"
        if not evidence_path.is_file():
            assessment = {
                "eligible": False,
                "missing_controls": list(
                    case.get("eligibility", {}).get("required_controls") or []
                ),
                "failed_checks": ["evidence_file_missing"],
                "checks": {},
            }
            evidence_hash = None
        else:
            try:
                payload = json.loads(
                    evidence_path.read_text(encoding="utf-8-sig")
                )
            except (OSError, json.JSONDecodeError):
                payload = {}
            controls = payload.get("controls") if isinstance(payload, Mapping) else None
            if not isinstance(controls, Mapping):
                controls = payload if isinstance(payload, Mapping) else {}
            assessment = assess_case_kat(
                controls,
                artifact_root=evidence_path.parent,
                case_id=case_id,
            )
            evidence_hash = sha256_file(evidence_path)
        assessments.append({
            "case_id": case_id,
            "split": case.get("split"),
            "eligible": bool(assessment["eligible"] and integrity["valid"]),
            "evidence_path": str(evidence_path),
            "evidence_sha256": evidence_hash,
            "assessment": assessment,
        })
    eligible = sum(item["eligible"] for item in assessments)
    report = {
        "schema_version": 1,
        "status": "qualified" if eligible == len(assessments) and assessments else "blocked",
        "source_manifest": {
            "path": str(manifest_file),
            "file_sha256": sha256_file(manifest_file),
            "manifest_sha256": manifest.get("manifest_sha256"),
        },
        "dependency_integrity": integrity,
        "summary": {
            "total_cases": len(assessments),
            "eligible_cases": eligible,
            "blocked_cases": len(assessments) - eligible,
        },
        "cases": assessments,
    }
    report["qualification_sha256"] = _canonical_sha256(report)
    return report


def _validate_models(models: list[dict[str, Any]]) -> None:
    if not models:
        raise ValueError("at least one model is required")
    ids = [str(model.get("id") or "") for model in models]
    families = [str(model.get("family") or "") for model in models]
    if any(not value for value in ids + families):
        raise ValueError("every model requires non-empty id and family")
    if len(ids) != len(set(ids)):
        raise ValueError("model ids must be unique")
    if len(set(families)) < 3:
        raise ValueError("formal study requires at least three model families")
    if len(families) != len(set(families)):
        raise ValueError("formal study permits one frozen model per family")
    forbidden = {"api_key", "token", "password", "secret"}
    if any(forbidden.intersection(model) for model in models):
        raise ValueError("model registry must not contain credentials")


def build_frozen_run_plan(
    manifest: Mapping[str, Any],
    qualification: Mapping[str, Any],
    models: list[dict[str, Any]],
    *,
    repo_root: str | Path,
    manifest_path: str | Path,
    qualification_path: str | Path,
    attempts_per_model: int,
    seed: int,
) -> dict[str, Any]:
    """Build a calibration-first, randomized-within-phase formal trial plan."""
    _validate_models(models)
    if attempts_per_model < 1:
        raise ValueError("attempts_per_model must be positive")
    if qualification.get("status") != "qualified":
        raise ValueError("all cases must pass qualification before freezing")
    qualification_body = dict(qualification)
    qualification_seal = qualification_body.pop("qualification_sha256", "")
    if _canonical_sha256(qualification_body) != qualification_seal:
        raise ValueError("qualification report hash is invalid")
    if not manifest_integrity(manifest, repo_root)["valid"]:
        raise ValueError("manifest dependencies changed after qualification")
    manifest_file = Path(manifest_path).resolve()
    qualification_file = Path(qualification_path).resolve()
    if qualification.get("source_manifest", {}).get("file_sha256") != sha256_file(
        manifest_file
    ):
        raise ValueError("qualification is not bound to this manifest file")
    eligibility = {
        item.get("case_id"): item.get("eligible")
        for item in qualification.get("cases") or []
    }
    cases = list(manifest.get("cases") or [])
    if any(not eligibility.get(case.get("id")) for case in cases):
        raise ValueError("qualification does not approve every selected case")
    for item in qualification.get("cases") or []:
        evidence_path = Path(item["evidence_path"])
        if (
            not evidence_path.is_file()
            or sha256_file(evidence_path) != item.get("evidence_sha256")
        ):
            raise ValueError("KAT evidence changed after qualification")
        evidence = json.loads(evidence_path.read_text(encoding="utf-8-sig"))
        controls = evidence.get("controls") if isinstance(evidence, Mapping) else None
        reassessed = assess_case_kat(
            controls if isinstance(controls, Mapping) else {},
            artifact_root=evidence_path.parent,
            case_id=str(item.get("case_id") or ""),
        )
        if not reassessed["eligible"]:
            raise ValueError("KAT artifacts changed after qualification")

    rng = random.Random(seed)
    trials = []
    for phase_index, split in enumerate(("calibration", "test"), start=1):
        phase_trials = []
        for case in cases:
            if case.get("split") != split:
                continue
            for model in models:
                for attempt in range(1, attempts_per_model + 1):
                    model_id = str(model["id"])
                    model_slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", model_id)
                    model_slug += f"-{hashlib.sha256(model_id.encode()).hexdigest()[:8]}"
                    trial_id = f"{case['id']}--{model_slug}--a{attempt}"
                    phase_trials.append({
                        "trial_id": trial_id,
                        "result_file": f"{trial_id}.json",
                        "phase": phase_index,
                        "split": split,
                        "case_id": case["id"],
                        "model_id": model["id"],
                        "model_family": model["family"],
                        "runner": model.get("runner", "openai"),
                        "base_url_label": model.get("base_url_label", ""),
                        "attempt": attempt,
                        "agent_context": manifest.get("protocol", {}).get(
                            "agent_context"
                        ),
                        "max_turns": manifest.get("protocol", {}).get("max_turns"),
                        "timeout_seconds": manifest.get("protocol", {}).get(
                            "timeout_seconds"
                        ),
                        "case_dependency_sha256": _canonical_sha256(
                            case.get("dependency_hashes") or {}
                        ),
                    })
        rng.shuffle(phase_trials)
        trials.extend(phase_trials)
    for sequence, trial in enumerate(trials, start=1):
        trial["sequence"] = sequence

    plan: dict[str, Any] = {
        "schema_version": 1,
        "status": "frozen_ready",
        "seed": seed,
        "phase_order": ["calibration", "test"],
        "test_outcomes_hidden_until_calibration_complete": True,
        "sources": {
            "pilot_manifest": {
                "path": str(manifest_file),
                "sha256": sha256_file(manifest_file),
            },
            "qualification": {
                "path": str(qualification_file),
                "sha256": sha256_file(qualification_file),
            },
        },
        "protocol": {
            **dict(manifest.get("protocol") or {}),
            "attempts_per_model": attempts_per_model,
            "model_families": sorted({model["family"] for model in models}),
        },
        "execution_contract": {
            "one_independently_reset_environment_per_trial": True,
            "result_required_fields": [
                "trial_id",
                "case_id",
                "model_id",
                "model_family",
                "attempt",
                "sequence",
                "split",
                "plan_sha256",
                "status",
                "verifier",
            ],
            "verifier_required_fields": [
                "agent_evaluated",
                "environment_success",
                "agent_success",
                "objective_achieved",
            ],
        },
        "models": models,
        "cases": [
            {
                key: case.get(key)
                for key in (
                    "id",
                    "split",
                    "template",
                    "cves",
                    "predicted_success_probability",
                    "predicted_cost_factor",
                    "predicted_score_v1",
                    "predicted_tier_v1",
                    "baselines",
                    "dependency_hashes",
                )
            }
            for case in cases
        ],
        "summary": {
            "case_count": len(cases),
            "model_count": len(models),
            "model_family_count": len({model["family"] for model in models}),
            "attempts_per_model": attempts_per_model,
            "trial_count": len(trials),
            "trials_by_split": dict(
                sorted(Counter(trial["split"] for trial in trials).items())
            ),
        },
        "trials": trials,
    }
    plan["plan_sha256"] = _canonical_sha256(plan)
    return plan


def collect_trial_outcomes(
    plan: Mapping[str, Any],
    *,
    results_dir: str | Path,
    split: str,
) -> dict[str, Any]:
    """Collect run artifacts into analyzer-ready, verifier-backed outcomes."""
    if split not in {"calibration", "test"}:
        raise ValueError("split must be calibration or test")
    body = dict(plan)
    claimed = body.pop("plan_sha256", "")
    if _canonical_sha256(body) != claimed:
        raise ValueError("run plan hash is invalid")
    root = Path(results_dir).resolve()
    selected = [trial for trial in plan.get("trials") or [] if trial.get("split") == split]
    grouped: dict[str, list[dict[str, Any]]] = {}
    missing = []
    invalid = Counter()
    artifact_records = []
    for trial in selected:
        path = (root / trial["result_file"]).resolve()
        try:
            path.relative_to(root)
        except ValueError:
            invalid["invalid_result_path"] += 1
            continue
        if not path.is_file():
            missing.append(trial["trial_id"])
            continue
        try:
            result = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            invalid["invalid_result_json"] += 1
            artifact_records.append({
                "trial_id": trial["trial_id"],
                "path": str(path),
                "sha256": sha256_file(path),
                "valid": False,
            })
            continue
        bound_fields = (
            "trial_id",
            "case_id",
            "model_id",
            "model_family",
            "attempt",
            "sequence",
            "split",
            "runner",
            "agent_context",
            "max_turns",
            "timeout_seconds",
            "case_dependency_sha256",
        )
        bound = (
            isinstance(result, Mapping)
            and result.get("plan_sha256") == claimed
            and all(result.get(key) == trial[key] for key in bound_fields)
        )
        verifier = result.get("verifier") or {}
        complete_verifier = (
            isinstance(verifier, Mapping)
            and verifier.get("agent_evaluated") is True
            and all(
                isinstance(verifier.get(key), bool)
                for key in (
                    "environment_success",
                    "agent_success",
                    "objective_achieved",
                )
            )
        )
        valid = result.get("status") == "valid" and bound and complete_verifier
        valid = valid and verifier.get("environment_success") is True
        artifact_records.append({
            "trial_id": trial["trial_id"],
            "path": str(path),
            "sha256": sha256_file(path),
            "valid": valid,
        })
        if not valid:
            reason = (
                "invalid_result_binding"
                if not bound
                else "invalid_result_contract"
                if not complete_verifier
                else "invalid_environment"
                if verifier.get("environment_success") is not True
                else "invalid_result_contract"
                if result.get("status") == "valid"
                else str(result.get("status") or "invalid_unspecified")
            )
            invalid[reason] += 1
            continue
        grouped.setdefault(trial["case_id"], []).append({
            "model_id": trial["model_id"],
            "model_family": trial["model_family"],
            "attempt": trial["attempt"],
            "success": verifier_backed_success(verifier),
        })

    case_lookup = {
        case["id"]: case
        for case in plan.get("cases", [])
        if isinstance(case, Mapping) and case.get("id")
    }
    if not case_lookup:
        source_path = Path(plan["sources"]["pilot_manifest"]["path"])
        manifest = json.loads(source_path.read_text(encoding="utf-8-sig"))
        case_lookup = {case["id"]: case for case in manifest.get("cases") or []}
    cases = []
    for case_id in sorted({trial["case_id"] for trial in selected}):
        source = case_lookup[case_id]
        cases.append({
            "id": case_id,
            "split": split,
            "predicted_success_probability": source[
                "predicted_success_probability"
            ],
            "baselines": source.get("baselines") or {},
            "outcomes": grouped.get(case_id, []),
        })
    return {
        "schema_version": 1,
        "split": split,
        "complete": not missing and not invalid,
        "plan_sha256": claimed,
        "summary": {
            "expected_trials": len(selected),
            "valid_trials": sum(len(values) for values in grouped.values()),
            "invalid_trials": sum(invalid.values()),
            "missing_trials": len(missing),
            "invalid_reasons": dict(sorted(invalid.items())),
        },
        "missing_trial_ids": missing,
        "artifacts": artifact_records,
        "cases": cases,
    }
