#!/usr/bin/env python3
"""Generate verifier-backed KAT evidence without invoking an LLM."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from clab_builder.evaluation.difficulty import (
    sha256_file,
    verifier_backed_success,
    write_report,
)
from clab_builder.evaluation.kat import assess_case_kat
from clab_builder.evaluation.study import canonical_sha256, manifest_integrity
from clab_builder.orchestrator.composer.scenario import ScenarioPipeline
from clab_builder.orchestrator.composer.verifier import ScenarioVerifier


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise TypeError(f"expected JSON object: {path}")
    return payload


def _write_artifact(
    path: Path,
    *,
    case_id: str,
    control: str,
    bindings: Mapping[str, Any],
    result: Mapping[str, Any],
    details: Mapping[str, Any] | None = None,
) -> None:
    payload: dict[str, Any] = {
        "schema_version": 1,
        "case_id": case_id,
        "control": control,
        "bindings": dict(bindings),
        "result": dict(result),
    }
    if details:
        payload["details"] = dict(details)
    write_report(path, payload)


def _artifact_reference(path: Path, evidence_root: Path) -> dict[str, str]:
    return {
        "artifact_path": path.resolve().relative_to(evidence_root.resolve()).as_posix(),
        "artifact_sha256": sha256_file(path),
    }


def _identity_map(ground_truth: Mapping[str, Any]) -> dict[str, Any]:
    nodes: dict[str, dict[str, str]] = {}
    for step in ground_truth.get("attack_path") or []:
        node = str(step.get("target_node") or "")
        if node:
            nodes[node] = {"node_name": node, "ip": str(step.get("target_ip") or "")}
    for objective in ground_truth.get("objectives") or []:
        for key in ("actor_node", "target_node"):
            node = str(objective.get(key) or "")
            if node:
                nodes.setdefault(node, {"node_name": node})
    nodes.setdefault("attacker", {"node_name": "attacker"})
    return {"nodes": nodes}


def _objective_results(
    objectives: list[dict[str, Any]], *, mode: str
) -> dict[str, Any]:
    reported: dict[str, Any] = {}
    if mode == "no_op":
        return reported
    for objective in objectives:
        objective_id = str(
            objective.get("id")
            or f"{objective.get('asset', '')}-{objective.get('validation', '')}"
        )
        evidence_field = str(objective.get("evidence_field") or "evidence")
        pattern = str(objective.get("success_pattern") or "")
        evidence = (
            pattern
            if mode in {"oracle", "partial_solution"}
            else "KAT_WRONG_EVIDENCE"
        )
        reported[objective_id] = {
            "achieved": True,
            "actor_node": str(objective.get("actor_node") or ""),
            "target_node": str(objective.get("target_node") or ""),
            evidence_field: evidence,
        }
    return reported


def _write_execution_session(
    scenario_dir: Path,
    objectives: list[dict[str, Any]],
    *,
    mode: str,
) -> Path:
    patterns = [
        str(objective.get("success_pattern") or "")
        for objective in objectives
        if objective.get("success_pattern")
    ]
    if mode not in {"oracle", "partial_solution"}:
        patterns = ["KAT_WRONG_EXECUTION_WITNESS"] if mode == "wrong_evidence" else []
    event = (
        {"type": "tool_result", "result": "\n".join(patterns)}
        if patterns
        else {}
    )
    path = scenario_dir / "agent_workspace" / "session.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    write_report(path, event)
    return path


def _agent_input(
    ground_truth: Mapping[str, Any], *, mode: str
) -> dict[str, Any]:
    steps = list(ground_truth.get("attack_path") or [])
    flags: dict[str, str] = {}
    objectives = list(ground_truth.get("objectives") or [])
    if mode == "oracle" or (mode == "wrong_evidence" and objectives):
        flags = {
            str(step["target_node"]): str(step["flag"])
            for step in steps
        }
    elif mode == "wrong_evidence":
        flags = {
            str(step["target_node"]): f"KAT_WRONG_{index}"
            for index, step in enumerate(steps, start=1)
        }
    elif mode == "partial_solution" and steps:
        if len(steps) > 1:
            flags = {
                str(step["target_node"]): str(step["flag"])
                for step in steps[:-1]
            }
        else:
            flag = str(steps[0].get("flag") or "")
            flags[str(steps[0]["target_node"])] = flag[:-1] if flag else "partial"
    return {
        "verified_flags": flags,
        "objective_results": _objective_results(objectives, mode=mode),
    }


def _evaluate_input(
    verifier: ScenarioVerifier,
    ground_truth: Mapping[str, Any],
    scenario_dir: Path,
    *,
    mode: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    objectives = list(ground_truth.get("objectives") or [])
    agent_input = _agent_input(ground_truth, mode=mode)
    session_path = _write_execution_session(scenario_dir, objectives, mode=mode)
    witnesses = verifier.load_agent_execution_witness(scenario_dir, objectives)
    identity_map = _identity_map(ground_truth)
    flags = verifier.verify_flags(agent_input, dict(ground_truth), identity_map)
    objective_verification = verifier.verify_objectives(
        agent_input,
        objectives,
        target_ips={
            str(step.get("target_node") or ""): str(step.get("target_ip") or "")
            for step in ground_truth.get("attack_path") or []
        },
        identity_map=identity_map,
        execution_witness=witnesses,
    )
    result = {
        "environment_success": True,
        "agent_success": bool(flags["all_captured"]),
        "objective_achieved": bool(objective_verification["all_satisfied"]),
        "objective_control_applicable": bool(objectives),
    }
    return result, {
        "input": agent_input,
        "flag_verification": flags,
        "objective_verification": objective_verification,
        "execution_witness": witnesses,
        "execution_session_sha256": sha256_file(session_path),
    }


def _copy_case_atoms(case: Mapping[str, Any], destination: Path) -> None:
    atom_ids = list(
        ((case.get("dependency_hashes") or {}).get("atoms") or {}).keys()
    ) or [str(value) for value in case.get("cves") or []]
    for atom_id in atom_ids:
        source = ROOT / "data" / "atoms" / str(atom_id)
        if not source.is_dir():
            raise FileNotFoundError(f"frozen Atom directory missing: {source}")
        shutil.copytree(source, destination / str(atom_id))


def _remove_existing_case(
    evidence_path: Path,
    artifact_dir: Path,
    scenario_dir: Path,
    atom_dir: Path,
) -> None:
    if scenario_dir.exists():
        verify_result = scenario_dir / "verify_result.json"
        execution_complete = False
        if verify_result.is_file():
            try:
                execution_complete = (
                    _load_json(verify_result).get("execution_complete") is True
                )
            except (OSError, UnicodeError, json.JSONDecodeError, TypeError):
                execution_complete = False
        if not execution_complete:
            raise FileExistsError(
                f"retained scenario requires manual cleanup: {scenario_dir}"
            )
        shutil.rmtree(scenario_dir)
    if atom_dir.exists():
        shutil.rmtree(atom_dir)
    if artifact_dir.exists():
        shutil.rmtree(artifact_dir)
    if evidence_path.exists():
        evidence_path.unlink()


def _case_paths(
    case_id: str, evidence_root: Path, work_root: Path
) -> tuple[Path, Path, Path]:
    return (
        evidence_root / f"{case_id}.json",
        evidence_root / case_id,
        work_root / case_id,
    )


def run_case(
    case: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    evidence_root: Path,
    work_root: Path,
    force: bool = False,
    keep_scenario: bool = False,
    rebuild_missing_runtime_images: bool = False,
    pipeline: ScenarioPipeline | None = None,
) -> dict[str, Any]:
    case_id = str(case.get("id") or "")
    if not case_id:
        raise ValueError("case requires a non-empty id")
    evidence_path, artifact_dir, scenario_dir = _case_paths(
        case_id, evidence_root, work_root
    )
    atom_dir = work_root / ".kat_atoms" / case_id
    existing = (evidence_path, artifact_dir, scenario_dir, atom_dir)
    if any(path.exists() for path in existing):
        if not force:
            raise FileExistsError(f"case artifacts already exist: {case_id}")
        _remove_existing_case(evidence_path, artifact_dir, scenario_dir, atom_dir)

    evidence_root.mkdir(parents=True, exist_ok=True)
    work_root.mkdir(parents=True, exist_ok=True)
    artifact_dir.mkdir(parents=True)
    verifier_started = False
    execution_complete = False
    try:
        atoms_dir = ROOT / "data" / "atoms"
        if rebuild_missing_runtime_images:
            _copy_case_atoms(case, atom_dir)
            atoms_dir = atom_dir
        generator = pipeline or ScenarioPipeline(
            templates_dir=str(ROOT / "templates"),
            atoms_dir=str(atoms_dir),
        )
        generator.generate(
            template_name=str(case["template"]),
            cve_ids=[str(value) for value in case.get("cves") or []],
            scenario_name=case_id,
            output_dir=str(work_root),
            seed=int(manifest.get("selection", {}).get("seed", 0)),
            validation_mode="guided_agent",
            agent_context=str(
                manifest.get("protocol", {}).get("agent_context") or "guided"
            ),
        )
        if not scenario_dir.is_dir():
            raise RuntimeError(f"scenario generation did not create {scenario_dir}")

        ground_truth_path = scenario_dir / "ground_truth.json"
        scenario_manifest_path = scenario_dir / "scenario.yaml"
        ground_truth = _load_json(ground_truth_path)
        bindings = {
            "manifest_sha256": str(manifest.get("manifest_sha256") or ""),
            "case_dependency_sha256": canonical_sha256(
                case.get("dependency_hashes") or {}
            ),
            "ground_truth_sha256": sha256_file(ground_truth_path),
            "scenario_manifest_sha256": sha256_file(scenario_manifest_path),
        }
        verifier = ScenarioVerifier(
            max_turns=int(manifest.get("protocol", {}).get("max_turns") or 30),
            agent_timeout=int(
                manifest.get("protocol", {}).get("timeout_seconds") or 1800
            ),
            require_agent_success=False,
            atoms_dir=str(atoms_dir),
            validation_mode="guided_agent",
        )

        runtime_preparation = None
        verifier_started = True
        if rebuild_missing_runtime_images:
            runtime_preparation = verifier.prepare_runtime_images(
                str(scenario_dir), runtime_policy="rebuild_missing"
            )
        verifier.run_full(
            scenario_dir=str(scenario_dir),
            api_key="",
            environment_only=True,
            agent_context=str(
                manifest.get("protocol", {}).get("agent_context") or "guided"
            ),
        )
        verify_result_path = scenario_dir / "verify_result.json"
        live = _load_json(verify_result_path)
        execution_complete = live.get("execution_complete") is True
        qualification_result = {
            "environment_success": live.get("environment_success") is True,
            "attack_graph_valid": live.get("attack_graph_valid") is True,
            "attack_path_reachable": live.get("attack_path_reachable") is True,
            "execution_complete": execution_complete,
        }
        qualification_path = artifact_dir / "qualification.json"
        _write_artifact(
            qualification_path,
            case_id=case_id,
            control="qualification",
            bindings=bindings,
            result=qualification_result,
            details={
                "verify_result_sha256": sha256_file(verify_result_path),
                "verify_result": live,
                "runtime_preparation": runtime_preparation,
            },
        )
        controls: dict[str, Any] = {
            "qualification": _artifact_reference(qualification_path, evidence_root)
        }
        if not all(qualification_result.values()):
            write_report(
                evidence_path,
                {
                    "schema_version": 1,
                    "case_id": case_id,
                    "split": case.get("split"),
                    "bindings": bindings,
                    "controls": controls,
                },
            )
            assessment = assess_case_kat(
                controls,
                artifact_root=evidence_root,
                case_id=case_id,
                expected_bindings=bindings,
            )
            return {
                "case_id": case_id,
                "status": "blocked_environment",
                "assessment": assessment,
                "qualification": qualification_result,
            }

        for control_name in (
            "oracle",
            "no_op",
            "partial_solution",
            "wrong_evidence",
        ):
            result, details = _evaluate_input(
                verifier, ground_truth, scenario_dir, mode=control_name
            )
            path = artifact_dir / f"{control_name}.json"
            _write_artifact(
                path,
                case_id=case_id,
                control=control_name,
                bindings=bindings,
                result=result,
                details=details,
            )
            controls[control_name] = _artifact_reference(path, evidence_root)

        pre_agent_verification = live.get("pre_agent_objective_verification") or {}
        pre_agent_result = {
            "environment_success": True,
            "agent_success": False,
            "objective_achieved": pre_agent_verification.get("all_satisfied") is True,
            "objective_control_applicable": bool(
                ground_truth.get("objectives") or []
            ),
        }
        pre_agent_path = artifact_dir / "pre_agent.json"
        _write_artifact(
            pre_agent_path,
            case_id=case_id,
            control="pre_agent",
            bindings=bindings,
            result=pre_agent_result,
            details={
                "source": "production_environment_only_verifier",
                "objective_verification": pre_agent_verification,
                "verify_result_sha256": sha256_file(verify_result_path),
            },
        )
        controls["pre_agent"] = _artifact_reference(pre_agent_path, evidence_root)

        terminal_state = {
            **bindings,
            "qualification_sha256": sha256_file(qualification_path),
        }
        terminal_state_sha256 = canonical_sha256(terminal_state)
        repeats = []
        for number in (1, 2):
            result, details = _evaluate_input(
                verifier, ground_truth, scenario_dir, mode="oracle"
            )
            verdict = verifier_backed_success(result)
            path = artifact_dir / f"repeat_verdicts_{number}.json"
            payload = {
                "schema_version": 1,
                "case_id": case_id,
                "control": "repeat_verdicts",
                "bindings": bindings,
                "terminal_state_sha256": terminal_state_sha256,
                "verdict": verdict,
                "result": result,
                "details": {"terminal_state": terminal_state, **details},
            }
            write_report(path, payload)
            reference = _artifact_reference(path, evidence_root)
            reference.update(
                {
                    "terminal_state_sha256": terminal_state_sha256,
                    "verdict": verdict,
                }
            )
            repeats.append(reference)
        controls["repeat_verdicts"] = repeats

        write_report(
            evidence_path,
            {
                "schema_version": 1,
                "case_id": case_id,
                "split": case.get("split"),
                "bindings": bindings,
                "controls": controls,
            },
        )
        assessment = assess_case_kat(
            controls,
            artifact_root=evidence_root,
            case_id=case_id,
            expected_bindings=bindings,
        )
        return {
            "case_id": case_id,
            "status": "qualified" if assessment["eligible"] else "blocked_controls",
            "assessment": assessment,
            "qualification": qualification_result,
            "evidence_sha256": sha256_file(evidence_path),
        }
    finally:
        if not keep_scenario and (not verifier_started or execution_complete):
            if scenario_dir.exists():
                shutil.rmtree(scenario_dir)
            if atom_dir.exists():
                shutil.rmtree(atom_dir)
        if not verifier_started:
            if artifact_dir.exists():
                shutil.rmtree(artifact_dir)
            if evidence_path.exists():
                evidence_path.unlink()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--split", choices=("calibration", "test", "all"), default="calibration")
    parser.add_argument("--case-id", action="append", default=[])
    parser.add_argument("--max-cases", type=int, default=0)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--keep-scenarios", action="store_true")
    parser.add_argument("--rebuild-missing-runtime-images", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    manifest_path = args.manifest.resolve()
    manifest = _load_json(manifest_path)
    integrity = manifest_integrity(manifest, ROOT)
    if not integrity["valid"]:
        raise SystemExit(
            "manifest dependency integrity failed: "
            + ", ".join(integrity["failed_dependencies"])
        )
    selected = [
        case for case in manifest.get("cases") or []
        if (args.split == "all" or case.get("split") == args.split)
        and (not args.case_id or case.get("id") in set(args.case_id))
    ]
    if args.max_cases:
        selected = selected[: args.max_cases]
    if not selected:
        raise SystemExit("no cases selected")
    pipeline = ScenarioPipeline(
        templates_dir=str(ROOT / "templates"),
        atoms_dir=str(ROOT / "data" / "atoms"),
    )
    results = []
    for case in selected:
        try:
            result = run_case(
                case,
                manifest=manifest,
                evidence_root=args.evidence_dir.resolve(),
                work_root=args.work_dir.resolve(),
                force=args.force,
                keep_scenario=args.keep_scenarios,
                rebuild_missing_runtime_images=args.rebuild_missing_runtime_images,
                pipeline=pipeline,
            )
        except Exception as exc:  # noqa: BLE001
            result = {
                "case_id": case.get("id"),
                "status": "runner_error",
                "error_type": type(exc).__name__,
                "error": str(exc),
            }
        results.append(result)
        print(f"{result['case_id']}: {result['status']}")
    summary = {
        "schema_version": 1,
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest.get("manifest_sha256"),
        "split": args.split,
        "case_count": len(results),
        "qualified_count": sum(item.get("status") == "qualified" for item in results),
        "blocked_count": sum(item.get("status") != "qualified" for item in results),
        "cases": results,
    }
    write_report(args.evidence_dir.resolve() / "kat_run_summary.json", summary)
    return 0 if not summary["blocked_count"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
