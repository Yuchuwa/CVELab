#!/usr/bin/env python3
"""Run serial Syspear trials on already environment-validated scenarios."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from clab_builder.orchestrator.composer.verifier import ScenarioVerifier  # noqa: E402


DEFAULT_CASES = [
    "matrix-2018-16509-2021-42013-2019-9193",
    "matrix-2012-1823-2021-42013-2014-3120",
    "matrix-2012-1823-2024-27348-2014-3120",
    "matrix-2012-1823-2022-24816-2015-1427",
]
DEFAULT_SOURCE_ROOT = ROOT / "data/scenarios/stratified-50-report557f500"
DEFAULT_ENVIRONMENT_RESULTS = (
    ROOT / "data/experiments/stratified-50/runs/imported-stratified50-environment-20260807"
)
DEFAULT_CASE_MANIFEST = ROOT / "data/stratified_50_ranges.json"
DEFAULT_WORKSPACE_PARENT = ROOT / "data/experiments/stratified-50/workspaces"


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--environment-results", type=Path, default=DEFAULT_ENVIRONMENT_RESULTS)
    parser.add_argument("--case-manifest", type=Path, default=DEFAULT_CASE_MANIFEST)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--workspace-root", type=Path,
        help="Optional mutable scenario workspace; defaults outside the result directory.",
    )
    parser.add_argument("--case", action="append", dest="cases")
    parser.add_argument("--all-cases", action="store_true")
    parser.add_argument(
        "--batch-size", type=int,
        help="Run one ordered batch from the environment-qualified 50 cases.",
    )
    parser.add_argument(
        "--batch-index", type=int, default=1,
        help="One-based ordered batch index used with --batch-size (default: 1).",
    )
    parser.add_argument("--max-turns", type=int, default=300)
    parser.add_argument("--agent-timeout", type=int, default=3600)
    parser.add_argument("--sysarmor", action="store_true")
    parser.add_argument(
        "--sysarmor-detection", action="store_true",
        help="Required: collect SysArmor signal frames during the Syspear attack.",
    )
    args = parser.parse_args()

    if not args.sysarmor or not args.sysarmor_detection:
        parser.error("Syspear experiments require both --sysarmor and --sysarmor-detection")

    if sum(bool(value) for value in (args.all_cases, args.cases, args.batch_size)) > 1:
        parser.error("choose exactly one of --all-cases, --case, or --batch-size")
    if args.batch_size is not None and args.batch_size <= 0:
        parser.error("--batch-size must be positive")
    if args.batch_index <= 0:
        parser.error("--batch-index must be positive")
    args.source_root = args.source_root.resolve()
    args.environment_results = args.environment_results.resolve()
    args.case_manifest = args.case_manifest.resolve()
    args.output = args.output.resolve()
    args.workspace_root = (
        args.workspace_root.resolve()
        if args.workspace_root
        else (DEFAULT_WORKSPACE_PARENT / args.output.name).resolve()
    )
    if args.all_cases or args.batch_size is not None:
        if not args.case_manifest.exists():
            parser.error(f"missing case manifest: {args.case_manifest}")
        case_manifest = json.loads(args.case_manifest.read_text())
        ordered_cases = [str(item.get("id") or "") for item in case_manifest.get("cases") or []]
        ordered_cases = [case_id for case_id in ordered_cases if case_id]
        if not ordered_cases:
            parser.error("case manifest contains no case IDs")
        if args.batch_size is None:
            cases = ordered_cases
        else:
            start = (args.batch_index - 1) * args.batch_size
            cases = ordered_cases[start:start + args.batch_size]
            if not cases:
                parser.error("--batch-index is outside the qualified case range")
    else:
        cases = args.cases or DEFAULT_CASES
    if args.output.exists():
        raise SystemExit(f"result output already exists: {args.output}; use a new run name")
    if args.workspace_root.exists():
        raise SystemExit(f"workspace root already exists: {args.workspace_root}; use a new path")
    args.output.mkdir(parents=True)
    args.workspace_root.mkdir(parents=True)
    selected: list[dict] = []
    for case_id in cases:
        env_path = args.environment_results / f"{case_id}.json"
        if not env_path.exists():
            raise SystemExit(f"missing environment result: {env_path}")
        env_result = json.loads(env_path.read_text())
        required_checks = (
            "environment_success",
            "environment_verified",
            "attack_graph_valid",
            "attack_path_reachable",
            "execution_complete",
        )
        missing_checks = [key for key in required_checks if not env_result.get(key)]
        sysarmor_preflight = dict(env_result.get("sysarmor") or {})
        if missing_checks or not sysarmor_preflight.get("enabled") or not (
            sysarmor_preflight.get("patch") or {}
        ).get("ok"):
            raise SystemExit(
                f"environment result is not a SysArmor-qualified pass: {case_id}; "
                f"missing={','.join(missing_checks) or 'none'}"
            )
        source = args.source_root / ("enterprise_3tier-" + case_id.removeprefix("matrix-"))
        if not source.exists():
            raise SystemExit(f"missing scenario directory: {source}")
        destination = args.workspace_root / source.name
        shutil.copytree(source, destination)
        selected.append({
            "case_id": case_id,
            "scenario_dir": str(destination),
            "source_scenario_dir": str(source),
            "environment_result": str(env_path),
        })

    verifier = ScenarioVerifier(
        max_turns=args.max_turns,
        agent_timeout=args.agent_timeout,
        require_agent_success=False,
        atoms_dir=str(ROOT / "data/atoms"),
        validation_mode="guided_agent",
    )
    run_id = f"syspear-imported-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    results: list[dict] = []
    for index, case in enumerate(selected, 1):
        scenario_dir = Path(case["scenario_dir"])
        print(f"[{index}/{len(selected)}] {case['case_id']}", flush=True)
        try:
            verifier.run_full(
                scenario_dir=str(scenario_dir), api_key="", base_url="", model="",
                environment_only=False, runtime_policy="verify_only",
                execution_context={
                    "run_id": run_id, "case_id": case["case_id"],
                    "worker_id": str(index), "lab_name": scenario_dir.name,
                    "agent_runner": "syspear", "noise_level": "none",
                    "requested_max_turns": args.max_turns,
                    "requested_agent_timeout": args.agent_timeout,
                },
                agent_context="l2", agent_runner="syspear",
                sysarmor={"enabled": True, "detection": True,
                          "signal_window": 30},
            )
            result_path = scenario_dir / "verify_result.json"
            result = json.loads(result_path.read_text()) if result_path.exists() else {
                "success": False, "failure_stage": "missing_result",
            }
        except Exception as exc:  # preserve a case result and continue serially
            result = {"success": False, "failure_stage": "worker_failed", "error": repr(exc)}
        result.update({
            "case_id": case["case_id"],
            "scenario_dir": str(scenario_dir),
            "source_scenario_dir": case["source_scenario_dir"],
            "environment_result": case["environment_result"],
        })
        (args.output / f"{case['case_id']}.json").write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n"
        )
        results.append(result)
        print(json.dumps({
            "case_id": case["case_id"],
            "environment_success": bool(result.get("environment_success")),
            "agent_evaluated": bool(result.get("agent_evaluated")),
            "agent_success": bool(result.get("agent_success")),
            "termination_reason": (result.get("agent_result") or {}).get("termination_reason", ""),
            "failure_stage": result.get("failure_stage", ""),
        }, ensure_ascii=False), flush=True)

    summary = {
        "created_at": now(), "run_id": run_id, "agent_runner": "syspear",
        "agent_context": "l2", "max_turns": args.max_turns,
        "agent_timeout": args.agent_timeout, "parallel": 1,
        "batch_size": args.batch_size,
        "batch_index": args.batch_index if args.batch_size is not None else None,
        "sysarmor": True, "sysarmor_detection": True,
        "selected_cases": len(selected), "completed_cases": len(results),
        "results": results,
    }
    (args.output / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n"
    )
    return 0 if len(results) == len(selected) else 2


if __name__ == "__main__":
    raise SystemExit(main())
