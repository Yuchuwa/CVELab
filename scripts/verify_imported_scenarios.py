#!/usr/bin/env python3
"""Run current environment-only verification on reconciled scenario snapshots."""

from __future__ import annotations

import argparse
import json
import secrets
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from clab_builder.orchestrator.composer.verifier import ScenarioVerifier


ROOT = Path(__file__).resolve().parents[1]


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--import-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--workspace-root", type=Path, required=True,
        help="Mutable per-run scenario copies; must be new unless --resume is used.",
    )
    parser.add_argument("--atoms-dir", type=Path, default=ROOT / "data/atoms")
    parser.add_argument("--max-cases", type=int, default=50)
    parser.add_argument("--sysarmor", action="store_true")
    parser.add_argument(
        "--sysarmor-detection", action="store_true",
        help="Start the SysArmor signal watcher during validation when enabled.",
    )
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    imported = json.loads(args.import_manifest.read_text())
    cases = list(imported.get("cases") or [])[: args.max_cases]
    if args.output.exists() and not args.resume:
        raise SystemExit(f"output already exists: {args.output}; use --resume")
    if args.workspace_root.exists() and not args.resume:
        raise SystemExit(
            f"workspace root already exists: {args.workspace_root}; use a new path"
        )
    args.output.mkdir(parents=True, exist_ok=True)
    args.workspace_root.mkdir(parents=True, exist_ok=args.resume)
    results: list[dict[str, Any]] = []
    completed_ids: set[str] = set()
    if args.resume:
        for path in args.output.glob("matrix-*.json"):
            try:
                previous = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError):
                continue
            if previous.get("case_id"):
                results.append(previous)
                completed_ids.add(str(previous["case_id"]))
    run_id = secrets.token_hex(12)
    verifier = ScenarioVerifier(
        atoms_dir=str(args.atoms_dir), validation_mode="guided_agent",
        require_agent_success=False,
    )
    pending = [case for case in cases if str(case["id"]) not in completed_ids]
    for index, case in enumerate(pending, start=len(results) + 1):
        source_scenario_dir = Path(case["scenario_dir"])
        scenario_dir = args.workspace_root / source_scenario_dir.name
        if scenario_dir.exists():
            raise SystemExit(
                f"workspace scenario already exists: {scenario_dir}; use a new workspace root"
            )
        shutil.copytree(source_scenario_dir, scenario_dir)
        result_path = scenario_dir / "verify_result.json"
        try:
            verifier.run_full(
                scenario_dir=str(scenario_dir), api_key="", base_url="", model="",
                environment_only=True, runtime_policy="verify_only",
                execution_context={
                    "run_id": run_id, "case_id": case["id"],
                    "worker_id": str(index), "lab_name": scenario_dir.name,
                    "agent_runner": "syspear", "noise_level": "none",
                },
                agent_context="l2", agent_runner="syspear",
                sysarmor={"enabled": bool(args.sysarmor),
                          "detection": bool(args.sysarmor_detection),
                          "signal_window": 30},
            )
            result = json.loads(result_path.read_text()) if result_path.exists() else {
                "case_id": case["id"], "scenario_dir": str(scenario_dir),
                "success": False, "failure_stage": "missing_result",
            }
        except Exception as exc:  # preserve the case-level failure and continue
            result = {
                "case_id": case["id"], "scenario_dir": str(scenario_dir),
                "success": False, "failure_stage": "worker_failed",
                "error": repr(exc), "execution_complete": False,
            }
        result["case_id"] = case["id"]
        result["source_scenario_dir"] = str(source_scenario_dir)
        result["imported_external_environment_success"] = bool(case.get("external_environment_success"))
        (args.output / f"{case['id']}.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
        results.append(result)
        print(json.dumps({
            "index": index, "total": len(cases), "case_id": case["id"],
            "environment_success": bool(result.get("environment_success")),
            "failure_stage": result.get("failure_stage", ""),
        }, ensure_ascii=False), flush=True)

    summary = {
        "created_at": now(), "run_id": run_id, "environment_only": True,
        "agent_runner": "syspear", "agent_context": "l2",
        "sysarmor": bool(args.sysarmor),
        "sysarmor_detection": bool(args.sysarmor_detection),
        "selected_cases": len(cases), "completed_cases": len(results), "results": results,
    }
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    return 0 if all(bool(item.get("environment_success")) for item in results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
