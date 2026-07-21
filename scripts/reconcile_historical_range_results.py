#!/usr/bin/env python3
"""Derive reusable Guided results from batches with a legacy cleanup marker.

The original result files are never modified.  This tool only accepts a
record when the Range and Agent outcome succeeded and the old lifecycle
failure is limited to the known ordering race where ContainerLab destroyed
the attacker before the control-network endpoint was detached.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


SUCCESS_FIELDS = (
    "environment_success",
    "attack_graph_valid",
    "attack_path_reachable",
    "guided_trial_evaluated",
    "agent_success",
    "objective_achieved",
)


def _rows(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict) and isinstance(payload.get("results"), list):
        return [row for row in payload["results"] if isinstance(row, dict)]
    if isinstance(payload, dict) and "environment_success" in payload:
        row = dict(payload)
        if not row.get("case_id"):
            ground_truth = path.parent / "ground_truth.json"
            if ground_truth.exists():
                truth = json.loads(ground_truth.read_text(encoding="utf-8"))
                cves = [
                    str(step["cve_id"])
                    for step in truth.get("attack_path", [])
                    if step.get("cve_id")
                ]
                if cves:
                    row["case_id"] = "matrix-" + "-".join(
                        cve.removeprefix("CVE-") for cve in cves
                    )
                    row["cves"] = cves
        row.setdefault("case_id", "")
        return [row]
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    raise ValueError(f"Unsupported result file: {path}")


def _cleanup(row: dict[str, Any]) -> dict[str, Any]:
    lifecycle = row.get("lifecycle") or {}
    return lifecycle.get("cleanup") or row.get("cleanup") or {}


def _successful_attack(row: dict[str, Any]) -> bool:
    return all(bool(row.get(field)) for field in SUCCESS_FIELDS)


def _endpoint_not_found_cleanup(row: dict[str, Any]) -> bool:
    """Recognise only the historical destroy-before-detach cleanup race."""
    cleanup = _cleanup(row)
    destroy = cleanup.get("destroy") or {}
    transport = cleanup.get("agent_transport") or {}
    errors = transport.get("errors") or []
    if not isinstance(errors, list):
        errors = [str(errors)]
    text = " ".join(str(error).lower() for error in errors)
    return (
        destroy.get("ok") is True
        and transport.get("ok") is False
        and "endpoint" in text
        and "not found" in text
    )


def _minimal_row(row: dict[str, Any], source: Path) -> dict[str, Any]:
    """Keep selection metadata while excluding session/flag observations."""
    allowed = (
        "case_id", "purpose", "cves", "asset_variants", "resolved_asset_bindings",
        "scenario_dir", "agent_context", "environment_success", "attack_graph_valid",
        "attack_path_reachable", "guided_trial_evaluated", "agent_success",
        "objective_achieved", "agent_termination_reason", "failure_stage",
        "execution_complete",
    )
    result = {key: row[key] for key in allowed if key in row}
    result["source_summary"] = str(source)
    return result


def reconcile(path: Path) -> tuple[list[dict[str, Any]], dict[str, int]]:
    accepted: list[dict[str, Any]] = []
    counts = {"rows": 0, "already_complete": 0, "reconciled": 0, "rejected": 0}
    for row in _rows(path):
        counts["rows"] += 1
        if not row.get("case_id") or not _successful_attack(row):
            counts["rejected"] += 1
            continue
        if row.get("execution_complete", True) is not False:
            clean = _minimal_row(row, path)
            clean["execution_complete_reconciled"] = False
            clean["reconciliation_status"] = "original_complete"
            accepted.append(clean)
            counts["already_complete"] += 1
            continue
        if not _endpoint_not_found_cleanup(row):
            counts["rejected"] += 1
            continue
        clean = _minimal_row(row, path)
        clean["execution_complete_reconciled"] = True
        clean["reconciliation_status"] = "accepted_cleanup_only"
        clean["reconciliation_evidence"] = {
            "original_execution_complete": False,
            "destroy_ok": True,
            "cleanup_failure_class": "attacker_endpoint_already_destroyed",
        }
        accepted.append(clean)
        counts["reconciled"] += 1
    return accepted, counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-summary", action="append", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)

    results: list[dict[str, Any]] = []
    totals = {"rows": 0, "already_complete": 0, "reconciled": 0, "rejected": 0}
    seen: set[str] = set()
    for value in args.source_summary:
        rows, counts = reconcile(Path(value))
        for key, count in counts.items():
            totals[key] += count
        for row in rows:
            case_id = str(row["case_id"])
            if case_id not in seen:
                seen.add(case_id)
                results.append(row)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "experiment": "historical-guided-result-reconciliation",
        "selection_contract": {
            "requires": list(SUCCESS_FIELDS),
            "accepted_cleanup_failure": "destroy_ok + attacker endpoint already destroyed",
            "original_files_unchanged": True,
        },
        "source_summaries": [str(value) for value in args.source_summary],
        "counts": {**totals, "accepted_unique": len(results)},
        "results": results,
    }
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(payload["counts"], ensure_ascii=False))
    print(f"reconciled_summary={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
