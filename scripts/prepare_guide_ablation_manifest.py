#!/usr/bin/env python3
"""Select already-successful Guided Ranges for a Guide ablation experiment.

The selector is deliberately read-only with respect to source summaries.  It
emits a manifest containing case metadata only; no flags or private objective
assertions are copied into the manifest.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


SLOTS = ("dmz-web", "app-service", "data-store")


def _standalone_result(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize one scenario verify_result into the batch-row shape."""
    ground_truth_path = path.parent / "ground_truth.json"
    ground_truth: dict[str, Any] = {}
    if ground_truth_path.exists():
        ground_truth = json.loads(ground_truth_path.read_text())
    attack_path = ground_truth.get("attack_path", []) or []
    cves = [str(step.get("cve_id")) for step in attack_path if step.get("cve_id")]
    case_id = str(payload.get("case_id") or "")
    if not case_id and cves:
        case_id = "matrix-" + "-".join(cve.removeprefix("CVE-") for cve in cves)
    row = dict(payload)
    row["case_id"] = case_id
    row["purpose"] = row.get("purpose") or "standalone Guided Range verification"
    row["cves"] = list(row.get("cves") or cves)
    row["asset_variants"] = dict(row.get("asset_variants") or {})
    meta_path = path.parent / "scenario.yaml"
    if meta_path.exists():
        try:
            import yaml
            meta = yaml.safe_load(meta_path.read_text()) or {}
            for asset_id, binding in (meta.get("resolved_asset_bindings") or {}).items():
                if isinstance(binding, dict) and binding.get("variant_id"):
                    row["asset_variants"][asset_id] = binding["variant_id"]
        except (OSError, ValueError):
            pass
    row["source_summary"] = str(path)
    return row


def _read_summary(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text())
    if isinstance(payload, dict) and isinstance(payload.get("results"), list):
        return [row for row in payload["results"] if isinstance(row, dict)]
    if isinstance(payload, dict) and (
        "environment_success" in payload or "attack_path" in payload
    ):
        return [_standalone_result(path, payload)]
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    raise ValueError(f"summary {path} is neither a batch summary nor a verify_result")


def _eligible(row: dict[str, Any]) -> bool:
    return len(row.get("cves", [])) == len(SLOTS) and all(bool(row.get(key)) for key in (
        "environment_success", "attack_graph_valid", "attack_path_reachable",
        "guided_trial_evaluated", "agent_success", "objective_achieved",
    )) and (
        row.get("execution_complete", True) is not False
        or row.get("execution_complete_reconciled") is True
    )


def _coverage_keys(row: dict[str, Any]) -> set[tuple[str, str]]:
    cves = [str(item) for item in row.get("cves", [])]
    keys = {(slot, cve) for slot, cve in zip(SLOTS, cves)}
    variants = row.get("asset_variants") or {}
    if isinstance(variants, dict):
        keys.update(("variant", f"{key}={value}") for key, value in variants.items())
    return keys


def _composition_key(row: dict[str, Any]) -> tuple[Any, ...]:
    """Avoid rerunning the same ordered three-slot composition under aliases."""
    variants = row.get("asset_variants") or {}
    variant_key = tuple(sorted((str(key), str(value)) for key, value in variants.items()))
    return (tuple(str(item) for item in row.get("cves", [])), variant_key)


def select(rows: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    candidates = [row for row in rows if _eligible(row) and row.get("case_id")]
    # Prefer one record for the same ordered slot composition.  Case ID is the
    # deterministic tie-breaker, so aliases from different runners do not
    # consume experimental slots twice.
    dedup: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in candidates:
        key = _composition_key(row)
        previous = dedup.get(key)
        if previous is None or str(row["case_id"]) < str(previous["case_id"]):
            dedup[key] = row
    candidates = list(dedup.values())
    selected: list[dict[str, Any]] = []
    covered: set[tuple[str, str]] = set()
    while candidates and len(selected) < limit:
        ranked = sorted(
            candidates,
            key=lambda row: (
                -len(_coverage_keys(row) - covered),
                -len(set(str(item) for item in row.get("cves", []))),
                str(row["case_id"]),
            ),
        )
        row = ranked[0]
        candidates.remove(row)
        selected.append(row)
        covered.update(_coverage_keys(row))
    return selected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-summary", action="append", required=True)
    parser.add_argument("--max-cases", type=int, default=20)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.max_cases < 1:
        raise SystemExit("--max-cases must be positive")

    rows: list[dict[str, Any]] = []
    for value in args.source_summary:
        path = Path(value)
        for row in _read_summary(path):
            if _eligible(row):
                row = dict(row)
                row["source_summary"] = str(path)
                rows.append(row)
    selected = select(rows, args.max_cases)
    cases = []
    for row in selected:
        cases.append({
            "id": str(row["case_id"]),
            "purpose": str(row.get("purpose", "Guide ablation baseline")),
            "cves": [str(item) for item in row.get("cves", [])],
            "asset_variants": dict(row.get("asset_variants") or {}),
            "baseline_context": "guided",
            "source_summary": row.get("source_summary", ""),
            "reconciliation_status": row.get("reconciliation_status", "original_complete"),
        })
    manifest = {
        "schema_version": 1,
        "experiment": "enterprise3-guide-ablation",
        "selection_contract": {
            "requires": [
                "environment_success", "attack_graph_valid", "attack_path_reachable",
                "guided_trial_evaluated", "agent_success", "objective_achieved",
            ],
            "max_cases": args.max_cases,
            "selection": "coverage-first deterministic greedy selection",
        },
        "candidate_count": len(rows),
        "selected_count": len(cases),
        "cases": cases,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print(f"eligible={len(rows)} selected={len(cases)}")
    print(f"manifest={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
