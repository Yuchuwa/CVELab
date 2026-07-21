#!/usr/bin/env python3
"""Build a reusable Range manifest from one or more verified Guided batches.

A Range is considered "verified-reusable" for downstream level/agent
experiments when, in its source batch, it passed the full Guided gate:
``environment_success`` + ``attack_graph_valid`` + ``attack_path_reachable``
+ ``guided_trial_success`` + ``objective_achieved`` all true. Only such Ranges
are emitted; failed or environment-only Ranges are recorded as rejected with
a reason, never silently dropped.

Each emitted case carries a ``validation_round`` provenance tag (the source
batch run_id, the agent_context/noise_level that validated it, and the
scenario directory) so later experiments can reuse the *same* Range set across
different levels / agents and trace which round each Range was validated in.

Read-only: this script never modifies verify_result.json, scenarios, or
atoms. It only scans batch summaries and per-scenario results.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

# The full-Guided gate. A Range must clear every field here to be considered
# verified-reusable. environment_only runs never qualify (no guided trial).
GUIDED_GATE = (
    "environment_success",
    "attack_graph_valid",
    "attack_path_reachable",
    "guided_trial_success",
    "objective_achieved",
)


def _load_batch(path: Path) -> dict[str, Any] | None:
    """Load a batch summary.json, returning None if not a guided-full batch."""
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if payload.get("environment_only"):
        return None  # environment-only batches never ran the Guided gate
    return payload


def _collect_verified(batch_dir: Path) -> list[dict[str, Any]]:
    """Return verified-reusable cases from a single batch directory."""
    summary = _load_batch(batch_dir / "summary.json")
    if not summary:
        return []
    round_tag = summary.get("validation_round") or {
        "run_id": summary.get("run_id", ""),
        "agent_context": summary.get("agent_context", "guided"),
        "noise_level": summary.get("noise_level", "none"),
        "environment_only": summary.get("environment_only", False),
        "created_at": summary.get("created_at", ""),
    }
    verified = []
    scenarios_root = batch_dir / "scenarios"
    for case in summary.get("results", []):
        case_id = case.get("case_id", "")
        scenario_dir = case.get("scenario_dir", "")
        vr_path = Path(scenario_dir) / "verify_result.json" if scenario_dir else None
        vr = {}
        if vr_path and vr_path.is_file():
            try:
                vr = json.loads(vr_path.read_text())
            except (OSError, json.JSONDecodeError):
                vr = {}
        gate_pass = all(bool(vr.get(field)) for field in GUIDED_GATE)
        if not gate_pass:
            continue
        verified.append({
            "id": case_id,
            "cves": list(case.get("cves", [])),
            "purpose": case.get("purpose", "guided-verified reusable Range"),
            "asset_variants": dict(case.get("asset_variants") or {}),
            "scenario_dir": scenario_dir,
            "validation_round": round_tag,
            "guided_gate": {field: bool(vr.get(field)) for field in GUIDED_GATE},
        })
    return verified


def _dedupe(verified: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Deduplicate by CVE triple (case id), keeping the latest validation round.

    Returns (kept, superseded). When the same case id appears in multiple
    batches, the most recent validated_at wins; earlier ones are recorded as
    superseded with the reason, never dropped silently.
    """
    by_id: dict[str, dict[str, Any]] = {}
    superseded: list[dict[str, Any]] = []
    for case in verified:
        cid = case["id"]
        prev = by_id.get(cid)
        if prev is None:
            by_id[cid] = case
            continue
        prev_ts = (prev.get("validation_round") or {}).get("created_at", "")
        cur_ts = (case.get("validation_round") or {}).get("created_at", "")
        if cur_ts > prev_ts:
            superseded.append({
                "id": cid,
                "superseded_by_run_id": (case.get("validation_round") or {}).get("run_id", ""),
                "reason": f"newer validation round {cur_ts} > {prev_ts}",
            })
            by_id[cid] = case
        else:
            superseded.append({
                "id": cid,
                "superseded_by_run_id": (prev.get("validation_round") or {}).get("run_id", ""),
                "reason": f"older validation round {cur_ts} <= {prev_ts}",
            })
    return list(by_id.values()), superseded


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "batches", nargs="+", type=Path,
        help="One or more batch output directories (each containing "
             "summary.json + scenarios/).",
    )
    parser.add_argument(
        "--output", type=Path, required=True,
        help="Output reusable manifest JSON path.",
    )
    parser.add_argument(
        "--exclude-ids", default="",
        help="Comma-separated case ids to exclude (e.g. a previous batch's "
             "case ids, so the new manifest does not repeat Ranges).",
    )
    args = parser.parse_args()

    exclude = {s.strip() for s in args.exclude_ids.split(",") if s.strip()}
    all_verified: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    per_batch_counts: list[dict[str, Any]] = []
    for batch_dir in args.batches:
        batch_dir = batch_dir.resolve()
        summary = _load_batch(batch_dir / "summary.json")
        if not summary:
            per_batch_counts.append({
                "batch": str(batch_dir),
                "status": "skipped_not_guided_full",
                "verified": 0,
            })
            continue
        verified = _collect_verified(batch_dir)
        total = len(summary.get("results", []))
        per_batch_counts.append({
            "batch": str(batch_dir),
            "run_id": summary.get("run_id", ""),
            "agent_context": summary.get("agent_context", "guided"),
            "noise_level": summary.get("noise_level", "none"),
            "total_cases": total,
            "verified": len(verified),
        })
        # Record rejected (gate-failed) cases with reasons, for traceability.
        scenarios_root = batch_dir / "scenarios"
        for case in summary.get("results", []):
            cid = case.get("case_id", "")
            scenario_dir = case.get("scenario_dir", "")
            vr = {}
            vr_path = Path(scenario_dir) / "verify_result.json" if scenario_dir else None
            if vr_path and vr_path.is_file():
                try:
                    vr = json.loads(vr_path.read_text())
                except (OSError, json.JSONDecodeError):
                    vr = {}
            if all(bool(vr.get(f)) for f in GUIDED_GATE):
                continue  # already kept
            failed_fields = [f for f in GUIDED_GATE if not vr.get(f)]
            rejected.append({
                "batch": str(batch_dir),
                "run_id": summary.get("run_id", ""),
                "id": cid,
                "scenario_dir": scenario_dir,
                "failure_stage": vr.get("failure_stage") or case.get("failure_stage"),
                "failed_gate_fields": failed_fields,
            })
        all_verified.extend(verified)

    kept, superseded = _dedupe(all_verified)
    # Apply explicit exclusions last, recording them as excluded (not dropped).
    excluded: list[str] = []
    final = []
    for case in kept:
        if case["id"] in exclude:
            excluded.append(case["id"])
            continue
        final.append(case)

    manifest = {
        "schema_version": 1,
        "experiment": "reusable-guided-verified-ranges",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "selection_contract": {
            "gate": list(GUIDED_GATE),
            "dedupe": "keep latest validation_round by created_at per case id",
        },
        "source_batches": per_batch_counts,
        "verified_case_count": len(kept),
        "superseded_duplicates": len(superseded),
        "excluded_ids": excluded,
        "rejected_gate_failures": len(rejected),
        "cases": final,
        "superseded": superseded,
        "rejected": rejected,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print(
        f"Reusable manifest: {args.output}\n"
        f"  source batches scanned: {len(per_batch_counts)}\n"
        f"  verified-reusable cases: {len(kept)} (deduped)\n"
        f"  excluded by --exclude-ids: {len(excluded)}\n"
        f"  superseded duplicates: {len(superseded)}\n"
        f"  rejected gate failures: {len(rejected)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())