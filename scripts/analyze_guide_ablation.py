#!/usr/bin/env python3
"""Pair Guided and No-Guide summaries without exposing private evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


NON_RESEARCH_FAILURES = {
    "agent_api_quota", "agent_api_protocol", "agent_transport",
    "worker_failed", "worker_timeout", "worker_launch", "cleanup_failed",
}


def _rows(path: Path) -> dict[str, dict[str, Any]]:
    payload = json.loads(path.read_text())
    values = payload.get("results", []) if isinstance(payload, dict) else payload
    return {str(row["case_id"]): row for row in values if isinstance(row, dict) and row.get("case_id")}


def _evaluable(row: dict[str, Any] | None) -> bool:
    if not row:
        return False
    if not all(bool(row.get(key)) for key in (
        "environment_success", "attack_graph_valid", "attack_path_reachable",
    )):
        return False
    if not bool(row.get("agent_evaluated", row.get("guided_trial_evaluated", False))):
        return False
    return str(row.get("failure_stage", "")) not in NON_RESEARCH_FAILURES and str(
        row.get("agent_termination_reason", "")
    ) not in NON_RESEARCH_FAILURES


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--guided-summary", required=True)
    parser.add_argument("--no-guide-summary", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    guided = _rows(Path(args.guided_summary))
    no_guide = _rows(Path(args.no_guide_summary))
    case_ids = sorted(set(guided) | set(no_guide))
    pairs = []
    for case_id in case_ids:
        left, right = guided.get(case_id), no_guide.get(case_id)
        left_ok, right_ok = _evaluable(left), _evaluable(right)
        pairs.append({
            "case_id": case_id,
            "cves": (left or right or {}).get("cves", []),
            "guided_present": left is not None,
            "no_guide_present": right is not None,
            "guided_evaluable": left_ok,
            "no_guide_evaluable": right_ok,
            "guided_agent_success": bool(left.get("agent_success")) if left_ok else None,
            "no_guide_agent_success": bool(right.get("agent_success")) if right_ok else None,
            "guided_objective_achieved": bool(left.get("objective_achieved")) if left_ok else None,
            "no_guide_objective_achieved": bool(right.get("objective_achieved")) if right_ok else None,
            "guided_failure_stage": left.get("failure_stage", "") if left else "missing",
            "no_guide_failure_stage": right.get("failure_stage", "") if right else "missing",
        })
    paired = [row for row in pairs if row["guided_evaluable"] and row["no_guide_evaluable"]]
    guided_success = sum(bool(row["guided_agent_success"]) for row in paired)
    no_guide_success = sum(bool(row["no_guide_agent_success"]) for row in paired)
    result = {
        "experiment": "enterprise3-guide-ablation",
        "guided_summary": str(args.guided_summary),
        "no_guide_summary": str(args.no_guide_summary),
        "pair_count": len(pairs),
        "paired_evaluable_count": len(paired),
        "guided_success_count": guided_success,
        "no_guide_success_count": no_guide_success,
        "guided_success_rate": guided_success / len(paired) if paired else None,
        "no_guide_success_rate": no_guide_success / len(paired) if paired else None,
        "objective_success_count": {
            "guided": sum(bool(row["guided_objective_achieved"]) for row in paired),
            "no_guide": sum(bool(row["no_guide_objective_achieved"]) for row in paired),
        },
        "pairs": pairs,
        "interpretation": "descriptive pilot; no target success rate is enforced",
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({
        key: result[key]
        for key in ("pair_count", "paired_evaluable_count", "guided_success_count", "no_guide_success_count", "guided_success_rate", "no_guide_success_rate")
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
