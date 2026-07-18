#!/usr/bin/env python3
"""Build a Guided-Agent manifest from successful environment-only shards."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_ENVIRONMENT_FIELDS = (
    "environment_success",
    "range_build_verified",
    "attack_graph_valid",
    "attack_path_reachable",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--environment-root",
        required=True,
        help="Directory containing shard-*/summary.json environment results.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Guided-Agent manifest path.",
    )
    return parser.parse_args()


def environment_passed(result: dict) -> bool:
    """Return whether an environment-only result is eligible for Agent trials."""
    return all(result.get(field) is True for field in REQUIRED_ENVIRONMENT_FIELDS)


def collect_environment_results(root: Path) -> tuple[list[dict], list[dict]]:
    """Collect unique passed cases and rejected result records from shard summaries."""
    passed: list[dict] = []
    rejected: list[dict] = []
    seen: set[str] = set()
    summaries = sorted(root.glob("shard-*/summary.json"))
    if not summaries:
        raise ValueError(f"No shard summaries found under {root}")

    for summary_path in summaries:
        try:
            summary = json.loads(summary_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Cannot read {summary_path}: {exc}") from exc
        results = summary.get("results")
        if not isinstance(results, list):
            raise ValueError(f"{summary_path} has no results list")
        for result in results:
            if not isinstance(result, dict):
                raise ValueError(f"{summary_path} contains an invalid result")
            case_id = str(result.get("case_id") or "")
            cves = result.get("cves")
            if not case_id or not isinstance(cves, list):
                raise ValueError(f"{summary_path} result is missing case_id or cves")
            if case_id in seen:
                raise ValueError(f"Duplicate case_id across shards: {case_id}")
            seen.add(case_id)
            if environment_passed(result):
                passed.append({
                    "id": case_id,
                    "cves": [str(cve) for cve in cves],
                    "purpose": str(result.get("purpose") or "environment-passed matrix combination"),
                    "asset_variants": dict(result.get("asset_variants") or {}),
                })
            else:
                rejected.append({
                    "id": case_id,
                    "cves": [str(cve) for cve in cves],
                    "failure_stage": str(result.get("failure_stage") or "environment_gate"),
                    "failed_conditions": [
                        field for field in REQUIRED_ENVIRONMENT_FIELDS
                        if result.get(field) is not True
                    ],
                    "error": str(result.get("error") or ""),
                })
    return passed, rejected


def main() -> int:
    args = parse_args()
    root = Path(args.environment_root)
    if not root.is_absolute():
        root = ROOT / root
    output = Path(args.output)
    if not output.is_absolute():
        output = ROOT / output

    cases, rejected = collect_environment_results(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source": "environment_only_shard_collection",
        "environment_root": str(root),
        "selection_criteria": list(REQUIRED_ENVIRONMENT_FIELDS),
        "accepted_case_count": len(cases),
        "rejected_case_count": len(rejected),
        "cases": cases,
        "rejections": rejected,
    }, indent=2, ensure_ascii=False) + "\n")
    print(f"Agent manifest saved to: {output}")
    print(f"accepted={len(cases)} rejected={len(rejected)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
