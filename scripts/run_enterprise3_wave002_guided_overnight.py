#!/usr/bin/env python3
"""Run Guided-Agent trials for environment-passed Wave002 combinations.

The source environment summary is treated as a gate: only cases with a
verified environment, valid attack graph, reachable attack path, and verified
runtime are handed to the existing Guided-Agent batch runner.  No API secret
is copied into the generated manifest.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "verify_enterprise3_guided_batch.py"
REQUIRED_ENVIRONMENT_FIELDS = (
    "environment_success",
    "range_build_verified",
    "attack_graph_valid",
    "attack_path_reachable",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--environment-summary",
        default="data/scenarios_enterprise3_wave002_env_representative/summary.json",
        help="Environment-only summary.json or a directory containing shard summaries.",
    )
    parser.add_argument(
        "--max-cases",
        type=int,
        default=0,
        help="Maximum passed cases to run; 0 means all passed cases (default: 0).",
    )
    parser.add_argument("--parallel", type=int, default=4)
    parser.add_argument("--max-turns", type=int, default=100)
    parser.add_argument("--agent-timeout", type=int, default=1800)
    parser.add_argument(
        "--output",
        default="data/scenarios_enterprise3_wave002_guided_overnight",
    )
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def resolve(path_value: str) -> Path:
    path = Path(path_value)
    return path if path.is_absolute() else ROOT / path


def summary_paths(source: Path) -> list[Path]:
    if source.is_file():
        return [source]
    direct = source / "summary.json"
    if direct.exists():
        return [direct]
    paths = sorted(source.glob("shard-*/summary.json"))
    if not paths:
        raise ValueError(f"No summary.json found under {source}")
    return paths


def collect_passed_cases(source: Path) -> list[dict]:
    passed: list[dict] = []
    seen: set[str] = set()
    for summary_path in summary_paths(source):
        try:
            payload = json.loads(summary_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Cannot read {summary_path}: {exc}") from exc
        results = payload.get("results")
        if not isinstance(results, list):
            raise ValueError(f"{summary_path} has no results list")
        for result in results:
            if not isinstance(result, dict):
                raise ValueError(f"{summary_path} contains an invalid result")
            case_id = str(result.get("case_id") or "")
            cves = result.get("cves")
            if not case_id or not isinstance(cves, list) or len(cves) != 3:
                raise ValueError(f"{summary_path} has an invalid case: {case_id!r}")
            if case_id in seen:
                raise ValueError(f"Duplicate case ID across summaries: {case_id}")
            seen.add(case_id)
            if not all(result.get(field) is True for field in REQUIRED_ENVIRONMENT_FIELDS):
                continue
            passed.append({
                "id": case_id,
                "cves": [str(cve) for cve in cves],
                "purpose": str(result.get("purpose") or "environment-passed matrix combination"),
                "asset_variants": dict(result.get("asset_variants") or {}),
            })
    if not passed:
        raise ValueError("No environment-passed cases were found")
    return passed


def write_manifest(path: Path, source: Path, cases: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source": "environment_passed_guided_queue",
        "environment_summary": str(source),
        "selection_criteria": list(REQUIRED_ENVIRONMENT_FIELDS),
        "selected_case_count": len(cases),
        "cases": cases,
    }, indent=2, ensure_ascii=False) + "\n")


def main() -> int:
    args = parse_args()
    if args.parallel < 1:
        raise SystemExit("--parallel must be at least 1")
    if args.max_cases < 0:
        raise SystemExit("--max-cases must be zero or positive")
    source = resolve(args.environment_summary)
    output = resolve(args.output)
    try:
        cases = collect_passed_cases(source)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Cannot prepare Guided-Agent queue: {exc}") from exc
    if args.max_cases:
        cases = cases[:args.max_cases]
    if not cases:
        raise SystemExit("No cases selected after --max-cases")

    manifest = output / "guided_manifest.json"
    write_manifest(manifest, source, cases)
    print(f"Guided manifest: {manifest}")
    print(f"Selected environment-passed cases: {len(cases)}")
    if args.dry_run:
        return 0

    command = [
        sys.executable,
        str(RUNNER),
        "--case-manifest", str(manifest),
        "--max-cases", str(len(cases)),
        "--parallel", str(args.parallel),
        "--max-turns", str(args.max_turns),
        "--agent-timeout", str(args.agent_timeout),
        "--output", str(output),
    ]
    if args.resume:
        command.append("--resume")
    return subprocess.run(command, cwd=ROOT).returncode


if __name__ == "__main__":
    raise SystemExit(main())
