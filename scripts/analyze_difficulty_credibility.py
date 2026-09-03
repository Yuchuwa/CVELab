#!/usr/bin/env python3
"""Analyze frozen probability predictions against run-level outcomes."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from clab_builder.evaluation.credibility import (
    analyze_against_baselines,
    analyze_probability_predictions,
)
from clab_builder.evaluation.difficulty import write_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "input",
        type=Path,
        help=(
            "JSON with cases containing id, predicted_success_probability, "
            "and run-level outcomes"
        ),
    )
    parser.add_argument("--output", "-o", type=Path, required=True)
    parser.add_argument(
        "--baselines",
        type=Path,
        help="Calibration-fit baseline mappings from manage_difficulty_study.py",
    )
    args = parser.parse_args()
    payload = json.loads(args.input.read_text(encoding="utf-8-sig"))
    cases = payload.get("cases") if isinstance(payload, dict) else payload
    if not isinstance(cases, list):
        raise SystemExit("input must be a list or an object containing cases")
    if isinstance(payload, dict) and payload.get("complete") is False:
        raise SystemExit("formal analysis requires a complete collected split")
    if args.baselines:
        baseline_fit = json.loads(args.baselines.read_text(encoding="utf-8-sig"))
        if not isinstance(payload, dict) or payload.get("complete") is not True:
            raise SystemExit("baseline comparison requires a complete collected split")
        if payload.get("split") != "test":
            raise SystemExit("baseline comparison is only valid on the test split")
        if baseline_fit.get("fit_split") != "calibration":
            raise SystemExit("baseline mappings must be fitted on calibration")
        plan_sha256 = payload.get("plan_sha256")
        if not plan_sha256 or baseline_fit.get("source_plan_sha256") != plan_sha256:
            raise SystemExit("baseline mappings and test outcomes use different plans")
        analysis = analyze_against_baselines(cases, baseline_fit)
    else:
        analysis = analyze_probability_predictions(cases)
    report = {
        "schema_version": 1,
        "source": str(args.input),
        "baseline_fit_source": str(args.baselines) if args.baselines else None,
        "analysis": analysis,
    }
    write_report(args.output, report)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
