#!/usr/bin/env python3
"""Qualify, freeze, and collect a verifier-backed difficulty study."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from clab_builder.evaluation.credibility import fit_baseline_models
from clab_builder.evaluation.difficulty import write_report
from clab_builder.evaluation.study import (
    assess_manifest_qualification,
    build_frozen_run_plan,
    collect_trial_outcomes,
)


ROOT = Path(__file__).resolve().parents[1]


def _read(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _write(path: Path, payload) -> None:
    write_report(path, payload)
    print(path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    qualify = commands.add_parser("qualify")
    qualify.add_argument("--manifest", type=Path, required=True)
    qualify.add_argument("--evidence-dir", type=Path, required=True)
    qualify.add_argument("--output", "-o", type=Path, required=True)

    freeze = commands.add_parser("freeze")
    freeze.add_argument("--manifest", type=Path, required=True)
    freeze.add_argument("--qualification", type=Path, required=True)
    freeze.add_argument("--models", type=Path, required=True)
    freeze.add_argument("--attempts-per-model", type=int, default=3)
    freeze.add_argument("--seed", type=int, default=20260903)
    freeze.add_argument("--output", "-o", type=Path, required=True)

    collect = commands.add_parser("collect")
    collect.add_argument("--plan", type=Path, required=True)
    collect.add_argument("--results-dir", type=Path, required=True)
    collect.add_argument("--split", choices=("calibration", "test"), required=True)
    collect.add_argument("--output", "-o", type=Path, required=True)

    fit = commands.add_parser("fit-baselines")
    fit.add_argument("--calibration", type=Path, required=True)
    fit.add_argument("--output", "-o", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "qualify":
        payload = assess_manifest_qualification(
            _read(args.manifest),
            manifest_path=args.manifest,
            evidence_dir=args.evidence_dir,
            repo_root=ROOT,
        )
    elif args.command == "freeze":
        model_payload = _read(args.models)
        models = model_payload.get("models") if isinstance(model_payload, dict) else model_payload
        if not isinstance(models, list):
            raise SystemExit("models file must be a list or contain a models list")
        payload = build_frozen_run_plan(
            _read(args.manifest),
            _read(args.qualification),
            models,
            repo_root=ROOT,
            manifest_path=args.manifest,
            qualification_path=args.qualification,
            attempts_per_model=args.attempts_per_model,
            seed=args.seed,
        )
    elif args.command == "collect":
        payload = collect_trial_outcomes(
            _read(args.plan),
            results_dir=args.results_dir,
            split=args.split,
        )
    else:
        calibration = _read(args.calibration)
        if calibration.get("split") != "calibration" or not calibration.get("complete"):
            raise SystemExit("baseline fitting requires complete calibration outcomes")
        if not calibration.get("plan_sha256"):
            raise SystemExit("calibration outcomes must be bound to a run plan")
        payload = fit_baseline_models(calibration.get("cases") or [])
        payload["source_plan_sha256"] = calibration.get("plan_sha256")
    _write(args.output, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
