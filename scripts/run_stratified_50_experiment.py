#!/usr/bin/env python3
"""Create a formal Stratified-50 experiment run and optionally execute it."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "data" / "experiments" / "stratified-50"
if str(PROTOCOL) not in sys.path:
    sys.path.insert(0, str(PROTOCOL))

from protocol.formal_run import (  # noqa: E402
    FormalRunConfig,
    create_formal_run,
    execution_env,
    refresh_case_index,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("qualification", "agent_trial"), default="qualification")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--case-manifest", default="data/stratified_50_ranges.json")
    parser.add_argument("--experiment-root", default="data/experiments/stratified-50")
    parser.add_argument("--agent-context", choices=("l0", "l1", "l2", "guided"), default="l2")
    parser.add_argument("--agent-runner", choices=("claude", "openai"), default="openai")
    parser.add_argument("--model", default="")
    parser.add_argument("--base-url-label", default="")
    parser.add_argument("--parent-qualification-run", default="")
    parser.add_argument("--max-cases", type=int, default=50)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--parallel", type=int, default=1)
    parser.add_argument("--max-turns", type=int, default=80)
    parser.add_argument("--agent-timeout", type=int, default=1800)
    parser.add_argument("--case-timeout", type=int, default=0)
    parser.add_argument("--noise-level", default="none")
    parser.add_argument("--sysarmor", action="store_true")
    parser.add_argument("--sysarmor-detection", action="store_true")
    parser.add_argument("--sysarmor-signal-window", type=int, default=30)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Run the underlying batch command after creating the formal manifest.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    config = FormalRunConfig(
        repo_root=ROOT,
        experiment_root=ROOT / args.experiment_root,
        case_manifest_path=ROOT / args.case_manifest,
        run_kind=args.kind,
        run_id=args.run_id or None,
        agent_context=args.agent_context,
        agent_runner=args.agent_runner,
        model_id=args.model,
        base_url_label=args.base_url_label,
        max_cases=args.max_cases,
        offset=args.offset,
        parallel=args.parallel,
        max_turns=args.max_turns,
        agent_timeout=args.agent_timeout,
        case_timeout=args.case_timeout,
        noise_level=args.noise_level,
        sysarmor=args.sysarmor,
        sysarmor_detection=args.sysarmor_detection,
        sysarmor_signal_window=args.sysarmor_signal_window,
        environment_only=args.kind == "qualification",
        parent_qualification_run=args.parent_qualification_run,
    )
    run = create_formal_run(config)
    print(f"created formal run: {run.run_dir}")
    print(f"manifest: {run.run_manifest_path}")
    print("batch command:")
    print(json.dumps(run.batch_command, ensure_ascii=False))
    if not args.execute:
        return 0
    completed = subprocess.run(
        run.batch_command,
        cwd=str(ROOT),
        stdin=subprocess.DEVNULL,
        env=execution_env(base_url_label=args.base_url_label),
    )
    refresh_case_index(run.run_dir)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
