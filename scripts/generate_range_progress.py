#!/usr/bin/env python3
"""Generate sanitized Range build and experiment progress views."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from clab_builder.shared.range_progress import (
    build_progress,
    discover_summaries,
    write_progress,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-root", type=Path, default=ROOT / "data")
    parser.add_argument(
        "--range-prefix",
        type=Path,
        default=ROOT / "data" / "range_build_status",
    )
    parser.add_argument(
        "--experiment-prefix",
        type=Path,
        default=ROOT / "data" / "experiment_status",
    )
    args = parser.parse_args()
    range_status, experiment_status = build_progress(
        discover_summaries(args.data_root),
        project_root=ROOT,
    )
    write_progress(
        range_status,
        experiment_status,
        range_prefix=args.range_prefix,
        experiment_prefix=args.experiment_prefix,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
