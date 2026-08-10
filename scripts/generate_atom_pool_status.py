#!/usr/bin/env python3
"""Generate the canonical Atom pool JSON and its CSV/Markdown views."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from clab_builder.shared.atom_pool_status import (
    build_snapshot,
    check_snapshot_files,
    load_planned_ids,
    write_snapshot,
)
from clab_builder.shared.atom_build_ledger import latest_attempts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--atoms-dir", type=Path, default=ROOT / "data" / "atoms")
    parser.add_argument(
        "--output-prefix", type=Path, default=ROOT / "data" / "atom_pool_status"
    )
    parser.add_argument(
        "--build-plan",
        type=Path,
        default=ROOT / "data" / "atom_build_plan.json",
        help="JSON file containing the planned Atom queue.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if JSON/CSV/Markdown status is missing or stale; write nothing.",
    )
    parser.add_argument(
        "--build-attempts",
        type=Path,
        default=None,
        help="Tracked Atom build-attempt ledger.",
    )
    args = parser.parse_args()
    ledger_path = args.build_attempts or args.atoms_dir.parent / "atom_build_attempts.json"
    snapshot = build_snapshot(
        args.atoms_dir,
        planned_ids=load_planned_ids(args.build_plan),
        build_attempts=latest_attempts(ledger_path),
    )
    if args.check:
        errors = check_snapshot_files(snapshot, args.output_prefix)
        if errors:
            for error in errors:
                print(f"ERROR: {error}", file=sys.stderr)
            return 1
        return 0
    write_snapshot(snapshot, args.output_prefix)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
