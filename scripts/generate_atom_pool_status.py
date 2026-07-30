#!/usr/bin/env python3
"""Generate the canonical Atom pool JSON and its CSV/Markdown views."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from clab_builder.shared.atom_pool_status import build_snapshot, write_snapshot


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
    args = parser.parse_args()
    plan = json.loads(args.build_plan.read_text()) if args.build_plan.is_file() else {}
    planned_ids = [
        item["cve_id"] if isinstance(item, dict) else str(item)
        for item in plan.get("planned", [])
    ]
    write_snapshot(
        build_snapshot(args.atoms_dir, planned_ids=planned_ids),
        args.output_prefix,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
