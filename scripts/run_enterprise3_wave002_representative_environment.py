#!/usr/bin/env python3
"""Run a coverage-representative Wave002 enterprise_3tier environment batch.

The script selects a deterministic, coverage-first subset from the already
generated no-deploy matrix, checks that the subset still covers every current
template slot Atom and customer-records backend variant, then delegates the
actual lifecycle to the shared parallel batch runner.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MATRIX_SELECTOR = ROOT / "scripts" / "generate_enterprise3_matrix.py"
RUNNER = ROOT / "scripts" / "verify_enterprise3_guided_batch.py"


def _load_selector():
    spec = importlib.util.spec_from_file_location("enterprise3_matrix_selector", MATRIX_SELECTOR)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load matrix selector: {MATRIX_SELECTOR}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--matrix",
        default="data/range_matrices/enterprise_3tier_wave002.json",
        help="Coverage-first no-deploy matrix JSON.",
    )
    parser.add_argument(
        "--max-cases",
        type=int,
        default=96,
        help="Number of representative cases (default: 96).",
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=4,
        help="Maximum parallel environment workers (default: 4).",
    )
    parser.add_argument(
        "--output",
        default="data/scenarios_enterprise3_wave002_env_representative",
        help="Batch output directory.",
    )
    parser.add_argument("--resume", action="store_true")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Write and report the selected manifest without deploying environments.",
    )
    return parser.parse_args()


def _resolve(path_value: str) -> Path:
    path = Path(path_value)
    return path if path.is_absolute() else ROOT / path


def _coverage_summary(cases: list[dict]) -> dict:
    return {
        "slot_atoms": {
            slot: sorted({case["slot_atoms"][slot] for case in cases})
            for slot in ("dmz-web", "app-service", "data-store")
        },
        "customer_records_variants": sorted({
            case.get("asset_variants", {}).get("customer-records")
            for case in cases
            if case.get("asset_variants", {}).get("customer-records")
        }),
    }


def _select_cases(matrix: dict, max_cases: int) -> tuple[list[dict], dict]:
    cases = matrix.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("matrix has no cases")
    if max_cases <= 0:
        raise ValueError("--max-cases must be positive")
    if max_cases > len(cases):
        raise ValueError(f"--max-cases {max_cases} exceeds matrix size {len(cases)}")

    selector = _load_selector()
    selected = selector.select_coverage_first(cases, max_cases)
    all_coverage = _coverage_summary(cases)
    selected_coverage = _coverage_summary(selected)
    if selected_coverage != all_coverage:
        missing_slots = {
            slot: sorted(set(all_coverage["slot_atoms"][slot]) - set(selected_coverage["slot_atoms"][slot]))
            for slot in all_coverage["slot_atoms"]
        }
        missing_variants = sorted(
            set(all_coverage["customer_records_variants"])
            - set(selected_coverage["customer_records_variants"])
        )
        raise ValueError(
            "representative subset does not cover the current matrix; "
            f"missing_slots={missing_slots}, missing_variants={missing_variants}; "
            "increase --max-cases"
        )
    return selected, selected_coverage


def _write_manifest(path: Path, matrix: dict, selected: list[dict], coverage: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "source": "enterprise3_wave002_coverage_first",
                "source_matrix": matrix.get("source", ""),
                "template": matrix.get("template", "enterprise_3tier"),
                "selection_strategy": "coverage_first_slot_atom_and_asset_variant",
                "selected_case_count": len(selected),
                "coverage": coverage,
                "cases": selected,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    )


def main() -> int:
    args = parse_args()
    if args.parallel < 1:
        raise SystemExit("--parallel must be at least 1")
    matrix_path = _resolve(args.matrix)
    output = _resolve(args.output)
    try:
        matrix = json.loads(matrix_path.read_text())
        selected, coverage = _select_cases(matrix, args.max_cases)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f"Cannot prepare representative batch: {exc}") from exc

    manifest_path = output / "representative_manifest.json"
    _write_manifest(manifest_path, matrix, selected, coverage)
    print(f"Representative manifest: {manifest_path}")
    print(f"Selected cases: {len(selected)}")
    print(f"Coverage: {json.dumps(coverage, ensure_ascii=False, sort_keys=True)}")
    if args.dry_run:
        return 0

    command = [
        sys.executable,
        str(RUNNER),
        "--case-manifest",
        str(manifest_path),
        "--max-cases",
        str(len(selected)),
        "--environment-only",
        "--parallel",
        str(args.parallel),
        "--output",
        str(output),
    ]
    if args.resume:
        command.append("--resume")
    return subprocess.run(command, cwd=ROOT).returncode


if __name__ == "__main__":
    raise SystemExit(main())
