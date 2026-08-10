#!/usr/bin/env python3
"""Migrate local Atom build directories into the tracked attempt ledger."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from clab_builder.shared.atom_build_ledger import load_ledger, write_ledger


def discover_legacy_attempts(atoms_dir: Path, existing: dict) -> list[dict]:
    known = {item["cve_id"] for item in existing.get("attempts", [])}
    timestamp = datetime.now(timezone.utc).isoformat()
    attempts = list(existing.get("attempts", []))
    for atom_dir in sorted(atoms_dir.iterdir()):
        if not atom_dir.is_dir() or (atom_dir / "atom.yaml").is_file():
            continue
        if not any(atom_dir.iterdir()) or atom_dir.name in known:
            continue
        attempts.append({
            "attempt_id": f"legacy-{atom_dir.name.lower()}",
            "cve_id": atom_dir.name,
            "state": "deferred",
            "started_at": timestamp,
            "updated_at": timestamp,
            "owner": "atomizer",
            "phase": "construction",
            "failure_class": "atom_yaml_missing",
            "source_kind": "legacy-local-evidence",
        })
        known.add(atom_dir.name)
    return {"schema_version": 1, "attempts": attempts}


def main() -> int:
    root = ROOT
    parser = argparse.ArgumentParser()
    parser.add_argument("--atoms-dir", type=Path, default=root / "data" / "atoms")
    parser.add_argument(
        "--ledger",
        type=Path,
        default=root / "data" / "atom_build_attempts.json",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Persist the migrated ledger; default is a read-only preview.",
    )
    args = parser.parse_args()
    existing = load_ledger(args.ledger)
    migrated = discover_legacy_attempts(args.atoms_dir, existing)
    added = len(migrated["attempts"]) - len(existing["attempts"])
    print(f"legacy_attempts_added={added}")
    if args.write:
        write_ledger(args.ledger, migrated)
        print(f"ledger_written={args.ledger}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
