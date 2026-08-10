#!/usr/bin/env python3
"""Run read-only checks over tracked Atom and Range status artifacts.

This is a release-integrator gate, not a business or experiment test.  It only
reads compact generated status files and the no-deploy matrix manifest.
"""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AssertionError(f"cannot load JSON artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise AssertionError(f"JSON artifact must be an object: {path}")
    return value


def _check_atom_status() -> dict:
    prefix = ROOT / "data" / "atom_pool_status"
    snapshot = _load(prefix.with_suffix(".json"))
    if snapshot.get("schema_version") != 2:
        raise AssertionError("Atom status must use schema_version 2")

    summary = snapshot.get("summary")
    if not isinstance(summary, dict):
        raise AssertionError("Atom status has no summary")
    lifecycle = {"planned", "building", "completed"}
    if set(summary) != {"total", *lifecycle}:
        raise AssertionError("Atom status summary has unexpected lifecycle keys")
    if summary["total"] != sum(summary[state] for state in lifecycle):
        raise AssertionError("Atom lifecycle counts do not add up")

    rows = snapshot.get("atoms")
    if not isinstance(rows, list) or len(rows) != summary["total"]:
        raise AssertionError("Atom status rows do not match total")
    if {row.get("build_status") for row in rows} - lifecycle:
        raise AssertionError("Atom status contains an unknown lifecycle state")
    if any(not row.get("cve_id") for row in rows):
        raise AssertionError("Atom status contains a row without cve_id")

    generated_at = snapshot.get("generated_at")
    snapshot_hash = snapshot.get("snapshot_hash")
    if not generated_at or not snapshot_hash:
        raise AssertionError("Atom status must expose generated_at and snapshot_hash")

    with prefix.with_suffix(".csv").open(newline="", encoding="utf-8") as stream:
        csv_rows = list(csv.DictReader(stream))
    if len(csv_rows) != summary["total"]:
        raise AssertionError("Atom CSV row count does not match JSON")
    if any(row.get("generated_at") != generated_at for row in csv_rows):
        raise AssertionError("Atom CSV generated_at differs from JSON")
    if any(row.get("snapshot_hash") != snapshot_hash for row in csv_rows):
        raise AssertionError("Atom CSV snapshot_hash differs from JSON")

    markdown = prefix.with_suffix(".md").read_text(encoding="utf-8")
    for marker in (
        f"Generated at: `{generated_at}`",
        f"Snapshot hash: `{snapshot_hash}`",
        f"- `total`: {summary['total']}",
        f"- `planned`: {summary['planned']}",
        f"- `building`: {summary['building']}",
        f"- `completed`: {summary['completed']}",
    ):
        if marker not in markdown:
            raise AssertionError(f"Atom Markdown view is missing {marker!r}")
    return snapshot


def _check_range_status(atom_snapshot: dict) -> None:
    status_path = ROOT / "data" / "range_matrix_status.json"
    status = _load(status_path)
    if status.get("schema_version") != 1:
        raise AssertionError("Range matrix status must use schema_version 1")

    atom_status = status.get("atom_status")
    if not isinstance(atom_status, dict):
        raise AssertionError("Range matrix status has no Atom provenance")
    if atom_status.get("snapshot_hash") != atom_snapshot.get("snapshot_hash"):
        raise AssertionError("Range matrix was generated from a stale Atom snapshot")
    if atom_status.get("completed_count") != atom_snapshot["summary"]["completed"]:
        raise AssertionError("Range matrix completed_count differs from Atom status")

    manifest_ref = status.get("matrix_manifest")
    if not isinstance(manifest_ref, str) or not manifest_ref:
        raise AssertionError("Range matrix status has no manifest reference")
    manifest_path = ROOT / manifest_ref
    if not manifest_path.is_file():
        raise AssertionError(f"Range matrix manifest is missing: {manifest_path}")
    actual_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    if actual_hash != status.get("matrix_manifest_sha256"):
        raise AssertionError("Range matrix manifest hash does not match status")

    manifest = _load(manifest_path)
    manifest_atom_status = manifest.get("atom_status")
    if not isinstance(manifest_atom_status, dict):
        raise AssertionError("Range matrix manifest has no Atom provenance")
    if manifest_atom_status.get("snapshot_hash") != atom_snapshot.get("snapshot_hash"):
        raise AssertionError("Range matrix manifest has stale Atom provenance")

    accepted = status.get("summary", {}).get("accepted_cases")
    manifest_accepted = manifest.get("accepted_case_count")
    if manifest_accepted is not None and manifest_accepted != accepted:
        raise AssertionError("Range matrix accepted count differs between views")


def main() -> int:
    try:
        atom_snapshot = _check_atom_status()
        _check_range_status(atom_snapshot)
    except (AssertionError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("status contracts: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
