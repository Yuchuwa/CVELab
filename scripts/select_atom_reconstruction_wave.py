#!/usr/bin/env python3
"""Select a reproducible Atom reconstruction wave from an audit and ledger.

The selector deliberately consumes the prior wave ledger instead of trusting
the audit's historical classification, because runtime rebuilds can make an
older audit row look stale again.  It emits every audit row as either selected
or excluded so the decision is reviewable and repeatable.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Any


CVE_PATTERN = re.compile(
    r"^\|\s*(CVE-[0-9]{4}-[0-9A-Za-z-]+)\s*\|", re.MULTILINE
)


def _ledger_statuses(path: Path) -> tuple[set[str], set[str]]:
    text = path.read_text()
    if "## B1 Runtime Rebuild Results" not in text:
        raise ValueError("B1 Runtime Rebuild Results section is missing")
    section = text.split("## B1 Runtime Rebuild Results", 1)[1]
    if "### Runtime Deferred" not in section:
        raise ValueError("B1 Runtime Deferred section is missing")
    ready_text, deferred_text = section.split("### Runtime Deferred", 1)
    ready = set(CVE_PATTERN.findall(ready_text))
    deferred = set(CVE_PATTERN.findall(deferred_text))
    return ready, deferred


def _capability_score(row: dict[str, Any]) -> int:
    capabilities = set(row.get("verified_capabilities") or [])
    return (
        (5 if "execute_command" in capabilities else 0)
        + (2 if "read_file" in capabilities else 0)
        + (1 if "read_credential" in capabilities else 0)
        + (1 if "network_vantage" in capabilities else 0)
    )


def _base_score(row: dict[str, Any]) -> int:
    return (
        int(row.get("value_score") or 0)
        + _capability_score(row)
        + (2 if row.get("source_image_local") == "present" else 0)
        + (2 if row.get("native_success") else 0)
        + (1 if row.get("environment_ready") else 0)
        + (1 if row.get("guide_ready") else 0)
    )


def _access_key(row: dict[str, Any]) -> str:
    access = row.get("required_service") or {}
    if not access:
        return ""
    return f"{access.get('protocol', '')}/{access.get('port', '')}"


def _selection_score(
    row: dict[str, Any],
    roles: set[str],
    families: set[str],
    capabilities: set[str],
) -> tuple[int, int, int, int, int, str]:
    role = row.get("service_role") or ""
    family = row.get("service_family") or ""
    row_capabilities = set(row.get("verified_capabilities") or [])
    diversity = (3 if role and role not in roles else 0) + (
        2 if family and family not in families else 0
    )
    capability_diversity = len(row_capabilities - capabilities)
    return (
        diversity,
        capability_diversity,
        _base_score(row),
        1 if row.get("source_image_local") == "present" else 0,
        1 if _access_key(row) else 0,
        row["cve_id"],
    )


def _selected_record(row: dict[str, Any], path: str, score: tuple[Any, ...]) -> dict[str, Any]:
    return {
        "cve_id": row["cve_id"],
        "planned_path": path,
        "source_audit_classification": row.get("classification"),
        "source_audit_reasons": row.get("reasons") or [],
        "value_score": row.get("value_score"),
        "selection_score": list(score),
        "service_role": row.get("service_role"),
        "service_family": row.get("service_family"),
        "service_access": row.get("required_service") or {},
        "verified_capabilities": row.get("verified_capabilities") or [],
        "source_image": row.get("source_image"),
        "source_image_local": row.get("source_image_local"),
        "native_success": row.get("native_success"),
        "environment_ready": row.get("environment_ready"),
        "guide_ready": row.get("guide_ready"),
        "runtime_ready": row.get("runtime_ready"),
    }


def select(rows: list[dict[str, Any]], ready: set[str], deferred: set[str], max_wave: int) -> dict[str, Any]:
    selected: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    eligible: list[dict[str, Any]] = []

    for row in rows:
        cve_id = row["cve_id"]
        if cve_id in ready:
            excluded.append({"cve_id": cve_id, "reason": "completed in B1: runtime-ready"})
        elif cve_id in deferred:
            excluded.append({"cve_id": cve_id, "reason": "deferred in B1; no new shared profile correction"})
        elif row.get("classification") == "range_ready":
            excluded.append({"cve_id": cve_id, "reason": "already range_ready in current audit"})
        else:
            eligible.append(row)

    rebuild = [r for r in eligible if r.get("classification") == "rebuild_runtime_or_bundle"]
    full = [r for r in eligible if r.get("classification") == "full_reconstruction"]

    # Do not spend a bounded runtime rebuild on entries that have neither a
    # capability grant nor a service access contract. They remain in the
    # ledger for a future generic contract decision.
    rebuild_eligible: list[dict[str, Any]] = []
    for row in rebuild:
        if not (row.get("verified_capabilities") or row.get("required_service")):
            excluded.append({
                "cve_id": row["cve_id"],
                "reason": "low marginal capability/access value for bounded runtime rebuild",
            })
        else:
            rebuild_eligible.append(row)

    roles: set[str] = set()
    families: set[str] = set()
    capabilities: set[str] = set()

    # Runtime rebuilds are preferred, while the same greedy diversity ranking
    # keeps a bounded wave from becoming another web-RCE-only batch.
    remaining_rebuild = rebuild_eligible[:]
    while remaining_rebuild and len(selected) < max_wave:
        row = max(
            remaining_rebuild,
            key=lambda r: _selection_score(r, roles, families, capabilities),
        )
        score = _selection_score(row, roles, families, capabilities)
        selected.append(_selected_record(row, "rebuild_runtime_or_bundle", score))
        remaining_rebuild.remove(row)
        roles.add(row.get("service_role") or "")
        if row.get("service_family"):
            families.add(row["service_family"])
        capabilities.update(row.get("verified_capabilities") or [])

    for row in remaining_rebuild:
        excluded.append({"cve_id": row["cve_id"], "reason": "lower marginal value after rebuild ranking"})

    remaining_full = full[:]
    while remaining_full and len(selected) < max_wave:
        row = max(
            remaining_full,
            key=lambda r: _selection_score(r, roles, families, capabilities),
        )
        score = _selection_score(row, roles, families, capabilities)
        selected.append(_selected_record(row, "full_reconstruction", score))
        remaining_full.remove(row)
        roles.add(row.get("service_role") or "")
        if row.get("service_family"):
            families.add(row["service_family"])
        capabilities.update(row.get("verified_capabilities") or [])

    for row in remaining_full:
        excluded.append({"cve_id": row["cve_id"], "reason": "lower marginal value after value/diversity ranking"})

    selected_ids = {row["cve_id"] for row in selected}
    excluded_ids = {row["cve_id"] for row in excluded}
    if selected_ids & excluded_ids:
        raise ValueError("candidate appears in both selected and excluded")
    if len(selected) > max_wave:
        raise ValueError("selected wave exceeds max_wave")
    if len(selected_ids) + len(excluded_ids) != len(rows):
        raise ValueError("selection does not account for every audit row")

    return {
        "source_audit": "data/atom_reconstruction_audit_wave_002.json",
        "b1_ledger": "data/atom_batch_2026-07-18_status.md",
        "max_wave": max_wave,
        "selection_policy": {
            "exclude_b1_runtime_ready": True,
            "exclude_b1_deferred_without_shared_profile_fix": True,
            "prefer_runtime_rebuild": True,
            "ranking": "verified capability, source availability, native/environment/Guide evidence, role and family diversity",
        },
        "selected": selected,
        "excluded": excluded,
    }


def write_csv(manifest: dict[str, Any], path: Path) -> None:
    fields = ["cve_id", "status", "planned_path", "value_score", "service_role", "service_family", "service_access", "verified_capabilities", "source_image", "source_image_local", "reason"]
    selected = {row["cve_id"]: row for row in manifest["selected"]}
    excluded = {row["cve_id"]: row for row in manifest["excluded"]}
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for cve_id, row in sorted(selected.items()):
            writer.writerow({
                "cve_id": cve_id,
                "status": "selected",
                "planned_path": row["planned_path"],
                "value_score": row["value_score"],
                "service_role": row["service_role"],
                "service_family": row["service_family"],
                "service_access": json.dumps(row["service_access"], sort_keys=True),
                "verified_capabilities": json.dumps(row["verified_capabilities"]),
                "source_image": row["source_image"],
                "source_image_local": row["source_image_local"],
                "reason": "selected by value/diversity policy",
            })
        for cve_id, row in sorted(excluded.items()):
            writer.writerow({"cve_id": cve_id, "status": "excluded", "reason": row["reason"]})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit", required=True, type=Path)
    parser.add_argument("--b1-ledger", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--csv-output", type=Path)
    parser.add_argument("--max-wave", type=int, default=25)
    args = parser.parse_args()

    rows = json.loads(args.audit.read_text())["rows"]
    ready, deferred = _ledger_statuses(args.b1_ledger)
    manifest = select(rows, ready, deferred, args.max_wave)
    args.output.write_text(json.dumps(manifest, indent=2) + "\n")
    if args.csv_output:
        write_csv(manifest, args.csv_output)
    print(f"selected={len(manifest['selected'])} excluded={len(manifest['excluded'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
