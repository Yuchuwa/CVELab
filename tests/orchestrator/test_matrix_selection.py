"""Regression tests for bounded, coverage-first Range matrix selection."""

import argparse
import importlib.util
import json
from pathlib import Path

import pytest
import yaml

from clab_builder.shared.atom_pool_status import build_snapshot

SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "scripts"
    / "generate_enterprise3_matrix.py"
)
SPEC = importlib.util.spec_from_file_location("enterprise3_matrix", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def _case(case_id, dmz, app, data, variant):
    return {
        "id": case_id,
        "slot_atoms": {
            "dmz-web": dmz,
            "app-service": app,
            "data-store": data,
        },
        "asset_variants": {"customer-records": variant},
    }


def test_coverage_first_prefers_new_slot_atoms_and_backend_variant():
    cases = [
        _case("a", "CVE-D1", "CVE-A1", "CVE-X1", "postgresql"),
        _case("b", "CVE-D2", "CVE-A2", "CVE-X2", "elasticsearch"),
        _case("c", "CVE-D1", "CVE-A2", "CVE-X3", "postgresql"),
    ]

    selected = MODULE.select_coverage_first(cases, 2)

    assert [case["id"] for case in selected] == ["a", "b"]
    features = set().union(*(MODULE._coverage_features(case) for case in selected))
    assert "asset-variant:customer-records:postgresql" in features
    assert "asset-variant:customer-records:elasticsearch" in features


def test_zero_limit_keeps_every_case_in_deterministic_order():
    cases = [
        _case("b", "CVE-D2", "CVE-A2", "CVE-X2", "elasticsearch"),
        _case("a", "CVE-D1", "CVE-A1", "CVE-X1", "postgresql"),
    ]

    assert [case["id"] for case in MODULE.select_coverage_first(cases, 0)] == ["a", "b"]


def test_runtime_ready_for_batch_requires_full_runtime_selection(monkeypatch):
    atom = object()
    monkeypatch.setattr(
        MODULE,
        "_runtime_image_selection",
        lambda _: {"selection": "source_image"},
    )
    assert MODULE.runtime_ready_for_batch(atom) is False

    monkeypatch.setattr(
        MODULE,
        "_runtime_image_selection",
        lambda _: {"selection": "runtime_image"},
    )
    assert MODULE.runtime_ready_for_batch(atom) is True


def test_range_matrix_reads_only_completed_atoms_from_v2_status(tmp_path):
    status_path = tmp_path / "atom-status.json"
    status_path.write_text(json.dumps({
        "schema_version": 2,
        "snapshot_hash": "snapshot-123",
        "atoms": [
            {"cve_id": "CVE-DONE", "build_status": "completed", "blockers": []},
            {
                "cve_id": "CVE-WIP",
                "build_status": "building",
                "blockers": ["environment_verified"],
            },
            {"cve_id": "CVE-NEXT", "build_status": "planned"},
        ],
    }))

    completed, metadata = MODULE.load_completed_atom_status(status_path)

    assert completed == {"CVE-DONE"}
    assert metadata["snapshot_hash"] == "snapshot-123"
    assert metadata["completed_count"] == 1
    assert {row["cve_id"] for row in metadata["rejections"]} == {
        "CVE-WIP",
        "CVE-NEXT",
    }


def test_matrix_rejects_snapshot_marking_live_building_atom_completed(tmp_path):
    atoms_dir = tmp_path / "atoms"
    atom_dir = atoms_dir / "CVE-VERIFIED-BUILDING"
    atom_dir.mkdir(parents=True)
    (atom_dir / "atom.yaml").write_text(yaml.safe_dump({
        "version": 3,
        "cve_id": "CVE-VERIFIED-BUILDING",
        "category": "test",
        "verified": True,
        "docker_image": "test:latest",
        "vuln_category": "RCE",
        "primary_mitre_phase": "initial_access",
        "service_role": "web_application",
        "exploit_complexity": "simple",
        "attack_method": "single_request",
    }))
    stale = build_snapshot(atoms_dir)
    stale["atoms"][0]["build_status"] = "completed"
    stale["atoms"][0]["blockers"] = []
    status_path = tmp_path / "atom-status.json"
    status_path.write_text(json.dumps(stale))
    build_plan = tmp_path / "build-plan.json"
    build_plan.write_text('{"planned": []}\n')
    args = argparse.Namespace(
        atoms_dir=str(atoms_dir),
        atom_status=str(status_path),
        build_plan=str(build_plan),
        templates_dir="templates",
        template="enterprise_3tier",
        max_cases=0,
    )

    with pytest.raises(ValueError, match="stale Atom build-status snapshot"):
        MODULE.build_manifest(args)


def test_compact_matrix_status_is_range_owned(tmp_path):
    manifest_path = tmp_path / "matrix.json"
    manifest_path.write_text("{}\n")
    payload = {
        "created_at": "2026-07-30T00:00:00+00:00",
        "template": "enterprise_3tier",
        "atom_status": {"schema_version": 2, "snapshot_hash": "atom-hash"},
        "candidate_atom_count": 2,
        "candidate_atom_ids": ["CVE-A", "CVE-B"],
        "accepted_case_count": 1,
        "cases": [{"cves": ["CVE-A"]}],
        "range_input_rejections": [
            {"cve_id": "CVE-C", "reason": "atom_build_not_completed"}
        ],
        "rejections": [
            {"candidate": "CVE-B", "reason": "slot_or_dependency_constraint"}
        ],
    }

    status = MODULE.build_matrix_status(payload, manifest_path)

    assert status["range_candidate_atom_ids"] == ["CVE-A", "CVE-B"]
    assert status["selected_atom_ids"] == ["CVE-A"]
    assert status["summary"]["selected_atoms"] == 1
    assert status["summary"]["selected_cases"] == 1
    assert status["range_input_rejection_counts"] == {
        "atom_build_not_completed": 1
    }


def test_tie_breaking_spreads_entry_cves_instead_of_one_dominating():
    """Once coverage saturates, the entry-point slot CVE must be balanced.

    Regression for the 2026-07-20 finding where the old max()-based tie-break
    kept returning the alphabetically-first case ID, so one entry CVE (with
    the smallest case IDs) ended up in ~70% of selected cases even though
    many other entry CVEs were available. The fix makes ties break by
    "entry CVE selected the fewest times so far", spreading entry CVEs.
    """
    from collections import Counter

    # 4 entry CVEs, each with several compatible downstream combinations, all
    # sharing the same asset variant so coverage saturates almost instantly.
    # Old behavior: CVE-A1 dominates (its case IDs sort first and all ties go
    # to max's first-equal). New behavior: all 4 entry CVEs spread evenly.
    cases = []
    downstreams = [("CVE-A1", "CVE-X1"), ("CVE-A2", "CVE-X1"),
                   ("CVE-A3", "CVE-X1"), ("CVE-A4", "CVE-X1")]
    for entry in ["CVE-D1", "CVE-D2", "CVE-D3", "CVE-D4"]:
        for app_cve, data_cve in downstreams:
            cases.append(_case(
                f"matrix-{entry[-2:]}-{app_cve}-{data_cve}",
                entry, app_cve, data_cve, "elasticsearch",
            ))

    selected = MODULE.select_coverage_first(cases, 8)

    dmz_counts = Counter(case["slot_atoms"]["dmz-web"] for case in selected)
    # Every entry CVE present in the selection (no single CVE dominating).
    assert len(dmz_counts) >= 3, dmz_counts
    # No entry CVE exceeds 3 of 8 (roughly even spread, not 5-6).
    assert max(dmz_counts.values()) <= 3, dmz_counts


def test_coverage_priority_still_beats_balance_when_uncovered_features_exist():
    """New coverage must still win over balance.

    A case adding an uncovered feature is picked before a case whose entry
    CVE has been selected fewer times but adds no new coverage.
    """
    cases = [
        _case("a", "CVE-D1", "CVE-A1", "CVE-X1", "postgresql"),
        _case("b", "CVE-D2", "CVE-A1", "CVE-X1", "elasticsearch"),
        _case("c", "CVE-D1", "CVE-A1", "CVE-X1", "postgresql"),
    ]

    selected = MODULE.select_coverage_first(cases, 2)

    # First pick covers slot + postgresql variant. Second pick must be "b"
    # because it adds the uncovered elasticsearch variant, even though "c"
    # would reuse the already-balanced CVE-D1 entry.
    assert [case["id"] for case in selected] == ["a", "b"]
