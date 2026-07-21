"""Regression tests for bounded, coverage-first Range matrix selection."""

import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "generate_enterprise3_matrix.py"
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
