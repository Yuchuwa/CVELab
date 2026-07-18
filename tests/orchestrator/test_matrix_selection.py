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
