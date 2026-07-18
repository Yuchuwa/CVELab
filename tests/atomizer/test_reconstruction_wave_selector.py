from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts"))

from select_atom_reconstruction_wave import select


def row(cve_id: str, classification: str, **overrides):
    value = {
        "cve_id": cve_id,
        "classification": classification,
        "value_score": 1,
        "service_role": "web_application",
        "service_family": None,
        "source_image": "vulhub/example:1",
        "source_image_local": "present",
        "required_service": {"protocol": "http", "port": 80},
        "verified_capabilities": ["execute_command", "read_file"],
        "native_success": True,
        "environment_ready": True,
        "guide_ready": True,
        "runtime_ready": False,
    }
    value.update(overrides)
    return value


def test_selector_excludes_b1_and_accounts_for_every_row():
    rows = [
        row("CVE-2024-0001", "rebuild_runtime_or_bundle"),
        row("CVE-2024-0002", "rebuild_runtime_or_bundle"),
        row("CVE-2024-0003", "full_reconstruction", value_score=3),
        row(
            "CVE-2024-0004",
            "rebuild_runtime_or_bundle",
            required_service={},
            verified_capabilities=[],
        ),
    ]
    manifest = select(rows, {"CVE-2024-0001"}, {"CVE-2024-0002"}, 2)

    assert [item["cve_id"] for item in manifest["selected"]] == ["CVE-2024-0003"]
    reasons = {item["cve_id"]: item["reason"] for item in manifest["excluded"]}
    assert reasons["CVE-2024-0001"].startswith("completed in B1")
    assert reasons["CVE-2024-0002"].startswith("deferred in B1")
    assert "low marginal capability" in reasons["CVE-2024-0004"]


def test_selector_prefers_role_diversity_without_duplicate_membership():
    rows = [
        row("CVE-2024-0010", "rebuild_runtime_or_bundle", value_score=5),
        row(
            "CVE-2024-0011",
            "rebuild_runtime_or_bundle",
            value_score=4,
            service_role="database",
            verified_capabilities=["read_file"],
        ),
        row("CVE-2024-0012", "full_reconstruction", value_score=3),
    ]
    manifest = select(rows, set(), set(), 2)
    selected = {item["cve_id"] for item in manifest["selected"]}
    excluded = {item["cve_id"] for item in manifest["excluded"]}

    assert selected == {"CVE-2024-0010", "CVE-2024-0011"}
    assert not selected & excluded
