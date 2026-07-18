"""Regression tests for environment-only shard collection."""

import importlib.util
import json
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "collect_enterprise3_agent_queue.py"
SPEC = importlib.util.spec_from_file_location("enterprise3_agent_queue", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def _result(case_id: str, *, passed: bool) -> dict:
    return {
        "case_id": case_id,
        "cves": ["CVE-1", "CVE-2", "CVE-3"],
        "purpose": "matrix case",
        "asset_variants": {"customer-records": "postgresql"},
        "environment_success": passed,
        "range_build_verified": passed,
        "attack_graph_valid": passed,
        "attack_path_reachable": passed,
        "failure_stage": "" if passed else "asset_setup",
    }


def test_collect_keeps_only_complete_environment_passes(tmp_path):
    shard = tmp_path / "shard-000"
    shard.mkdir()
    (shard / "summary.json").write_text(json.dumps({
        "results": [_result("pass", passed=True), _result("fail", passed=False)]
    }))

    cases, rejected = MODULE.collect_environment_results(tmp_path)

    assert [case["id"] for case in cases] == ["pass"]
    assert rejected[0]["id"] == "fail"
    assert "environment_success" in rejected[0]["failed_conditions"]


def test_collect_rejects_duplicate_case_ids(tmp_path):
    for index in range(2):
        shard = tmp_path / f"shard-{index:03d}"
        shard.mkdir()
        (shard / "summary.json").write_text(json.dumps({
            "results": [_result("duplicate", passed=True)]
        }))

    try:
        MODULE.collect_environment_results(tmp_path)
    except ValueError as exc:
        assert "Duplicate case_id" in str(exc)
    else:
        raise AssertionError("expected duplicate case IDs to be rejected")
