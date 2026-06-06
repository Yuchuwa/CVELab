"""Tests for Dataset Saver"""

import json
import pytest
from pathlib import Path

from clab_builder.orchestrator.composer.dataset_saver import (
    _scenario_to_record,
    save_parquet,
    load_parquet,
    DatasetManager,
)


def _make_scenario(name="test-scenario", tpl="dmz_simple", hash_val="abc123"):
    return {
        "name": name,
        "hash": hash_val,
        "template": tpl,
        "clab": {"name": name, "topology": {"nodes": {}, "links": []}},
        "cve_setup": [],
        "injections": [
            {"ip_id": "dmz-target-1", "cve_id": "CVE-2014-6271", "flag": "flag{aaa}", "node_name": "target-1", "zone": "dmz"},
        ],
        "ground_truth": {
            "scenario": name,
            "template": tpl,
            "attack_path": [
                {"step": 1, "target_node": "target-1", "cve_id": "CVE-2014-6271", "zone": "dmz", "flag": "flag{aaa}"},
            ],
        },
    }


def _make_verify_result(all_captured=True):
    return {
        "agent_result": {"success": True, "evidence": ["exploit worked"]},
        "flag_verification": {
            "all_captured": all_captured,
            "per_target": {"target-1": {"match": all_captured, "expected": "flag{aaa}", "captured": "flag{aaa}" if all_captured else ""}},
        },
    }


class TestScenarioToRecord:
    def test_basic_record(self):
        scenario = _make_scenario()
        verify = _make_verify_result()
        record = _scenario_to_record(scenario, verify)

        assert record["scenario_name"] == "test-scenario"
        assert record["template"] == "dmz_simple"
        assert record["scenario_hash"] == "abc123"
        assert record["all_flags_captured"] is True
        assert record["agent_success"] is True
        assert record["num_targets"] == 1
        assert record["verified_at"]

    def test_record_contains_cve_ids(self):
        scenario = _make_scenario()
        verify = _make_verify_result()
        record = _scenario_to_record(scenario, verify)

        cve_ids = json.loads(record["cve_ids"])
        assert "CVE-2014-6271" in cve_ids

    def test_record_attack_path(self):
        scenario = _make_scenario()
        verify = _make_verify_result()
        record = _scenario_to_record(scenario, verify)

        path = json.loads(record["attack_path"])
        assert len(path) == 1
        assert path[0]["flag_captured"] is True


class TestParquetIO:
    def test_save_and_load(self, tmp_path):
        records = [
            {"scenario_name": "s1", "scenario_hash": "h1", "template": "dmz_simple"},
            {"scenario_name": "s2", "scenario_hash": "h2", "template": "dmz_simple"},
        ]
        path = str(tmp_path / "test.parquet")
        save_parquet(records, path)
        loaded = load_parquet(path)
        assert len(loaded) == 2
        assert loaded[0]["scenario_name"] == "s1"

    def test_dedup_on_save(self, tmp_path):
        records = [
            {"scenario_name": "s1", "scenario_hash": "h1", "template": "dmz_simple"},
            {"scenario_name": "s1-dup", "scenario_hash": "h1", "template": "dmz_simple"},
            {"scenario_name": "s2", "scenario_hash": "h2", "template": "dmz_simple"},
        ]
        path = str(tmp_path / "test.parquet")
        save_parquet(records, path)
        loaded = load_parquet(path)
        assert len(loaded) == 2  # h1 deduplicated


class TestDatasetManager:
    def test_add_scenario(self, tmp_path):
        dm = DatasetManager(data_dir=str(tmp_path))

        scenario = _make_scenario()
        verify = _make_verify_result()
        added = dm.add_scenario(scenario, verify)

        assert added is True
        assert dm.parquet_path.exists()

    def test_skip_unverified(self, tmp_path):
        dm = DatasetManager(data_dir=str(tmp_path))

        scenario = _make_scenario()
        verify = _make_verify_result(all_captured=False)
        added = dm.add_scenario(scenario, verify)

        assert added is False
        assert not dm.parquet_path.exists()

    def test_dedup(self, tmp_path):
        dm = DatasetManager(data_dir=str(tmp_path))

        scenario = _make_scenario()
        verify = _make_verify_result()

        added1 = dm.add_scenario(scenario, verify)
        added2 = dm.add_scenario(scenario, verify)  # same hash

        assert added1 is True
        assert added2 is False

    def test_add_multiple(self, tmp_path):
        dm = DatasetManager(data_dir=str(tmp_path))

        for i in range(3):
            s = _make_scenario(name=f"s-{i}", hash_val=f"h-{i}")
            v = _make_verify_result()
            dm.add_scenario(s, v)

        stats = dm.get_stats()
        assert stats["total"] == 3

    def test_stats_empty(self, tmp_path):
        dm = DatasetManager(data_dir=str(tmp_path))
        stats = dm.get_stats()
        assert stats["total"] == 0

    def test_stats_by_template(self, tmp_path):
        dm = DatasetManager(data_dir=str(tmp_path))

        dm.add_scenario(_make_scenario(name="s1", tpl="dmz_simple", hash_val="h1"), _make_verify_result())
        dm.add_scenario(_make_scenario(name="s2", tpl="dmz_simple", hash_val="h2"), _make_verify_result())
        dm.add_scenario(_make_scenario(name="s3", tpl="enterprise_3tier", hash_val="h3"), _make_verify_result())

        stats = dm.get_stats()
        assert stats["total"] == 3
        assert stats["by_template"]["dmz_simple"] == 2
        assert stats["by_template"]["enterprise_3tier"] == 1
