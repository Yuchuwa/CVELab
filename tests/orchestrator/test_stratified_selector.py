"""Tests for the difficulty-stratified selector."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import importlib.util
_spec = importlib.util.spec_from_file_location(
    "select_difficulty_stratified", ROOT / "scripts" / "select_difficulty_stratified.py")
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


def _mk_case(cid, cves):
    return {"id": cid, "cves": cves, "purpose": "t",
            "slot_atoms": {"dmz-web": cves[0], "app-service": cves[1], "data-store": cves[2]},
            "service_families": {}, "asset_variants": {}}


def test_pass_rates_conditional(tmp_path):
    cases = [
        {"cves": ["A", "X", "D"], "t1": True, "t2": True, "t3": True},
        {"cves": ["A", "X", "D"], "t1": True, "t2": False, "t3": False},
        {"cves": ["A", "Y", "D"], "t1": False, "t2": False, "t3": False},
    ]
    e, m, d = _mod._pass_rates(cases)
    # entry A: 2 passed / 3 total
    assert e["A"] == [2, 3]
    # mid X conditional on entry pass: 1 passed / 2 total (only 2 cases had t1)
    assert m["X"] == [1, 2]
    # mid Y: entry never passed, so 0/0 in mid dict
    assert m["Y"] == [0, 0]
    # data D conditional on entry+mid pass: 1/1
    assert d["D"] == [1, 1]


def test_tier_thresholds():
    assert _mod._tier(8, 10) == "easy"      # 0.80
    assert _mod._tier(7, 10) == "easy"      # 0.70
    assert _mod._tier(5, 10) == "mid"       # 0.50
    assert _mod._tier(4, 10) == "mid"       # 0.40
    assert _mod._tier(3, 10) == "hard"      # 0.30
    assert _mod._tier(0, 5) == "hard"
    assert _mod._tier(0, 1) == "unknown"    # n<2


def test_cell_observations_buckets_by_entry_mid_tier():
    cases = [
        {"cves": ["A", "X", "D"], "t1": True, "t2": True, "t3": True},
        {"cves": ["A", "X", "D"], "t1": True, "t2": False, "t3": False},
    ]
    e = {"A": [2, 2]}   # easy
    m = {"X": [1, 2]}   # mid (0.5)
    obs = _mod._cell_observations(cases, e, m)
    assert obs[("easy", "mid")]["n"] == 2
    assert obs[("easy", "mid")]["flag3"] == 1
    assert obs[("easy", "mid")]["sum_flag"] == 4  # (1+1+1) + (1+0+0)
