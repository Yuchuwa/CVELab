"""Tests for the reusable-Range manifest builder (validation-round provenance)."""

import importlib.util
import json
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "build_reusable_ranges_manifest.py"
SPEC = importlib.util.spec_from_file_location("reusable_manifest", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def _write_batch(batch_dir: Path, run_id: str, results: list[dict]) -> None:
    """Write a fake batch summary + per-scenario verify_result.json files."""
    batch_dir.mkdir(parents=True, exist_ok=True)
    scenarios = batch_dir / "scenarios"
    enriched = []
    for case in results:
        sd = scenarios / case["scenario_name"]
        sd.mkdir(parents=True, exist_ok=True)
        vr_path = sd / "verify_result.json"
        vr_path.write_text(json.dumps(case["verify_result"]))
        enriched.append({
            "case_id": case["case_id"],
            "cves": case["cves"],
            "purpose": case.get("purpose", "auto-compatible combination"),
            "asset_variants": case.get("asset_variants", {}),
            "scenario_dir": str(sd),
        })
    (batch_dir / "summary.json").write_text(json.dumps({
        "run_id": run_id,
        "validation_mode": "guided_agent",
        "environment_only": False,
        "agent_context": "guided",
        "noise_level": "none",
        "validation_round": {
            "run_id": run_id,
            "agent_context": "guided",
            "noise_level": "none",
            "environment_only": False,
            "created_at": f"2026-07-20T00:00:{run_id[-1:]}0Z",
        },
        "results": enriched,
    }))


GATE_FIELDS = (
    "environment_success", "attack_graph_valid", "attack_path_reachable",
    "guided_trial_success", "objective_achieved",
)


def _vr(**overrides) -> dict:
    base = {f: True for f in GATE_FIELDS}
    base["validation_mode"] = "guided_agent"
    base["agent_context"] = "guided"
    base.update(overrides)
    return base


def _case(case_id, cves, scenario_name, vr, **extra):
    return {
        "case_id": case_id, "cves": cves, "scenario_name": scenario_name,
        "verify_result": vr, **extra,
    }


def test_only_full_guided_gate_cases_are_kept(tmp_path):
    batch = tmp_path / "batch_ok"
    _write_batch(batch, "run1111111", [
        _case("good-a", ["CVE-A", "CVE-B", "CVE-C"], "s-good-a", _vr()),
        _case("bad-env", ["CVE-X", "CVE-Y", "CVE-Z"], "s-bad-env",
              _vr(environment_success=False, failure_stage="setup:asset_setup")),
        _case("bad-agent", ["CVE-P", "CVE-Q", "CVE-R"], "s-bad-agent",
              _vr(guided_trial_success=False, objective_achieved=False,
                  failure_stage="agent")),
    ])
    out = tmp_path / "manifest.json"
    rc = MODULE.main.__wrapped__ if hasattr(MODULE.main, "__wrapped__") else None
    import subprocess, sys
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), str(batch), "--output", str(out)],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    m = json.loads(out.read_text())
    kept_ids = {c["id"] for c in m["cases"]}
    assert kept_ids == {"good-a"}
    assert m["verified_case_count"] == 1
    assert m["rejected_gate_failures"] == 2
    # Each kept case carries validation_round provenance.
    kept = m["cases"][0]
    assert kept["validation_round"]["run_id"] == "run1111111"
    assert kept["scenario_dir"].endswith("s-good-a")
    assert kept["guided_gate"] == {f: True for f in GATE_FIELDS}


def test_environment_only_batch_is_skipped(tmp_path):
    batch = tmp_path / "batch_env"
    batch.mkdir()
    (batch / "summary.json").write_text(json.dumps({
        "run_id": "envonly", "validation_mode": "guided_agent",
        "environment_only": True, "results": [],
    }))
    out = tmp_path / "manifest.json"
    import subprocess, sys
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), str(batch), "--output", str(out)],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0
    m = json.loads(out.read_text())
    assert m["verified_case_count"] == 0
    assert m["source_batches"][0]["status"] == "skipped_not_guided_full"


def test_dedupe_keeps_latest_validation_round(tmp_path):
    b1 = tmp_path / "b1"
    b2 = tmp_path / "b2"
    # Same case id in both batches, b2 has later created_at.
    _write_batch(b1, "runaaa111", [
        _case("dup-1", ["CVE-A", "CVE-B", "CVE-C"], "s-dup-old", _vr()),
    ])
    # Override b1's validation_round created_at to an earlier time.
    s1 = json.loads((b1 / "summary.json").read_text())
    s1["validation_round"]["created_at"] = "2026-07-20T00:00:00Z"
    (b1 / "summary.json").write_text(json.dumps(s1))
    _write_batch(b2, "runbbb222", [
        _case("dup-1", ["CVE-A", "CVE-B", "CVE-C"], "s-dup-new", _vr()),
    ])
    s2 = json.loads((b2 / "summary.json").read_text())
    s2["validation_round"]["created_at"] = "2026-07-20T12:00:00Z"
    (b2 / "summary.json").write_text(json.dumps(s2))

    out = tmp_path / "manifest.json"
    import subprocess, sys
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), str(b1), str(b2), "--output", str(out)],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    m = json.loads(out.read_text())
    assert m["verified_case_count"] == 1
    kept = m["cases"][0]
    # Latest round (b2) wins.
    assert kept["validation_round"]["run_id"] == "runbbb222"
    assert kept["scenario_dir"].endswith("s-dup-new")
    assert m["superseded_duplicates"] == 1
    assert m["superseded"][0]["id"] == "dup-1"


def test_exclude_ids_removes_specified_cases(tmp_path):
    batch = tmp_path / "b"
    _write_batch(batch, "runcccc33", [
        _case("keep-me", ["CVE-A", "CVE-B", "CVE-C"], "s-keep", _vr()),
        _case("exclude-me", ["CVE-X", "CVE-Y", "CVE-Z"], "s-exc", _vr()),
    ])
    out = tmp_path / "manifest.json"
    import subprocess, sys
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), str(batch), "--output", str(out),
         "--exclude-ids", "exclude-me"],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0
    m = json.loads(out.read_text())
    kept_ids = {c["id"] for c in m["cases"]}
    assert kept_ids == {"keep-me"}
    assert "exclude-me" in m["excluded_ids"]