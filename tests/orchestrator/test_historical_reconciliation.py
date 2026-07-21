import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "reconcile_historical_range_results.py"
SPEC = importlib.util.spec_from_file_location("historical_reconciliation", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def _row(**overrides):
    row = {
        "case_id": "case-1",
        "environment_success": True,
        "attack_graph_valid": True,
        "attack_path_reachable": True,
        "guided_trial_evaluated": True,
        "agent_success": True,
        "objective_achieved": True,
        "execution_complete": False,
        "lifecycle": {
            "cleanup": {
                "destroy": {"ok": True},
                "agent_transport": {
                    "ok": False,
                    "errors": ["endpoint attacker not found"],
                },
            },
        },
    }
    row.update(overrides)
    return row


def test_accepts_only_destroy_then_endpoint_not_found_race(tmp_path):
    source = tmp_path / "summary.json"
    source.write_text(json.dumps({"results": [_row()]}))
    rows, counts = MODULE.reconcile(source)
    assert len(rows) == 1
    assert rows[0]["execution_complete_reconciled"] is True
    assert rows[0]["reconciliation_status"] == "accepted_cleanup_only"
    assert counts["reconciled"] == 1


def test_rejects_other_cleanup_failure(tmp_path):
    source = tmp_path / "summary.json"
    row = _row()
    row["lifecycle"]["cleanup"]["destroy"] = {"ok": False}
    source.write_text(json.dumps({"results": [row]}))
    rows, counts = MODULE.reconcile(source)
    assert rows == []
    assert counts["rejected"] == 1


def test_reconciled_output_does_not_copy_observed_progress(tmp_path):
    source = tmp_path / "summary.json"
    row = _row(observed_progress={"flag_claims": [{"reported_flag": "flag{secret}"}]})
    source.write_text(json.dumps({"results": [row]}))
    output = tmp_path / "reconciled.json"
    assert MODULE.main(["--source-summary", str(source), "--output", str(output)]) == 0
    payload = json.loads(output.read_text())
    assert "observed_progress" not in payload["results"][0]
    assert "flag{secret}" not in output.read_text()


def test_derives_case_id_for_standalone_verify_result(tmp_path):
    source = tmp_path / "verify_result.json"
    (tmp_path / "ground_truth.json").write_text(json.dumps({
        "attack_path": [
            {"cve_id": "CVE-2012-1823"},
            {"cve_id": "CVE-2018-16509"},
            {"cve_id": "CVE-2019-9193"},
        ],
    }))
    source.write_text(json.dumps(_row(case_id="")))
    rows, counts = MODULE.reconcile(source)
    assert rows[0]["case_id"] == "matrix-2012-1823-2018-16509-2019-9193"
    assert counts["reconciled"] == 1
