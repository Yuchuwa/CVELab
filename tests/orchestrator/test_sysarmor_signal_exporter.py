import importlib.util
import json
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/export_sysarmor_signals.py"


def load_exporter():
    spec = importlib.util.spec_from_file_location("export_sysarmor_signals", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_export_writes_per_case_target_jsonl_and_summary(tmp_path):
    exporter = load_exporter()
    batch = tmp_path / "batch"
    batch.mkdir()
    (batch / "summary.json").write_text(json.dumps({
        "results": [
            {
                "case_id": "case-a",
                "agent_success": True,
                "flag_verification": {
                    "all_captured": True,
                    "per_target": {
                        "target-1": {"captured": True},
                        "target-2": {"captured": False},
                    },
                },
                "sysarmor": {
                    "detection": {
                        "signal_count_before": 1,
                        "signal_count_after": 2,
                        "signal_detected": True,
                    },
                    "signals_before": {
                        "target-1": [{"signalFrame": {"signal": {"id": "old"}}}],
                    },
                    "signals_after": {
                        "target-1": [
                            {"signalFrame": {"signal": {"id": "old"}}},
                            {"signalFrame": {"signal": {"id": "new"}}},
                        ],
                        "target-2": [],
                    },
                },
            }
        ],
    }), encoding="utf-8")

    out = tmp_path / "signals"
    summary = exporter.export_signals(batch, out)

    assert summary["cases"][0]["case_id"] == "case-a"
    assert summary["cases"][0]["signal_detected"] is True
    assert summary["cases"][0]["signals_after_total"] == 2
    assert (out / "case-a" / "target-1-before.jsonl").read_text().count("\n") == 1
    assert (out / "case-a" / "target-1-after.jsonl").read_text().count("\n") == 2
    assert (out / "case-a" / "target-2-after.jsonl").read_text() == ""
    written = json.loads((out / "summary.json").read_text())
    assert written == summary


def test_export_prefers_full_scenario_flag_verification(tmp_path):
    exporter = load_exporter()
    batch = tmp_path / "batch"
    scenario = batch / "scenarios" / "case-a-scenario"
    scenario.mkdir(parents=True)
    (scenario / "verify_result.json").write_text(json.dumps({
        "agent_success": True,
        "flag_verification": {
            "all_captured": True,
            "per_target": {
                "target-1": {"captured": "flag{one}", "match": True},
                "target-2": {"captured": "flag{two}", "match": True},
                "target-3": {"captured": "flag{three}", "match": True},
            },
        },
    }), encoding="utf-8")
    (batch / "summary.json").write_text(json.dumps({
        "results": [
            {
                "case_id": "case-a",
                "agent_success": True,
                "scenario_dir": str(scenario),
                "sysarmor": {
                    "detection": {"signal_detected": False},
                    "signals_before": {},
                    "signals_after": {},
                },
            }
        ],
    }), encoding="utf-8")

    summary = exporter.export_signals(batch, tmp_path / "signals")

    case = summary["cases"][0]
    assert case["flags_all_captured"] is True
    assert case["flags_per_target"]["target-3"]["captured"] == "flag{three}"
