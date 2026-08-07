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


def test_export_writes_windowed_jsonl_and_summary(tmp_path):
    exporter = load_exporter()
    batch = tmp_path / "batch"
    batch.mkdir()
    pre = {"signalFrame": {"signal": {"id": "pre-1"}}}
    attack = {"signalFrame": {"signal": {"id": "attack-1", "ruleId": "rule-a"}}}
    grace = {"signalFrame": {"signal": {"id": "grace-1"}}}
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
                    "detection": {"signal_detected": True},
                    "signals_pre_attack": {"target-1": [pre]},
                    "signals_attack_window": {"target-1": [attack], "target-2": []},
                    "signals_grace_window": {"target-1": [grace]},
                },
            }
        ],
    }), encoding="utf-8")

    out = tmp_path / "signals"
    summary = exporter.export_signals(batch, out)

    case = summary["cases"][0]
    assert case["case_id"] == "case-a"
    assert case["signal_detected"] is True
    assert case["pre_attack_count"] == 1
    assert case["attack_window_count"] == 1
    assert case["grace_window_count"] == 1
    assert case["new_attack_signal_count"] == 1
    assert case["expected_signal_hit"] is False
    assert case["new_rule_ids"] == ["rule-a"]
    assert (out / "case-a" / "target-1-pre-attack.jsonl").read_text().count("\n") == 1
    assert (out / "case-a" / "target-1-attack-window.jsonl").read_text().count("\n") == 1
    assert (out / "case-a" / "target-1-grace-window.jsonl").read_text().count("\n") == 1
    written = json.loads((out / "summary.json").read_text())
    assert written == summary


def test_new_attack_signal_count_subtracts_pre_attack_baseline(tmp_path):
    exporter = load_exporter()
    batch = tmp_path / "batch"
    batch.mkdir()
    existing = {
        "signalFrame": {
            "agentId": "agent-a",
            "sequence": "1",
            "signal": {"id": "sig-1", "ruleId": "rule-a"},
        }
    }
    new = {
        "signalFrame": {
            "agentId": "agent-a",
            "sequence": "2",
            "signal": {"id": "sig-2", "ruleId": "rule-b"},
        }
    }
    (batch / "summary.json").write_text(json.dumps({
        "results": [
            {
                "case_id": "case-a",
                "sysarmor": {
                    "signals_pre_attack": {"target-1": [existing]},
                    "signals_attack_window": {"target-1": [existing, new]},
                    "signals_grace_window": {},
                },
            }
        ],
    }), encoding="utf-8")

    summary = exporter.export_signals(batch, tmp_path / "signals")
    case = summary["cases"][0]
    assert case["pre_attack_count"] == 1
    assert case["attack_window_count"] == 2
    assert case["new_attack_signal_count"] == 1
    assert case["new_rule_ids"] == ["rule-b"]


def test_agent_restart_does_not_hide_new_attack_signal_with_reused_sequence():
    exporter = load_exporter()
    pre = {
        "target-1": [{
            "signalFrame": {
                "agentId": "agent-before",
                "sequence": "1",
                "signal": {"id": "sig-1"},
            }
        }]
    }
    attack = {
        "target-1": [{
            "signalFrame": {
                "agentId": "agent-after",
                "sequence": "1",
                "signal": {"id": "sig-1"},
            }
        }]
    }

    new = exporter._new_signals_by_target(pre, attack)

    assert new == attack


def test_new_attack_signal_count_deduplicates_repeated_after_frames():
    exporter = load_exporter()
    frame = {
        "signalFrame": {
            "agentId": "agent-a",
            "sequence": "1",
            "signal": {"id": "sig-1"},
        }
    }

    new = exporter._new_signals_by_target({}, {"target-1": [frame, frame]})

    assert new == {"target-1": [frame]}


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
                    "signals_pre_attack": {},
                    "signals_attack_window": {},
                    "signals_grace_window": {},
                },
            }
        ],
    }), encoding="utf-8")

    summary = exporter.export_signals(batch, tmp_path / "signals")

    case = summary["cases"][0]
    assert case["flags_all_captured"] is True
    assert case["flags_per_target"]["target-3"]["captured"] == "flag{three}"


def test_expected_signal_hit_is_case_level(tmp_path):
    exporter = load_exporter()
    batch = tmp_path / "batch"
    batch.mkdir()
    expected = tmp_path / "expected.json"
    expected.write_text(json.dumps({
        "cases": {
            "case-a": {
                "expected_rule_ids": [
                    "workload_executes_shell_or_interpreter",
                    "network_client_used_in_workload",
                ]
            }
        }
    }), encoding="utf-8")
    (batch / "summary.json").write_text(json.dumps({
        "results": [
            {
                "case_id": "case-a",
                "sysarmor": {
                    "detection": {"signal_detected": True},
                    "signals_pre_attack": {},
                    "signals_attack_window": {
                        "target-1": [
                            {"signalFrame": {"signal": {"ruleId": "workload_executes_shell_or_interpreter"}}}
                        ],
                        "target-2": [
                            {"signalFrame": {"signal": {"ruleId": "network_client_used_in_workload"}}}
                        ],
                    },
                    "signals_grace_window": {},
                },
            }
        ],
    }), encoding="utf-8")

    summary = exporter.export_signals(batch, tmp_path / "signals", expected)

    case = summary["cases"][0]
    verdict = case["expected_signal_detection"]
    assert case["expected_signal_hit"] is True
    assert verdict["evaluated"] is True
    assert verdict["detected"] is True
    assert verdict["missing_rule_ids"] == []


def test_expected_signal_hit_reports_missing_rules(tmp_path):
    exporter = load_exporter()
    batch = tmp_path / "batch"
    batch.mkdir()
    expected = tmp_path / "expected.json"
    expected.write_text(json.dumps({
        "cases": {
            "case-a": {
                "expected_rule_ids": [
                    "workload_executes_shell_or_interpreter",
                    "execution_tool_opens_network_connection",
                ]
            }
        }
    }), encoding="utf-8")
    (batch / "summary.json").write_text(json.dumps({
        "results": [
            {
                "case_id": "case-a",
                "sysarmor": {
                    "detection": {"signal_detected": True},
                    "signals_pre_attack": {},
                    "signals_attack_window": {
                        "target-1": [
                            {"signalFrame": {"signal": {"ruleId": "workload_executes_shell_or_interpreter"}}}
                        ]
                    },
                    "signals_grace_window": {},
                },
            }
        ],
    }), encoding="utf-8")

    summary = exporter.export_signals(batch, tmp_path / "signals", expected)

    case = summary["cases"][0]
    verdict = case["expected_signal_detection"]
    assert case["expected_signal_hit"] is False
    assert verdict["detected"] is False
    assert verdict["missing_rule_ids"] == ["execution_tool_opens_network_connection"]


def test_expected_signal_hit_requires_new_attack_signal(tmp_path):
    exporter = load_exporter()
    batch = tmp_path / "batch"
    batch.mkdir()
    expected = tmp_path / "expected.json"
    expected.write_text(json.dumps({
        "cases": {
            "case-a": {
                "expected_rule_ids": ["workload_executes_shell_or_interpreter"]
            }
        }
    }), encoding="utf-8")
    existing_shell_signal = {
        "signalFrame": {
            "sequence": "10",
            "signal": {
                "id": "sig-10",
                "ruleId": "workload_executes_shell_or_interpreter",
            },
        }
    }
    new_unrelated_signal = {
        "signalFrame": {
            "sequence": "11",
            "signal": {
                "id": "sig-11",
                "ruleId": "account_database_read",
            },
        }
    }
    (batch / "summary.json").write_text(json.dumps({
        "results": [
            {
                "case_id": "case-a",
                "sysarmor": {
                    "detection": {"signal_detected": True},
                    "signals_pre_attack": {"target-1": [existing_shell_signal]},
                    "signals_attack_window": {"target-1": [existing_shell_signal, new_unrelated_signal]},
                    "signals_grace_window": {},
                },
            }
        ],
    }), encoding="utf-8")

    summary = exporter.export_signals(batch, tmp_path / "signals", expected)

    case = summary["cases"][0]
    assert case["new_attack_signal_count"] == 1
    assert case["new_rule_ids"] == ["account_database_read"]
    assert case["expected_signal_hit"] is False
    verdict = case["expected_signal_detection"]
    assert verdict["observed_rule_ids"] == ["account_database_read"]
    assert verdict["missing_rule_ids"] == ["workload_executes_shell_or_interpreter"]


def test_expected_signal_hit_is_not_evaluated_when_watcher_not_ready(tmp_path):
    exporter = load_exporter()
    batch = tmp_path / "batch"
    batch.mkdir()
    expected = tmp_path / "expected.json"
    expected.write_text(json.dumps({
        "cases": {
            "case-a": {
                "expected_rule_ids": ["workload_executes_shell_or_interpreter"]
            }
        }
    }), encoding="utf-8")
    (batch / "summary.json").write_text(json.dumps({
        "results": [
            {
                "case_id": "case-a",
                "sysarmor": {
                    "detection": {
                        "signal_detected": True,
                        "not_evaluable_reason": "watcher_not_ready",
                    },
                    "signals_pre_attack": {},
                    "signals_attack_window": {
                        "target-1": [
                            {"signalFrame": {"signal": {"ruleId": "workload_executes_shell_or_interpreter"}}}
                        ]
                    },
                    "signals_grace_window": {},
                },
            }
        ],
    }), encoding="utf-8")

    summary = exporter.export_signals(batch, tmp_path / "signals", expected)

    case = summary["cases"][0]
    assert case["signal_detected"] is False
    assert case["expected_signal_hit"] is False
    verdict = case["expected_signal_detection"]
    assert verdict["evaluated"] is False
    assert verdict["missing_rule_ids"] == []
