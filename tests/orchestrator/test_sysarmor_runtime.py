import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from clab_builder.orchestrator.composer import sysarmor_runtime


def test_patch_clab_for_sysarmor_targets_only_attack_path_nodes():
    clab = {
        "name": "case-a",
        "topology": {
            "nodes": {
                "attacker": {"image": "attacker"},
                "target-1": {
                    "image": "original-1",
                    "cmd": "run-1",
                    "binds": ["/data:/data:ro"],
                },
                "target-2": {"image": "original-2", "privileged": True},
            }
        },
    }
    ground_truth = {
        "attack_path": [
            {"service_node": "target-1"},
            {"target_node": "target-2"},
        ]
    }

    targets = sysarmor_runtime.patch_clab_for_sysarmor(clab, ground_truth)

    assert targets == ["target-1", "target-2"]
    assert clab["topology"]["nodes"]["target-1"]["image"] == "original-1"
    assert clab["topology"]["nodes"]["target-1"]["cmd"] == "run-1"
    assert clab["topology"]["nodes"]["target-1"]["restart-policy"] == "unless-stopped"
    assert "/data:/data:ro" in clab["topology"]["nodes"]["target-1"]["binds"]
    assert "/sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro" in clab["topology"]["nodes"]["target-1"]["binds"]
    assert "/sys/fs/bpf:/sys/fs/bpf" in clab["topology"]["nodes"]["target-2"]["binds"]
    assert "privileged" not in clab["topology"]["nodes"]["target-2"]
    assert clab["topology"]["nodes"]["attacker"] == {"image": "attacker"}


def test_signal_delta_reports_detected_when_after_count_increases():
    result = sysarmor_runtime.evaluate_signal_delta(
        before={"target-1": [{"id": "old"}]},
        after={"target-1": [{"id": "old"}, {"id": "new"}], "target-2": []},
        attack_executed=True,
        attack_success=True,
    )

    assert result["signal_count_before"] == 1
    assert result["signal_count_after"] == 2
    assert result["signal_detected"] is True
    assert result["attack_executed"] is True
    assert result["attack_success"] is True


def test_signal_delta_requires_attack_execution():
    result = sysarmor_runtime.evaluate_signal_delta(
        before={},
        after={"target-1": [{"id": "new"}]},
        attack_executed=False,
        attack_success=False,
    )

    assert result["signal_detected"] is False
    assert result["not_evaluable_reason"] == "attack_not_executed"


def test_collect_recent_signals_counts_json_lines_per_target(tmp_path):
    scenario = tmp_path / "scenario"
    scenario.mkdir()
    (scenario / "clab.yaml").write_text("name: lab-a\n", encoding="utf-8")
    completed = subprocess.CompletedProcess(
        [],
        0,
        '{"signalFrame":{"signal":{"id":"a"}}}\nnot-json\n{"signalFrame":{"signal":{"id":"b"}}}\n',
        "",
    )
    with patch.object(sysarmor_runtime.subprocess, "run", return_value=completed) as run:
        signals = sysarmor_runtime.collect_recent_signals(scenario, ["target-1"], limit=20)

    assert list(signals) == ["target-1"]
    assert [item["signalFrame"]["signal"]["id"] for item in signals["target-1"]] == ["a", "b"]
    command = run.call_args.args[0]
    assert command[:3] == ["docker", "exec", "clab-lab-a-target-1"]
    assert command[-6:] == ["--include-recent", "--include-events", "--limit", "20", "--timeout", "10s"]


def test_inject_sysarmor_runtime_invokes_checked_in_injector(tmp_path):
    scenario = tmp_path / "scenario"
    scenario.mkdir()
    (scenario / "clab.yaml").write_text("name: lab-a\n", encoding="utf-8")
    with patch.object(sysarmor_runtime.subprocess, "run") as run:
        run.return_value = subprocess.CompletedProcess([], 0, "ok", "")
        result = sysarmor_runtime.inject_sysarmor_runtime(scenario, ["target-1", "target-2"])

    assert result["ok"] is True
    assert run.call_args.kwargs["timeout"] == 900
    command = run.call_args.args[0]
    assert command[0].endswith("inject-runtime.sh")
    assert command[-4:] == ["--target", "target-1", "--target", "target-2"]


def test_inject_sysarmor_runtime_timeout_output_is_json_serializable(tmp_path):
    scenario = tmp_path / "scenario"
    scenario.mkdir()
    (scenario / "clab.yaml").write_text("name: lab-a\n", encoding="utf-8")

    timeout = subprocess.TimeoutExpired(
        ["inject-runtime.sh"], timeout=300, output=b"partial stdout", stderr=b"partial stderr"
    )
    with patch.object(sysarmor_runtime.subprocess, "run", side_effect=timeout):
        result = sysarmor_runtime.inject_sysarmor_runtime(scenario, ["target-1"])

    assert result["ok"] is False
    assert result["timed_out"] is True
    assert result["stdout"] == "partial stdout"
    assert result["stderr"] == "partial stderr"
    json.dumps(result)


class _FakeProcess:
    def __init__(self, *, returncode: int | None = None):
        self.returncode = returncode
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        if self.returncode is None:
            self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


def test_start_signal_watchers_launches_one_process_per_target(tmp_path):
    scenario = tmp_path / "scenario"
    scenario.mkdir()
    (scenario / "clab.yaml").write_text("name: lab-a\n", encoding="utf-8")

    created: list[_FakeProcess] = []

    def fake_popen(command, stdout=None, stderr=None, text=None):
        created.append(_FakeProcess())
        return created[-1]

    with patch.object(sysarmor_runtime.subprocess, "Popen", side_effect=fake_popen):
        watchers = sysarmor_runtime.start_signal_watchers(scenario, ["target-1", "target-2"])

    assert sorted(watchers) == ["target-1", "target-2"]
    first = watchers["target-1"]
    assert first["container"] == "clab-lab-a-target-1"
    assert first["process"] is created[0]
    assert Path(first["stdout_path"]).name == "target-1.jsonl"
    assert Path(first["stderr_path"]).name == "target-1.stderr.log"
    assert first["command"][:3] == ["docker", "exec", "clab-lab-a-target-1"]


def test_wait_signal_watchers_ready_reports_early_exit(tmp_path):
    watchers = {
        "target-1": {
            "process": _FakeProcess(returncode=7),
            "stdout_path": str(tmp_path / "target-1.jsonl"),
            "stderr_path": str(tmp_path / "target-1.stderr.log"),
            "command": ["docker", "exec"],
        }
    }

    result = sysarmor_runtime.wait_signal_watchers_ready(watchers, timeout=0.1, poll_interval=0.01)

    assert result["ok"] is False
    assert result["ready_targets"] == []
    assert result["failed_targets"]["target-1"]["returncode"] == 7


def test_classify_signal_frames_by_window_uses_observed_at():
    frames = {
        "target-1": [
            {"signalFrame": {"observedAt": "2026-08-04T10:00:00Z", "signal": {"id": "pre"}}},
            {"signalFrame": {"observedAt": "2026-08-04T10:00:02Z", "signal": {"id": "attack"}}},
            {"signalFrame": {"observedAt": "2026-08-04T10:00:04Z", "signal": {"id": "grace"}}},
        ]
    }

    buckets = sysarmor_runtime.classify_signal_frames_by_window(
        frames,
        attack_started_at="2026-08-04T10:00:01Z",
        attack_finished_at="2026-08-04T10:00:03Z",
        grace_finished_at="2026-08-04T10:00:05Z",
    )

    assert [item["signalFrame"]["signal"]["id"] for item in buckets["pre_attack"]["target-1"]] == ["pre"]
    assert [item["signalFrame"]["signal"]["id"] for item in buckets["attack_window"]["target-1"]] == ["attack"]
    assert [item["signalFrame"]["signal"]["id"] for item in buckets["grace_window"]["target-1"]] == ["grace"]


def test_evaluate_signal_stream_uses_attack_window_for_detection():
    result = sysarmor_runtime.evaluate_signal_stream(
        pre_attack={"target-1": [{"signalFrame": {"signal": {"id": "old"}}}]},
        attack_window={"target-1": [{"signalFrame": {"signal": {"id": "new"}}}]},
        grace_window={"target-1": [{"signalFrame": {"signal": {"id": "later"}}}]},
        attack_executed=True,
        attack_success=False,
    )

    assert result["signal_count_before"] == 1
    assert result["signal_count_after"] == 1
    assert result["signal_count_grace"] == 1
    assert result["signal_detected"] is True
    assert result["attack_success"] is False


def test_evaluate_signal_stream_can_be_marked_not_detected_when_not_evaluable():
    result = sysarmor_runtime.evaluate_signal_stream(
        pre_attack={},
        attack_window={"target-1": [{"signalFrame": {"signal": {"id": "new"}}}]},
        grace_window={},
        attack_executed=True,
        attack_success=True,
    )

    result["signal_detected"] = False
    result["event_stream_visible"] = False
    result["sysarmor_healthy"] = False
    result["not_evaluable_reason"] = "watcher_not_ready"

    assert result["signal_count_after"] == 1
    assert result["signal_detected"] is False
    assert result["not_evaluable_reason"] == "watcher_not_ready"
