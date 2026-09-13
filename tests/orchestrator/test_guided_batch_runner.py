import importlib.util
import json
import os
import signal
import subprocess
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "verify_enterprise3_guided_batch.py"
SPEC = importlib.util.spec_from_file_location("enterprise3_batch_runner_retry", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)

_should_retry = MODULE._should_retry
summarize = MODULE.summarize
parse_args = MODULE.parse_args
digest_inputs = MODULE._digest_inputs
write_summary = MODULE._write_summary
update_current_attempt_record = MODULE._update_current_attempt_record
release_control_lease = MODULE.release_control_lease
copy_reused_scenario = MODULE._copy_reused_scenario
load_reuse_source = MODULE._load_reuse_source
resume_contract_matches = MODULE._resume_contract_matches


def test_cleanup_failure_after_agent_trial_is_not_retried():
    result = {
        "failure_stage": "",
        "cleanup_failed": True,
        "guided_trial_evaluated": True,
    }

    assert _should_retry(result, attempts=1, interrupted=False) is False


def test_cleanup_failure_before_agent_trial_can_be_retried():
    result = {
        "failure_stage": "",
        "cleanup_failed": True,
        "guided_trial_evaluated": False,
    }

    assert _should_retry(result, attempts=1, interrupted=False) is True


def test_attempt_record_update_repairs_legacy_missing_history():
    """Interrupted/legacy case state must not crash coordinator cleanup."""
    case_state = {"case": {"id": "case-1"}, "attempts": 1}

    update_current_attempt_record(
        case_state,
        failure_stage="agent_quota_exhausted",
        success=False,
    )

    assert case_state["attempt_records"] == [{
        "attempt": 1,
        "started_at": "",
        "log_path": "",
        "failure_stage": "agent_quota_exhausted",
        "success": False,
    }]


def test_release_control_lease_disconnects_endpoints_before_rm(monkeypatch):
    calls = []

    def fake_run(command, **_kwargs):
        calls.append(command)
        if command[:3] == ["docker", "network", "inspect"]:
            return subprocess.CompletedProcess(
                command, 0, json.dumps([{"Containers": {"attacker-id": {}}}]), ""
            )
        if command[:3] == ["docker", "network", "disconnect"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[:3] == ["docker", "network", "rm"]:
            return subprocess.CompletedProcess(command, 0, "network-id", "")
        raise AssertionError(command)

    monkeypatch.setattr(MODULE.subprocess, "run", fake_run)
    result = release_control_lease({"network_name": "cvelab-agent-test"})

    assert result["ok"] is True
    assert ["docker", "network", "disconnect", "-f", "cvelab-agent-test", "attacker-id"] in calls
    assert ["docker", "network", "rm", "cvelab-agent-test"] in calls


def test_release_control_lease_reports_active_endpoint_failure(monkeypatch):
    def fake_run(command, **_kwargs):
        if command[:3] == ["docker", "network", "inspect"]:
            return subprocess.CompletedProcess(
                command, 0, json.dumps([{"Containers": {"attacker-id": {}}}]), ""
            )
        if command[:3] == ["docker", "network", "disconnect"]:
            return subprocess.CompletedProcess(command, 1, "", "permission denied")
        if command[:3] == ["docker", "network", "rm"]:
            return subprocess.CompletedProcess(command, 1, "", "active endpoints")
        raise AssertionError(command)

    monkeypatch.setattr(MODULE.subprocess, "run", fake_run)
    result = release_control_lease({"network_name": "cvelab-agent-test"})

    assert result["ok"] is False
    assert any("active endpoints" in error for error in result["errors"])


def test_cleanup_only_is_a_mode_of_existing_batch_runner():
    assert parse_args(["--cleanup-only"]).cleanup_only is True


def test_reuse_scenarios_option_is_available():
    assert parse_args([
        "--reuse-scenarios-from", "data/old-batch",
    ]).reuse_scenarios_from == "data/old-batch"


def test_template_is_supported_and_part_of_experiment_fingerprint():
    default = parse_args([])
    enterprise5 = parse_args(["--template", "enterprise_5tier"])

    assert enterprise5.template == "enterprise_5tier"
    assert digest_inputs([], default) != digest_inputs([], enterprise5)


def test_manifest_template_must_match_requested_template(tmp_path: Path):
    manifest = tmp_path / "matrix.json"
    manifest.write_text(json.dumps({
        "template": "enterprise_5tier",
        "cases": [],
    }))

    with pytest.raises(SystemExit, match="template differs"):
        MODULE.load_manifest_cases(str(manifest), expected_template="enterprise_3tier")


def test_resume_parallel_option_is_available():
    args = parse_args(["--resume", "--resume-parallel", "2"])

    assert args.resume_parallel == 2


def test_resume_contract_permits_only_scheduler_parallel_change(tmp_path: Path):
    scenario = tmp_path / "scenario"
    scenario.mkdir()
    for name in ("scenario.yaml", "ground_truth.json", "clab.yaml"):
        (scenario / name).write_text("{}\n")
    args = parse_args([
        "--resume", "--resume-parallel", "2", "--agent-context", "l1",
        "--noise-level", "none", "--agent-runner", "openai", "--model", "kimi-k3",
        "--max-turns", "300", "--agent-timeout", "3600", "--case-timeout", "5400",
        "--seed", "1",
    ])
    case = {"id": "case-1", "cves": ["CVE-2021-0001"]}
    state = {
        "selected_case_ids": ["case-1"],
        "options": {
            "environment_only": False, "generate_only": False,
            "agent_timeout": 3600, "max_turns": 300, "seed": 1,
            "case_timeout": 5400, "agent_context": "l1", "noise_level": "none",
            "noise_activity": None, "noise_activity_config": MODULE.noise_activity_config(args),
            "model": "kimi-k3", "agent_runner": "openai", "reuse_scenarios_from": "",
            "parallel": 8,
        },
        "cases": {"case-1": {"case": case, "scenario_dir": str(scenario)}},
    }

    assert resume_contract_matches(state, [case], args)
    state["options"]["max_turns"] = 100
    assert not resume_contract_matches(state, [case], args)


def test_copy_reused_scenario_preserves_fixture_and_discards_old_result(tmp_path: Path):
    source = tmp_path / "source" / "e3-old"
    source.mkdir(parents=True)
    (source / "scenario.yaml").write_text("name: e3-old\nip: 10.10.1.9\n")
    (source / "ground_truth.json").write_text(
        '{"scenario": "e3-old", "attack_path": []}\n'
    )
    (source / "clab.yaml").write_text("name: e3-old\n")
    ansible = source / "ansible"
    ansible.mkdir()
    (ansible / "base.yaml").write_text("docker exec clab-e3-old-target-1\n")
    workspace = source / "agent_workspace"
    workspace.mkdir()
    (workspace / "session.json").write_text("old agent evidence\n")
    (source / "verify_result.json").write_text('{"old": true}\n')

    target = tmp_path / "target" / "e3-new"
    copied = copy_reused_scenario(source, target, "e3-new")

    assert copied["source_lab_name"] == "e3-old"
    assert "10.10.1.9" in (target / "scenario.yaml").read_text()
    assert "e3-new" in (target / "ground_truth.json").read_text()
    assert "clab-e3-new-target-1" in (target / "ansible" / "base.yaml").read_text()
    assert not (target / "agent_workspace").exists()
    assert not (target / "verify_result.json").exists()


def test_reuse_source_rejects_a_non_topology_clab_file(tmp_path: Path):
    source = tmp_path / "source"
    scenario = source / "scenarios" / "e3-old"
    scenario.mkdir(parents=True)
    (scenario / "scenario.yaml").write_text("name: e3-old\nagent_context: l1\n")
    (scenario / "ground_truth.json").write_text(
        '{"scenario": "e3-old", "noise_nodes": []}\n'
    )
    (scenario / "clab.yaml").write_text('{"cases": {"not": "a topology"}}\n')
    (scenario / "ansible").mkdir()
    (source / "batch_state.json").write_text(json.dumps({
        "cases": {
            "case-1": {
                "case": {"id": "case-1", "cves": []},
                "lab_name": "e3-old",
                "scenario_dir": str(scenario),
            },
        },
    }))

    with pytest.raises(SystemExit, match="topology is invalid"):
        load_reuse_source(
            source, [{"id": "case-1", "cves": []}],
            agent_context="l1", noise_level="none",
        )


def test_reuse_source_rejects_legacy_l1_for_entry_discovery(tmp_path: Path):
    source = tmp_path / "source"
    scenario = source / "scenarios" / "e3-old"
    scenario.mkdir(parents=True)
    (scenario / "scenario.yaml").write_text(
        "name: e3-old\nagent_context: l1\ninjections: []\n"
    )
    (scenario / "ground_truth.json").write_text(
        '{"scenario": "e3-old", "noise_nodes": []}\n'
    )
    (scenario / "clab.yaml").write_text(
        "name: e3-old\ntopology: {nodes: {attacker: {}}}\n"
    )
    (scenario / "ansible").mkdir()
    (source / "batch_state.json").write_text(json.dumps({
        "cases": {
            "case-1": {
                "case": {"id": "case-1", "cves": []},
                "lab_name": "e3-old",
                "scenario_dir": str(scenario),
            },
        },
    }))

    with pytest.raises(SystemExit, match="context differs"):
        load_reuse_source(
            source, [{"id": "case-1", "cves": []}],
            agent_context="l1_entry_discovery", noise_level="none",
        )


def test_cleanup_only_sweeps_runtime_prepared_topologies(tmp_path, monkeypatch):
    scenario_dir = tmp_path / "scenario"
    scenario_dir.mkdir()
    (scenario_dir / "clab.yaml").write_text("name: fixture\n")
    result_path = tmp_path / "result.json"
    state = {
        "selected_case_ids": ["case-1"],
        "cases": {
            "case-1": {
                "case": {"id": "case-1", "purpose": "test", "cves": []},
                "status": "runtime_prepared",
                "scenario_dir": str(scenario_dir),
                "result_path": str(result_path),
                "attempts": 0,
            },
        },
    }
    calls = []
    monkeypatch.setattr(
        MODULE, "_janitor",
        lambda item, _management: calls.append(item["case"]["id"]) or {"ok": True},
    )
    monkeypatch.setattr(MODULE, "_persist", lambda *_args: None)

    MODULE._cleanup_incomplete_cases(
        state, tmp_path, {}, reason="cleanup_only", include_prepared=True,
    )

    assert calls == ["case-1"]
    assert state["cases"]["case-1"]["status"] == "interrupted"


def test_batch_state_normalization_keeps_attempt_history_explicit():
    state = MODULE.normalize_batch_state({
        "schema_version": 1,
        "cases": {
            "case-1": {
                "case": {"id": "case-1"},
                "status": "running",
                "attempts": 1,
                "attempt_records": [{"attempt": 1}],
            },
        },
    })

    assert state["cases"]["case-1"]["attempt_records"] == [{"attempt": 1}]


def test_batch_state_normalization_keeps_worker_lifecycle_fields():
    state = MODULE.normalize_batch_state({
        "schema_version": 1,
        "cases": {
            "case-1": {
                "case": {"id": "case-1"},
                "status": "running",
                "attempts": 1,
                "worker_pid": 123,
                "worker_pgid": 123,
                "worker_start_ticks": "456",
                "worker_result_path": "/tmp/attempt.json",
                "attempt_fence_path": "/tmp/fence.json",
            },
        },
    })

    item = state["cases"]["case-1"]
    assert item["worker_pid"] == 123
    assert item["worker_pgid"] == 123
    assert item["worker_start_ticks"] == "456"
    assert item["worker_result_path"] == "/tmp/attempt.json"
    assert item["attempt_fence_path"] == "/tmp/fence.json"


def test_persist_preserves_case_entry_identity(tmp_path: Path, monkeypatch):
    case = {
        "case": {"id": "case-1"},
        "status": "running",
        "attempts": 1,
        "scenario_dir": str(tmp_path / "scenario"),
        "result_path": str(tmp_path / "result.json"),
        "worker_pid": 123,
    }
    state = {
        "schema_version": 1,
        "options": {},
        "selected_case_ids": ["case-1"],
        "cases": {"case-1": case},
    }
    monkeypatch.setattr(MODULE, "_write_summary", lambda *_args: None)
    monkeypatch.setattr(MODULE, "atomic_json", lambda *_args: None)

    MODULE._persist(tmp_path, state)

    assert state["cases"]["case-1"] is case
    assert case["worker_pid"] == 123


def test_worker_result_fence_blocks_late_write_after_revoke(tmp_path: Path, monkeypatch):
    fence = tmp_path / "fence.json"
    result_path = tmp_path / "attempt.json"
    spec = {
        "run_id": "run-1",
        "case": {"id": "case-1"},
        "attempt": 1,
        "attempt_token": "token-1",
        "attempt_fence_path": str(fence),
        "worker_result_path": str(result_path),
        "coordinator_pid": os.getpid(),
        "coordinator_start_ticks": MODULE._proc_start_ticks(os.getpid()),
    }
    MODULE.atomic_json(fence, {
        "token": "token-1", "run_id": "run-1", "case_id": "case-1",
        "attempt": 1, "coordinator_pid": os.getpid(),
        "coordinator_start_ticks": MODULE._proc_start_ticks(os.getpid()),
    })

    monkeypatch.setattr(MODULE.os, "getppid", lambda: os.getpid())
    assert MODULE._write_worker_result(spec, {"success": True}) == 0
    case_state = {
        "case": {"id": "case-1"}, "attempts": 1,
        "result_path": str(tmp_path / "canonical.json"),
        "worker_result_path": str(result_path),
        "attempt_fence_path": str(fence),
    }
    assert MODULE._load_attempt_result(case_state)["success"] is True

    MODULE._revoke_attempt_fence(case_state)
    assert MODULE._write_worker_result(spec, {"success": False}) == 125
    assert json.loads(result_path.read_text())["success"] is True


def test_process_group_escalates_after_grace_timeout(monkeypatch):
    signals = []
    waits = iter((False, True))
    monkeypatch.setattr(MODULE, "_process_group_exists", lambda _pgid: True)
    monkeypatch.setattr(MODULE, "_wait_process_group_exit", lambda _pgid, _timeout: next(waits))
    monkeypatch.setattr(
        MODULE.os, "killpg", lambda pgid, signum: signals.append((pgid, signum))
    )

    result = MODULE._terminate_process_group(321, 321, grace_seconds=1, kill_grace_seconds=1)

    assert result["ok"] is True
    assert signals == [(321, signal.SIGTERM), (321, signal.SIGKILL)]


def test_incomplete_cleanup_stops_workers_before_janitor(tmp_path: Path, monkeypatch):
    scenario_dir = tmp_path / "scenario"
    scenario_dir.mkdir()
    (scenario_dir / "clab.yaml").write_text("name: fixture\n")
    item = {
        "case": {"id": "case-1", "purpose": "test", "cves": []},
        "status": "running",
        "attempts": 1,
        "scenario_dir": str(scenario_dir),
        "result_path": str(tmp_path / "result.json"),
        "worker_result_path": str(tmp_path / "attempt.json"),
        "attempt_fence_path": str(tmp_path / "fence.json"),
        "worker_pid": 321,
        "worker_pgid": 321,
        "attempt_records": [{"attempt": 1}],
    }
    state = {"selected_case_ids": ["case-1"], "cases": {"case-1": item}}
    events = []
    monkeypatch.setattr(MODULE, "_revoke_attempt_fence", lambda _item: events.append("revoke"))
    monkeypatch.setattr(
        MODULE, "_terminate_recorded_worker",
        lambda _item: events.append("terminate") or {"ok": True},
    )
    monkeypatch.setattr(MODULE, "_load_attempt_result", lambda _item: None)
    monkeypatch.setattr(
        MODULE, "_janitor", lambda _item, _management: events.append("janitor") or {"ok": True}
    )
    monkeypatch.setattr(MODULE, "_save_case_result", lambda *_args: None)
    monkeypatch.setattr(MODULE, "_persist", lambda *_args: None)

    MODULE._cleanup_incomplete_cases(state, tmp_path, {}, reason="coordinator_exit")

    assert events == ["revoke", "terminate", "janitor"]


def test_summary_preserves_agent_evaluation_marker(tmp_path: Path):
    summary = summarize(
        {"id": "case-1", "purpose": "test", "cves": ["CVE-TEST"]},
        tmp_path,
        {
            "success": True,
            "agent_evaluated": True,
            "guided_trial_evaluated": True,
            "agent_success": True,
        },
    )

    assert summary["agent_evaluated"] is True
    assert summary["guided_trial_evaluated"] is True
    assert summary["success"] is True


def test_no_guide_context_is_included_in_batch_summary():
    args = parse_args(["--agent-context", "no-guide"])
    assert args.agent_context == "no-guide"
    summary = summarize(
        {"id": "case-1", "purpose": "test", "cves": ["CVE-TEST"]},
        Path("/tmp/case-1"),
        {"agent_context": "no_guide", "agent_evaluated": True},
    )
    assert summary["agent_context"] == "no_guide"


def test_no_hint_context_is_supported_and_recorded():
    args = parse_args(["--agent-context", "no-hint"])
    assert args.agent_context == "no-hint"
    summary = summarize(
        {"id": "case-no-hint", "purpose": "test", "cves": ["CVE-TEST"]},
        Path("/tmp/case-no-hint"),
        {
            "agent_context": "no_hint",
            "hint_profile": "exploit_hints_removed",
            "prompt_hygiene": {"ok": True},
            "agent_evaluated": True,
        },
    )
    assert summary["agent_context"] == "no_hint"
    assert summary["hint_profile"] == "exploit_hints_removed"
    assert summary["prompt_hygiene"]["ok"] is True


def test_l1_entry_discovery_context_is_supported_and_recorded():
    args = parse_args(["--agent-context", "l1-entry-discovery"])
    assert args.agent_context == "l1-entry-discovery"
    summary = summarize(
        {"id": "case-entry", "purpose": "test", "cves": ["CVE-TEST"]},
        Path("/tmp/case-entry"),
        {"agent_context": "l1_entry_discovery"},
    )
    assert summary["agent_context"] == "l1_entry_discovery"
    assert summary["agent_exposure_profile"]["profile"] == (
        "level_l1_entry_discovery_hints_removed"
    )


def test_summary_preserves_requested_profile_on_mismatch():
    summary = summarize(
        {"id": "case-mismatch", "purpose": "test", "cves": ["CVE-TEST"]},
        Path("/tmp/case-mismatch"),
        {
            "agent_context": "guided",
            "agent_exposure_profile": {"context": "guided"},
            "requested_agent_context": "no_guide",
            "requested_agent_exposure_profile": {"context": "no_guide"},
            "failure_stage": "agent_exposure_profile_mismatch",
        },
    )

    assert summary["requested_agent_context"] == "no_guide"
    assert summary["requested_agent_exposure_profile"]["context"] == "no_guide"


def test_model_is_part_of_experiment_fingerprint():
    first = parse_args(["--model", "model-a"])
    second = parse_args(["--model", "model-b"])

    assert digest_inputs([], first) != digest_inputs([], second)


def test_exposure_profile_and_seed_are_part_of_experiment_fingerprint():
    guided = parse_args(["--agent-context", "guided", "--seed", "1"])
    no_hint = parse_args(["--agent-context", "no-hint", "--seed", "1"])
    other_seed = parse_args(["--agent-context", "guided", "--seed", "2"])

    assert digest_inputs([], guided) != digest_inputs([], no_hint)
    assert digest_inputs([], guided) != digest_inputs([], other_seed)


def test_noise_activity_is_part_of_fingerprint_and_case_summary():
    off = parse_args(["--noise-level", "high", "--noise-activity", "off"])
    normal = parse_args(["--noise-level", "high", "--noise-activity", "normal"])
    assert digest_inputs([], off) != digest_inputs([], normal)

    activity = {"mode": "normal", "activity_valid": True}
    summary = summarize(
        {"id": "case-noise", "purpose": "test", "cves": ["CVE-TEST"]},
        Path("/tmp/case-noise"),
        {"noise_activity": activity},
    )
    assert summary["noise_activity"] == activity


def test_noise_activity_config_is_part_of_fingerprint_and_parsed():
    baseline = parse_args(["--noise-level", "high", "--noise-activity", "normal"])
    changed = parse_args([
        "--noise-level", "high", "--noise-activity", "normal",
        "--noise-interval-min", "1", "--noise-interval-max", "1",
        "--noise-duration", "30", "--noise-max-failures", "2",
    ])
    assert baseline.noise_interval_min == 2
    assert baseline.noise_interval_max == 5
    assert baseline.noise_duration == 0
    assert baseline.noise_max_failures == 0
    assert digest_inputs([], baseline) != digest_inputs([], changed)


def test_generate_only_requires_runtime_preflight_before_success(tmp_path, monkeypatch):
    """A generated scenario with a failed image check cannot be reported green."""
    ready_result = tmp_path / "ready.json"
    failed_result = tmp_path / "failed.json"
    state = {
        "selected_case_ids": ["ready", "failed"],
        "cases": {
            "ready": {
                "case": {"id": "ready", "purpose": "test", "cves": ["CVE-READY"]},
                "status": "generated", "scenario_dir": str(tmp_path / "ready"),
                "result_path": str(ready_result),
            },
            "failed": {
                "case": {"id": "failed", "purpose": "test", "cves": ["CVE-FAILED"]},
                "status": "generated", "scenario_dir": str(tmp_path / "failed"),
                "result_path": str(failed_result),
            },
        },
    }
    args = parse_args(["--generate-only", "--agent-context", "l1"])

    def fake_prewarm(current, _args, _output):
        current["cases"]["ready"]["status"] = "runtime_prepared"
        current["cases"]["failed"]["status"] = "completed"
        failed_result.write_text(json.dumps({
            "case_id": "failed", "success": False,
            "failure_stage": "runtime_materialization",
        }))

    monkeypatch.setattr(MODULE, "_prewarm_cases", fake_prewarm)
    monkeypatch.setattr(MODULE, "_persist", lambda *_args: None)
    ok = MODULE._complete_generate_only_preflight(
        state, args, tmp_path, {"context": "l1"},
    )

    assert ok is False
    assert state["cases"]["ready"]["status"] == "completed"
    assert state["cases"]["failed"]["status"] == "completed"
    assert json.loads(ready_result.read_text())["success"] is True
    failed = json.loads(failed_result.read_text())
    assert failed["success"] is False
    assert failed["failure_stage"] == "runtime_materialization"


def test_hygiene_abort_and_not_evaluated_are_outside_agent_denominator():
    assert MODULE._agent_attempt_evaluated({
        "agent_evaluated": True,
        "agent_termination_reason": "prompt_hygiene",
    }) is False
    assert MODULE._agent_attempt_evaluated({
        "agent_evaluated": True,
        "prompt_hygiene": {"profile": "not_evaluated", "ok": None},
    }) is False
    assert MODULE._agent_attempt_evaluated({
        "agent_evaluated": True,
        "prompt_hygiene": {"profile": "not_applicable", "ok": True},
    }) is True


def test_batch_summary_records_model_and_runner(tmp_path):
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps({"case_id": "case-1"}))
    state = {
        "run_id": "run-1",
        "created_at": "2026-07-30T00:00:00+00:00",
        "fingerprint": "fingerprint",
        "selected_case_ids": ["case-1"],
        "cases": {
            "case-1": {
                "result_path": str(result_path),
                "status": "completed",
            }
        },
        "options": {
            "environment_only": False,
            "agent_context": "l2",
            "noise_level": "none",
            "noise_activity": "normal",
            "model": "model-a",
            "agent_runner": "openai",
            "max_turns": 100,
            "agent_timeout": 1800,
        },
    }

    write_summary(tmp_path, state)
    summary = json.loads((tmp_path / "summary.json").read_text())

    assert summary["model"] == "model-a"
    assert summary["agent_runner"] == "openai"
    assert summary["noise_activity"] == "normal"
    assert summary["validation_round"]["model"] == "model-a"
    assert summary["validation_round"]["noise_activity"] == "normal"
    assert summary["agent_exposure_profile"]["context"] == "l2"
    assert summary["validation_round"]["agent_exposure_profile"]["context"] == "l2"
