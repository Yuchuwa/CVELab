import importlib.util
import json
from pathlib import Path


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
    assert summary["validation_round"]["model"] == "model-a"
    assert summary["agent_exposure_profile"]["context"] == "l2"
    assert summary["validation_round"]["agent_exposure_profile"]["context"] == "l2"
