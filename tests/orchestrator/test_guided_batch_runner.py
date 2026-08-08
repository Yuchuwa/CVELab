import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "verify_enterprise3_guided_batch.py"
SPEC = importlib.util.spec_from_file_location("enterprise3_batch_runner_retry", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)

_should_retry = MODULE._should_retry
summarize = MODULE.summarize
parse_args = MODULE.parse_args
_runner_requires_api_key = MODULE._runner_requires_api_key
validate_agent_parallelism = MODULE.validate_agent_parallelism


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


def test_syspear_runner_is_selectable_without_llm_api_key():
    args = parse_args(["--agent-runner", "syspear"])

    assert args.agent_runner == "syspear"
    assert _runner_requires_api_key("syspear") is False
    assert _runner_requires_api_key("openai") is True


def test_syspear_runner_requires_serial_batch_execution():
    validate_agent_parallelism("syspear", 1)
    try:
        validate_agent_parallelism("syspear", 2)
    except ValueError as exc:
        assert "serially" in str(exc)
    else:
        raise AssertionError("Syspear parallel execution must be rejected")
