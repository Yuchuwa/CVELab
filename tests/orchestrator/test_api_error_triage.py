"""Tests for the API error triage added 2026-07-25.

Covers the three-layer contract:
  1. openai_scenario_runner._classify_api_error — text + status-code
     classification into fatal / rate_limit / transient / other.
  2. openai_scenario_runner custom exceptions (QuotaExhaustedError,
     RateLimitPersistentError) propagate to the caller without retry for
     fatal, and only after exhausting retries for rate_limit.
  3. verifier._failure_stage maps the runner's termination_reason values
     to the failure_stage constants the coordinator keys on.

The coordinator's fatal-stop / paused-requeue logic is exercised here via
the shared constants (FATAL_API_STAGE / RATE_LIMIT_API_STAGE) rather than a
full subprocess mock, keeping the test deterministic and fast.
"""
from __future__ import annotations

import pytest


def _runner_module():
    """Import the openai runner module, skipping if openai SDK is absent."""
    import importlib
    try:
        import openai  # noqa: F401
    except ImportError:  # pragma: no cover
        pytest.skip("openai SDK not installed")
    return importlib.import_module("clab_builder.orchestrator.composer.openai_scenario_runner")


def _make_api_error(status_code: int, message: str):
    """Build an openai.APIError-shaped object without hitting the network."""
    openai = pytest.importorskip("openai")
    try:
        return openai.APIError(message, response=_DummyResponse(status_code), body=None)
    except TypeError:
        # Newer openai SDK signatures vary; fall back to a bare Exception with
        # a status_code attribute so _classify_api_error's isinstance + getattr
        # path still exercises the status-code branch.
        class _Stub(Exception):
            def __init__(self, status, msg):
                super().__init__(msg)
                self.status_code = status
        return _Stub(status_code, message)


class _DummyResponse:
    def __init__(self, status_code: int):
        self.status_code = status_code
        self.headers = {}


class TestClassifyApiError:
    """_classify_api_error must separate fatal quota errors from rate-limit
    and transient errors, because the coordinator stops the whole batch on
    fatal but only pauses a single case on rate-limit."""

    def test_fatal_by_text_marker(self):
        m = _runner_module()
        for marker in ["insufficient balance", "quota exceeded", "余额不足",
                       "billing required", "payment required", "credit exhausted"]:
            exc = Exception(marker)
            assert m._classify_api_error(exc) == "fatal", marker

    def test_fatal_by_status_402_403(self):
        m = _runner_module()
        assert m._classify_api_error(_make_api_error(402, "bad request")) == "fatal"
        assert m._classify_api_error(_make_api_error(403, "forbidden")) == "fatal"

    def test_rate_limit_by_text_marker(self):
        m = _runner_module()
        for marker in ["rate limit exceeded", "engine overloaded", "too many requests",
                       "concurrent request limit", "429 too many", "请求过多"]:
            exc = Exception(marker)
            assert m._classify_api_error(exc) == "rate_limit", marker

    def test_rate_limit_by_status_429(self):
        m = _runner_module()
        assert m._classify_api_error(_make_api_error(429, "slow down")) == "rate_limit"

    def test_transient_5xx(self):
        m = _runner_module()
        assert m._classify_api_error(_make_api_error(500, "internal")) == "transient"
        assert m._classify_api_error(_make_api_error(503, "unavailable")) == "transient"

    def test_transient_connection_error(self):
        from openai import APIConnectionError
        import httpx

        m = _runner_module()
        # DNS/TCP/TLS handshake failures have no HTTP status and should be
        # retried (gateway cold start, transient network blip).
        req = httpx.Request("POST", "https://api.moonshot.cn/v1/chat/completions")
        exc = APIConnectionError(message="Connection error.", request=req)
        assert m._classify_api_error(exc) == "transient"

    def test_transient_timeout_error(self):
        from openai import APITimeoutError
        import httpx

        m = _runner_module()
        # Request timeouts also have no HTTP status and should be retried.
        req = httpx.Request("POST", "https://api.moonshot.cn/v1/chat/completions")
        exc = APITimeoutError(request=req)
        assert m._classify_api_error(exc) == "transient"

    def test_other_for_unclassified(self):
        m = _runner_module()
        assert m._classify_api_error(_make_api_error(400, "bad json")) == "other"
        assert m._classify_api_error(Exception("context length exceeded")) == "other"

    def test_fatal_wins_over_rate_limit_when_quota_wrapped_in_429(self):
        """Gateways sometimes wrap a quota-exhaustion body in a 429/5xx
        status. Fatal must take priority so the batch stops rather than
        pausing and retrying a case that can never succeed."""
        m = _runner_module()
        # 429 status + quota text → fatal (text wins).
        exc = _make_api_error(429, "insufficient balance")
        assert m._classify_api_error(exc) == "fatal"


class TestStreamCompletionEscalation:
    """_stream_completion must raise QuotaExhaustedError immediately (no
    retry) for fatal errors, and RateLimitPersistentError only after the
    retry budget is exhausted for rate-limit errors."""

    def test_fatal_raises_immediately_no_retry(self, monkeypatch):
        m = _runner_module()
        sleeps = []
        monkeypatch.setattr("time.sleep", lambda s: sleeps.append(s))

        class _Client:
            class chat:
                class completions:
                    @staticmethod
                    def create(**kwargs):
                        raise _make_api_error(402, "insufficient balance")

        with pytest.raises(m.QuotaExhaustedError):
            m._stream_completion(_Client(), "m", [], 100)
        # Fatal must not retry → no sleeps at all.
        assert sleeps == []

    def test_rate_limit_persists_into_RateLimitPersistentError(self, monkeypatch):
        m = _runner_module()
        monkeypatch.setattr("time.sleep", lambda s: None)

        class _Client:
            class chat:
                class completions:
                    @staticmethod
                    def create(**kwargs):
                        raise _make_api_error(429, "too many requests")

        with pytest.raises(m.RateLimitPersistentError):
            m._stream_completion(_Client(), "m", [], 100)

    def test_transient_eventually_propagates_as_generic_error(self, monkeypatch):
        m = _runner_module()
        monkeypatch.setattr("time.sleep", lambda s: None)

        class _Client:
            class chat:
                class completions:
                    @staticmethod
                    def create(**kwargs):
                        raise _make_api_error(500, "internal error")

        # After MAX_RETRIES transient errors propagate as a generic Exception
        # (not QuotaExhaustedError, not RateLimitPersistentError).
        with pytest.raises(Exception) as ei:
            m._stream_completion(_Client(), "m", [], 100)
        assert not isinstance(ei.value, m.QuotaExhaustedError)
        assert not isinstance(ei.value, m.RateLimitPersistentError)


class TestFailureStageMapping:
    """The verifier must map the runner's termination_reason to the
    failure_stage constants the coordinator keys on."""

    def _common(self):
        return {
            "environment_success": True,
            "setup_results": {},
            "environment": {"all_targets_verified": True},
            "validation_mode": "guided_agent",
            "reference_verified": False,
            "agent_transport": {"ok": True},
            "agent_evaluated": True,
            "attack_graph_valid": True,
            "attack_path_reachable": True,
            "guided_trial_success": False,
            "objective_achieved": False,
            "guide_preflight": {"integrity_valid": True},
        }

    def test_quota_exhausted_maps_to_fatal_stage(self):
        from clab_builder.orchestrator.composer.verifier import ScenarioVerifier
        assert ScenarioVerifier._failure_stage(
            **self._common(), agent_termination_reason="quota_exhausted"
        ) == "agent_quota_exhausted"

    def test_rate_limit_persistent_maps_to_rate_limit_stage(self):
        from clab_builder.orchestrator.composer.verifier import ScenarioVerifier
        assert ScenarioVerifier._failure_stage(
            **self._common(), agent_termination_reason="rate_limit_persistent"
        ) == "agent_rate_limit"

    def test_legacy_agent_api_quota_still_maps_to_fatal_stage(self):
        """Claude-SDK runner still emits the legacy 'agent_api_quota'
        termination reason; the consolidated failure_stage must be the same
        as the new 'quota_exhausted' so the coordinator's fatal-stop branch
        fires for both runners."""
        from clab_builder.orchestrator.composer.verifier import ScenarioVerifier
        assert ScenarioVerifier._failure_stage(
            **self._common(), agent_termination_reason="agent_api_quota"
        ) == "agent_quota_exhausted"


class TestCoordinatorConstants:
    """The coordinator's fatal/rate-limit branches key on
    FATAL_API_STAGE / RATE_LIMIT_API_STAGE; these must equal the
    failure_stage values the verifier emits, otherwise the triage silently
    no-ops."""

    def test_constants_match_verifier_output(self):
        # Import the batch module via its full path (it lives under scripts/).
        import importlib.util
        import sys
        spec = importlib.util.spec_from_file_location(
            "verify_enterprise3_guided_batch",
            "scripts/verify_enterprise3_guided_batch.py",
        )
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        sys.modules["verify_enterprise3_guided_batch"] = mod
        spec.loader.exec_module(mod)
        assert mod.FATAL_API_STAGE == "agent_quota_exhausted"
        assert mod.RATE_LIMIT_API_STAGE == "agent_rate_limit"

    def test_coordinator_action_policy(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "verify_enterprise3_guided_batch",
            "scripts/verify_enterprise3_guided_batch.py",
        )
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert mod._api_error_action(mod.FATAL_API_STAGE, 1) == "stop"
        assert mod._api_error_action(mod.RATE_LIMIT_API_STAGE, 1) == "pause"
        assert mod._api_error_action(mod.RATE_LIMIT_API_STAGE, 3) == "pause"
        assert mod._api_error_action(mod.RATE_LIMIT_API_STAGE, 4) == "finalize"
        assert mod._api_error_action("agent", 1) == "ordinary"
