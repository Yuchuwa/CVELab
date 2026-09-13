"""Tests for openai_scenario_runner argument parsing robustness."""

import json
import sys
from types import SimpleNamespace
from pathlib import Path

import pytest

# Import the module directly without requiring package installation.
RUNNER = Path(__file__).resolve().parents[2] / "src" / "clab_builder" / "orchestrator" / "composer" / "openai_scenario_runner.py"


@pytest.fixture(scope="module")
def runner():
    spec = __import__("importlib.util").util.spec_from_file_location("openai_scenario_runner", RUNNER)
    module = __import__("importlib.util").util.module_from_spec(spec)
    sys.modules["openai_scenario_runner"] = module
    spec.loader.exec_module(module)
    return module


class TestParseToolArguments:
    def test_normal_object(self, runner):
        assert runner._parse_tool_arguments('{"command": "ls", "timeout": 60}') == {
            "command": "ls",
            "timeout": 60,
        }

    def test_double_encoded_string(self, runner):
        # vLLM/Hermes sometimes wraps the JSON object in a JSON string literal.
        raw = '"{\\"command\\": \\"nmap -sV\\", \\"timeout\\": 120000}"'
        assert runner._parse_tool_arguments(raw) == {
            "command": "nmap -sV",
            "timeout": 120000,
        }

    def test_malformed_string_returns_error_marker(self, runner):
        # Model emitted a string literal, not a valid object.
        raw = '"{\\"commanmap -sV\\", \\"timeout\\": 120000}"'
        parsed = runner._parse_tool_arguments(raw)
        assert parsed.get("__parse_error__") is True
        assert "__raw__" in parsed

    def test_invalid_json_returns_error_marker(self, runner):
        assert runner._parse_tool_arguments("not json").get("__parse_error__") is True

    def test_empty_arguments(self, runner):
        assert runner._parse_tool_arguments("") == {}
        assert runner._parse_tool_arguments(None) == {}

    def test_dict_passthrough(self, runner):
        d = {"command": "id"}
        assert runner._parse_tool_arguments(d) is d

    def test_non_string_non_dict(self, runner):
        parsed = runner._parse_tool_arguments(123)
        assert parsed.get("__parse_error__") is True
        assert parsed.get("__raw__") == "123"


class TestToolEnvironment:
    def test_model_credentials_are_not_inherited_by_tools(self, runner, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "secret")
        monkeypatch.setenv("OPENAI_BASE_URL", "http://gateway")
        monkeypatch.setenv("PATH", "/bin")

        env = runner._tool_environment()

        assert "OPENAI_API_KEY" not in env
        assert "OPENAI_BASE_URL" not in env
        assert env["PATH"] == "/bin"


class TestFinalReportRecovery:
    def test_finalization_prompt_is_compact_and_schema_explicit(self, runner):
        prompt = runner._finalization_prompt(1, "length")

        assert "single line" in prompt
        assert "Markdown fences" in prompt
        for field in (
            "success",
            "verified_flags",
            "objective_results",
            "attack_log",
            "evidence",
            "failed_targets",
        ):
            assert field in prompt

    def test_extract_json_skips_truncated_report_and_reads_later_complete_report(self, runner):
        from clab_builder.orchestrator.composer.scenario_runner import extract_json

        text = (
            "The first report was cut off:\n"
            "```json\n"
            '{"success": true, "verified_flags": '
            '{"target-1": "flag{old}"}, "target'
            "\n```\n"
            "Retry:\n"
            "```JSON\n"
            '{"success": true, "verified_flags": '
            '{"target-1": "flag{new}"}, '
            '"objective_results": {"read-customer-records": '
            '{"achieved": true, "evidence": "CVELAB-CANARY"}}, '
            '"attack_log": [{"actions": ["value with } brace"]}], '
            '"evidence": [], "failed_targets": []}'
            "\n```"
        )

        result = extract_json(text)

        assert result is not None
        assert result["verified_flags"]["target-1"] == "flag{new}"
        assert result["objective_results"]["read-customer-records"]["achieved"] is True

    def test_extract_json_does_not_promote_nested_payload_to_report(self, runner):
        from clab_builder.orchestrator.composer.scenario_runner import extract_json

        # The outer report is truncated after a complete objective payload.
        # The nested object must not satisfy the final-report contract on its
        # own; otherwise the runner would mark a malformed report structured.
        text = (
            "```json\n"
            '{"success": true, "objective_results": '
            '{"read-customer-records": {"evidence": "partial"}'
            "\n```\n"
        )

        assert extract_json(text) is None

    def test_extract_json_rejects_invalid_report_field_shapes(self, runner):
        from clab_builder.orchestrator.composer.scenario_runner import extract_json

        text = '{"success": true, "verified_flags": ["flag{not-a-map}"]}'

        assert extract_json(text) is None

    def test_agent_report_cannot_overwrite_runner_audit_fields(self, runner, tmp_path, monkeypatch):
        import openai

        class FakeCompletions:
            @staticmethod
            def create(**kwargs):
                return iter([SimpleNamespace(
                    choices=[SimpleNamespace(
                        delta=SimpleNamespace(
                            content=(
                                '{"success": true, "agent_context": "l0", '
                                '"agent_exposure_profile": {"context": "l0"}, '
                                '"prompt_hygiene": {"ok": false}, '
                                '"verified_flags": {"target-1": "flag{x}"}}'
                            ),
                            reasoning_content=None,
                            tool_calls=None,
                        ),
                        finish_reason="stop",
                    )]
                )])

        fake_client = SimpleNamespace(
            chat=SimpleNamespace(completions=FakeCompletions())
        )
        monkeypatch.setattr(openai, "OpenAI", lambda **kwargs: fake_client)
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("OPENAI_BASE_URL", "http://gateway")

        input_path = tmp_path / "input.json"
        output_path = tmp_path / "output.json"
        input_path.write_text(json.dumps({
            "schema_version": 1,
            "scenario_name": "audit-boundary",
            "attacker_ip": "10.0.0.2",
            "agent_context": "guided",
            "agent_exposure_profile": {
                "schema_version": 1, "context": "guided",
                "profile": "full_guide", "hint_profile": "full_guide",
            },
            "targets": [{
                "node_name": "target-1", "cve_id": "CVE-TEST",
                "ip": "10.0.0.3", "ports": [80], "zone": "dmz",
            }],
        }))

        runner.run_agent(str(input_path), str(output_path), max_turns=1)

        result = json.loads(output_path.read_text())
        assert result["success"] is False
        assert result["agent_context"] == "guided"
        assert result["agent_exposure_profile"]["context"] == "guided"
        assert result["prompt_hygiene"]["profile"] == "not_applicable"
        assert result["agent_reported"]["success"] is True
        assert result["agent_reported"]["prompt_hygiene"]["ok"] is False

    def test_tool_history_empty_completion_gets_bounded_finalization(self, runner, tmp_path, monkeypatch):
        import openai

        class FakeCompletions:
            def __init__(self):
                self.calls = 0

            def create(self, **kwargs):
                self.calls += 1
                if self.calls == 1:
                    tool_call = SimpleNamespace(
                        index=0,
                        id="call-1",
                        function=SimpleNamespace(
                            name="Bash", arguments='{"command":"id"}'
                        ),
                    )
                    return iter([SimpleNamespace(
                        choices=[SimpleNamespace(
                            delta=SimpleNamespace(
                                content=None,
                                reasoning_content="reasoning-before-tool",
                                tool_calls=[tool_call],
                            ),
                            finish_reason="tool_calls",
                        )]
                    )])
                if self.calls == 2:
                    assert any(
                        item.get("reasoning_content") == "reasoning-before-tool"
                        for item in kwargs["messages"]
                    )
                    # A reasoning-only completion must not be replayed as an
                    # assistant message with neither content nor tool_calls.
                    assert not any(
                        item.get("role") == "assistant"
                        and item.get("content") is None
                        and not item.get("tool_calls")
                        for item in kwargs["messages"]
                    )
                    return iter([SimpleNamespace(
                        choices=[SimpleNamespace(
                            delta=SimpleNamespace(
                                content=None,
                                reasoning_content="reasoning-only-after-tool",
                                tool_calls=None,
                            ),
                            finish_reason="stop",
                        )]
                    )])
                assert kwargs.get("tools"), (
                    "soft first finalization must keep tools enabled"
                )
                return iter([SimpleNamespace(
                    choices=[SimpleNamespace(
                        delta=SimpleNamespace(
                            content='{"success": false, "evidence": ["final"]}',
                            tool_calls=None,
                        ),
                        finish_reason="stop",
                    )]
                )])

        completions = FakeCompletions()
        fake_client = SimpleNamespace(
            chat=SimpleNamespace(completions=completions)
        )
        monkeypatch.setattr(openai, "OpenAI", lambda **kwargs: fake_client)
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("OPENAI_BASE_URL", "http://gateway")
        monkeypatch.setitem(runner.TOOL_HANDLERS, "Bash", lambda args: "uid=1000(agent)")

        input_path = tmp_path / "input.json"
        output_path = tmp_path / "output.json"
        input_path.write_text(json.dumps({
            "scenario_name": "finalization-test",
            "attacker_ip": "10.0.0.2",
            "agent_context": "guided",
            "targets": [{
                "node_name": "target-1",
                "cve_id": "CVE-TEST",
                "ip": "10.0.0.3",
                "ports": [80],
                "zone": "dmz",
            }],
        }))

        runner.run_agent(str(input_path), str(output_path), max_turns=5)

        result = json.loads(output_path.read_text())
        assert result["structured_result"] is True
        assert result["response_diagnostics"]["empty_completions"] == 1
        assert result["response_diagnostics"]["finalization_attempts"] == 1
        assert result["termination_reason"] == "completed"
        session = (tmp_path / "session.json").read_text()
        assert "finalization_request" in session
        assert completions.calls == 3

    def test_stream_completion_exposes_finish_and_reasoning_metadata(self, runner):
        class _Completions:
            @staticmethod
            def create(**kwargs):
                return iter([SimpleNamespace(
                    choices=[SimpleNamespace(
                        delta=SimpleNamespace(
                            content="thinking",
                            reasoning_content="internal reasoning",
                            tool_calls=None,
                        ),
                        finish_reason="stop",
                    )]
                )])

        client = SimpleNamespace(chat=SimpleNamespace(completions=_Completions()))
        content, tool_calls, metadata = runner._stream_completion(client, "model", [], 100)
        assert content == "thinking"
        assert tool_calls == []
        assert metadata == {
            "finish_reason": "stop",
            "reasoning_content": "internal reasoning",
        }


class TestDeadlineAndSignalPersistence:
    """Deadline finalization + SIGTERM persistence for externally timed-out runs."""

    @staticmethod
    def _write_input(tmp_path):
        input_path = tmp_path / "input.json"
        output_path = tmp_path / "output.json"
        input_path.write_text(json.dumps({
            "scenario_name": "deadline-test",
            "attacker_ip": "10.0.0.2",
            "agent_context": "guided",
            "targets": [{
                "node_name": "target-1", "cve_id": "CVE-TEST",
                "ip": "10.0.0.3", "ports": [80], "zone": "dmz",
            }],
        }))
        return input_path, output_path

    @staticmethod
    def _tool_call_chunk(content=None):
        tool_call = SimpleNamespace(
            index=0, id="call-1",
            function=SimpleNamespace(name="Bash", arguments='{"command":"id"}'),
        )
        return SimpleNamespace(choices=[SimpleNamespace(
            delta=SimpleNamespace(
                content=content, reasoning_content=None, tool_calls=[tool_call]),
            finish_reason="tool_calls",
        )])

    @staticmethod
    def _content_chunk(content):
        return SimpleNamespace(choices=[SimpleNamespace(
            delta=SimpleNamespace(
                content=content, reasoning_content=None, tool_calls=None),
            finish_reason="stop",
        )])

    def test_deadline_forces_finalization_with_tools_disabled(
        self, runner, tmp_path, monkeypatch,
    ):
        import openai

        report = (
            '{"success": true, "verified_flags": {"target-1": "flag{x}"}, '
            '"evidence": ["done"]}'
        )

        class FakeCompletions:
            def __init__(self):
                self.calls = 0
                self.tools_seen = []

            def create(self, **kwargs):
                self.calls += 1
                self.tools_seen.append(kwargs.get("tools"))
                if self.calls == 1:
                    return iter([TestDeadlineAndSignalPersistence._tool_call_chunk()])
                return iter([TestDeadlineAndSignalPersistence._content_chunk(report)])

        completions = FakeCompletions()
        fake_client = SimpleNamespace(
            chat=SimpleNamespace(completions=completions)
        )
        monkeypatch.setattr(openai, "OpenAI", lambda **kwargs: fake_client)
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("OPENAI_BASE_URL", "http://gateway")
        monkeypatch.setenv("AGENT_DEADLINE_EPOCH", "1")
        monkeypatch.setenv("AGENT_FINALIZE_MARGIN", "150")
        monkeypatch.setenv("AGENT_EXIT_MARGIN", "45")
        remaining = iter([1000.0, 100.0, 100.0])
        monkeypatch.setattr(
            runner, "_deadline_remaining", lambda _epoch: next(remaining, 100.0)
        )
        # The tool output carries the flag the final report will claim, so the
        # report-consistency check sees it as observed run evidence.
        monkeypatch.setitem(runner.TOOL_HANDLERS, "Bash", lambda args: "uid=1000(agent)\nflag{x}")

        input_path, output_path = self._write_input(tmp_path)
        runner.run_agent(str(input_path), str(output_path), max_turns=10)

        result = json.loads(output_path.read_text())
        assert result["structured_result"] is True
        assert result["agent_reported"]["success"] is True
        assert result["termination_reason"] == "completed"
        assert result["response_diagnostics"]["finalization_attempts"] == 1
        assert completions.calls == 2
        # Normal exploration exposes tools; the deadline finalization request
        # must be text-only so the model cannot start another long tool call.
        assert completions.tools_seen[0]
        assert completions.tools_seen[1] is None
        assert "finalization_request" in (tmp_path / "session.json").read_text()

    def test_soft_finalization_allows_continuation_then_hard_close(
        self, runner, tmp_path, monkeypatch,
    ):
        """r15 regression: a mid-run reasoning-overflow turn (empty content,
        finish_reason=length, no tool calls) must not hard-close the run.

        Flow: tool turn → reasoning-overflow (soft prompt, tools stay on) →
        agent continues with another tool turn → reasoning-only again (hard
        close, tools disabled) → final report accepted.
        """
        import openai

        class FakeCompletions:
            def __init__(self):
                self.calls = 0
                self.tools_seen = []

            def create(self, **kwargs):
                self.calls += 1
                self.tools_seen.append(kwargs.get("tools"))
                if self.calls in (1, 3):
                    return iter([TestDeadlineAndSignalPersistence._tool_call_chunk()])
                if self.calls in (2, 4):
                    # Reasoning-overflow / narration turn: no content, no
                    # tool calls, finish_reason=length (or stop).
                    return iter([SimpleNamespace(choices=[SimpleNamespace(
                        delta=SimpleNamespace(
                            content="", reasoning_content="long plan",
                            tool_calls=None,
                        ),
                        finish_reason="length" if self.calls == 2 else "stop",
                    )])])
                return iter([TestDeadlineAndSignalPersistence._content_chunk(
                    '{"success": true, "verified_flags": '
                    '{"target-1": "flag{x}"}, "evidence": ["done"]}'
                )])

        completions = FakeCompletions()
        fake_client = SimpleNamespace(
            chat=SimpleNamespace(completions=completions)
        )
        monkeypatch.setattr(openai, "OpenAI", lambda **kwargs: fake_client)
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("OPENAI_BASE_URL", "http://gateway")
        monkeypatch.setitem(
            runner.TOOL_HANDLERS, "Bash", lambda args: "uid=1000(agent)\nflag{x}",
        )
        input_path, output_path = self._write_input(tmp_path)

        runner.run_agent(str(input_path), str(output_path), max_turns=10)

        result = json.loads(output_path.read_text())
        assert result["structured_result"] is True
        assert result["response_diagnostics"]["finalization_attempts"] == 2
        assert completions.calls == 5
        # Soft round (after call 2) keeps tools; hard round (after call 4)
        # goes text-only (tools omitted from the request).
        assert completions.tools_seen[2], "soft finalization must keep tools"
        assert completions.tools_seen[4] is None
        session = (tmp_path / "session.json").read_text()
        assert session.count("finalization_request") == 2
        assert "continue working with tool calls" in session
        assert "Stop all tool use now" in session

    def test_deadline_exit_margin_stops_before_any_api_call(
        self, runner, tmp_path, monkeypatch,
    ):
        import openai

        class FakeCompletions:
            calls = 0

            def create(self, **kwargs):
                type(self).calls += 1
                raise AssertionError("API must not be called once the exit margin is reached")

        fake_client = SimpleNamespace(
            chat=SimpleNamespace(completions=FakeCompletions())
        )
        monkeypatch.setattr(openai, "OpenAI", lambda **kwargs: fake_client)
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("OPENAI_BASE_URL", "http://gateway")
        monkeypatch.setenv("AGENT_DEADLINE_EPOCH", "1")
        monkeypatch.setenv("AGENT_EXIT_MARGIN", "45")
        monkeypatch.setattr(runner, "_deadline_remaining", lambda _epoch: 10.0)

        input_path, output_path = self._write_input(tmp_path)
        runner.run_agent(str(input_path), str(output_path), max_turns=5)

        result = json.loads(output_path.read_text())
        assert FakeCompletions.calls == 0
        assert result["termination_reason"] == "agent_timeout"
        assert result["structured_result"] is False
        assert any(
            "agent_deadline" in item for item in result["agent_reported"]["evidence"]
        )

    def test_sigterm_persists_partial_output_and_restores_handler(
        self, runner, tmp_path, monkeypatch,
    ):
        import openai
        import signal as signal_module

        class FakeCompletions:
            def __init__(self):
                self.calls = 0

            def create(self, **kwargs):
                self.calls += 1
                if self.calls == 1:
                    return iter([TestDeadlineAndSignalPersistence._tool_call_chunk(
                        content="Working on target-1"
                    )])
                raise KeyboardInterrupt("received signal 15")

        completions = FakeCompletions()
        fake_client = SimpleNamespace(
            chat=SimpleNamespace(completions=completions)
        )
        monkeypatch.setattr(openai, "OpenAI", lambda **kwargs: fake_client)
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("OPENAI_BASE_URL", "http://gateway")
        monkeypatch.setitem(runner.TOOL_HANDLERS, "Bash", lambda args: "uid=1000(agent)")

        input_path, output_path = self._write_input(tmp_path)
        runner.run_agent(str(input_path), str(output_path), max_turns=5)

        result = json.loads(output_path.read_text())
        assert completions.calls == 2
        assert result["termination_reason"] == "agent_timeout"
        assert result["partial_result"] is True
        assert any(
            "termination signal" in item
            for item in result["agent_reported"]["evidence"]
        )
        assert (tmp_path / "session.json").exists()
        # run_agent must not leak its SIGTERM handler into the host process.
        assert signal_module.getsignal(signal_module.SIGTERM) is not runner._raise_on_sigterm

    def test_env_float_parsing(self, runner, monkeypatch):
        monkeypatch.delenv("AGENT_DEADLINE_EPOCH", raising=False)
        assert runner._env_float("AGENT_DEADLINE_EPOCH", 0.0) == 0.0
        monkeypatch.setenv("AGENT_DEADLINE_EPOCH", "")
        assert runner._env_float("AGENT_DEADLINE_EPOCH", 0.0) == 0.0
        monkeypatch.setenv("AGENT_DEADLINE_EPOCH", "not-a-number")
        assert runner._env_float("AGENT_DEADLINE_EPOCH", 7.0) == 7.0
        monkeypatch.setenv("AGENT_DEADLINE_EPOCH", "123.5")
        assert runner._env_float("AGENT_DEADLINE_EPOCH", 0.0) == 123.5


class TestFlagLedger:
    """Runner-side flag ledger: survives compression, injected at finalization."""

    def test_finalization_prompt_includes_observed_flags_with_attribution(
        self, runner, tmp_path, monkeypatch,
    ):
        import openai

        report = (
            '{"success": true, "verified_flags": {"target-1": '
            '"flag{aaaa1111bbbb}"}, "evidence": ["done"]}'
        )
        finalization_messages = []

        class FakeCompletions:
            def __init__(self):
                self.calls = 0

            def create(self, **kwargs):
                self.calls += 1
                if self.calls == 1:
                    tool_call = SimpleNamespace(
                        index=0, id="call-1",
                        function=SimpleNamespace(
                            name="Bash", arguments='{"command":"cat /flag"}'
                        ),
                    )
                    return iter([SimpleNamespace(choices=[SimpleNamespace(
                        delta=SimpleNamespace(
                            content="Reading target-1 flag now",
                            reasoning_content=None,
                            tool_calls=[tool_call],
                        ),
                        finish_reason="tool_calls",
                    )])])
                if self.calls == 2:
                    # Reasoning-only completion: triggers bounded finalization.
                    return iter([SimpleNamespace(choices=[SimpleNamespace(
                        delta=SimpleNamespace(
                            content=None, reasoning_content="thinking",
                            tool_calls=None,
                        ),
                        finish_reason="stop",
                    )])])
                finalization_messages.extend(
                    m.get("content", "") for m in kwargs["messages"]
                    if m.get("role") == "user"
                )
                return iter([SimpleNamespace(choices=[SimpleNamespace(
                    delta=SimpleNamespace(content=report, tool_calls=None),
                    finish_reason="stop",
                )])])

        completions = FakeCompletions()
        fake_client = SimpleNamespace(
            chat=SimpleNamespace(completions=completions)
        )
        monkeypatch.setattr(openai, "OpenAI", lambda **kwargs: fake_client)
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("OPENAI_BASE_URL", "http://gateway")
        # The flag only ever appears inside this tool result; the final report
        # can only carry it if the runner ledger re-presents it.
        monkeypatch.setitem(
            runner.TOOL_HANDLERS, "Bash",
            lambda args: "uid=0(root)\nflag{aaaa1111bbbb}",
        )

        input_path = tmp_path / "input.json"
        output_path = tmp_path / "output.json"
        input_path.write_text(json.dumps({
            "scenario_name": "flag-ledger",
            "attacker_ip": "10.0.0.2",
            "agent_context": "guided",
            "targets": [{
                "node_name": "target-1", "cve_id": "CVE-TEST",
                "ip": "10.0.0.3", "ports": [80], "zone": "dmz",
            }],
        }))

        runner.run_agent(str(input_path), str(output_path), max_turns=5)

        result = json.loads(output_path.read_text())
        assert result["structured_result"] is True
        assert result["agent_reported"]["verified_flags"] == {
            "target-1": "flag{aaaa1111bbbb}"
        }
        # The note lists the observed token as memory assistance.  It must not
        # attach a heuristic target attribution: pivot commands constantly
        # mention upstream hosts, so nearest-mention attribution mis-binds
        # flags (r11 / diverse_r3 case-1/case-4 followed wrong injected
        # attributions into swapped reports).
        assert any(
            "flag{aaaa1111bbbb}" in content for content in finalization_messages
        )
        assert not any(
            "target-1=flag{" in content for content in finalization_messages
        )

    def test_context_budget_compression_preserves_flag_tokens(self, runner):
        long_result = "x" * 1500 + " flag{abcd1234efgh5678} " + "y" * 1500
        messages = [
            {"role": "system", "content": "s"},
            {"role": "user", "content": "u"},
            {"role": "tool", "tool_call_id": "c1", "content": long_result},
            {"role": "assistant", "content": "a1"},
            {"role": "assistant", "content": "a2"},
            {"role": "assistant", "content": "a3"},
            {"role": "assistant", "content": "a4"},
            {"role": "assistant", "content": "a5"},
        ]

        compressed, _ = runner._ensure_context_budget(
            messages, 16000, exact_prompt_tokens=1000, exact_max_context=2000,
        )

        compressed_tool = compressed[2]["content"]
        assert "truncated" in compressed_tool
        assert "flag{abcd1234efgh5678}" in compressed_tool

    def test_finalization_prompt_unchanged_without_observed_flags(self, runner):
        # Attempt 1 is the soft prompt (tools stay enabled); the hard close
        # only comes at attempt 2+ or when explicitly forced (deadline path).
        assert runner._finalization_prompt(1, "", "") == runner.SOFT_FINALIZATION_PROMPT
        assert runner._finalization_prompt(2, "", "") == runner.FINAL_REPORT_PROMPT
        assert runner._finalization_prompt(
            1, "deadline (10s left)", "", hard=True
        ).startswith(runner.FINAL_REPORT_PROMPT)
        with_flags = runner._finalization_prompt(1, "stop", "flag{x} (first seen turn 0)")
        assert "Runner note" in with_flags
        assert "flag{x} (first seen turn 0)" in with_flags

    def test_observed_flag_note_empty_ledger(self, runner):
        assert runner._observed_flag_note({}) == ""

    def test_observed_flag_note_lists_tokens_without_attribution(self, runner):
        ledger = {
            "flag{from-target-2}": {"turn": 3, "source": "tool"},
            "flag{from-target-1}": {"turn": 1, "source": "tool"},
        }
        # The note must never produce "target-N=" bindings: nearest-mention
        # attribution mis-binds flags on pivot chains (r11 / diverse_r3).
        note = runner._observed_flag_note(ledger)
        assert "flag{from-target-1}" in note
        assert "flag{from-target-2}" in note
        assert "target-1=" not in note and "target-2=" not in note

    def test_observed_flag_note_renders_first_seen_provenance(self, runner):
        ledger = {
            "flag{echoed}": {"turn": 71, "source": "tool",
                             "cmd": 'echo "t1: flag{echoed}"'},
            "flag{real}": {"turn": 1, "source": "tool",
                           "cmd": "curl -s http://10.0.0.3/index.php"},
        }
        note = runner._observed_flag_note(ledger)
        # Chronological order: the target-produced token precedes the
        # self-echoed one, and each carries its source command so the model
        # can spot recap-echo laundering (r14).
        assert note.index("flag{real}") < note.index("flag{echoed}")
        assert "first seen turn 1" in note and "10.0.0.3" in note
        assert "first seen turn 71" in note and "echo" in note


class TestReportFlagConsistency:
    """Voluntary final reports must not contain flags never observed in the run."""

    @staticmethod
    def _write_input(tmp_path):
        input_path = tmp_path / "input.json"
        output_path = tmp_path / "output.json"
        input_path.write_text(json.dumps({
            "scenario_name": "flag-consistency",
            "attacker_ip": "10.0.0.2",
            "agent_context": "guided",
            "targets": [{
                "node_name": "target-1", "cve_id": "CVE-TEST",
                "ip": "10.0.0.3", "ports": [80], "zone": "dmz",
            }],
        }))
        return input_path, output_path

    @staticmethod
    def _install_client(monkeypatch, runner, completions):
        import openai
        fake_client = SimpleNamespace(
            chat=SimpleNamespace(completions=completions)
        )
        monkeypatch.setattr(openai, "OpenAI", lambda **kwargs: fake_client)
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("OPENAI_BASE_URL", "http://gateway")
        monkeypatch.setitem(
            runner.TOOL_HANDLERS, "Bash",
            lambda args: "uid=0(root)\nflag{real-aaa}",
        )

    @staticmethod
    def _tool_turn(content=None):
        tool_call = SimpleNamespace(
            index=0, id="call-1",
            function=SimpleNamespace(name="Bash", arguments='{"command":"cat /flag"}'),
        )
        return SimpleNamespace(choices=[SimpleNamespace(
            delta=SimpleNamespace(content=content, reasoning_content=None,
                                  tool_calls=[tool_call]),
            finish_reason="tool_calls",
        )])

    @staticmethod
    def _report_turn(flag_value):
        report = json.dumps({
            "success": True,
            "verified_flags": {"target-1": flag_value},
            "evidence": ["done"],
        })
        return SimpleNamespace(choices=[SimpleNamespace(
            delta=SimpleNamespace(content=report, reasoning_content=None,
                                  tool_calls=None),
            finish_reason="stop",
        )])

    def test_unobserved_report_flags_helper(self, runner):
        ledger = {"flag{real-aaa}": {"turn": 0, "source": "tool"}}
        assert runner._unobserved_report_flags(
            {"verified_flags": {"target-1": "flag{real-aaa}"}}, ledger,
        ) == set()
        assert runner._unobserved_report_flags(
            {"verified_flags": {"target-1": "flag{wrong-bbb}"}}, ledger,
        ) == {"flag{wrong-bbb}"}
        assert runner._unobserved_report_flags({}, ledger) == set()
        assert runner._unobserved_report_flags(
            {"verified_flags": ["flag{not-a-map}"]}, ledger,
        ) == set()

    def test_corrupted_voluntary_report_gets_one_bounded_correction(
        self, runner, tmp_path, monkeypatch,
    ):
        class FakeCompletions:
            def __init__(self):
                self.calls = 0
                self.tools_seen = []

            def create(self, **kwargs):
                self.calls += 1
                self.tools_seen.append(kwargs.get("tools"))
                if self.calls == 1:
                    return iter([TestReportFlagConsistency._tool_turn(
                        content="Reading target-1 flag now"
                    )])
                if self.calls == 2:
                    # Voluntary final report with a flag value that never
                    # appeared in this run's evidence.
                    return iter([TestReportFlagConsistency._report_turn(
                        "flag{wrong-bbb}"
                    )])
                return iter([TestReportFlagConsistency._report_turn(
                    "flag{real-aaa}"
                )])

        completions = FakeCompletions()
        self._install_client(monkeypatch, runner, completions)
        input_path, output_path = self._write_input(tmp_path)

        runner.run_agent(str(input_path), str(output_path), max_turns=10)

        result = json.loads(output_path.read_text())
        assert result["structured_result"] is True
        # The corrected report is the one that ships.
        assert result["agent_reported"]["verified_flags"] == {
            "target-1": "flag{real-aaa}"
        }
        assert result["response_diagnostics"]["rejected_flag_values"] == [
            "flag{wrong-bbb}"
        ]
        assert completions.calls == 3
        # The correction round is text-only.
        assert completions.tools_seen[2] is None
        session = (tmp_path / "session.json").read_text()
        assert "report_correction_request" in session
        assert "flag{wrong-bbb}" in session

    def test_clean_report_gets_one_evidence_confirmation(self, runner, tmp_path, monkeypatch):
        class FakeCompletions:
            def __init__(self):
                self.calls = 0

            def create(self, **kwargs):
                self.calls += 1
                if self.calls == 1:
                    return iter([TestReportFlagConsistency._tool_turn()])
                return iter([TestReportFlagConsistency._report_turn("flag{real-aaa}")])

        completions = FakeCompletions()
        self._install_client(monkeypatch, runner, completions)
        input_path, output_path = self._write_input(tmp_path)

        runner.run_agent(str(input_path), str(output_path), max_turns=5)

        result = json.loads(output_path.read_text())
        assert result["structured_result"] is True
        assert result["response_diagnostics"]["rejected_flag_values"] == []
        # A ledger-clean voluntary report still gets exactly one evidence
        # confirmation round (ledger-present values can be mis-bound or
        # self-echoed); the re-emitted report is then accepted.
        assert result["response_diagnostics"]["evidence_confirmation_sent"] is True
        assert completions.calls == 3
        session = (tmp_path / "session.json").read_text()
        assert "evidence_confirmation_request" in session
        assert "report_correction_request" not in session
        # The confirmation presents first-seen provenance so the model can
        # distinguish a target-produced token from its own recap echo.
        assert "first seen turn 0" in session
        assert "cat /flag" in session

    def test_rejection_still_fires_after_a_bounded_finalization(
        self, runner, tmp_path, monkeypatch,
    ):
        """P1 must not be weakened by the evidence-confirmation gate: a report
        answering a bounded finalization prompt still gets rejected when it
        contains a value that never appeared in run tool output."""

        class FakeCompletions:
            def __init__(self):
                self.calls = 0

            def create(self, **kwargs):
                self.calls += 1
                if self.calls == 1:
                    return iter([TestReportFlagConsistency._tool_turn()])
                if self.calls == 2:
                    # Reasoning-only pause -> soft bounded finalization.
                    return iter([SimpleNamespace(choices=[SimpleNamespace(
                        delta=SimpleNamespace(
                            content="", reasoning_content="plan",
                            tool_calls=None,
                        ),
                        finish_reason="stop",
                    )])])
                if self.calls == 3:
                    # Report answering the soft prompt, with a fabricated value.
                    return iter([TestReportFlagConsistency._report_turn(
                        "flag{wrong-bbb}"
                    )])
                return iter([TestReportFlagConsistency._report_turn(
                    "flag{real-aaa}"
                )])

        completions = FakeCompletions()
        self._install_client(monkeypatch, runner, completions)
        input_path, output_path = self._write_input(tmp_path)

        runner.run_agent(str(input_path), str(output_path), max_turns=10)

        result = json.loads(output_path.read_text())
        assert result["structured_result"] is True
        assert result["agent_reported"]["verified_flags"] == {
            "target-1": "flag{real-aaa}"
        }
        assert result["response_diagnostics"]["rejected_flag_values"] == [
            "flag{wrong-bbb}"
        ]
        assert result["response_diagnostics"]["finalization_attempts"] == 1
        session = (tmp_path / "session.json").read_text()
        assert "report_correction_request" in session
        assert "evidence_confirmation_request" not in session

    def test_correction_exhaustion_accepts_second_report(
        self, runner, tmp_path, monkeypatch,
    ):
        class FakeCompletions:
            def __init__(self):
                self.calls = 0

            def create(self, **kwargs):
                self.calls += 1
                if self.calls == 1:
                    return iter([TestReportFlagConsistency._tool_turn()])
                if self.calls == 2:
                    return iter([TestReportFlagConsistency._report_turn("flag{wrong-bbb}")])
                # Still inconsistent after the correction round: accept and
                # record rather than looping.
                return iter([TestReportFlagConsistency._report_turn("flag{wrong-ccc}")])

        completions = FakeCompletions()
        self._install_client(monkeypatch, runner, completions)
        input_path, output_path = self._write_input(tmp_path)

        runner.run_agent(str(input_path), str(output_path), max_turns=10)

        result = json.loads(output_path.read_text())
        assert result["structured_result"] is True
        assert result["agent_reported"]["verified_flags"] == {
            "target-1": "flag{wrong-ccc}"
        }
        assert result["response_diagnostics"]["rejected_flag_values"] == [
            "flag{wrong-bbb}"
        ]
        assert completions.calls == 3
