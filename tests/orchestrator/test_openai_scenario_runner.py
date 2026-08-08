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
                    return iter([SimpleNamespace(
                        choices=[SimpleNamespace(
                            delta=SimpleNamespace(content=None, tool_calls=None),
                            finish_reason="stop",
                        )]
                    )])
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
