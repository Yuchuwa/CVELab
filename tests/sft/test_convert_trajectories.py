"""Tests for trajectory-to-SFT conversion."""

import json
import sys
from pathlib import Path

import pytest

# Import the converter directly without package installation.
CONVERTER = Path(__file__).resolve().parents[2] / "sft" / "convert_trajectories_to_sft.py"


@pytest.fixture(scope="module")
def converter():
    spec = __import__("importlib.util").util.spec_from_file_location("convert_trajectories_to_sft", CONVERTER)
    module = __import__("importlib.util").util.module_from_spec(spec)
    sys.modules["convert_trajectories_to_sft"] = module
    spec.loader.exec_module(module)
    return module


class TestNormalizeEvents:
    def test_tool_arguments_are_dicts(self, converter):
        """Claude tool_use input must be kept as dict, not JSON string.

        The Qwen2.5 chat template uses `tool_call.arguments | tojson`. If the
        arguments are already a JSON string, the template renders a double-encoded
        string literal inside <tool_call> tags, which vLLM's Hermes parser cannot
        consume as tool arguments.
        """
        events = [
            {
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [
                        {"type": "text", "text": "I'll run a command."},
                        {
                            "type": "tool_use",
                            "id": "call_1",
                            "name": "Bash",
                            "input": {"command": "id", "timeout": 120},
                        },
                    ],
                },
            },
            {
                "type": "user",
                "message": {
                    "role": "user",
                    "content": [{"type": "tool_result", "tool_use_id": "call_1", "content": "uid=0"}],
                },
            },
        ]
        messages = converter._normalize_events(events)
        assert len(messages) == 2
        msg = messages[0]
        assert msg["role"] == "assistant"
        assert len(msg["tool_calls"]) == 1
        fn = msg["tool_calls"][0]["function"]
        assert fn["name"] == "Bash"
        assert isinstance(fn["arguments"], dict)
        assert fn["arguments"] == {"command": "id", "timeout": 120}

    def test_string_tool_arguments_are_parsed(self, converter):
        """Some backends may serialize tool input as a string; tolerate it."""
        events = [
            {
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "call_1",
                            "name": "Bash",
                            "input": '{"command":"id","timeout":120}',
                        },
                    ],
                },
            },
            {
                "type": "user",
                "message": {
                    "role": "user",
                    "content": [{"type": "tool_result", "tool_use_id": "call_1", "content": "uid=0"}],
                },
            },
        ]
        messages = converter._normalize_events(events)
        assert messages[0]["tool_calls"][0]["function"]["arguments"] == {"command": "id", "timeout": 120}

    def test_sdk_noise_tools_are_dropped(self, converter):
        """TaskCreate/Update/etc. must not leak into training data."""
        events = [
            {
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [
                        {"type": "tool_use", "id": "t1", "name": "TaskCreate", "input": {"description": "x"}},
                        {"type": "tool_use", "id": "t2", "name": "Bash", "input": {"command": "id"}},
                    ],
                },
            },
            {
                "type": "user",
                "message": {
                    "role": "user",
                    "content": [{"type": "tool_result", "tool_use_id": "t2", "content": "uid=0"}],
                },
            },
        ]
        messages = converter._normalize_events(events)
        assert len(messages) == 2
        assert len(messages[0]["tool_calls"]) == 1
        assert messages[0]["tool_calls"][0]["function"]["name"] == "Bash"


class TestRenderedFormat:
    def test_qwen_template_renders_tool_arguments_as_object(self):
        """The converted messages must render with JSON-object arguments.

        This is the contract vLLM's Hermes tool-call parser expects for
        Qwen2.5-Instruct served with --tool-call-parser hermes.
        """
        from transformers import AutoTokenizer

        tokenizer = AutoTokenizer.from_pretrained("Qwen/Qwen2.5-7B-Instruct", trust_remote_code=True)
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Run id"},
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "Bash",
                            "arguments": {"command": "id", "timeout": 120},
                        },
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "call_1", "content": "uid=0"},
        ]
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "Bash",
                    "description": "Run shell commands",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "command": {"type": "string"},
                            "timeout": {"type": "integer"},
                        },
                        "required": ["command"],
                    },
                },
            }
        ]
        text = tokenizer.apply_chat_template(messages, tools=tools, tokenize=False, add_generation_prompt=False)
        import re

        blocks = re.findall(r"<tool_call>\n(.*?)\n</tool_call>", text, re.DOTALL)
        # The Qwen template includes an example block in the system prompt; skip it.
        tool_blocks = [b for b in blocks if '"name":' in b and '"Bash"' in b]
        assert tool_blocks, "expected a Bash tool_call block in rendered text"
        parsed = json.loads(tool_blocks[0])
        assert isinstance(parsed["arguments"], dict)
        assert parsed["arguments"]["command"] == "id"


class TestCompression:
    def test_total_budget_compresses_many_medium_tool_results(self, converter):
        messages = [{"role": "system", "content": "system"}, {"role": "user", "content": "task"}]
        for index in range(20):
            call_id = f"call_{index}"
            messages.extend(
                [
                    {
                        "role": "assistant",
                        "content": "thinking " * 10,
                        "tool_calls": [
                            {
                                "id": call_id,
                                "type": "function",
                                "function": {"name": "Bash", "arguments": {"command": "id"}},
                            }
                        ],
                    },
                    {"role": "tool", "tool_call_id": call_id, "content": "result " * 100},
                ]
            )

        compressed, changed = converter._compress_messages(messages, target_tokens=2048)

        assert changed
        assert converter._estimate_tokens(compressed) <= 2048
        calls = [
            call["id"]
            for message in compressed
            if message.get("role") == "assistant"
            for call in message.get("tool_calls", [])
        ]
        results = [message["tool_call_id"] for message in compressed if message.get("role") == "tool"]
        assert calls == results
