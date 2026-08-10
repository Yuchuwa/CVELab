"""Tests for trajectory-to-SFT conversion."""

import hashlib
import json
import sys
from pathlib import Path

import pytest

# Import the converter directly without package installation.
CONVERTER = Path(__file__).resolve().parents[2] / "sft" / "convert_trajectories_to_sft.py"
TRAINER = Path(__file__).resolve().parents[2] / "sft" / "train_sft.py"


@pytest.fixture(scope="module")
def converter():
    spec = __import__("importlib.util").util.spec_from_file_location("convert_trajectories_to_sft", CONVERTER)
    module = __import__("importlib.util").util.module_from_spec(spec)
    sys.modules["convert_trajectories_to_sft"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def trainer():
    spec = __import__("importlib.util").util.spec_from_file_location("train_sft", TRAINER)
    module = __import__("importlib.util").util.module_from_spec(spec)
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
        pytest.importorskip("transformers")
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


def _write_source(root: Path, name: str, session, *, openai: bool, case_id: str | None = None):
    case_dir = root / name
    workspace = case_dir / "agent_workspace"
    workspace.mkdir(parents=True)
    verify_result = {
        "agent_context": "l2",
        "agent_success": True,
        "scenario_name": name,
        "validation_round": {"case_id": case_id or name, "run_id": "run-1"},
        "flag_verification": {"per_target": {}},
    }
    (case_dir / "verify_result.json").write_text(json.dumps(verify_result))
    session_path = workspace / "session.json"
    if openai:
        session_path.write_text("".join(json.dumps(event) + "\n" for event in session))
        (workspace / "input.json").write_text(
            json.dumps(
                {
                    "agent_context": "l2",
                    "scenario_name": name,
                    "attacker_ip": "192.0.2.10",
                    "targets": [{"ip": "192.0.2.20", "zone": "dmz"}],
                }
            )
        )
    else:
        session_path.write_text(json.dumps(session))
    return case_dir


def _claude_session():
    return [
        {"type": "user", "message": {"role": "user", "content": "Inspect the target."}},
        {
            "type": "assistant",
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "claude-call-1",
                        "name": "Bash",
                        "input": {"command": "id"},
                    }
                ],
            },
        },
        {
            "type": "user",
            "message": {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "claude-call-1",
                        "content": "uid=0",
                    }
                ],
            },
        },
    ]


def _openai_session():
    return [
        {
            "type": "assistant",
            "message": {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": "openai-call-1",
                        "type": "function",
                        "function": {"name": "Bash", "arguments": '{"command":"id"}'},
                    }
                ],
            },
            "turn": 0,
        },
        {
            "type": "tool",
            "message": {
                "role": "tool",
                "name": "Bash",
                "args": {"command": "id"},
                "result": "uid=0",
            },
            "turn": 0,
        },
    ]


class TestCorpusConversion:
    def test_claude_and_openai_sessions_emit_versioned_deterministic_manifest(
        self, converter, trainer, tmp_path
    ):
        pytest.importorskip("datasets")
        root = tmp_path / "sources"
        _write_source(root, "claude-case", _claude_session(), openai=False)
        _write_source(root, "openai-case", _openai_session(), openai=True)
        invalid = _write_source(root, "invalid-case", [], openai=False)
        (invalid / "agent_workspace" / "session.json").write_text("not json")
        unsupported = _write_source(root, "unsupported-case", [], openai=False)
        (unsupported / "agent_workspace" / "session.json").write_text(
            json.dumps([{"unsupported": True}])
        )

        out = tmp_path / "corpus" / "corpus.jsonl"
        report_path = tmp_path / "reports" / "report.json"
        args = converter._build_parser().parse_args(
            [
                "--root",
                str(root),
                "--sample-mode",
                "full",
                "--out",
                str(out),
                "--report",
                str(report_path),
            ]
        )
        report = converter.convert(args)
        rows = [json.loads(line) for line in out.read_text().splitlines()]

        assert len(rows) == 2
        assert {row["session_format"] for row in rows} == {
            "claude_json_array",
            "openai_jsonl",
        }
        assert all(row["schema_version"] == converter.SFT_RECORD_SCHEMA_VERSION for row in rows)
        assert all(row["messages"] for row in rows)  # trainer consumes this field unchanged
        assert len({row["sample_id"] for row in rows}) == 2
        assert all(len(row["source_content_sha256"]) == 64 for row in rows)

        assert report["schema_version"] == converter.CORPUS_MANIFEST_SCHEMA_VERSION
        assert report["source_counts"] == {"discovered": 4, "converted": 2, "skipped": 2}
        assert report["skipped_by_reason"] == {
            "invalid_openai_jsonl_line_1": 1,
            "unsupported_claude_event_shape": 1,
        }
        assert report["output"]["sha256"] == hashlib.sha256(out.read_bytes()).hexdigest()
        assert report["output"]["record_count"] == 2
        assert report["converter"]["version"] == converter.CONVERTER_VERSION
        assert str(root) not in json.dumps(report["converter"]["arguments"])
        assert "secret" not in json.dumps(report).lower()

        dataset = trainer.load_jsonl_dataset(str(out))
        assert len(dataset) == 2
        assert all(row["messages"] for row in dataset)

        training_args = trainer._build_parser().parse_args(
            [
                "--corpus",
                str(out),
                "--corpus-manifest",
                str(report_path),
                "--output",
                str(tmp_path / "adapter"),
                "--validate-only",
            ]
        )
        loaded_records, loaded_manifest, corpus_info = trainer.load_validated_corpus(training_args)
        assert len(loaded_records) == 2
        assert loaded_manifest["corpus_id"] == report["corpus_id"]
        assert corpus_info["sha256"] == report["output"]["sha256"]

        manifest_only_args = trainer._build_parser().parse_args(
            [
                "--corpus-manifest",
                str(report_path),
                "--output",
                str(tmp_path / "adapter-manifest-only"),
                "--validate-only",
            ]
        )
        manifest_records, _, _ = trainer.load_validated_corpus(manifest_only_args)
        assert len(manifest_records) == 2

        first_ids = ([row["sample_id"] for row in rows], report["corpus_id"])
        second_report = converter.convert(args)
        second_rows = [json.loads(line) for line in out.read_text().splitlines()]
        assert ([row["sample_id"] for row in second_rows], second_report["corpus_id"]) == first_ids

    def test_duplicate_task_ids_fail_validation(self, converter, tmp_path):
        root = tmp_path / "sources"
        _write_source(root, "attempt-a", _claude_session(), openai=False, case_id="same-case")
        _write_source(root, "attempt-b", _claude_session(), openai=False, case_id="same-case")
        args = converter._build_parser().parse_args(
            [
                "--root",
                str(root),
                "--sample-mode",
                "full",
                "--out",
                str(tmp_path / "corpus.jsonl"),
                "--report",
                str(tmp_path / "report.json"),
            ]
        )

        with pytest.raises(ValueError, match="duplicate task_id values: same-case.run-1.full"):
            converter.convert(args)
