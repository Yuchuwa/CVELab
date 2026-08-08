"""Adapter tool-call format smoke test.

Validates that a served Qwen2.5+LoRA adapter can emit valid Hermes/Qwen-style
<tool_call> blocks with JSON-object arguments, both on a short prompt and on
a realistic CVELab Range prompt. This is intended as a gate before spending
time on a full Range batch evaluation.

Usage against the running vLLM server:

    python sft/adapter_smoke_test.py \
        --base-url http://172.17.0.1:8000/v1 \
        --model qwen25-7b-lora \
        --range-input data/guide_ablation/sft_v1_eval_v5/scenarios/e3-1563ab36-3747cb9c75d2f9bf/agent_workspace/input.json

Returns non-zero if any tool_call block has malformed arguments.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import openai

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from clab_builder.orchestrator.composer.scenario_runner import (  # noqa: E402
    SYSTEM_PROMPT,
    NO_HINT_SYSTEM_PROMPT,
    _resolve_level,
    build_prompt,
)

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "Bash",
            "description": "Run a shell command in the attacker container",
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

TOOL_CALL_RE = re.compile(r"<tool_call>\n(.*?)\n</tool_call>", re.DOTALL)


def _extract_arguments_stream(client: openai.OpenAI, model: str, messages: list, max_tokens: int = 256) -> str:
    """Run one streaming completion and return the raw arguments text."""
    args = ""
    resp = client.chat.completions.create(
        model=model,
        messages=messages,
        tools=TOOLS,
        max_tokens=max_tokens,
        temperature=0,
        stream=True,
    )
    for chunk in resp:
        delta = chunk.choices[0].delta if chunk.choices else None
        if delta and delta.tool_calls:
            for tc in delta.tool_calls:
                if tc.function and tc.function.arguments:
                    args += tc.function.arguments
    return args


def _validate_arguments(args: str, label: str) -> bool:
    """Return True if args is a valid JSON object (not a string literal)."""
    try:
        parsed = json.loads(args)
    except json.JSONDecodeError as exc:
        print(f"[FAIL] {label}: not valid JSON: {exc}")
        print(f"       raw: {args[:200]!r}")
        return False

    if isinstance(parsed, str):
        print(f"[FAIL] {label}: arguments is a JSON string literal (double-encoded)")
        print(f"       raw: {args[:200]!r}")
        return False

    if not isinstance(parsed, dict):
        print(f"[FAIL] {label}: arguments is {type(parsed).__name__}, expected dict")
        print(f"       raw: {args[:200]!r}")
        return False

    print(f"[PASS] {label}: arguments object ok, keys={list(parsed.keys())}")
    return True


def _run_multi_turn(client: openai.OpenAI, model: str, messages: list, turns: int = 2) -> list[tuple[int, str]]:
    """Run several assistant/tool round trips and return all argument strings.

    The model is primed with a simple user request. Each assistant turn is
    expected to produce a Bash tool call. We feed a synthetic tool result back
    so the next assistant turn can be evaluated. This catches degradation that
    only appears after the model sees <tool_response> content.
    """
    results: list[tuple[int, str]] = []
    for turn in range(turns):
        args = _extract_arguments_stream(client, model, messages, max_tokens=256)
        results.append((turn, args))
        if not args:
            break
        # Append a synthetic assistant tool_call and tool response so we can
        # continue the conversation. We don't know the exact id the model used,
        # but the OpenAI API only needs consistent tool_call_id.
        fake_id = f"call_smoke_{turn}"
        messages.append({
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": fake_id,
                    "type": "function",
                    "function": {"name": "Bash", "arguments": args},
                }
            ],
        })
        messages.append({"role": "tool", "tool_call_id": fake_id, "content": "[synthetic result]"})
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base-url", default="http://172.17.0.1:8000/v1")
    ap.add_argument("--api-key", default="local")
    ap.add_argument("--model", default="qwen25-7b-lora")
    ap.add_argument(
        "--range-input",
        default="data/guide_ablation/sft_v1_eval_v5/scenarios/"
                "e3-1563ab36-3747cb9c75d2f9bf/agent_workspace/input.json",
    )
    args = ap.parse_args()

    client = openai.OpenAI(api_key=args.api_key, base_url=args.base_url)
    ok = True

    # 1. Short prompt: base tool-calling capability.
    short_messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {
            "role": "user",
            "content": (
                "Run nmap -sV -p- --min-rate 1000 192.168.100.2 with timeout 120000 "
                "using the Bash tool."
            ),
        },
    ]
    args_text = _extract_arguments_stream(client, args.model, short_messages, max_tokens=256)
    ok &= _validate_arguments(args_text, "short prompt")

    # 2. Realistic Range prompt: long context, multi-target, multi-hop.
    input_path = Path(args.range_input)
    if not input_path.exists():
        print(f"[SKIP] Range input not found: {input_path}")
    else:
        input_data = json.loads(input_path.read_text())
        range_prompt = build_prompt(input_data)
        ctx = input_data.get("agent_context", "l2")
        level = _resolve_level(ctx)
        range_system = NO_HINT_SYSTEM_PROMPT if level or ctx == "no_hint" else SYSTEM_PROMPT
        range_messages = [
            {"role": "system", "content": range_system},
            {"role": "user", "content": range_prompt},
        ]
        args_text = _extract_arguments_stream(client, args.model, range_messages, max_tokens=512)
        ok &= _validate_arguments(args_text, "range prompt turn 0")
        multi_results = _run_multi_turn(client, args.model, list(range_messages), turns=3)
        for turn, args_text in multi_results:
            ok &= _validate_arguments(args_text, f"range prompt turn {turn}")

    # 3. Multi-turn short prompt: verify the model keeps producing valid tool
    # arguments after seeing a synthetic tool result.
    multi_results = _run_multi_turn(client, args.model, list(short_messages), turns=2)
    for turn, args_text in multi_results:
        ok &= _validate_arguments(args_text, f"short prompt turn {turn}")

    if ok:
        print(f"[OK] {args.model} adapter passes tool-call format smoke test.")
        return 0
    else:
        print(f"[ERROR] {args.model} adapter has malformed tool-call output.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
