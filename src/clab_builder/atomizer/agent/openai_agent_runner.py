"""OpenAI-protocol Agent Runner — LLM + tool-calling loop without claude_agent_sdk.

Why this exists: the default `agent_runner.py` uses `claude_agent_sdk`, which
is bound to the Claude CLI / Anthropic protocol. Some deployed LLM gateways
expose models (e.g. GLM-5.2) only via the OpenAI-compatible `/v1` endpoint and
do NOT speak the Anthropic protocol. For those models we need an agent harness
that drives the model through the OpenAI chat-completions API with function
calling.

Important gateway behavior: GLM-5.2 on the PKU gateway only returns
`tool_calls` in **streaming** responses; non-streaming responses carry
`reasoning_content` but drop `tool_calls`. This runner therefore always uses
`stream=True` and aggregates tool_calls from the stream.

It reuses the pure helpers from `agent_runner.py` (SYSTEM_PROMPT, build_prompt,
extract_json, extract_flag, redact_secrets) so the task contract, output JSON
schema, and secret redaction stay identical across the two harnesses.

Usage (run inside the agent container, same as agent_runner.py):
    python3 openai_agent_runner.py \
        --input /workspace/input.json \
        --output /workspace/output.json \
        --max-turns 80
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

# Reuse the shared prompt + extraction helpers so both runners behave the
# same from the pipeline's perspective. The default agent_runner.py is mounted
# alongside this file as /opt/agent_runner_lib.py (this file itself is mounted
# at /opt/agent_runner.py so the container entrypoint is uniform). The import
# is deferred so this module can be syntax-checked / imported on the host
# (where agent_runner_lib does not exist) without erroring; it only needs to
# resolve inside the agent container at runtime.
sys.path.insert(0, "/opt")


def _load_shared_helpers():
    from agent_runner_lib import (  # noqa: E402
        SYSTEM_PROMPT,
        build_prompt,
        extract_json,
        extract_flag,
        redact_secrets,
    )
    return SYSTEM_PROMPT, build_prompt, extract_json, extract_flag, redact_secrets

DEFAULT_MAX_TURNS = 80

# Adaptive overhead added to the fast JSON-length token estimate once the API
# reports a real context-length error. The heuristic denominator of 3.2 can
# undercount the served tokenizer for some prompts, so we learn the gap from the
# server's exact token count and make the estimator truly conservative.
_TOKEN_ESTIMATE_OVERHEAD = 0

# Tools exposed to the model: bash (run shell commands), read_file, write_file.
# These mirror the claude_agent_sdk built-in tools the default runner uses.
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "bash",
            "description": "Execute a bash command in the shell and return stdout+stderr.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "The shell command to execute"},
                },
                "required": ["command"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a file's content.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute path to the file"},
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write content to a file (overwrite).",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute path to the file"},
                    "content": {"type": "string", "description": "Content to write"},
                },
                "required": ["path", "content"],
                "additionalProperties": False,
            },
        },
    },
]


def _run_bash(command: str) -> str:
    """Execute a shell command, return combined stdout+stderr (truncated)."""
    try:
        r = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=120,
        )
        out = (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        out = f"[command timed out after 120s]\n{command}"
    except Exception as exc:  # noqa: BLE001
        out = f"[execution error] {exc}"
    # Keep tool results bounded so the context window does not blow up.
    if len(out) > 20000:
        out = out[:20000] + f"\n...[truncated, {len(out)} bytes total]"
    return out


def _read_file(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")[:20000]
    except Exception as exc:  # noqa: BLE001
        return f"[read error] {exc}"


def _write_file(path: str, content: str) -> str:
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(content, encoding="utf-8")
        return f"wrote {len(content)} bytes to {path}"
    except Exception as exc:  # noqa: BLE001
        return f"[write error] {exc}"


TOOL_HANDLERS = {
    "bash": lambda args: _run_bash(args.get("command", "")),
    "read_file": lambda args: _read_file(args.get("path", "")),
    "write_file": lambda args: _write_file(args.get("path", ""), args.get("content", "")),
}


def _estimate_messages_tokens(messages: list[dict]) -> int:
    """Fast, conservative token estimate for a messages list."""
    global _TOKEN_ESTIMATE_OVERHEAD
    return int(len(json.dumps(messages, ensure_ascii=False)) / 3.2) + _TOKEN_ESTIMATE_OVERHEAD


def _parse_context_length_error(text: str) -> tuple[int, int, int] | None:
    """Parse OpenAI/vLLM context-length error text.

    Returns (max_context_tokens, prompt_tokens, completion_tokens) or None.
    Example: \"This model's maximum context length is 32768 tokens. However, you
    requested 34029 tokens (21060 in the messages, 12969 in the completion).\"
    """
    m = re.search(
        r"maximum context length is (\d+) tokens.*requested (\d+) tokens \((\d+) in the messages, (\d+) in the completion\)",
        text,
        re.IGNORECASE,
    )
    if m:
        return int(m.group(1)), int(m.group(3)), int(m.group(4))
    return None


def _ensure_context_budget(
    messages: list[dict],
    requested_max_tokens: int,
    min_output_tokens: int = 1024,
    context_margin: int = 256,
    exact_prompt_tokens: int | None = None,
    exact_max_context: int | None = None,
) -> tuple[list[dict], int]:
    """Trim messages and/or cap max_tokens so prompt+completion fits the model.

    Prevents the OpenAI/vLLM server from rejecting requests because
    prompt tokens + max_tokens exceed the model context length.
    """
    max_context = exact_max_context or int(os.environ.get("LLM_MAX_CONTEXT_LENGTH", "32768"))
    allowed_total = max_context - context_margin

    prompt_tokens = exact_prompt_tokens if exact_prompt_tokens is not None else _estimate_messages_tokens(messages)
    if prompt_tokens + requested_max_tokens <= allowed_total:
        return messages, requested_max_tokens

    capped_max_tokens = max(min_output_tokens, allowed_total - prompt_tokens)
    if prompt_tokens + capped_max_tokens <= allowed_total:
        return messages, capped_max_tokens

    compressed = []
    for i, msg in enumerate(messages):
        if (
            msg.get("role") == "tool"
            and i < len(messages) - 5
            and isinstance(msg.get("content"), str)
            and len(msg["content"]) > 1000
        ):
            msg = dict(msg)
            c = msg["content"]
            msg["content"] = (
                f"{c[:400]}\n[...truncated {len(c) - 800} chars...]\n{c[-400:]}"
            )
        compressed.append(msg)
    prompt_tokens = _estimate_messages_tokens(compressed)
    capped_max_tokens = max(min_output_tokens, allowed_total - prompt_tokens)
    if prompt_tokens + capped_max_tokens <= allowed_total:
        return compressed, capped_max_tokens

    trimmed = list(compressed)
    while len(trimmed) > 2 and _estimate_messages_tokens(trimmed) + min_output_tokens > allowed_total:
        trimmed = [trimmed[0], trimmed[1]] + trimmed[3:]
        while len(trimmed) > 2 and trimmed[2].get("role") == "tool":
            trimmed = trimmed[:2] + trimmed[3:]
        if len(trimmed) <= 2:
            break

    prompt_tokens = _estimate_messages_tokens(trimmed)
    capped_max_tokens = max(min_output_tokens, allowed_total - prompt_tokens)
    return trimmed, capped_max_tokens


def _stream_completion(client, model: str, messages: list, max_tokens: int):
    """Call the model with stream=True and aggregate content + tool_calls.

    Streaming is mandatory for GLM-5.2 on this gateway: tool_calls are only
    emitted in the streamed chunks, never in the non-streaming response.
    Returns (content, tool_calls_list) where each tool_call is
    {id, name, arguments}.

    Context-length errors from the API are parsed for the exact prompt token
    count; the budget is tightened and the estimator gap is learned so the
    same turn can be retried without user intervention.
    """
    while True:
        budgeted_messages, budgeted_max_tokens = _ensure_context_budget(messages, max_tokens)
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=budgeted_messages,
                tools=TOOLS,
                max_tokens=budgeted_max_tokens,
                temperature=0,
                stream=True,
            )
            content_parts: list[str] = []
            # tool_call fragments keyed by index
            tc_buf: dict[int, dict[str, str]] = {}
            for chunk in resp:
                if not chunk.choices:
                    continue
                delta = chunk.choices[0].delta
                if delta is None:
                    continue
                if delta.content:
                    content_parts.append(delta.content)
                if delta.tool_calls:
                    for tc in delta.tool_calls:
                        idx = tc.index
                        if idx not in tc_buf:
                            tc_buf[idx] = {"id": tc.id or f"call_{idx}", "name": "", "arguments": ""}
                        if tc.id:
                            tc_buf[idx]["id"] = tc.id
                        if tc.function and tc.function.name:
                            tc_buf[idx]["name"] = tc.function.name
                        if tc.function and tc.function.arguments:
                            tc_buf[idx]["arguments"] += tc.function.arguments
            content = "".join(content_parts)
            tool_calls = [tc_buf[i] for i in sorted(tc_buf.keys())]
            return content, tool_calls
        except Exception as exc:
            err_text = str(exc)
            if "maximum context length" in err_text.lower():
                parsed = _parse_context_length_error(err_text)
                if parsed:
                    model_max, actual_prompt, _requested_completion = parsed
                    current_estimate = _estimate_messages_tokens(messages)
                    if actual_prompt > current_estimate:
                        global _TOKEN_ESTIMATE_OVERHEAD
                        _TOKEN_ESTIMATE_OVERHEAD = max(
                            _TOKEN_ESTIMATE_OVERHEAD, actual_prompt - current_estimate
                        )
                        print(
                            f"[Warn] context-length error: actual_prompt={actual_prompt} "
                            f"estimate={current_estimate}; overhead now {_TOKEN_ESTIMATE_OVERHEAD}",
                            file=sys.stderr,
                        )
                    messages, max_tokens = _ensure_context_budget(
                        messages, max_tokens,
                        exact_prompt_tokens=actual_prompt,
                        exact_max_context=model_max,
                    )
                    continue
            raise


def run_agent(input_path: str, output_path: str, max_turns: int = DEFAULT_MAX_TURNS):
    """OpenAI-protocol agent main loop."""
    import openai

    SYSTEM_PROMPT, build_prompt, extract_json, extract_flag, redact_secrets = _load_shared_helpers()

    with open(input_path) as f:
        input_data = json.load(f)
    prompt = build_prompt(input_data)

    model = os.environ.get("MODEL", "glm-5.2")
    base_url = os.environ.get("OPENAI_BASE_URL") or os.environ.get("LLM_BASE_URL") or ""
    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("LLM_API_KEY") or os.environ.get("ANTHROPIC_API_KEY") or ""
    # The gateway exposes OpenAI at <host>/v1; accept either a bare host or a
    # host that already ends with /v1.
    if base_url and not base_url.rstrip("/").endswith("/v1"):
        base_url = base_url.rstrip("/") + "/v1"
    if not api_key:
        print("[Error] no API key found (OPENAI_API_KEY/LLM_API_KEY/ANTHROPIC_API_KEY)", file=sys.stderr)
        return

    client = openai.OpenAI(api_key=api_key, base_url=base_url or None)
    # GLM-5.2 is a reasoning model; give enough room for reasoning + output.
    max_tokens = int(os.environ.get("MAX_TOKENS", "16000"))

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]

    result = {
        "success": False,
        "evidence": [],
        "exploit_steps": [],
        "exploit_guide": {},
        "mitre_mapping": {},
        "captured_flag": "",
    }

    full_text = ""
    # Session log (JSONL) — mirrors the claude_agent_sdk native session so the
    # pipeline's session-recovery / transcript tooling keeps working.
    session_events: list[dict] = []

    def _log_event(ev: dict) -> None:
        session_events.append(ev)

    try:
        for turn in range(max_turns):
            content, tool_calls = _stream_completion(client, model, messages, max_tokens)
            if content:
                full_text += content + "\n"
                print(f"[Agent] {content[:200]}", file=sys.stderr)
                _log_event({"role": "assistant", "content": content, "turn": turn})

            if not tool_calls:
                # No tool calls: the model produced a (final) text answer.
                break

            # Record the assistant tool-call message and execute each tool.
            assistant_msg = {
                "role": "assistant",
                "content": content or None,
                "tool_calls": [
                    {
                        "id": tc["id"],
                        "type": "function",
                        "function": {"name": tc["name"], "arguments": tc["arguments"]},
                    }
                    for tc in tool_calls
                ],
            }
            messages.append(assistant_msg)
            _log_event({"role": "assistant", "tool_calls": assistant_msg["tool_calls"], "turn": turn})

            for tc in tool_calls:
                name = tc["name"]
                try:
                    args = json.loads(tc["arguments"]) if tc["arguments"] else {}
                except json.JSONDecodeError:
                    args = {}
                print(f"[Tool] {name}: {json.dumps(args)[:120]}", file=sys.stderr)
                handler = TOOL_HANDLERS.get(name)
                tool_result = handler(args) if handler else f"[unknown tool] {name}"
                messages.append({"role": "tool", "tool_call_id": tc["id"], "content": tool_result})
                _log_event({"role": "tool", "name": name, "args": args, "result": tool_result, "turn": turn})
                print(f"[ToolResult] {tool_result[:160]}", file=sys.stderr)
        else:
            # Loop completed without the model emitting a final answer.
            result["evidence"].append(f"Agent reached max-turns ({max_turns}) without a final report")

    except Exception as exc:  # noqa: BLE001
        print(f"[Error] {exc}", file=sys.stderr)
        result["evidence"].append(f"Agent error: {exc}")

    # Extract the structured JSON report from the agent's text output.
    extracted = extract_json(full_text)
    if extracted:
        prior_evidence = list(result.get("evidence") or [])
        merged = dict(result)
        merged.update(extracted)
        extracted_evidence = list(extracted.get("evidence") or [])
        combined = prior_evidence + [e for e in extracted_evidence if e not in prior_evidence]
        merged["evidence"] = combined
        result = merged
    else:
        result["evidence"].append(full_text[:2000])
    result.setdefault("captured_flag", "")
    if not result.get("captured_flag"):
        result["captured_flag"] = extract_flag(full_text)

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"[Output] {output_path}", file=sys.stderr)

    # Save a redacted JSONL session next to the output, matching the default
    # runner's session.json contract so downstream code can recover from it.
    session_path = str(output_path).replace("output.json", "session.json")
    session_text = "\n".join(json.dumps(ev, ensure_ascii=False) for ev in session_events)
    Path(session_path).write_text(redact_secrets(session_text), encoding="utf-8")
    print(f"[Session] openai runner -> {session_path} ({len(session_events)} events)", file=sys.stderr)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--max-turns", type=int, default=DEFAULT_MAX_TURNS,
                        help=f"Maximum agent turns (default: {DEFAULT_MAX_TURNS})")
    args = parser.parse_args()
    run_agent(args.input, args.output, args.max_turns)