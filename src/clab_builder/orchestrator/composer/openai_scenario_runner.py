#!/usr/bin/env python3
"""OpenAI-protocol Range Agent Runner — same task contract as scenario_runner.py
but drives the model via the OpenAI chat-completions API instead of
claude_agent_sdk.

Why this exists: Claude Code SDK's built-in Agent/Task tools expose a ``model``
parameter (haiku/sonnet/opus) to the main model. When the LLM gateway has no
channel for the chosen sub-model (e.g. 503 No available channel for
claude-haiku-4-5), sub-agent calls fail and the trial is mislabeled
agent_api_protocol. This runner uses a plain OpenAI function-calling loop with
a fixed, self-defined tool set (Bash/Read/Write/WebSearch) — there is no
built-in Agent tool, so no model-selection footgun.

It reuses the pure helpers from scenario_runner (SYSTEM_PROMPT,
NO_HINT_SYSTEM_PROMPT, build_prompt, extract_json, extract_observed_progress,
classify_termination, audit_no_hint, _resolve_level) so the prompt contract,
output JSON schema, level/hygiene audit, and termination classification stay
identical to the Claude SDK runner.

Usage (run inside the agent container, same entrypoint as scenario_runner.py):
    python3 /opt/scenario_runner.py \\
        --input /tmp/scenario_input.json \\
        --output /tmp/scenario_output.json \\
        --max-turns 500
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from typing import Any

# In the attacker container this file is /opt/scenario_runner.py and the
# Claude-SDK scenario_runner.py is copied alongside as
# /opt/scenario_runner_lib.py. Add /opt to sys.path so the lib import resolves
# inside the container. On the host (tests) the package path works.
sys.path.insert(0, "/opt")

# Reuse the shared pure helpers from scenario_runner so both runners behave
# the same from the verifier's perspective.
try:
    from scenario_runner_lib import (  # noqa: E402
        SYSTEM_PROMPT,
        NO_HINT_SYSTEM_PROMPT,
        build_prompt,
        extract_json,
        extract_observed_progress,
        classify_termination,
        audit_no_hint,
        _resolve_level,
    )
except ImportError:
    from clab_builder.orchestrator.composer.scenario_runner import (  # noqa: E402
        SYSTEM_PROMPT,
        NO_HINT_SYSTEM_PROMPT,
        build_prompt,
        extract_json,
        extract_observed_progress,
        classify_termination,
        audit_no_hint,
        _resolve_level,
    )

DEFAULT_MAX_TURNS = 500

# Tools exposed to the model. A fixed, self-defined set — no built-in Agent /
# Task tool, so the model cannot request a sub-model (haiku/sonnet) that the
# gateway may not serve. WebSearch is kept because a real attacker has internet
# access; it is implemented as a passthrough note (the model is told the
# command shape) rather than a live search backend, matching the Claude SDK
# runner's WebSearch behavior in this offline range.
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "Bash",
            "description": "Execute a bash command in the shell and return stdout+stderr.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "The shell command to execute"},
                    "timeout": {"type": "integer", "description": "Optional timeout in seconds (default 120)"},
                },
                "required": ["command"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "Read",
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
            "name": "Write",
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
    {
        "type": "function",
        "function": {
            "name": "WebSearch",
            "description": "Search the public web for exploit details, CVE descriptions, or PoC code. Returns the top results.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                },
                "required": ["query"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "WebFetch",
            "description": "Fetch the content of a URL and return it as text.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to fetch"},
                    "prompt": {"type": "string", "description": "Optional: what to extract from the page"},
                },
                "required": ["url"],
                "additionalProperties": False,
            },
        },
    },
]


def _run_bash(command: str, timeout: int = 120) -> str:
    try:
        r = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=timeout,
        )
        out = (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        out = f"[command timed out after {timeout}s]\n{command}"
    except Exception as exc:  # noqa: BLE001
        out = f"[execution error] {exc}"
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


def _web_search(query: str) -> str:
    # Best-effort: use curl against a search endpoint. In the offline range
    # this often returns nothing useful, but the tool is available so the
    # model is not artificially blocked from trying (mirrors the Claude SDK
    # runner's WebSearch availability).
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", "15",
             f"https://html.duckduckgo.com/html/?q={query.replace(' ', '+')}"],
            capture_output=True, text=True, timeout=20,
        )
        out = r.stdout or ""
        # Strip HTML tags crudely.
        text = re.sub(r"<[^>]+>", " ", out)
        text = re.sub(r"\s+", " ", text).strip()
        return text[:4000] if text else "[no results]"
    except Exception as exc:  # noqa: BLE001
        return f"[search error] {exc}"


def _web_fetch(url: str, prompt: str = "") -> str:
    try:
        r = subprocess.run(
            ["curl", "-sL", "--max-time", "20", url],
            capture_output=True, text=True, timeout=25,
        )
        out = re.sub(r"<[^>]+>", " ", r.stdout or "")
        out = re.sub(r"\s+", " ", out).strip()
        return out[:8000] if out else "[empty response]"
    except Exception as exc:  # noqa: BLE001
        return f"[fetch error] {exc}"


TOOL_HANDLERS = {
    "Bash": lambda args: _run_bash(args.get("command", ""), int(args.get("timeout", 120) or 120)),
    "Read": lambda args: _read_file(args.get("path", "")),
    "Write": lambda args: _write_file(args.get("path", ""), args.get("content", "")),
    "WebSearch": lambda args: _web_search(args.get("query", "")),
    "WebFetch": lambda args: _web_fetch(args.get("url", ""), args.get("prompt", "")),
}


def _to_namespace(value: Any) -> Any:
    if isinstance(value, dict):
        return SimpleNamespace(**{k: _to_namespace(v) for k, v in value.items()})
    if isinstance(value, list):
        return [_to_namespace(v) for v in value]
    return value


class _StdlibOpenAICompletions:
    def __init__(self, api_key: str, base_url: str | None):
        self.api_key = api_key
        self.base_url = (base_url or "https://api.openai.com/v1").rstrip("/")

    def create(self, **payload):
        url = f"{self.base_url}/chat/completions"
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "text/event-stream",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                content_type = response.headers.get("Content-Type", "")
                if "text/event-stream" not in content_type:
                    raw = response.read().decode("utf-8", errors="replace")
                    data = json.loads(raw)
                    return [_to_namespace(data)]

                chunks = []
                for raw_line in response:
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line or line.startswith(":"):
                        continue
                    if not line.startswith("data:"):
                        continue
                    data = line[len("data:"):].strip()
                    if data == "[DONE]":
                        break
                    chunks.append(_to_namespace(json.loads(data)))
                return chunks
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"OpenAI-compatible API HTTP {exc.code}: {error_body}") from exc


class _StdlibOpenAIClient:
    def __init__(self, api_key: str, base_url: str | None):
        self.chat = SimpleNamespace(
            completions=_StdlibOpenAICompletions(api_key=api_key, base_url=base_url)
        )


def _make_completion_client(api_key: str, base_url: str | None):
    try:
        import openai
    except ModuleNotFoundError as exc:
        if exc.name == "openai" or "openai" in str(exc):
            return _StdlibOpenAIClient(api_key=api_key, base_url=base_url)
        raise
    return openai.OpenAI(api_key=api_key, base_url=base_url or None)


def _stream_completion(client, model: str, messages: list, max_tokens: int):
    """Call the model with stream=True and aggregate content + tool_calls.

    Some gateways (e.g. GLM-5.2) only return tool_calls in streaming
    responses, so we always stream and aggregate.
    """
    resp = client.chat.completions.create(
        model=model,
        messages=messages,
        tools=TOOLS,
        max_tokens=max_tokens,
        temperature=0,
        stream=True,
    )
    content_parts: list[str] = []
    tc_buf: dict[int, dict[str, str]] = {}
    for chunk in resp:
        if not chunk.choices:
            continue
        delta = chunk.choices[0].delta
        if delta is None:
            continue
        content_delta = getattr(delta, "content", None)
        if content_delta:
            content_parts.append(content_delta)
        tool_call_delta = getattr(delta, "tool_calls", None)
        if tool_call_delta:
            for tc in tool_call_delta:
                idx = getattr(tc, "index", 0)
                tc_id = getattr(tc, "id", None)
                function = getattr(tc, "function", None)
                function_name = getattr(function, "name", None) if function else None
                function_arguments = getattr(function, "arguments", None) if function else None
                if idx not in tc_buf:
                    tc_buf[idx] = {"id": tc_id or f"call_{idx}", "name": "", "arguments": ""}
                if tc_id:
                    tc_buf[idx]["id"] = tc_id
                if function_name:
                    tc_buf[idx]["name"] = function_name
                if function_arguments:
                    tc_buf[idx]["arguments"] += function_arguments
    content = "".join(content_parts)
    tool_calls = [tc_buf[i] for i in sorted(tc_buf.keys())]
    return content, tool_calls


def run_agent(input_path: str, output_path: str, max_turns: int = DEFAULT_MAX_TURNS):
    """OpenAI-protocol Range agent main loop."""
    with open(input_path) as f:
        input_data = json.load(f)

    prompt = build_prompt(input_data)
    agent_context = str(input_data.get("agent_context", "guided"))
    level = _resolve_level(agent_context)
    needs_hygiene = agent_context == "no_hint" or bool(level)
    system_prompt = NO_HINT_SYSTEM_PROMPT if needs_hygiene else SYSTEM_PROMPT

    model = os.environ.get("MODEL", "gpt-5.6-luna")
    base_url = os.environ.get("OPENAI_BASE_URL") or os.environ.get("LLM_BASE_URL") or os.environ.get("ANTHROPIC_BASE_URL") or ""
    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("LLM_API_KEY") or os.environ.get("ANTHROPIC_API_KEY") or ""
    if base_url and not base_url.rstrip("/").endswith("/v1"):
        base_url = base_url.rstrip("/") + "/v1"
    if not api_key:
        print("[Error] no API key found", file=sys.stderr)
        return

    client = _make_completion_client(api_key=api_key, base_url=base_url or None)
    max_tokens = int(os.environ.get("MAX_TOKENS", "16000"))

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt},
    ]

    result = {
        "scenario_name": input_data.get("scenario_name", ""),
        "agent_context": agent_context,
        "success": False,
        "verified_flags": {},
        "objective_results": {},
        "attack_log": [],
        "evidence": [],
        "failed_targets": [],
        "observed_progress": {"flag_claims": [], "targets_with_claimed_flags": []},
    }
    result["prompt_hygiene"] = (
        audit_no_hint(input_data, prompt)
        if needs_hygiene
        else {"profile": "not_applicable", "ok": True, "violations": []}
    )
    if needs_hygiene and not result["prompt_hygiene"]["ok"]:
        result["evidence"].append("prompt hygiene audit failed")
        result["termination_reason"] = "prompt_hygiene"
        result["structured_result"] = False
        result["partial_result"] = False
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"[Output] {output_path}", file=sys.stderr)
        return

    full_text = ""
    session_events: list[dict] = []
    termination_hint = ""

    try:
        for turn in range(max_turns):
            content, tool_calls = _stream_completion(client, model, messages, max_tokens)
            if content:
                full_text += content + "\n"
                print(f"[Agent] {content[:200]}", file=sys.stderr)
                session_events.append({"type": "assistant", "message": {"role": "assistant", "content": content}, "turn": turn})

            if not tool_calls:
                break

            assistant_msg = {
                "role": "assistant",
                "content": content or None,
                "tool_calls": [
                    {"id": tc["id"], "type": "function",
                     "function": {"name": tc["name"], "arguments": tc["arguments"]}}
                    for tc in tool_calls
                ],
            }
            messages.append(assistant_msg)
            session_events.append({"type": "assistant", "message": {"role": "assistant", "tool_calls": assistant_msg["tool_calls"]}, "turn": turn})

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
                session_events.append({"type": "tool", "message": {"role": "tool", "name": name, "args": args, "result": tool_result[:500]}, "turn": turn})
                print(f"[ToolResult] {tool_result[:160]}", file=sys.stderr)
        else:
            termination_hint = f"Agent reached max-turns ({max_turns}) without a final report"
            result["evidence"].append(termination_hint)

    except Exception as exc:  # noqa: BLE001
        print(f"[Error] {exc}", file=sys.stderr)
        result["evidence"].append(f"Agent error: {exc}")
        termination_hint = f"{termination_hint}\n{exc}"

    extracted = extract_json(full_text)
    if extracted:
        result.update(extracted)
    else:
        result["evidence"].append(full_text[:2000])
    partial_result = bool(full_text.strip())
    result["partial_result"] = partial_result
    result["structured_result"] = bool(extracted)
    result["observed_progress"] = extract_observed_progress(full_text, input_data.get("targets", []))
    result["termination_reason"] = classify_termination(
        f"{termination_hint}\n{full_text}\n{result.get('evidence', [])}",
        structured_result=bool(extracted),
        partial_result=partial_result,
    )

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"[Output] {output_path}", file=sys.stderr)

    # Save a session.json in the same shape as the Claude SDK runner so the
    # verifier's reverify_from_session.py and transcript tooling keep working.
    session_path = str(output_path).replace("output.json", "session.json")
    with open(session_path, "w") as f:
        for ev in session_events:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    print(f"[Session] openai runner -> {session_path} ({len(session_events)} events)", file=sys.stderr)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--max-turns", type=int, default=DEFAULT_MAX_TURNS)
    args = parser.parse_args()
    run_agent(args.input, args.output, max_turns=args.max_turns)
