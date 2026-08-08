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
MAX_FINALIZATION_ATTEMPTS = 2
FINAL_REPORT_PROMPT = (
    "You have finished tool use. Do not call any more tools. "
    "Return only the final structured JSON object required by the system prompt. "
    "Include the verified flags/objective results and evidence you actually obtained; "
    "do not invent missing values."
)

# Adaptive overhead added to the fast JSON-length token estimate once the API
# reports a real context-length error.  The denominator of 3.2 is a rough
# heuristic; the true tokenizer plus message/tool overhead can be higher for
# some prompts, so we learn the gap from the server's exact token count and
# make the estimator truly conservative for the rest of the run.
_TOKEN_ESTIMATE_OVERHEAD = 0

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

_TOOL_SECRET_ENV = {
    "OPENAI_API_KEY",
    "LLM_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENAI_BASE_URL",
    "LLM_BASE_URL",
    "ANTHROPIC_BASE_URL",
}


def _tool_environment() -> dict[str, str]:
    """Keep model API credentials out of Agent tool subprocesses."""
    env = os.environ.copy()
    for key in _TOOL_SECRET_ENV:
        env.pop(key, None)
    return env


def _run_bash(command: str, timeout: int = 120) -> str:
    try:
        r = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=timeout,
            env=_tool_environment(),
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
            capture_output=True, text=True, timeout=20, env=_tool_environment(),
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
            capture_output=True, text=True, timeout=25, env=_tool_environment(),
        )
        out = re.sub(r"<[^>]+>", " ", r.stdout or "")
        out = re.sub(r"\s+", " ", out).strip()
        return out[:8000] if out else "[empty response]"
    except Exception as exc:  # noqa: BLE001
        return f"[fetch error] {exc}"


def _parse_tool_arguments(raw: Any) -> dict:
    """Parse model-supplied tool arguments into a dict.

    Some served models (e.g. Hermes tool-call parser over Qwen2.5-LoRA)
    return the ``arguments`` field as a JSON-encoded string literal rather
    than as a raw JSON object, or generate malformed JSON fragments. We
    accept:

      - a JSON object (normal case)
      - a JSON string that itself encodes a JSON object (double-encoded)
      - malformed JSON -> return an empty-ish dict with an error marker

    Returning a dict keeps the ``TOOL_HANDLERS`` lambdas (which all call
    ``args.get``) from crashing the runner on a bad model turn.
    """
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        return {"__parse_error__": True, "__raw__": str(raw)}

    # Try the direct JSON object first.
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
        # Double-encoded string: try to unwrap one level.
        if isinstance(parsed, str):
            try:
                inner = json.loads(parsed)
                if isinstance(inner, dict):
                    return inner
                return {"__parse_error__": True, "__raw__": raw, "__inner_type__": type(inner).__name__}
            except json.JSONDecodeError:
                return {"__parse_error__": True, "__raw__": raw}
        return {"__parse_error__": True, "__raw__": raw, "__type__": type(parsed).__name__}
    except json.JSONDecodeError:
        return {"__parse_error__": True, "__raw__": raw}


TOOL_HANDLERS = {
    "Bash": lambda args: _run_bash(args.get("command", ""), int(args.get("timeout", 120) or 120)),
    "Read": lambda args: _read_file(args.get("path", "")),
    "Write": lambda args: _write_file(args.get("path", ""), args.get("content", "")),
    "WebSearch": lambda args: _web_search(args.get("query", "")),
    "WebFetch": lambda args: _web_fetch(args.get("url", ""), args.get("prompt", "")),
}


def _to_namespace(value: Any) -> Any:
    if isinstance(value, dict):
        return SimpleNamespace(**{key: _to_namespace(item) for key, item in value.items()})
    if isinstance(value, list):
        return [_to_namespace(item) for item in value]
    return value


class _StdlibOpenAICompletions:
    def __init__(self, api_key: str, base_url: str | None):
        self.api_key = api_key
        self.base_url = (base_url or "https://api.openai.com/v1").rstrip("/")

    def create(self, **payload):
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "text/event-stream",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                if "text/event-stream" not in response.headers.get("Content-Type", ""):
                    return [_to_namespace(json.loads(response.read().decode("utf-8", errors="replace")))]
                chunks = []
                for raw_line in response:
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line or line.startswith(":") or not line.startswith("data:"):
                        continue
                    data = line[len("data:"):].strip()
                    if data == "[DONE]":
                        break
                    chunks.append(_to_namespace(json.loads(data)))
                return chunks
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"OpenAI-compatible API HTTP {exc.code}: {body}") from exc


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


class QuotaExhaustedError(Exception):
    """Fatal: API quota/balance exhausted. Stops the whole batch."""


class RateLimitPersistentError(Exception):
    """Persistent rate limiting after exhausting retries. Pauses this case."""


# Substrings (lowercased) that indicate a fatal quota/balance exhaustion,
# regardless of HTTP status code. Gateways wrap quota errors in many shapes
# (402, 403, 400, 500), so text matching is required alongside status codes.
_FATAL_MARKERS = (
    "quota", "balance", "insufficient", "insufficient_quota",
    "billing", "payment", "credit", "exhausted", "no enough balance",
    "额度", "余额不足", "欠费", "套餐用尽",
)

# Substrings that indicate a rate-limit / concurrency-cap error (transient
# but potentially persistent): retry with backoff, and if it keeps failing,
# pause this case so other cases can progress.
_RATE_LIMIT_MARKERS = (
    "overloaded", "rate_limit", "rate limit", "429",
    "too many requests", "concurrent", "concurrency", "throttl",
    "请求过多", "并发",
)


def _classify_api_error(exc: Exception) -> str:
    """Return 'fatal' | 'rate_limit' | 'transient' | 'other' for an API error.

    Order matters: fatal must win over rate_limit, because some gateways wrap
    a quota-exhaustion body in a 429/5xx status. We read status_code via
    getattr unconditionally (gateway errors are often plain Exceptions with a
    status_code attribute, not openai.APIError subclasses), then check the
    SDK exception type, then fall back to message text.
    """
    try:
        from openai import RateLimitError, APIConnectionError, APITimeoutError
    except ImportError:
        RateLimitError = APIConnectionError = APITimeoutError = ()

    msg = str(exc).lower()
    # getattr (not isinstance) so gateway-wrapped plain Exceptions carrying a
    # status_code attribute are classified the same as SDK errors.
    raw_status = getattr(exc, "status_code", 0) or 0
    try:
        status = int(raw_status)
    except (TypeError, ValueError):
        status = 0

    # 1. Fatal by text marker (highest priority — gateways wrap quota in anything)
    if any(m in msg for m in _FATAL_MARKERS):
        return "fatal"
    # 2. Fatal by status code (auth/billing errors cannot recover in a batch)
    if status in (401, 402, 403):
        return "fatal"

    # 3. Rate-limit by text marker
    if any(m in msg for m in _RATE_LIMIT_MARKERS):
        return "rate_limit"
    # 4. Rate-limit by SDK type / status
    if isinstance(exc, RateLimitError) or status == 429:
        return "rate_limit"

    # 5. Transient server errors (5xx), connection-layer failures (DNS/TCP/
    # TLS handshake, gateway not ready), and explicit request timeouts — retry,
    # not fatal/rate_limit.
    if status >= 500:
        return "transient"
    if isinstance(exc, (APIConnectionError, APITimeoutError)):
        return "transient"

    return "other"


def _estimate_messages_tokens(messages: list[dict]) -> int:
    """Fast, conservative token estimate for a messages list."""
    # trl/jsonl tokenization is ~3.5 chars/token; use a smaller denominator to be
    # conservative (overcount) and avoid underestimating the API context limit.
    # The overhead is raised at runtime when the API tells us the true count.
    global _TOKEN_ESTIMATE_OVERHEAD
    return int(len(json.dumps(messages, ensure_ascii=False)) / 3.2) + _TOKEN_ESTIMATE_OVERHEAD


def _parse_context_length_error(text: str) -> tuple[int, int, int] | None:
    """Parse OpenAI/vLLM context-length error text.

    Returns (max_context_tokens, prompt_tokens, completion_tokens) or None.
    Example: "This model's maximum context length is 32768 tokens. However, you
    requested 34029 tokens (21060 in the messages, 12969 in the completion)."
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

    The OpenAI/vLLM server rejects requests where prompt tokens + max_tokens
    exceed the model's context length.  This helper keeps the conversation under
    budget by first capping max_tokens, then compressing old tool results, and
    finally dropping the oldest non-essential messages while keeping the system
    message and the first user prompt intact.
    """
    max_context = exact_max_context or int(os.environ.get("LLM_MAX_CONTEXT_LENGTH", "32768"))
    allowed_total = max_context - context_margin

    # 1. First try to satisfy the request by only shrinking max_tokens.
    #    If the API has already told us the exact prompt token count, use it
    #    so the first budget calculation is precise; otherwise fall back to
    #    the conservative JSON-length estimate (which includes any overhead we
    #    have learned from earlier context errors).
    prompt_tokens = exact_prompt_tokens if exact_prompt_tokens is not None else _estimate_messages_tokens(messages)
    if prompt_tokens + requested_max_tokens <= allowed_total:
        return messages, requested_max_tokens

    capped_max_tokens = max(min_output_tokens, allowed_total - prompt_tokens)
    if prompt_tokens + capped_max_tokens <= allowed_total:
        return messages, capped_max_tokens

    # 2. Still over budget: compress old tool results so we don't lose turns.
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

    # 3. Drop oldest messages after the system + first user prompt, but keep
    # tool-call / tool-result pairs intact: if a dropped message was an
    # assistant with tool_calls, the following tool messages become orphaned and
    # are also removed in the next iteration.
    trimmed = list(compressed)
    while len(trimmed) > 2 and _estimate_messages_tokens(trimmed) + min_output_tokens > allowed_total:
        trimmed = [trimmed[0], trimmed[1]] + trimmed[3:]
        # Remove any leading tool message that lost its assistant tool_call.
        while len(trimmed) > 2 and trimmed[2].get("role") == "tool":
            trimmed = trimmed[:2] + trimmed[3:]
        if len(trimmed) <= 2:
            break

    prompt_tokens = _estimate_messages_tokens(trimmed)
    capped_max_tokens = max(min_output_tokens, allowed_total - prompt_tokens)
    return trimmed, capped_max_tokens


def _stream_completion(client, model: str, messages: list, max_tokens: int):
    """Call the model with stream=True and aggregate content + tool_calls.

    Some gateways (e.g. GLM-5.2) only return tool_calls in streaming
    responses, so we always stream and aggregate.

    API errors are classified into three buckets (see _classify_api_error):
      - fatal (quota/balance exhausted): raises QuotaExhaustedError
        immediately, no retry. The coordinator must stop the whole batch.
      - rate_limit (429/overloaded/concurrency): retries with exponential
        backoff up to MAX_RETRIES; if still failing, raises
        RateLimitPersistentError. The coordinator pauses this case and
        retries it after the other cases finish.
      - transient (5xx): same retry as rate_limit, but on final failure
        raises the original error (treated as a normal agent failure).

    Retries do not consume the turn budget. See WORK_PROGRESS_REPORT
    2026-07-24 '429 retry' and 2026-07-25 'API error triage'.
    """
    import time

    MAX_RETRIES = 5
    # Temperature: default 0 for deterministic, reproducible output (control
    # variable for ablation/model comparison). Reasoning models (kimi-k3,
    # GLM, etc.) reject temperature=0 with 'only 1 is allowed'; allow override
    # via LLM_TEMPERATURE env var so those models can be used without code
    # changes. See WORK_PROGRESS_REPORT 2026-07-24 'kimi temperature' analysis.
    temperature = float(os.environ.get("LLM_TEMPERATURE", "0"))

    for attempt in range(MAX_RETRIES):
        try:
            messages, max_tokens = _ensure_context_budget(messages, max_tokens)
            resp = client.chat.completions.create(
                model=model,
                messages=messages,
                tools=TOOLS,
                max_tokens=max_tokens,
                temperature=temperature,
                stream=True,
            )
            content_parts: list[str] = []
            reasoning_parts: list[str] = []
            tc_buf: dict[int, dict[str, str]] = {}
            finish_reason = ""
            for chunk in resp:
                if not chunk.choices:
                    continue
                choice = chunk.choices[0]
                choice_finish_reason = getattr(choice, "finish_reason", None)
                if choice_finish_reason:
                    finish_reason = str(choice_finish_reason)
                delta = getattr(choice, "delta", None)
                if delta is None:
                    continue
                content = getattr(delta, "content", None)
                if content:
                    content_parts.append(str(content))
                reasoning_content = getattr(delta, "reasoning_content", None)
                if reasoning_content:
                    reasoning_parts.append(str(reasoning_content))
                tool_call_deltas = getattr(delta, "tool_calls", None) or []
                if tool_call_deltas:
                    for tc in tool_call_deltas:
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
            return content, tool_calls, {
                "finish_reason": finish_reason,
                "reasoning_content": "".join(reasoning_parts),
            }
        except QuotaExhaustedError:
            raise
        except Exception as exc:  # noqa: BLE001
            # Context-length errors give us the exact prompt token count. Use it
            # to tighten our budget and learn the estimator gap, then retry the
            # same turn without consuming a retry attempt.
            err_text = str(exc)
            if "maximum context length" in err_text.lower():
                parsed = _parse_context_length_error(err_text)
                if parsed:
                    model_max, actual_prompt, requested_completion = parsed
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
            cls = _classify_api_error(exc)
            # Fatal: never retry — escalate immediately so the coordinator
            # can stop the whole batch and save remaining quota.
            if cls == "fatal":
                print(f"[Fatal] API quota/balance exhausted, stopping: {str(exc)[:160]}", file=sys.stderr)
                raise QuotaExhaustedError(str(exc)) from exc
            # rate_limit / transient: retry with exponential backoff.
            if cls in ("rate_limit", "transient") and attempt < MAX_RETRIES - 1:
                wait = 2 ** attempt  # 1, 2, 4, 8, 16s
                print(f"[Warn] {cls} API error (attempt {attempt+1}/{MAX_RETRIES}), retrying in {wait}s: {str(exc)[:120]}", file=sys.stderr)
                time.sleep(wait)
                continue
            # Final attempt or unclassified error.
            if cls == "rate_limit":
                print(f"[Warn] rate-limit persistent after {MAX_RETRIES} attempts, pausing case: {str(exc)[:120]}", file=sys.stderr)
                raise RateLimitPersistentError(str(exc)) from exc
            raise


def run_agent(input_path: str, output_path: str, max_turns: int = DEFAULT_MAX_TURNS):
    """OpenAI-protocol Range agent main loop."""
    import openai

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
    tool_history = False
    finalization_attempts = 0
    response_diagnostics = {
        "finish_reasons": [],
        "empty_completions": 0,
        "reasoning_content_chars": 0,
        "finalization_attempts": 0,
    }
    # Set by the fatal/rate-limit except handlers to override the
    # classify_termination() result, so the specific API error class is not
    # erased by the generic termination classifier.
    termination_override = ""

    try:
        for turn in range(max_turns):
            content, tool_calls, metadata = _stream_completion(
                client, model, messages, max_tokens
            )
            finish_reason = str(metadata.get("finish_reason") or "")
            reasoning_content = str(metadata.get("reasoning_content") or "")
            response_diagnostics["finish_reasons"].append(finish_reason)
            response_diagnostics["reasoning_content_chars"] += len(reasoning_content)
            if not content and not tool_calls:
                response_diagnostics["empty_completions"] += 1

            assistant_event = {
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": content or "",
                    "finish_reason": finish_reason,
                },
                "turn": turn,
            }
            if reasoning_content:
                assistant_event["message"]["reasoning_content"] = reasoning_content[:4000]
            session_events.append(assistant_event)

            if content:
                full_text += content + "\n"
                print(f"[Agent] {content[:200]}", file=sys.stderr)

            assistant_message = {
                "role": "assistant",
                "content": content or None,
            }
            # Reasoning-capable gateways require this field to be passed back
            # with the assistant turn that produced tool calls.  Dropping it
            # lets the first tool call succeed but makes the next request fail
            # with "reasoning_content ... must be passed back".
            if reasoning_content:
                assistant_message["reasoning_content"] = reasoning_content

            if not tool_calls:
                if content or reasoning_content:
                    messages.append(assistant_message)
                # Some gateways end a tool-using turn with an empty assistant
                # message, or with prose that does not satisfy the JSON
                # contract. Give the model a bounded chance to close the
                # contract before classifying the run as incomplete. The
                # continuation consumes a normal turn from max_turns.
                if (
                    tool_history
                    and not extract_json(full_text)
                    and finalization_attempts < MAX_FINALIZATION_ATTEMPTS
                    and turn + 1 < max_turns
                ):
                    finalization_attempts += 1
                    response_diagnostics["finalization_attempts"] = finalization_attempts
                    messages.append({"role": "user", "content": FINAL_REPORT_PROMPT})
                    session_events.append({
                        "type": "finalization_request",
                        "message": {"role": "user", "content": FINAL_REPORT_PROMPT},
                        "turn": turn,
                    })
                    continue
                if tool_history and not extract_json(full_text):
                    termination_hint = (
                        "agent_incomplete: tool calls completed without a final structured report"
                    )
                break

            assistant_msg = {
                **assistant_message,
                "tool_calls": [
                    {"id": tc["id"], "type": "function",
                     "function": {"name": tc["name"], "arguments": tc["arguments"]}}
                    for tc in tool_calls
                ],
            }
            messages.append(assistant_msg)
            session_events.append({"type": "assistant", "message": {"role": "assistant", "tool_calls": assistant_msg["tool_calls"]}, "turn": turn})
            tool_history = True

            for tc in tool_calls:
                name = tc["name"]
                args = _parse_tool_arguments(tc["arguments"])
                print(f"[Tool] {name}: {json.dumps(args)[:120]}", file=sys.stderr)
                handler = TOOL_HANDLERS.get(name)
                tool_result = handler(args) if handler else f"[unknown tool] {name}"
                messages.append({"role": "tool", "tool_call_id": tc["id"], "content": tool_result})
                session_events.append({"type": "tool", "message": {"role": "tool", "name": name, "args": args, "result": tool_result}, "turn": turn})
                print(f"[ToolResult] {tool_result[:160]}", file=sys.stderr)
        else:
            termination_hint = f"Agent reached max-turns ({max_turns}) without a final report"
            result["evidence"].append(termination_hint)

    except QuotaExhaustedError as exc:
        # Fatal: signal the coordinator to stop the whole batch.
        print(f"[Fatal] quota exhausted, signaling batch stop: {exc}", file=sys.stderr)
        result["evidence"].append(f"API quota exhausted: {exc}")
        termination_override = "quota_exhausted"
        result["api_error_class"] = "quota_exhausted"
    except RateLimitPersistentError as exc:
        # Persistent rate limit: signal the coordinator to pause this case
        # (don't count as failure, retry at end of batch).
        print(f"[Warn] rate-limit persistent, signaling case pause: {exc}", file=sys.stderr)
        result["evidence"].append(f"API rate-limit persistent: {exc}")
        termination_override = "rate_limit_persistent"
        result["api_error_class"] = "rate_limit_persistent"
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
    result["response_diagnostics"] = response_diagnostics
    result["observed_progress"] = extract_observed_progress(full_text, input_data.get("targets", []))
    if termination_override:
        result["termination_reason"] = termination_override
    else:
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
