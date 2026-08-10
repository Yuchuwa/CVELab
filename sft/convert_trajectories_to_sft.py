"""Convert CVELab attack trajectories into SFT chat JSONL.

Reads Claude JSON-array and OpenAI JSONL session.json files from clean-context
scenarios (l0/l1/l2/no_hint), locates each captured flag's position in the
session, and emits OpenAI-style tool-call chat samples:

  {"task_id": "...hop{N}", "is_resolved": true,
   "messages": [{"role":"system",...}, {"role":"user",...},
                {"role":"assistant","content":..,"tool_calls":[...]},
                {"role":"tool","tool_call_id":..,"content":..}, ...]}

Prefix policy:
  - For each trajectory capturing n flags (n in 1..3):
      k in 1..n-1 : sample = events[0 .. flag_k_event]   (sub-skill, ends at flag capture)
      k = n       : sample = full session                  (includes final structured report)
  This guarantees one "full" sample per trajectory teaches the final JSON output,
  while shorter prefixes teach per-hop exploitation.

Length policy (no hard tail truncation):
  - Samples <= MAX_LEN tokens: keep verbatim.
  - Samples  > MAX_LEN tokens: compress verbose tool_result content first
    (keep head+tail, mark truncation), then if still over, drop.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

# Import the system prompts from the orchestrator package.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from clab_builder.orchestrator.composer.scenario_runner import (  # noqa: E402
    SYSTEM_PROMPT,
    NO_HINT_SYSTEM_PROMPT,
    _resolve_level,
    build_prompt,
)

CHARS_PER_TOKEN = 3.5
MAX_LEN_TOKENS = 32768
TOOL_RESULT_KEEP_HEAD = 1500
TOOL_RESULT_KEEP_TAIL = 1500
CONVERTER_VERSION = "1.0.0"
SFT_RECORD_SCHEMA_VERSION = "cvelab.sft-record.v1"
CORPUS_MANIFEST_SCHEMA_VERSION = "cvelab.sft-corpus-manifest.v1"

# Claude-Code SDK built-in tools that are NOT in the eval (openai) toolset.
# Strip their calls and results so the model does not learn to call them.
SDK_NOISE_TOOLS = {"TaskCreate", "TaskUpdate", "TaskList", "TaskGet", "TaskClose"}
# Eval-time toolset the model should learn to call.
EVAL_TOOLS = {"Bash", "Read", "Write", "WebSearch", "WebFetch"}


# Forbidden oracle fields that must never appear in the task input. The agent
# *discovering* a flag in a tool_result during the run is legitimate signal;
# the *task prompt* must be clean.
LEAK_PATTERNS = [
    "flag_hint",
    "flag_verify_command",
    "reference_command",
    "success_pattern",
    "/flag",
    "echo $flag",
    "env | grep flag",
]


class SkipSource(Exception):
    """A classified source-level conversion skip."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _source_content_hash(paths: list[str]) -> str:
    """Hash source files without copying their potentially private values."""
    digest = hashlib.sha256()
    for path in sorted(paths):
        source = Path(path)
        if not source.exists():
            continue
        digest.update(source.name.encode())
        digest.update(b"\0")
        digest.update(source.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _load_session(path: str) -> tuple[list[dict], str]:
    """Load a Claude JSON array or an OpenAI JSONL event session."""
    raw = Path(path).read_text(encoding="utf-8", errors="strict")
    if not raw.strip():
        raise SkipSource("invalid_session_empty")

    if raw.lstrip().startswith("["):
        try:
            events = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SkipSource("invalid_claude_json_array") from exc
        if not isinstance(events, list) or not events:
            raise SkipSource("invalid_claude_json_array")
        if not all(
            isinstance(event, dict) and isinstance(event.get("message"), dict)
            for event in events
        ):
            raise SkipSource("unsupported_claude_event_shape")
        return events, "claude_json_array"

    events = []
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SkipSource(f"invalid_openai_jsonl_line_{line_number}") from exc
        if not isinstance(event, dict):
            raise SkipSource("unsupported_openai_event_shape")
        events.append(event)
    if not events:
        raise SkipSource("invalid_session_empty")
    messages = [event.get("message", event) for event in events]
    if not all(
        isinstance(message, dict) and message.get("role") in {"user", "assistant", "tool"}
        for message in messages
    ) or not any(message.get("role") == "assistant" for message in messages):
        raise SkipSource("unsupported_openai_event_shape")
    return events, "openai_jsonl"


def _event_text(ev: dict) -> str:
    """Flatten an event's message content to a single string (for search/length)."""
    m = ev.get("message", ev)
    c = m.get("content")
    out = ""
    if isinstance(c, str):
        out = c
    elif isinstance(c, list):
        for b in c:
            if not isinstance(b, dict):
                out += json.dumps(b, ensure_ascii=False) if b else ""
                continue
            if b.get("type") == "thinking":
                out += b.get("thinking") or ""
            elif b.get("type") == "tool_use":
                out += json.dumps(b.get("input") or {}, ensure_ascii=False)
            elif b.get("type") == "tool_result":
                tc = b.get("content")
                if isinstance(tc, str):
                    out += tc
                elif isinstance(tc, list):
                    for b2 in tc:
                        out += json.dumps(b2, ensure_ascii=False) if isinstance(b2, dict) else str(b2)
            else:
                out += json.dumps(b, ensure_ascii=False)
    elif c is not None:
        out = json.dumps(c, ensure_ascii=False)
    if m.get("reasoning_content"):
        out += str(m["reasoning_content"])
    if m.get("tool_calls"):
        out += json.dumps(m["tool_calls"], ensure_ascii=False)
    if m.get("result") is not None:
        out += str(m["result"])
    return out


def _find_flag_events(session: list, flags: list) -> list:
    """Return event index where each flag first appears, or None."""
    hits = []
    for fi, fl in enumerate(flags):
        found = None
        for ei, ev in enumerate(session):
            if fl and fl in _event_text(ev):
                found = ei
                break
        hits.append(found)
    return hits


def _compress_tool_result(content: str) -> str:
    """Compress a verbose tool result to head+tail with a truncation marker."""
    if len(content) <= TOOL_RESULT_KEEP_HEAD + TOOL_RESULT_KEEP_TAIL + 80:
        return content
    head = content[:TOOL_RESULT_KEEP_HEAD]
    tail = content[-TOOL_RESULT_KEEP_TAIL:]
    dropped = len(content) - TOOL_RESULT_KEEP_HEAD - TOOL_RESULT_KEEP_TAIL
    return f"{head}\n[...truncated {dropped} chars...]\n{tail}"


THINKING_KEEP_HEAD = 800
THINKING_KEEP_TAIL = 400


def _compress_thinking(text: str) -> str:
    """Compress a long thinking block to head+tail."""
    if len(text) <= THINKING_KEEP_HEAD + THINKING_KEEP_TAIL + 80:
        return text
    head = text[:THINKING_KEEP_HEAD]
    tail = text[-THINKING_KEEP_TAIL:]
    dropped = len(text) - THINKING_KEEP_HEAD - THINKING_KEEP_TAIL
    return f"{head}\n[...{dropped} chars elided...]\n{tail}"


def _normalize_events(events: list) -> list:
    """Convert Claude content-block events to OpenAI tool-call chat messages.

    Drops SDK noise tools (TaskCreate etc.). Multi-tool assistant turns are
    preserved as a single assistant message with multiple tool_calls.
    """
    messages = []
    kept_tool_ids = set()
    for ev in events:
        etype = ev.get("type")
        m = ev.get("message", {})
        role = m.get("role", etype)
        c = m.get("content")

        # --- user message with string content (the task prompt) ---
        if role == "user" and isinstance(c, str):
            messages.append({"role": "user", "content": c})
            continue

        # --- user message carrying tool_result blocks ---
        if role == "user" and isinstance(c, list):
            for b in c:
                if not isinstance(b, dict):
                    continue
                if b.get("type") == "tool_result":
                    tid = b.get("tool_use_id", "")
                    if tid not in kept_tool_ids:
                        continue
                    tc = b.get("content")
                    if isinstance(tc, list):
                        tc = "\n".join(
                            json.dumps(x, ensure_ascii=False) if isinstance(x, dict) else str(x)
                            for x in tc
                        )
                    if not isinstance(tc, str):
                        tc = json.dumps(tc, ensure_ascii=False)
                    # Find the tool name for this id to detect SDK-noise results.
                    # We don't track name here; rely on the matching tool_use
                    # already filtered below. Keep result; noise calls are
                    # dropped at the assistant side, so their results have no
                    # matching tool_call_id and will be dropped by the SFT
                    # trainer's template. To be safe, we keep all tool results.
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tid,
                        "content": tc,
                    })
            continue

        # --- assistant message ---
        if role == "assistant":
            if isinstance(c, str):
                # plain text assistant turn (e.g. final report)
                if c.strip():
                    messages.append({"role": "assistant", "content": c})
                continue
            if isinstance(c, list):
                thinking_parts = []
                text_parts = []
                tool_calls = []
                for b in c:
                    if not isinstance(b, dict):
                        continue
                    btype = b.get("type")
                    if btype == "thinking":
                        th = (b.get("thinking") or "").strip()
                        if th:
                            thinking_parts.append(th)
                    elif btype == "text":
                        tx = (b.get("text") or "").strip()
                        if tx:
                            text_parts.append(tx)
                    elif btype == "tool_use":
                        name = b.get("name", "")
                        if name not in EVAL_TOOLS:
                            continue  # strip tools unavailable during evaluation
                        # Keep arguments as a Python dict so the Qwen chat
                        # template renders them as a JSON object inside
                        # <tool_call> tags. json.dumps() would produce a JSON
                        # string literal, which vLLM's Hermes tool parser
                        # cannot consume as tool arguments.
                        args = b.get("input") or {}
                        if isinstance(args, str):
                            try:
                                args = json.loads(args)
                            except json.JSONDecodeError:
                                args = {}
                        tool_id = b.get("id", "")
                        if not tool_id:
                            continue
                        kept_tool_ids.add(tool_id)
                        tool_calls.append({
                            "id": tool_id,
                            "type": "function",
                            "function": {
                                "name": name,
                                "arguments": args,
                            },
                        })
                content_text = ""
                if thinking_parts:
                    content_text += "\n\n".join(thinking_parts)
                if text_parts:
                    content_text = (content_text + "\n\n" + "\n\n".join(text_parts)).strip() if content_text else "\n\n".join(text_parts)
                msg = {"role": "assistant"}
                if content_text:
                    msg["content"] = content_text
                else:
                    msg["content"] = ""  # tool_calls-only turns still need a content key
                if tool_calls:
                    msg["tool_calls"] = tool_calls
                # Skip pure-noise assistant turns (no content and no tool_calls).
                if not msg.get("tool_calls") and not msg.get("content"):
                    continue
                messages.append(msg)
                continue
    return _repair_tool_pairs(messages)


def _normalize_openai_events(events: list) -> list:
    """Convert the OpenAI runner's JSONL event stream to trainer messages."""
    messages = []
    pending_calls: list[tuple[str, str]] = []
    for ev in events:
        message = ev.get("message") or ev
        role = message.get("role")
        if role == "user":
            content = message.get("content")
            if isinstance(content, str) and content:
                messages.append({"role": "user", "content": content})
            continue

        if role == "assistant":
            content = message.get("content") or message.get("reasoning_content") or ""
            calls = []
            for call in message.get("tool_calls") or []:
                function = call.get("function") or {}
                name = function.get("name", "")
                call_id = call.get("id", "")
                if name not in EVAL_TOOLS or not call_id:
                    continue
                arguments = function.get("arguments") or {}
                if isinstance(arguments, str):
                    try:
                        arguments = json.loads(arguments)
                    except json.JSONDecodeError:
                        arguments = {}
                if not isinstance(arguments, dict):
                    arguments = {}
                calls.append({
                    "id": call_id,
                    "type": "function",
                    "function": {"name": name, "arguments": arguments},
                })
                pending_calls.append((call_id, name))
            if content or calls:
                normalized = {"role": "assistant", "content": str(content)}
                if calls:
                    normalized["tool_calls"] = calls
                messages.append(normalized)
            continue

        if role == "tool":
            name = str(message.get("name") or "")
            call_id = str(message.get("tool_call_id") or "")
            if not call_id:
                matching_index = next(
                    (
                        index
                        for index, (_, pending_name) in enumerate(pending_calls)
                        if not name or pending_name == name
                    ),
                    None,
                )
                if matching_index is None:
                    continue
                call_id, _ = pending_calls.pop(matching_index)
            else:
                pending_calls = [item for item in pending_calls if item[0] != call_id]
            result = message.get("result", message.get("content", ""))
            if not isinstance(result, str):
                result = json.dumps(result, ensure_ascii=False)
            messages.append({"role": "tool", "tool_call_id": call_id, "content": result})
    return _repair_tool_pairs(messages)


def _normalize_session(events: list, session_format: str, session_dir: str) -> list:
    if session_format == "claude_json_array":
        return _normalize_events(events)

    messages = _normalize_openai_events(events)
    if messages and messages[0].get("role") == "user":
        return messages
    input_path = Path(session_dir) / "input.json"
    if not input_path.exists():
        raise SkipSource("missing_openai_input")
    try:
        input_data = json.loads(input_path.read_text())
        if input_data.get("agent_context") == "no-guide":
            input_data["agent_context"] = "no_guide"
        prompt = build_prompt(input_data)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise SkipSource("invalid_openai_input") from exc
    return [{"role": "user", "content": prompt}, *messages]


def _repair_tool_pairs(messages: list) -> list:
    """Keep only assistant/tool messages with valid OpenAI tool-call pairs."""
    available_results = {
        m.get("tool_call_id")
        for m in messages
        if m.get("role") == "tool" and m.get("tool_call_id")
    }
    repaired = []
    for message in messages:
        if message.get("role") == "assistant" and message.get("tool_calls"):
            calls = [
                call for call in message["tool_calls"]
                if call.get("id") in available_results
                and call.get("function", {}).get("name") in EVAL_TOOLS
            ]
            message = dict(message)
            if calls:
                message["tool_calls"] = calls
            else:
                message.pop("tool_calls", None)
            if not message.get("content") and not message.get("tool_calls"):
                continue
        elif message.get("role") == "tool":
            if message.get("tool_call_id") not in {
                call.get("id")
                for item in messages
                if item.get("role") == "assistant"
                for call in item.get("tool_calls", [])
                if call.get("function", {}).get("name") in EVAL_TOOLS
            }:
                continue
        repaired.append(message)
    return repaired


def _estimate_tokens(messages: list) -> int:
    return int(len(json.dumps(messages, ensure_ascii=False)) / CHARS_PER_TOKEN)


def _compress_messages(messages: list, target_tokens: int) -> tuple[list, bool]:
    """Compress verbose tool results and thinking to fit target token budget.

    Pass 1: compress every tool result longer than the keep threshold.
    Pass 2: compress long thinking blocks in assistant content.
    Pass 3: if still over, shorten tool results further (halve keep sizes).
    Returns (compressed_messages, any_compressed).
    """
    any_compressed = False

    def _maybe_compress_tool(msg, keep_h, keep_t):
        nonlocal any_compressed
        if msg.get("role") != "tool":
            return
        c = msg.get("content", "")
        if len(c) > keep_h + keep_t + 80:
            msg["content"] = _compress_tool_result(c) if (keep_h, keep_t) == (TOOL_RESULT_KEEP_HEAD, TOOL_RESULT_KEEP_TAIL) else (
                c[:keep_h] + f"\n[...truncated {len(c)-keep_h-keep_t} chars...]\n" + c[-keep_t:]
            )
            any_compressed = True

    def _maybe_compress_thinking(msg):
        nonlocal any_compressed
        if msg.get("role") != "assistant":
            return
        c = msg.get("content", "")
        if c and len(c) > THINKING_KEEP_HEAD + THINKING_KEEP_TAIL + 80:
            # only compress if this looks like a thinking block (long prose before tool calls)
            msg["content"] = _compress_thinking(c)
            any_compressed = True

    # Pass 1: compress all overlong tool results once.
    for m in messages:
        _maybe_compress_tool(m, TOOL_RESULT_KEEP_HEAD, TOOL_RESULT_KEEP_TAIL)
    # Pass 2: compress overlong thinking.
    for m in messages:
        _maybe_compress_thinking(m)
    # Pass 3: iteratively halve tool-result keep sizes until under target.
    keep_h, keep_t = TOOL_RESULT_KEEP_HEAD, TOOL_RESULT_KEEP_TAIL
    while _estimate_tokens(messages) > target_tokens:
        keep_h, keep_t = max(keep_h // 2, 200), max(keep_t // 2, 200)
        if keep_h == 200 and keep_t == 200:
            # already at floor; compress every tool result to 200+200
            changed = False
            for m in messages:
                c = m.get("content", "")
                if m.get("role") == "tool" and len(c) > 480:
                    m["content"] = c[:200] + f"\n[...truncated {len(c)-400} chars...]\n" + c[-200:]
                    any_compressed = True
                    changed = True
            if not changed or _estimate_tokens(messages) <= target_tokens:
                break
            if keep_h == 200:
                break

    def _truncate_text(content: str, limit: int) -> str:
        if len(content) <= limit:
            return content
        head = max(limit // 2, 1)
        tail = max(limit - head - 40, 1)
        dropped = len(content) - head - tail
        return f"{content[:head]}\n[...truncated {dropped} chars...]\n{content[-tail:]}"

    # A trajectory can exceed the budget through many medium-sized outputs,
    # even when no individual result is large. Preserve the call/result
    # sequence and progressively reduce payload text as one total budget.
    for limit in (320, 96, 32):
        if _estimate_tokens(messages) <= target_tokens:
            break
        for message in messages:
            if message.get("role") == "tool":
                content = message.get("content", "")
                compact = _truncate_text(content, limit)
                if compact != content:
                    message["content"] = compact
                    any_compressed = True

    for limit in (600, 240, 80):
        if _estimate_tokens(messages) <= target_tokens:
            break
        for message in messages:
            if message.get("role") == "assistant":
                content = message.get("content", "")
                compact = _truncate_text(content, limit)
                if compact != content:
                    message["content"] = compact
                    any_compressed = True

    return messages, any_compressed


def _system_prompt_for(ctx: str) -> str:
    """Select the system prompt matching the agent_context the trajectory ran under.

    All modern eval contexts (including guided) use the unified no-hint system
    prompt. The task prompt may contain varying amounts of guidance (l0/l1/l2 or
    full exploit guides), but the system-level contract remains the same: no
    fixed flag locations or read commands are provided by the system message.
    """
    if ctx in ("l0", "l1", "l2", "no_hint", "no-guide", "no_guide", "guided"):
        return NO_HINT_SYSTEM_PROMPT
    return SYSTEM_PROMPT


def _leak_scan(messages: list) -> list:
    """Scan task-input text (system + first user) for forbidden oracle fields."""
    found = []
    # Only scan the task prompt (system + first user message), not the whole
    # conversation: the agent legitimately encounters flags later.
    scan_text = ""
    for m in messages[:2]:
        scan_text += m.get("content", "") or ""
        scan_text += json.dumps(m.get("tool_calls", []), ensure_ascii=False)
    low = scan_text.lower()
    for pat in LEAK_PATTERNS:
        if pat.lower() in low:
            found.append(pat)
    return found


def _process_trajectory(vr_path: str, max_len_tokens: int, default_context: str = "guided") -> list:
    """Return list of SFT sample dicts for one trajectory (one per captured hop)."""
    try:
        d = json.loads(Path(vr_path).read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SkipSource("invalid_verify_result") from exc
    ctx = d.get("agent_context") or default_context
    ALLOWED_CONTEXTS = {"l0", "l1", "l2", "no_hint", "no-guide", "no_guide", "guided"}
    if ctx not in ALLOWED_CONTEXTS:
        raise SkipSource("unsupported_agent_context")
    fv = d.get("flag_verification") or {}
    per = fv.get("per_target") or {}
    n_captured = sum(1 for x in per.values() if isinstance(x, dict) and x.get("match") is True)
    if n_captured < 1:
        raise SkipSource("no_verified_flags")

    sd = os.path.dirname(vr_path)
    sj = os.path.join(sd, "agent_workspace", "session.json")
    gt = os.path.join(sd, "ground_truth.json")
    if not os.path.exists(sj):
        raise SkipSource("missing_session")
    if not os.path.exists(gt):
        raise SkipSource("missing_ground_truth")
    session, session_format = _load_session(sj)
    try:
        g = json.loads(Path(gt).read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SkipSource("invalid_ground_truth") from exc
    flags = [x.get("flag") for x in g.get("attack_path", []) if x.get("flag")]
    if len(flags) < n_captured:
        # ground truth has fewer flags than captured; clamp
        n_captured = len(flags)

    flag_events = _find_flag_events(session, flags[:n_captured])
    # Only keep flags that were actually located in the session.
    located = [(fl, ei) for fl, ei in zip(flags[:n_captured], flag_events) if ei is not None]
    if not located:
        raise SkipSource("verified_flags_not_found_in_session")

    system_prompt = _system_prompt_for(ctx)
    case_id = (d.get("validation_round") or {}).get("case_id") or os.path.basename(sd)
    samples = []

    for k in range(1, len(located) + 1):
        # Every sample is a prefix ending at the k-th flag capture event.
        # (No full-session samples: the failed tail after the last success is
        # noise, and the final structured report is handled separately below.)
        end_event = located[k - 1][1]
        events_slice = session[: end_event + 1]
        sample_kind = f"hop{k}"

        messages = _normalize_session(events_slice, session_format, os.path.dirname(sj))
        messages = [{"role": "system", "content": system_prompt}] + messages
        # If the first non-system message is not a user message, the session
        # format is unexpected; skip.
        if len(messages) < 2 or messages[1].get("role") != "user":
            continue

        toks = _estimate_tokens(messages)
        compressed = False
        if toks > max_len_tokens:
            messages, compressed = _compress_messages(messages, max_len_tokens)
            toks = _estimate_tokens(messages)

        leaks = _leak_scan(messages)
        if leaks:
            # record but still emit with a leak flag for manual review
            pass

        samples.append({
            "task_id": f"{case_id}.{sample_kind}",
            "case_id": case_id,
            "is_resolved": True,
            "n_hops_captured": k,
            "agent_context": ctx,
            "session_format": session_format,
            "est_tokens": toks,
            "compressed": compressed,
            "leaks": leaks,
            "messages": messages,
        })

    # For fully-successful trajectories (all flags captured AND verified),
    # add one short sample that teaches the final structured JSON report:
    # the full session's last assistant text message containing the report.
    all_flags_located = len(located) == len(flags) and all(e is not None for e in flag_events)
    if all_flags_located and d.get("agent_success"):
        final_report = _extract_final_report(session)
        if final_report:
            normalized_session = _normalize_session(session, session_format, os.path.dirname(sj))
            task_prompt = next(
                (
                    message.get("content", "")
                    for message in normalized_session
                    if message.get("role") == "user"
                ),
                "",
            )
            report_messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": task_prompt},
                {"role": "assistant", "content": final_report},
            ]
            toks = _estimate_tokens(report_messages)
            samples.append({
                "task_id": f"{case_id}.report",
                "case_id": case_id,
                "is_resolved": True,
                "n_hops_captured": len(located),
                "agent_context": ctx,
                "session_format": session_format,
                "est_tokens": toks,
                "compressed": False,
                "leaks": _leak_scan(report_messages),
                "messages": report_messages,
            })

    if not samples:
        raise SkipSource("session_has_no_supported_user_conversation")
    return samples


def _process_full_trajectory(
    vr_path: str,
    max_len_tokens: int,
    default_context: str = "guided",
    include_unresolved: bool = True,
) -> list:
    """Convert one complete attempt without creating hop prefixes."""
    try:
        d = json.loads(Path(vr_path).read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SkipSource("invalid_verify_result") from exc
    ctx = d.get("agent_context") or default_context
    if ctx not in {"l0", "l1", "l2", "no_hint", "no-guide", "no_guide", "guided"}:
        raise SkipSource("unsupported_agent_context")

    resolved = bool(d.get("agent_success", d.get("success", False)))
    if not include_unresolved and not resolved:
        raise SkipSource("unresolved_excluded")

    sd = os.path.dirname(vr_path)
    sj = os.path.join(sd, "agent_workspace", "session.json")
    if not os.path.exists(sj):
        raise SkipSource("missing_session")
    session, session_format = _load_session(sj)
    messages = [{"role": "system", "content": _system_prompt_for(ctx)}]
    messages.extend(_normalize_session(session, session_format, os.path.dirname(sj)))
    if len(messages) < 2 or messages[1].get("role") != "user":
        raise SkipSource("session_has_no_supported_user_conversation")

    toks = _estimate_tokens(messages)
    compressed = False
    if toks > max_len_tokens:
        messages, compressed = _compress_messages(messages, max_len_tokens)
        toks = _estimate_tokens(messages)

    case_id = (d.get("validation_round") or {}).get("case_id") or os.path.basename(sd)
    attempt_id = (
        (d.get("validation_round") or {}).get("run_id")
        or d.get("scenario_name")
        or os.path.basename(sd)
    )
    attempt_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(attempt_id))
    per = (d.get("flag_verification") or {}).get("per_target") or {}
    n_captured = sum(
        1 for item in per.values()
        if isinstance(item, dict) and item.get("match") is True
    )
    return [{
        "task_id": f"{case_id}.{attempt_id}.full",
        "case_id": case_id,
        "is_resolved": resolved,
        "n_hops_captured": n_captured,
        "agent_context": ctx,
        "session_format": session_format,
        "sample_kind": "full",
        "attempt_id": attempt_id,
        "est_tokens": toks,
        "compressed": compressed,
        "leaks": _leak_scan(messages),
        "messages": messages,
    }]


def _extract_final_report(session: list) -> str:
    """Find the last assistant text message that looks like a structured JSON report."""
    for ev in reversed(session):
        m = ev.get("message", ev)
        if m.get("role") != "assistant":
            continue
        c = m.get("content")
        text = ""
        if isinstance(c, str):
            text = c
        elif isinstance(c, list):
            text = "\n".join((b.get("text") or "") for b in c if isinstance(b, dict) and b.get("type") == "text")
        if '"success"' in text and '"verified_flags"' in text:
            return text
    return ""


def _sample_id(sample: dict) -> str:
    identity = {
        "converter_version": CONVERTER_VERSION,
        "source_content_sha256": sample["source_content_sha256"],
        "task_id": sample["task_id"],
        "messages": sample["messages"],
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"sft-{_sha256_bytes(encoded.encode())}"


def _validate_unique_task_ids(samples: list[dict]) -> None:
    counts = Counter(sample["task_id"] for sample in samples)
    duplicates = sorted(task_id for task_id, count in counts.items() if count > 1)
    if duplicates:
        raise ValueError(f"duplicate task_id values: {', '.join(duplicates)}")
    sample_ids = [sample["sample_id"] for sample in samples]
    if len(sample_ids) != len(set(sample_ids)):
        raise ValueError("duplicate stable sample_id values")


def _safe_mkdir_parent(path: str) -> None:
    parent = Path(path).parent
    if str(parent) != ".":
        parent.mkdir(parents=True, exist_ok=True)


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--root",
        action="append",
        default=None,
        help="Directory to scan for Range verify_result.json files (can be repeated)",
    )
    ap.add_argument(
        "--default-context",
        default="guided",
        help="Context label for trajectories that do not set agent_context in verify_result.json",
    )
    ap.add_argument("--out", default="data/sft/cve_attack_sft_v1.jsonl")
    ap.add_argument("--report", default="data/sft/length_report.json")
    ap.add_argument("--max-len", type=int, default=MAX_LEN_TOKENS)
    ap.add_argument(
        "--sample-mode", choices=("prefix", "full"), default="prefix",
        help="Legacy flag-capture prefixes, or complete independent attempts",
    )
    ap.add_argument(
        "--include-unresolved", action="store_true",
        help="In full mode, retain attempts whose agent did not resolve the task",
    )
    ap.add_argument(
        "--drop-leaks", action="store_true",
        help="Drop samples whose task input contains a forbidden oracle field",
    )
    return ap


def convert(args: argparse.Namespace) -> dict:
    if args.root is None:
        args.root = ["data/guide_ablation"]
    max_len = args.max_len

    _safe_mkdir_parent(args.out)
    skipped_overlong = 0
    leaks_total = 0
    skipped_leaks = 0
    sources: list[dict] = []

    # Collect best trajectory per case_id to avoid duplicate reruns.
    # Sort key prefers more captured hops and a final report (all flags captured).
    case_trajectories: dict[str, tuple[tuple[int, bool], list[dict], dict]] = {}
    full_attempts: list[tuple[list[dict], dict]] = []

    for root_index, root in enumerate(args.root):
        pattern = os.path.join(root, "**", "verify_result.json")
        for vr in sorted(glob.glob(pattern, recursive=True)):
            relative_path = Path(vr).resolve().relative_to(Path(root).resolve()).as_posix()
            source_identity = f"root{root_index}/{relative_path}"
            source_dir = os.path.dirname(vr)
            session_path = os.path.join(source_dir, "agent_workspace", "session.json")
            source_hash = _source_content_hash(
                [
                    vr,
                    session_path,
                    os.path.join(source_dir, "ground_truth.json"),
                    os.path.join(source_dir, "agent_workspace", "input.json"),
                ]
            )
            source = {
                "source_identity": source_identity,
                "source_content_sha256": source_hash,
                "status": "pending",
                "emitted_count": 0,
            }
            sources.append(source)
            try:
                if args.sample_mode == "full":
                    samples = _process_full_trajectory(
                        vr,
                        max_len,
                        args.default_context,
                        include_unresolved=args.include_unresolved,
                    )
                else:
                    samples = _process_trajectory(vr, max_len, args.default_context)
            except SkipSource as exc:
                source.update(status="skipped", skip_reason=exc.reason)
                print(f"[skip:{exc.reason}] {source_identity}", file=sys.stderr)
                continue
            except Exception as exc:
                reason = f"conversion_error_{type(exc).__name__}"
                source.update(status="skipped", skip_reason=reason)
                print(f"[skip:{reason}] {source_identity}", file=sys.stderr)
                continue
            if not samples:
                source.update(status="skipped", skip_reason="no_samples_emitted")
                continue
            source["session_format"] = samples[0]["session_format"]
            for sample in samples:
                sample.update(
                    {
                        "schema_version": SFT_RECORD_SCHEMA_VERSION,
                        "converter_version": CONVERTER_VERSION,
                        "source_identity": source_identity,
                        "source_content_sha256": source_hash,
                    }
                )
                sample["sample_id"] = _sample_id(sample)
            if args.sample_mode == "full":
                full_attempts.append((samples, source))
                continue
            case_id = samples[0]["task_id"].split(".", 1)[0]
            max_n = max(s["n_hops_captured"] for s in samples)
            is_full = any(s["task_id"].endswith(".report") for s in samples)
            key = (max_n, is_full)
            existing = case_trajectories.get(case_id)
            if existing is None or key > existing[0]:
                if existing is not None:
                    existing[2].update(status="skipped", skip_reason="superseded_case_trajectory")
                case_trajectories[case_id] = (key, samples, source)
            else:
                source.update(status="skipped", skip_reason="superseded_case_trajectory")

    all_samples = []
    source_samples = (
        full_attempts
        if args.sample_mode == "full"
        else [(samples, source) for _, samples, source in case_trajectories.values()]
    )
    for samples, source in source_samples:
        dropped_for_source = Counter()
        for s in samples:
            if s["est_tokens"] > max_len:
                skipped_overlong += 1
                dropped_for_source["overlong"] += 1
                continue
            if s["leaks"] and args.drop_leaks:
                skipped_leaks += 1
                dropped_for_source["leak"] += 1
                continue
            all_samples.append(s)
            source["emitted_count"] += 1
            if s["leaks"]:
                leaks_total += 1
        if dropped_for_source:
            source["dropped_sample_counts"] = dict(dropped_for_source)
        if source["emitted_count"]:
            source["status"] = "converted"
        else:
            source.update(status="skipped", skip_reason="all_samples_filtered")

    _validate_unique_task_ids(all_samples)

    by_ctx = Counter(s["agent_context"] for s in all_samples)
    by_hop = Counter(s["n_hops_captured"] for s in all_samples)

    output_content = "".join(json.dumps(s, ensure_ascii=False) + "\n" for s in all_samples)
    Path(args.out).write_text(output_content)
    output_sha256 = _sha256_bytes(output_content.encode())
    output_path = Path(args.out).resolve()
    report_path = Path(args.report).resolve()
    portable_output_path = os.path.relpath(output_path, report_path.parent)

    lens = sorted(s["est_tokens"] for s in all_samples)
    n = len(lens)
    safe_arguments = {
        "default_context": args.default_context,
        "drop_leaks": args.drop_leaks,
        "include_unresolved": args.include_unresolved,
        "max_len": args.max_len,
        "root_count": len(args.root),
        "sample_mode": args.sample_mode,
    }
    source_manifest = [
        {
            key: value
            for key, value in source.items()
            if key
            in {
                "source_identity",
                "source_content_sha256",
                "session_format",
                "status",
                "skip_reason",
                "emitted_count",
                "dropped_sample_counts",
            }
        }
        for source in sorted(sources, key=lambda item: item["source_identity"])
    ]
    skipped_sources = [source for source in source_manifest if source["status"] == "skipped"]
    corpus_identity = {
        "converter": {
            "name": Path(__file__).name,
            "version": CONVERTER_VERSION,
            "arguments": safe_arguments,
        },
        "sources": source_manifest,
        "output_sha256": output_sha256,
        "record_count": n,
    }
    corpus_id = "sft-corpus-" + _sha256_bytes(
        json.dumps(
            corpus_identity,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
    )
    report = {
        "schema_version": CORPUS_MANIFEST_SCHEMA_VERSION,
        "record_schema_version": SFT_RECORD_SCHEMA_VERSION,
        "corpus_id": corpus_id,
        "converter": corpus_identity["converter"],
        "sources": source_manifest,
        "source_counts": {
            "discovered": len(source_manifest),
            "converted": sum(source["status"] == "converted" for source in source_manifest),
            "skipped": len(skipped_sources),
        },
        "skipped_sources": skipped_sources,
        "skipped_by_reason": dict(Counter(source["skip_reason"] for source in skipped_sources)),
        "corpus_sha256": output_sha256,
        # Keep the corpus location relative to the report, so --out and
        # --report may live in different directories without embedding an
        # absolute machine path. The basename remains for old consumers.
        "output": {
            "file_name": Path(args.out).name,
            "path": portable_output_path,
            "sha256": output_sha256,
            "record_count": n,
        },
        "n_samples": n,
        "skipped_overlong": skipped_overlong,
        "skipped_leaks": skipped_leaks,
        "leak_flagged_samples": leaks_total,
        "by_context": dict(by_ctx),
        "by_hops_captured": dict(by_hop),
        "by_resolved": dict(Counter(s.get("is_resolved") for s in all_samples)),
        "by_sample_kind": dict(Counter(s.get("sample_kind", "prefix") for s in all_samples)),
        "token_stats": {
            "min": min(lens) if lens else 0,
            "median": lens[n // 2] if lens else 0,
            "mean": sum(lens) // n if lens else 0,
            "p90": lens[int(n * 0.9)] if lens else 0,
            "max": max(lens) if lens else 0,
        },
    }
    _safe_mkdir_parent(args.report)
    Path(args.report).write_text(json.dumps(report, indent=2) + "\n")

    print(json.dumps(report, indent=2))
    print(f"\nWrote {n} samples -> {args.out}")
    return report


def main():
    args = _build_parser().parse_args()
    convert(args)


if __name__ == "__main__":
    main()
