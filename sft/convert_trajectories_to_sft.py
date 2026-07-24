"""Convert CVELab attack trajectories into SFT chat JSONL.

Reads Claude-SDK format session.json from clean-context scenarios
(l0/l1/l2/no_hint), locates each captured flag's position in the session,
and emits OpenAI-style tool-call chat samples:

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
import json
import os
import re
import sys
import glob
from collections import Counter

# Import the system prompts from the orchestrator package.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from clab_builder.orchestrator.composer.scenario_runner import (  # noqa: E402
    SYSTEM_PROMPT,
    NO_HINT_SYSTEM_PROMPT,
    _resolve_level,
)

CHARS_PER_TOKEN = 3.5
MAX_LEN_TOKENS = 32768
TOOL_RESULT_KEEP_HEAD = 1500
TOOL_RESULT_KEEP_TAIL = 1500

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


def _event_text(ev: dict) -> str:
    """Flatten an event's message content to a single string (for search/length)."""
    m = ev.get("message", {})
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
                        if name in SDK_NOISE_TOOLS:
                            continue  # strip SDK noise
                        tool_calls.append({
                            "id": b.get("id", ""),
                            "type": "function",
                            "function": {
                                "name": name,
                                "arguments": json.dumps(b.get("input") or {}, ensure_ascii=False),
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
    return messages


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
    return messages, any_compressed


def _system_prompt_for(ctx: str) -> str:
    """Select the system prompt matching the agent_context the trajectory ran under."""
    level = _resolve_level(ctx)
    if level in ("l0", "l1", "l2") or ctx == "no_hint":
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


def _process_trajectory(vr_path: str, max_len_tokens: int) -> list:
    """Return list of SFT sample dicts for one trajectory (one per captured hop)."""
    d = json.load(open(vr_path))
    ctx = d.get("agent_context", "")
    if ctx not in {"l0", "l1", "l2", "no_hint"}:
        return []
    fv = d.get("flag_verification") or {}
    per = fv.get("per_target") or {}
    n_captured = sum(1 for x in per.values() if isinstance(x, dict) and x.get("match") is True)
    if n_captured < 1:
        return []

    sd = os.path.dirname(vr_path)
    sj = os.path.join(sd, "agent_workspace", "session.json")
    gt = os.path.join(sd, "ground_truth.json")
    if not (os.path.exists(sj) and os.path.exists(gt)):
        return []
    with open(sj) as f:
        if not f.read(5).lstrip().startswith("["):
            return []  # only Claude-format sessions
    session = json.load(open(sj))
    g = json.load(open(gt))
    flags = [x.get("flag") for x in g.get("attack_path", []) if x.get("flag")]
    if len(flags) < n_captured:
        # ground truth has fewer flags than captured; clamp
        n_captured = len(flags)

    flag_events = _find_flag_events(session, flags[:n_captured])
    # Only keep flags that were actually located in the session.
    located = [(fl, ei) for fl, ei in zip(flags[:n_captured], flag_events) if ei is not None]
    if not located:
        return []

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

        messages = _normalize_events(events_slice)
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
            "is_resolved": True,
            "n_hops_captured": k,
            "agent_context": ctx,
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
            report_messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": _event_text(session[0]) if session else ""},
                {"role": "assistant", "content": final_report},
            ]
            toks = _estimate_tokens(report_messages)
            samples.append({
                "task_id": f"{case_id}.report",
                "is_resolved": True,
                "n_hops_captured": len(located),
                "agent_context": ctx,
                "est_tokens": toks,
                "compressed": False,
                "leaks": _leak_scan(report_messages),
                "messages": report_messages,
            })

    return samples


def _extract_final_report(session: list) -> str:
    """Find the last assistant text message that looks like a structured JSON report."""
    for ev in reversed(session):
        m = ev.get("message", {})
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


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default="data/guide_ablation")
    ap.add_argument("--out", default="data/sft/cve_attack_sft_v1.jsonl")
    ap.add_argument("--report", default="data/sft/length_report.json")
    ap.add_argument("--max-len", type=int, default=MAX_LEN_TOKENS)
    args = ap.parse_args()
    max_len = args.max_len

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    all_samples = []
    skipped_overlong = 0
    leaks_total = 0
    by_ctx = Counter()
    by_hop = Counter()

    for vr in sorted(glob.glob(os.path.join(args.root, "*/scenarios/*/verify_result.json"))):
        try:
            samples = _process_trajectory(vr, max_len)
        except Exception as exc:
            print(f"[skip] {vr}: {exc}", file=sys.stderr)
            continue
        for s in samples:
            if s["est_tokens"] > max_len:
                skipped_overlong += 1
                continue
            all_samples.append(s)
            by_ctx[s["agent_context"]] += 1
            by_hop[s["n_hops_captured"]] += 1
            if s["leaks"]:
                leaks_total += 1

    with open(args.out, "w") as f:
        for s in all_samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    lens = sorted(s["est_tokens"] for s in all_samples)
    n = len(lens)
    report = {
        "n_samples": n,
        "skipped_overlong": skipped_overlong,
        "leak_flagged_samples": leaks_total,
        "by_context": dict(by_ctx),
        "by_hops_captured": dict(by_hop),
        "token_stats": {
            "min": min(lens) if lens else 0,
            "median": lens[n // 2] if lens else 0,
            "mean": sum(lens) // n if lens else 0,
            "p90": lens[int(n * 0.9)] if lens else 0,
            "max": max(lens) if lens else 0,
        },
    }
    os.makedirs(os.path.dirname(args.report), exist_ok=True)
    with open(args.report, "w") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))
    print(f"\nWrote {n} samples -> {args.out}")


if __name__ == "__main__":
    main()
