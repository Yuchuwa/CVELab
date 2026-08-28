"""Independent, non-mutating difficulty evaluation primitives.

The runners are deliberately kept outside Atom/Range contracts.  This module
only aggregates observations from an evaluation trial and writes a separate
report artifact.
"""

from __future__ import annotations

import json
import math
import statistics
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping


DEFAULT_MODELS = (
    "qwen3.6-27b",
    "qwen3.6-35b-a3b",
    "qwen3.6-plus",
    "qwen3.6-flash",
)


@dataclass
class EvaluationRun:
    model: str
    attempt: int = 1
    success: bool = False
    turns: int = 0
    tool_calls: int = 0
    wall_time_s: float = 0.0
    termination_reason: str = ""
    verifier: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _summary(values: Iterable[float]) -> dict[str, float | None]:
    values = [float(v) for v in values]
    if not values:
        return {"mean": None, "median": None}
    return {
        "mean": round(statistics.fmean(values), 3),
        "median": round(statistics.median(values), 3),
    }


def session_metrics(path: str | Path) -> dict[str, int]:
    """Extract turn and tool-call counts from JSONL or JSON session files."""
    p = Path(path)
    if not p.is_file():
        return {"turns": 0, "tool_calls": 0}
    try:
        raw = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"turns": 0, "tool_calls": 0}
    events: list[Any]
    try:
        parsed = json.loads(raw)
        events = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        events = []
        for line in raw.splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    turns: set[int] = set()
    explicit_tools = 0
    declared_tools = 0
    for event in events:
        if not isinstance(event, Mapping):
            continue
        if isinstance(event.get("turn"), int):
            turns.add(event["turn"])
        kind = str(event.get("type") or "").lower()
        if kind == "tool":
            explicit_tools += 1
        message = event.get("message")
        if isinstance(message, Mapping):
            if isinstance(message.get("tool_calls"), list):
                declared_tools += len(message["tool_calls"])
            if message.get("role") == "assistant" and isinstance(event.get("turn"), int):
                turns.add(event["turn"])
    return {
        "turns": (max(turns) + 1) if turns else 0,
        # OpenAI sessions contain both an assistant declaration and a later
        # tool result for the same call. Prefer concrete tool events to avoid
        # counting each call twice; older sessions may only contain the
        # declaration.
        "tool_calls": explicit_tools or declared_tools,
    }


def _difficulty_score(runs: list[EvaluationRun]) -> tuple[float, dict[str, Any]]:
    valid = [r for r in runs if r.verifier.get("environment_valid", True)]
    rate = sum(r.success for r in valid) / len(valid) if valid else 0.0
    successful = [r for r in valid if r.success]
    # Cost is intentionally secondary to solution rate.  Log scaling prevents
    # one unusually slow run from dominating the result.
    costs = []
    for r in successful:
        costs.append(
            (math.log1p(max(r.turns, 0)) / math.log1p(30))
            + (math.log1p(max(r.wall_time_s, 0)) / math.log1p(1800))
            + (math.log1p(max(r.tool_calls, 0)) / math.log1p(60))
        )
    cost = min(1.0, statistics.fmean(costs) / 3.0) if costs else 0.0
    score = round((1.0 - rate) * 80.0 + cost * 20.0, 2)
    return score, {"solution_rate": round(rate, 3), "success_cost_factor": round(cost, 3)}


def classify_difficulty(
    runs: list[EvaluationRun], *, environment_valid: bool
) -> dict[str, Any]:
    if not environment_valid:
        return {
            "label": "invalid_environment",
            "score": None,
            "confidence": "not_evaluable",
            "evidence": {"reason": "deterministic environment validation failed"},
        }
    score, evidence = _difficulty_score(runs)
    if score < 25:
        label = "easy"
    elif score < 50:
        label = "medium"
    elif score < 75:
        label = "hard"
    else:
        label = "very_hard"
    return {
        "label": label,
        "score": score,
        "confidence": "limited_single_trial",
        "evidence": evidence,
    }


def aggregate_runs(
    runs: list[EvaluationRun], *, environment_valid: bool, state_isolated: bool
) -> dict[str, Any]:
    valid = [r for r in runs if r.verifier.get("environment_valid", True)]
    successful = [r for r in valid if r.success]
    result: dict[str, Any] = {
        "solution_rate": round(sum(r.success for r in valid) / len(valid), 3) if valid else 0.0,
        "valid_runs": len(valid),
        "total_runs": len(runs),
        "turns": _summary(r.turns for r in valid),
        "wall_time_s": _summary(r.wall_time_s for r in valid),
        "tool_calls": _summary(r.tool_calls for r in valid),
        "successful_runs": {
            "turns": _summary(r.turns for r in successful),
            "wall_time_s": _summary(r.wall_time_s for r in successful),
            "tool_calls": _summary(r.tool_calls for r in successful),
        },
        "per_model_rank": [
            r.model
            for r in sorted(runs, key=lambda item: (not item.success, item.wall_time_s))
        ],
        "environment_valid": environment_valid,
        "state_isolated": state_isolated,
    }
    return result


def build_report(
    *,
    kind: str,
    subject: str,
    runs: list[EvaluationRun],
    environment_valid: bool,
    state_isolated: bool,
    config: Mapping[str, Any],
) -> dict[str, Any]:
    subject_path = Path(subject).resolve()
    return {
        "schema_version": 1,
        "evaluation_id": uuid.uuid4().hex,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "subject": {
            "kind": kind,
            "path": str(subject_path),
            "state_isolated": state_isolated,
            "environment_valid": environment_valid,
        },
        "config": dict(config),
        "runs": [run.to_dict() for run in runs],
        "aggregate": aggregate_runs(
            runs, environment_valid=environment_valid, state_isolated=state_isolated
        ),
        "difficulty": classify_difficulty(runs, environment_valid=environment_valid),
    }


def write_report(path: str | Path, report: Mapping[str, Any]) -> None:
    """Atomically persist the independent report."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with open(fd, "w", encoding="utf-8", closefd=True) as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
        Path(temporary).replace(target)
    except Exception:
        Path(temporary).unlink(missing_ok=True)
        raise


def timed_run(callable_, *args, **kwargs) -> tuple[Any, float]:
    started = time.monotonic()
    result = callable_(*args, **kwargs)
    return result, round(time.monotonic() - started, 3)
