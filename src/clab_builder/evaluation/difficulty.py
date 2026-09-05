"""Independent, non-mutating difficulty evaluation primitives.

The runners are deliberately kept outside Atom/Range contracts.  This module
only aggregates observations from an evaluation trial and writes a separate
report artifact.
"""

from __future__ import annotations

import hashlib
import json
import math
import statistics
import tempfile
import time
import uuid
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .constants import DIFFICULTY_THRESHOLDS


@dataclass
class EvaluationRun:
    """一个模型的一次评估结果。

    `success` 必须来自 CVELab 的 verifier，而不是模型自己在文本中声称
    成功。`verifier` 保留原始判定字段，方便之后审计为什么成功或失败。
    """

    model: str
    attempt: int = 1
    success: bool = False
    turns: int = 0
    tool_calls: int = 0
    wall_time_s: float = 0.0
    termination_reason: str = ""
    status: str = "valid"
    verifier: dict[str, Any] = field(default_factory=dict)
    artifacts: dict[str, Any] = field(default_factory=dict)
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


def _valid_runs(runs: Iterable[EvaluationRun]) -> list[EvaluationRun]:
    return [
        run
        for run in runs
        if run.status == "valid"
        and run.verifier.get("environment_valid") is True
    ]


def verifier_backed_success(result: Mapping[str, Any]) -> bool:
    """Return only an explicit three-gate verifier success."""
    return bool(
        result.get("environment_success") is True
        and result.get("agent_success") is True
        and result.get("objective_achieved") is True
    )


def trial_specs(
    models: Iterable[str], attempts_per_model: int
) -> list[tuple[str, int]]:
    if attempts_per_model < 1:
        raise ValueError("attempts_per_model must be positive")
    model_list = list(models)
    if not model_list:
        raise ValueError("at least one model is required")
    return [
        (model, attempt)
        for model in model_list
        for attempt in range(1, attempts_per_model + 1)
    ]


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def wilson_interval(
    successes: int, total: int, *, z: float = 1.959963984540054
) -> dict[str, float | int | None]:
    """Return a two-sided Wilson interval for a binomial success probability."""
    if successes < 0 or total < 0 or successes > total:
        raise ValueError("successes must satisfy 0 <= successes <= total")
    if total == 0:
        return {
            "method": "wilson",
            "confidence_level": 0.95,
            "successes": successes,
            "total": total,
            "lower": None,
            "upper": None,
        }
    rate = successes / total
    z2 = z * z
    denominator = 1.0 + z2 / total
    center = (rate + z2 / (2.0 * total)) / denominator
    half_width = (
        z
        * math.sqrt(rate * (1.0 - rate) / total + z2 / (4.0 * total * total))
        / denominator
    )
    return {
        "method": "wilson",
        "confidence_level": 0.95,
        "successes": successes,
        "total": total,
        "lower": round(max(0.0, center - half_width), 4),
        "upper": round(min(1.0, center + half_width), 4),
    }


def _normalized_cost(run: EvaluationRun) -> float:
    components = (
        math.log1p(max(run.turns, 0)) / math.log1p(30),
        math.log1p(max(run.wall_time_s, 0)) / math.log1p(1800),
        math.log1p(max(run.tool_calls, 0)) / math.log1p(60),
    )
    return min(1.0, statistics.fmean(components))


def _label_for_score(score: float) -> str:
    if score < DIFFICULTY_THRESHOLDS[0]:
        return "easy"
    if score < DIFFICULTY_THRESHOLDS[1]:
        return "medium"
    if score < DIFFICULTY_THRESHOLDS[2]:
        return "hard"
    return "very_hard"


def _labels_for_score_interval(lower: float, upper: float) -> list[str]:
    labels = []
    for label, start, end in (
        ("easy", 0.0, 25.0),
        ("medium", 25.0, 50.0),
        ("hard", 50.0, 75.0),
        ("very_hard", 75.0, 100.0),
    ):
        if lower <= end and upper >= start:
            labels.append(label)
    return labels


def session_metrics(path: str | Path) -> dict[str, int]:
    """从 Runner 产生的 session 中提取 turns 和实际工具调用次数。

    OpenAI runner 通常会同时记录：
    1. assistant 发出的 tool-call 声明；
    2. 工具真正执行后的 tool 事件。

    两者描述的是同一次调用，所以有实际 tool 事件时优先使用它们，避免
    把工具调用数计算成真实值的两倍。
    """
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
        role = str(event.get("role") or "").lower()
        if kind == "tool" or role == "tool":
            explicit_tools += 1
        if role == "assistant" and isinstance(event.get("turn"), int):
            turns.add(event["turn"])
        if isinstance(event.get("tool_calls"), list):
            declared_tools += len(event["tool_calls"])
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
    """计算一个可解释的 0-100 难度分。

    解决率占 80%，执行成本占 20%。成本使用对数归一化，避免某一次极慢
    的运行完全淹没解决率这个更重要的指标。
    """
    valid = _valid_runs(runs)
    rate = sum(r.success for r in valid) / len(valid) if valid else 0.0
    successful = [r for r in valid if r.success]
    failed = [r for r in valid if not r.success]
    # Cost is intentionally secondary to solution rate.  Log scaling prevents
    # one unusually slow run from dominating the result.
    success_cost = (
        statistics.fmean(_normalized_cost(run) for run in successful)
        if successful
        else None
    )
    failure_cost = (
        statistics.fmean(_normalized_cost(run) for run in failed)
        if failed
        else None
    )
    # Preserve the frozen v1 score for comparability. Failure cost is reported
    # separately rather than silently changing historical 80/20 semantics.
    score_cost = success_cost or 0.0
    score = round((1.0 - rate) * 80.0 + score_cost * 20.0, 2)
    interval = wilson_interval(sum(run.success for run in valid), len(valid))
    lower_rate = interval["lower"]
    upper_rate = interval["upper"]
    score_interval = {
        "lower": (
            round((1.0 - float(upper_rate)) * 80.0 + score_cost * 20.0, 2)
            if upper_rate is not None
            else None
        ),
        "upper": (
            round((1.0 - float(lower_rate)) * 80.0 + score_cost * 20.0, 2)
            if lower_rate is not None
            else None
        ),
        "method": "wilson_solution_rate_with_fixed_v1_success_cost",
    }
    return score, {
        "solution_rate": round(rate, 3),
        "solution_rate_interval": interval,
        "success_cost_factor": (
            round(success_cost, 3) if success_cost is not None else None
        ),
        "failure_cost_factor": (
            round(failure_cost, 3) if failure_cost is not None else None
        ),
        "score_interval": score_interval,
    }


def classify_difficulty(
    runs: list[EvaluationRun],
    *,
    environment_valid: bool,
    state_isolated: bool = True,
) -> dict[str, Any]:
    # 环境自身没有启动成功时，模型失败不能说明环境困难。
    valid = _valid_runs(runs)
    if not environment_valid:
        return {
            "label": "invalid_environment",
            "score": None,
            "confidence": "not_evaluable",
            "evidence": {"reason": "deterministic environment validation failed"},
        }
    if not state_isolated:
        return {
            "label": "not_evaluable",
            "score": None,
            "confidence": "not_evaluable",
            "evidence": {"reason": "trial state was not isolated"},
        }
    if not valid:
        return {
            "label": "not_evaluable",
            "score": None,
            "confidence": "not_evaluable",
            "evidence": {"reason": "no valid Agent runs"},
        }
    score, evidence = _difficulty_score(runs)
    label = _label_for_score(score)
    score_interval = evidence["score_interval"]
    plausible_labels = _labels_for_score_interval(
        score_interval["lower"], score_interval["upper"]
    )
    confidence = (
        "tier_resolved"
        if plausible_labels == [label]
        else "tier_uncertain"
    )
    return {
        "label": label,
        "score": score,
        "confidence": confidence,
        "plausible_labels": plausible_labels,
        "evidence": evidence,
    }


def aggregate_runs(
    runs: list[EvaluationRun], *, environment_valid: bool, state_isolated: bool
) -> dict[str, Any]:
    # 无效环境运行不参与解决率和模型成本统计，但仍保留在 runs 中，
    # 这样报告不会丢失诊断信息。
    valid = _valid_runs(runs)
    successful = [r for r in valid if r.success]
    failed = [r for r in valid if not r.success]
    invalid = [
        run
        for run in runs
        if not (
            run.status == "valid"
            and run.verifier.get("environment_valid") is True
        )
    ]
    successes = sum(r.success for r in valid)
    invalid_reasons = Counter(
        run.status or run.termination_reason or "invalid" for run in invalid
    )
    per_model = {}
    for model in sorted({run.model for run in valid}):
        model_runs = [run for run in valid if run.model == model]
        model_successes = sum(run.success for run in model_runs)
        per_model[model] = {
            "successful_runs": model_successes,
            "valid_runs": len(model_runs),
            "solution_rate": round(model_successes / len(model_runs), 3),
            "solution_rate_interval": wilson_interval(
                model_successes, len(model_runs)
            ),
        }
    result: dict[str, Any] = {
        "solution_rate": round(successes / len(valid), 3) if valid else None,
        "solution_rate_interval": wilson_interval(successes, len(valid)),
        "valid_runs": len(valid),
        "invalid_runs": len(invalid),
        "total_runs": len(runs),
        "turns": _summary(r.turns for r in valid),
        "wall_time_s": _summary(r.wall_time_s for r in valid),
        "tool_calls": _summary(r.tool_calls for r in valid),
        "successful_runs": {
            "count": len(successful),
            "turns": _summary(r.turns for r in successful),
            "wall_time_s": _summary(r.wall_time_s for r in successful),
            "tool_calls": _summary(r.tool_calls for r in successful),
        },
        "failed_runs": {
            "count": len(failed),
            "turns": _summary(r.turns for r in failed),
            "wall_time_s": _summary(r.wall_time_s for r in failed),
            "tool_calls": _summary(r.tool_calls for r in failed),
        },
        "invalid_run_reasons": dict(sorted(invalid_reasons.items())),
        "per_model": per_model,
        "per_model_rank": [
            r.model
            for r in sorted(valid, key=lambda item: (not item.success, item.wall_time_s))
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
        "schema_version": 2,
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
        "difficulty": classify_difficulty(
            runs,
            environment_valid=environment_valid,
            state_isolated=state_isolated,
        ),
    }


def write_report(path: str | Path, report: Mapping[str, Any]) -> None:
    """原子写入独立报告，避免中断时留下半个 JSON 文件。"""
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
    """执行一个评估动作并只测量其墙钟时间。"""
    started = time.monotonic()
    result = callable_(*args, **kwargs)
    return result, round(time.monotonic() - started, 3)
