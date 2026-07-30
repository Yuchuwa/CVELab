"""Sanitized Range build and experiment progress views."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


PASSED = "passed"
FAILED = "failed"
NOT_EVALUATED = "not_evaluated"
BUILD_STAGES = (
    "generation",
    "environment",
    "range_build",
    "attack_graph",
    "attack_path",
    "cleanup",
)
EXPERIMENT_STAGES = ("agent", "objective")


def discover_summaries(data_root: Path) -> list[Path]:
    """Find Range batch summaries without entering runtime/secret directories."""
    found: list[Path] = []
    skip_at_data_root = {"atoms", "sft", "vulhub", "generated"}
    skip_anywhere = {
        ".batch",
        ".workspace",
        "agent_workspace",
        "scenarios",
        "__pycache__",
    }
    for current, dirs, files in os.walk(data_root, onerror=lambda _exc: None):
        current_path = Path(current)
        if current_path == data_root:
            dirs[:] = [name for name in dirs if name not in skip_at_data_root]
        dirs[:] = [
            name
            for name in dirs
            if name not in skip_anywhere and not name.startswith(".")
        ]
        if "summary.json" in files:
            found.append(current_path / "summary.json")
    return sorted(found)


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def _stage(status: str, source: str) -> dict[str, str]:
    return {"status": status, "source": source}


def _bool_stage(
    row: dict[str, Any],
    success_key: str,
    *,
    evaluated_keys: Iterable[str] = (),
) -> dict[str, str]:
    value = row.get(success_key)
    evaluated_values = [
        row.get(key) for key in evaluated_keys if key in row
    ]
    if value is True:
        return _stage(PASSED, success_key)
    if any(value is True for value in evaluated_values):
        return _stage(FAILED, success_key)
    if value is False and not evaluated_values:
        return _stage(FAILED, success_key)
    return _stage(NOT_EVALUATED, success_key)


def _attempt_stages(row: dict[str, Any]) -> dict[str, dict[str, str]]:
    deterministic_present = any(
        key in row
        for key in (
            "environment_success",
            "range_build_verified",
            "attack_graph_valid",
            "attack_path_reachable",
        )
    )
    if row.get("generated") is True:
        generation = _stage(PASSED, "generated")
    elif row.get("generated") is False:
        generation = _stage(FAILED, "generated")
    elif deterministic_present or row.get("scenario_dir"):
        generation = _stage(PASSED, "legacy_inference")
    else:
        generation = _stage(NOT_EVALUATED, "generated")

    environment = _bool_stage(
        row,
        "environment_success",
        evaluated_keys=("environment_verified",),
    )
    graph = _bool_stage(row, "attack_graph_valid")
    path = _bool_stage(row, "attack_path_reachable")
    if "range_build_verified" in row:
        range_build = _bool_stage(row, "range_build_verified")
    elif all(
        stage["status"] == PASSED for stage in (environment, graph, path)
    ):
        range_build = _stage(PASSED, "legacy_inference")
    else:
        range_build = _stage(NOT_EVALUATED, "range_build_verified")

    if row.get("cleanup_failed") is True:
        cleanup = _stage(FAILED, "cleanup_failed")
    elif row.get("cleanup_failed") is False:
        cleanup = _stage(PASSED, "cleanup_failed")
    else:
        cleanup = _stage(NOT_EVALUATED, "cleanup_failed")

    agent_evaluated = any(
        row.get(key) is True
        for key in ("agent_evaluated", "guided_trial_evaluated")
    )
    agent = _bool_stage(
        row,
        "agent_success",
        evaluated_keys=("agent_evaluated", "guided_trial_evaluated"),
    )
    if row.get("objective_achieved") is True:
        objective = _stage(PASSED, "objective_achieved")
    elif agent_evaluated and row.get("objective_achieved") is False:
        objective = _stage(FAILED, "objective_achieved")
    else:
        objective = _stage(NOT_EVALUATED, "objective_achieved")

    return {
        "generation": generation,
        "environment": environment,
        "range_build": range_build,
        "attack_graph": graph,
        "attack_path": path,
        "cleanup": cleanup,
        "agent": agent,
        "objective": objective,
    }


def _build_outcome(stages: dict[str, dict[str, str]]) -> str:
    required = (
        stages["generation"],
        stages["environment"],
        stages["range_build"],
        stages["attack_graph"],
        stages["attack_path"],
    )
    if all(stage["status"] == PASSED for stage in required):
        return "succeeded"
    if any(stage["status"] == FAILED for stage in required):
        return "failed"
    return "incomplete"


def _range_key(
    template: str,
    case_id: str,
    cves: list[str],
    asset_variants: dict[str, Any],
    noise_level: str,
) -> str:
    identity = {
        "template": template,
        "case_id": case_id,
        "cves": cves,
        "asset_variants": asset_variants,
        "noise_level": noise_level,
    }
    return hashlib.sha256(
        json.dumps(identity, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()[:16]


def _load_batches(
    summary_paths: Iterable[Path],
    *,
    project_root: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    batches: list[dict[str, Any]] = []
    for path in summary_paths:
        try:
            raw = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(raw, dict):
            continue
        results = raw.get("results")
        if not isinstance(results, list):
            continue
        if not (
            raw.get("template")
            or raw.get("validation_mode")
            or any(isinstance(row, dict) and row.get("case_id") for row in results)
        ):
            continue

        source = _relative(path, project_root)
        validation_round = raw.get("validation_round") or {}
        template = str(raw.get("template") or "unknown")
        if template == "unknown" and any(
            "enterprise_3tier" in str(row.get("purpose") or "")
            for row in results
            if isinstance(row, dict)
        ):
            template = "enterprise_3tier"
        context = str(raw.get("agent_context") or "unknown")
        noise = str(raw.get("noise_level") or "unknown")
        model = str(
            raw.get("model")
            or validation_round.get("model")
            or "unknown_not_recorded"
        )
        runner = str(
            raw.get("agent_runner")
            or validation_round.get("agent_runner")
            or "unknown_not_recorded"
        )
        batch_attempts: list[dict[str, Any]] = []
        for index, result in enumerate(results):
            if not isinstance(result, dict):
                continue
            case_id = str(
                result.get("case_id")
                or result.get("id")
                or f"unnamed-{index + 1}"
            )
            cves = [str(value) for value in (result.get("cves") or [])]
            asset_variants = dict(result.get("asset_variants") or {})
            result_noise = str(result.get("noise_level") or noise)
            stages = _attempt_stages(result)
            range_key = _range_key(
                template,
                case_id,
                cves,
                asset_variants,
                result_noise,
            )
            attempt_id = hashlib.sha256(
                f"{source}:{raw.get('run_id', '')}:{case_id}:{index}".encode()
            ).hexdigest()[:20]
            attempt = {
                "attempt_id": attempt_id,
                "range_key": range_key,
                "case_id": case_id,
                "template": template,
                "cves": cves,
                "asset_variants": asset_variants,
                "source_summary": source,
                "run_id": str(raw.get("run_id") or ""),
                "created_at": str(raw.get("created_at") or ""),
                "validation_mode": str(
                    raw.get("validation_mode") or "unknown"
                ),
                "environment_only": bool(raw.get("environment_only", False)),
                "agent_context": str(
                    result.get("agent_context") or context
                ),
                "noise_level": result_noise,
                "model": model,
                "agent_runner": runner,
                "max_turns": validation_round.get("max_turns"),
                "agent_timeout": validation_round.get("agent_timeout"),
                "build_outcome": _build_outcome(stages),
                "failure_stage": str(result.get("failure_stage") or ""),
                "execution_complete": result.get("execution_complete"),
                "stages": stages,
            }
            attempts.append(attempt)
            batch_attempts.append(attempt)

        batches.append(
            _batch_progress(
                raw,
                source=source,
                template=template,
                context=context,
                noise=noise,
                model=model,
                runner=runner,
                attempts=batch_attempts,
            )
        )
    return attempts, batches


def _count_stage(
    attempts: list[dict[str, Any]],
    stage_name: str,
    status: str,
) -> int:
    return sum(
        attempt["stages"][stage_name]["status"] == status
        for attempt in attempts
    )


def _batch_progress(
    raw: dict[str, Any],
    *,
    source: str,
    template: str,
    context: str,
    noise: str,
    model: str,
    runner: str,
    attempts: list[dict[str, Any]],
) -> dict[str, Any]:
    validation_round = raw.get("validation_round") or {}
    return {
        "source_summary": source,
        "run_id": str(raw.get("run_id") or ""),
        "created_at": str(raw.get("created_at") or ""),
        "template": template,
        "validation_mode": str(raw.get("validation_mode") or "unknown"),
        "environment_only": bool(raw.get("environment_only", False)),
        "agent_context": context,
        "noise_level": noise,
        "model": model,
        "agent_runner": runner,
        "max_turns": validation_round.get("max_turns"),
        "agent_timeout": validation_round.get("agent_timeout"),
        "selected_cases": len(raw.get("selected_cases") or []),
        "result_records": len(attempts),
        "build_succeeded": sum(
            attempt["build_outcome"] == "succeeded" for attempt in attempts
        ),
        "build_failed": sum(
            attempt["build_outcome"] == "failed" for attempt in attempts
        ),
        "build_incomplete": sum(
            attempt["build_outcome"] == "incomplete" for attempt in attempts
        ),
        "agent_evaluated": sum(
            attempt["stages"]["agent"]["status"] != NOT_EVALUATED
            for attempt in attempts
        ),
        "agent_succeeded": _count_stage(attempts, "agent", PASSED),
        "objective_succeeded": _count_stage(attempts, "objective", PASSED),
    }


def build_progress(
    summary_paths: Iterable[Path],
    *,
    project_root: Path,
    generated_at: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    attempts, batches = _load_batches(
        summary_paths,
        project_root=project_root,
    )
    grouped: dict[str, list[dict[str, Any]]] = {}
    for attempt in attempts:
        grouped.setdefault(attempt["range_key"], []).append(attempt)

    ranges: list[dict[str, Any]] = []
    for range_key, range_attempts in sorted(grouped.items()):
        ordered = sorted(
            range_attempts,
            key=lambda row: (row["created_at"], row["source_summary"]),
        )
        latest = ordered[-1]
        counts = Counter(row["build_outcome"] for row in ordered)
        ranges.append(
            {
                "range_key": range_key,
                "case_id": latest["case_id"],
                "template": latest["template"],
                "cves": latest["cves"],
                "asset_variants": latest["asset_variants"],
                "noise_level": latest["noise_level"],
                "latest_build_outcome": latest["build_outcome"],
                "latest_attempt_id": latest["attempt_id"],
                "latest_stages": latest["stages"],
                "latest_failure_stage": latest["failure_stage"],
                "latest_source_summary": latest["source_summary"],
                "attempt_count": len(ordered),
                "successful_attempts": counts["succeeded"],
                "failed_attempts": counts["failed"],
                "incomplete_attempts": counts["incomplete"],
            }
        )

    digest_payload = {"ranges": ranges, "attempts": attempts}
    snapshot_hash = hashlib.sha256(
        json.dumps(digest_payload, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()
    timestamp = generated_at or datetime.now(timezone.utc).isoformat()
    range_status = {
        "schema_version": 1,
        "generated_at": timestamp,
        "snapshot_hash": snapshot_hash,
        "definitions": {
            "range_identity": (
                "template + case_id + ordered CVEs + asset variants + noise level"
            ),
            "build_succeeded": (
                "generation, environment, Range build, attack graph and "
                "attack path all passed"
            ),
            "build_failed": (
                "at least one deterministic build stage explicitly failed"
            ),
            "build_incomplete": (
                "no deterministic failure, but at least one required stage "
                "was not evaluated"
            ),
        },
        "summary": {
            "summary_files": len(batches),
            "attempt_records": len(attempts),
            "unique_ranges": len(ranges),
            "latest_build_succeeded": sum(
                row["latest_build_outcome"] == "succeeded" for row in ranges
            ),
            "latest_build_failed": sum(
                row["latest_build_outcome"] == "failed" for row in ranges
            ),
            "latest_build_incomplete": sum(
                row["latest_build_outcome"] == "incomplete" for row in ranges
            ),
        },
        "templates": _template_summary(ranges),
        "ranges": ranges,
        "attempts": attempts,
    }
    experiment_status = {
        "schema_version": 1,
        "generated_at": timestamp,
        "source_range_snapshot_hash": snapshot_hash,
        "owner": "B. Range and evaluation",
        "summary": {
            "batches": len(batches),
            "result_records": len(attempts),
            "batches_with_recorded_model": sum(
                batch["model"] != "unknown_not_recorded" for batch in batches
            ),
            "agent_evaluated": sum(
                batch["agent_evaluated"] for batch in batches
            ),
            "agent_succeeded": sum(
                batch["agent_succeeded"] for batch in batches
            ),
            "objective_succeeded": sum(
                batch["objective_succeeded"] for batch in batches
            ),
        },
        "batches": batches,
    }
    return range_status, experiment_status


def _template_summary(ranges: list[dict[str, Any]]) -> dict[str, Any]:
    templates: dict[str, list[dict[str, Any]]] = {}
    for row in ranges:
        templates.setdefault(row["template"], []).append(row)
    return {
        template: {
            "unique_ranges": len(rows),
            "latest_build_succeeded": sum(
                row["latest_build_outcome"] == "succeeded" for row in rows
            ),
            "latest_build_failed": sum(
                row["latest_build_outcome"] == "failed" for row in rows
            ),
            "latest_build_incomplete": sum(
                row["latest_build_outcome"] == "incomplete" for row in rows
            ),
        }
        for template, rows in sorted(templates.items())
    }


def render_range_csv(snapshot: dict[str, Any]) -> str:
    fields = [
        "attempt_id",
        "range_key",
        "case_id",
        "template",
        "cves",
        "noise_level",
        "build_outcome",
        *BUILD_STAGES,
        "failure_stage",
        "source_summary",
        "created_at",
    ]
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for attempt in snapshot["attempts"]:
        writer.writerow(
            {
                "attempt_id": attempt["attempt_id"],
                "range_key": attempt["range_key"],
                "case_id": attempt["case_id"],
                "template": attempt["template"],
                "cves": ",".join(attempt["cves"]),
                "noise_level": attempt["noise_level"],
                "build_outcome": attempt["build_outcome"],
                **{
                    stage: attempt["stages"][stage]["status"]
                    for stage in BUILD_STAGES
                },
                "failure_stage": attempt["failure_stage"],
                "source_summary": attempt["source_summary"],
                "created_at": attempt["created_at"],
            }
        )
    return stream.getvalue()


def render_range_markdown(snapshot: dict[str, Any]) -> str:
    lines = [
        "# Range Build Status",
        "",
        "Status: generated snapshot",
        "",
        f"Generated at: `{snapshot['generated_at']}`",
        "",
        f"Snapshot hash: `{snapshot['snapshot_hash']}`",
        "",
        "Agent and objective outcomes are not Range build gates.",
        "",
        "## Summary",
        "",
    ]
    lines.extend(
        f"- `{key}`: {value}" for key, value in snapshot["summary"].items()
    )
    lines.extend(["", "## Templates", ""])
    for template, values in snapshot["templates"].items():
        lines.append(
            f"- `{template}`: unique={values['unique_ranges']}, "
            f"succeeded={values['latest_build_succeeded']}, "
            f"failed={values['latest_build_failed']}, "
            f"incomplete={values['latest_build_incomplete']}"
        )
    lines.extend(["", "## Latest Range State by Template", ""])
    for template in snapshot["templates"]:
        lines.extend([f"### `{template}`", ""])
        template_rows = [
            row for row in snapshot["ranges"] if row["template"] == template
        ]
        for outcome in ("succeeded", "failed", "incomplete"):
            lines.extend([f"#### `{outcome}`", ""])
            outcome_rows = [
                row
                for row in template_rows
                if row["latest_build_outcome"] == outcome
            ]
            if not outcome_rows:
                lines.append("- None")
                continue
            for row in outcome_rows:
                stages = ", ".join(
                    f"{name}={row['latest_stages'][name]['status']}"
                    for name in BUILD_STAGES
                )
                lines.append(
                    f"- `{row['case_id']}` / `{row['noise_level']}`; "
                    f"CVEs={','.join(row['cves']) or 'unknown'}; {stages}; "
                    f"attempts={row['attempt_count']}; "
                    f"source=`{row['latest_source_summary']}`"
                )
            lines.append("")
    lines.extend(["", "## Attempt Ledger", ""])
    for attempt in snapshot["attempts"]:
        stages = ", ".join(
            f"{name}={attempt['stages'][name]['status']}"
            for name in BUILD_STAGES
        )
        lines.append(
            f"- `{attempt['template']}` / `{attempt['case_id']}` — "
            f"`{attempt['build_outcome']}`; {stages}; "
            f"source=`{attempt['source_summary']}`"
        )
    lines.append("")
    return "\n".join(lines)


def render_experiment_csv(snapshot: dict[str, Any]) -> str:
    fields = [
        "source_summary",
        "created_at",
        "template",
        "model",
        "agent_runner",
        "agent_context",
        "noise_level",
        "max_turns",
        "agent_timeout",
        "result_records",
        "build_succeeded",
        "build_failed",
        "build_incomplete",
        "agent_evaluated",
        "agent_succeeded",
        "objective_succeeded",
    ]
    stream = io.StringIO()
    writer = csv.DictWriter(
        stream,
        fieldnames=fields,
        extrasaction="ignore",
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(snapshot["batches"])
    return stream.getvalue()


def render_experiment_markdown(snapshot: dict[str, Any]) -> str:
    lines = [
        "# Experiment Progress",
        "",
        "Status: generated snapshot",
        "",
        f"Generated at: `{snapshot['generated_at']}`",
        "",
        f"Owner: `{snapshot['owner']}`",
        "",
        "## Summary",
        "",
    ]
    lines.extend(
        f"- `{key}`: {value}" for key, value in snapshot["summary"].items()
    )
    lines.extend(["", "## Batches", ""])
    for batch in snapshot["batches"]:
        lines.append(
            f"- `{batch['source_summary']}` — model=`{batch['model']}`, "
            f"context=`{batch['agent_context']}`, noise=`{batch['noise_level']}`, "
            f"results={batch['result_records']}, "
            f"build={batch['build_succeeded']}/{batch['result_records']}, "
            f"agent={batch['agent_succeeded']}/{batch['agent_evaluated']}, "
            f"objective={batch['objective_succeeded']}/"
            f"{batch['agent_evaluated']}"
        )
    lines.append("")
    return "\n".join(lines)


def write_progress(
    range_status: dict[str, Any],
    experiment_status: dict[str, Any],
    *,
    range_prefix: Path,
    experiment_prefix: Path,
) -> None:
    range_prefix.parent.mkdir(parents=True, exist_ok=True)
    range_prefix.with_suffix(".json").write_text(
        json.dumps(range_status, indent=2, ensure_ascii=False) + "\n"
    )
    range_prefix.with_suffix(".csv").write_text(render_range_csv(range_status))
    range_prefix.with_suffix(".md").write_text(
        render_range_markdown(range_status)
    )
    experiment_prefix.with_suffix(".json").write_text(
        json.dumps(experiment_status, indent=2, ensure_ascii=False) + "\n"
    )
    experiment_prefix.with_suffix(".csv").write_text(
        render_experiment_csv(experiment_status)
    )
    experiment_prefix.with_suffix(".md").write_text(
        render_experiment_markdown(experiment_status)
    )
