from __future__ import annotations

import dataclasses
import hashlib
import json
import secrets
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal


RunKind = Literal["qualification", "agent_trial"]


@dataclasses.dataclass(frozen=True)
class FormalRunConfig:
    repo_root: Path
    experiment_root: Path
    case_manifest_path: Path
    run_kind: RunKind
    run_id: str | None = None
    agent_context: str = "l2"
    agent_runner: str = "openai"
    model_id: str = ""
    base_url_label: str = ""
    max_cases: int = 50
    offset: int = 0
    parallel: int = 1
    max_turns: int = 80
    agent_timeout: int = 1800
    case_timeout: int = 0
    noise_level: str = "none"
    environment_only: bool | None = None
    parent_qualification_run: str = ""
    batch_script: str = "scripts/verify_enterprise3_guided_batch.py"


@dataclasses.dataclass(frozen=True)
class FormalRun:
    run_dir: Path
    run_manifest_path: Path
    case_index_path: Path
    batch_output_dir: Path
    batch_command: list[str]


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_dump(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def _json_replace(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def load_case_manifest(path: Path, max_cases: int, offset: int = 0) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    raw_cases = payload.get("cases") if isinstance(payload, dict) else payload
    if not isinstance(raw_cases, list):
        raise ValueError("case manifest must contain a cases list")
    if offset < 0:
        raise ValueError("offset must be non-negative")
    if max_cases <= 0:
        raise ValueError("max_cases must be positive")
    selected = raw_cases[offset : offset + max_cases]
    cases: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in selected:
        if not isinstance(item, dict) or not item.get("id") or not isinstance(item.get("cves"), list):
            raise ValueError("each manifest case requires id and cves")
        case_id = str(item["id"])
        if case_id in seen:
            raise ValueError(f"duplicate case id: {case_id}")
        seen.add(case_id)
        cases.append(
            {
                "id": case_id,
                "cves": [str(cve) for cve in item["cves"]],
                "purpose": str(item.get("purpose", "matrix-generated combination")),
                "asset_variants": dict(item.get("asset_variants") or {}),
                "slot_atoms": dict(item.get("slot_atoms") or {}),
                "service_families": dict(item.get("service_families") or {}),
            }
        )
    return cases


def make_run_id(run_kind: RunKind) -> str:
    prefix = "qual" if run_kind == "qualification" else "trial"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{prefix}-{stamp}-{secrets.token_hex(4)}"


def git_metadata(repo_root: Path) -> dict[str, Any]:
    def run_git(args: list[str]) -> str:
        result = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            return ""
        return result.stdout.strip()

    status = run_git(["status", "--short"])
    return {
        "commit": run_git(["rev-parse", "HEAD"]),
        "dirty": bool(status),
        "status_short": status.splitlines(),
    }


def build_batch_command(config: FormalRunConfig, batch_output_dir: Path) -> list[str]:
    environment_only = config.environment_only
    if environment_only is None:
        environment_only = config.run_kind == "qualification"
    command = [
        sys.executable,
        str(config.repo_root / config.batch_script),
        "--case-manifest",
        str(config.case_manifest_path),
        "--max-cases",
        str(config.max_cases),
        "--offset",
        str(config.offset),
        "--output",
        str(batch_output_dir.relative_to(config.repo_root)),
        "--agent-context",
        config.agent_context.replace("-", "_"),
        "--agent-runner",
        config.agent_runner,
        "--parallel",
        str(config.parallel),
        "--max-turns",
        str(config.max_turns),
        "--agent-timeout",
        str(config.agent_timeout),
        "--noise-level",
        config.noise_level,
    ]
    if config.case_timeout > 0:
        command.extend(["--case-timeout", str(config.case_timeout)])
    if config.model_id:
        command.extend(["--model", config.model_id])
    if environment_only:
        command.append("--environment-only")
    return command


def create_formal_run(config: FormalRunConfig) -> FormalRun:
    if config.run_kind == "agent_trial" and not config.parent_qualification_run:
        raise ValueError("agent_trial requires a parent qualification run")
    repo_root = config.repo_root.resolve()
    experiment_root = config.experiment_root.resolve()
    case_manifest_path = config.case_manifest_path.resolve()
    run_id = config.run_id or make_run_id(config.run_kind)
    run_dir = experiment_root / "runs" / run_id
    batch_output_dir = run_dir / "batch"
    run_dir.mkdir(parents=True, exist_ok=False)
    for child in ("artifacts", "logs", "cases"):
        (run_dir / child).mkdir(parents=True, exist_ok=True)
    batch_output_dir.mkdir(parents=True, exist_ok=True)

    cases = load_case_manifest(case_manifest_path, config.max_cases, config.offset)
    batch_command = build_batch_command(config, batch_output_dir)
    manifest = {
        "schema_version": 1,
        "run_id": run_id,
        "run_kind": config.run_kind,
        "created_at": utcnow(),
        "repository": git_metadata(repo_root),
        "source_manifest": {
            "path": str(case_manifest_path),
            "sha256": sha256_file(case_manifest_path),
            "offset": config.offset,
            "max_cases": config.max_cases,
        },
        "selected_case_ids": [case["id"] for case in cases],
        "cases": cases,
        "agent": {
            "context": config.agent_context.replace("-", "_"),
            "runner": config.agent_runner,
            "model_id": config.model_id,
            "base_url_label": config.base_url_label,
            "max_turns": config.max_turns,
            "agent_timeout": config.agent_timeout,
        },
        "execution": {
            "environment_only": (
                config.environment_only
                if config.environment_only is not None
                else config.run_kind == "qualification"
            ),
            "parallel": config.parallel,
            "case_timeout": config.case_timeout,
            "noise_level": config.noise_level,
        },
        "parent_qualification_run": config.parent_qualification_run,
        "paths": {
            "run_dir": str(run_dir),
            "batch_output_dir": str(batch_output_dir),
            "case_index": str(run_dir / "case_index.json"),
        },
        "batch_command": batch_command,
    }
    _json_dump(run_dir / "run_manifest.json", manifest)
    index = build_initial_case_index(manifest)
    _json_dump(run_dir / "case_index.json", index)
    return FormalRun(
        run_dir=run_dir,
        run_manifest_path=run_dir / "run_manifest.json",
        case_index_path=run_dir / "case_index.json",
        batch_output_dir=batch_output_dir,
        batch_command=batch_command,
    )


def build_initial_case_index(manifest: dict[str, Any]) -> dict[str, Any]:
    cases = []
    for case in manifest["cases"]:
        cases.append(
            {
                "case_id": case["id"],
                "cves": case["cves"],
                "status": "not_started",
                "failure_domain": "",
                "failure_code": "",
                "result_path": "",
                "log_paths": [],
                "qualification": {
                    "eligible": False,
                    "stage": "not_started",
                    "reason_code": "",
                },
                "agent_trial": {
                    "evaluated": False,
                    "success": None,
                },
            }
        )
    return {
        "schema_version": 1,
        "run_id": manifest["run_id"],
        "run_kind": manifest["run_kind"],
        "updated_at": utcnow(),
        "totals": _totals(cases),
        "cases": cases,
    }


def _failure_domain(stage: str) -> str:
    if stage in {"runtime_materialization"}:
        return "runtime"
    if stage in {"deploy", "worker_timeout"}:
        return "deploy"
    if stage in {"setup", "base_setup"}:
        return "setup"
    if stage in {"generation"}:
        return "generation"
    if stage in {"agent_transport", "agent"}:
        return "agent"
    if stage:
        return stage
    return ""


def _case_from_result(case: dict[str, Any], result_path: Path) -> dict[str, Any]:
    result = json.loads(result_path.read_text(encoding="utf-8"))
    stage = str(result.get("failure_stage") or "")
    env_ok = bool(
        result.get("environment_success")
        or result.get("environment_verified")
        or (result.get("success") and not result.get("agent_evaluated"))
    )
    agent_evaluated = bool(result.get("agent_evaluated") or result.get("guided_trial_evaluated"))
    agent_success = bool(result.get("agent_success") or result.get("guided_trial_success"))
    status = "qualified" if env_ok else "failed"
    failure_domain = "" if env_ok else _failure_domain(stage)
    return {
        "case_id": case["id"],
        "cves": case["cves"],
        "status": status,
        "failure_domain": failure_domain,
        "failure_code": stage,
        "result_path": str(result_path),
        "log_paths": [],
        "qualification": {
            "eligible": env_ok,
            "stage": "environment" if env_ok else stage,
            "reason_code": "" if env_ok else str(result.get("error") or stage),
        },
        "agent_trial": {
            "evaluated": agent_evaluated,
            "success": agent_success if agent_evaluated else None,
        },
    }


def _totals(cases: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "total": len(cases),
        "qualified": sum(1 for item in cases if item["status"] == "qualified"),
        "failed": sum(1 for item in cases if item["status"] == "failed"),
        "not_started": sum(1 for item in cases if item["status"] == "not_started"),
        "agent_evaluated": sum(1 for item in cases if item["agent_trial"]["evaluated"]),
        "agent_success": sum(1 for item in cases if item["agent_trial"]["success"] is True),
    }


def refresh_case_index(run_dir: Path) -> dict[str, Any]:
    manifest = json.loads((run_dir / "run_manifest.json").read_text(encoding="utf-8"))
    result_root = run_dir / "batch/.batch/results"
    cases = []
    for case in manifest["cases"]:
        result_path = result_root / f"{case['id']}.json"
        if result_path.exists():
            cases.append(_case_from_result(case, result_path))
        else:
            cases.append(build_initial_case_index({**manifest, "cases": [case]})["cases"][0])
    index = {
        "schema_version": 1,
        "run_id": manifest["run_id"],
        "run_kind": manifest["run_kind"],
        "updated_at": utcnow(),
        "totals": _totals(cases),
        "cases": cases,
    }
    _json_replace(run_dir / "case_index.json", index)
    return index
