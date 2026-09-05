"""Atom adapter for an already running single-CVE environment."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

import yaml

from clab_builder.atomizer.agent.researcher import CVEInput, SecurityResearcherAgent

from .difficulty import EvaluationRun, session_metrics, timed_run, trial_specs


def evaluate_atom(
    atom_dir: str,
    *,
    container: str,
    target_ip: str,
    models: tuple[str, ...],
    api_key: str,
    base_url: str,
    max_turns: int,
    timeout: int,
    attempts_per_model: int = 1,
    reset: Callable[[], None] | None = None,
) -> tuple[list[EvaluationRun], bool, bool]:
    """让模型 × attempt 次试验连接到同一个已启动的 Atom 目标容器。

    A reset callback is required for strict isolation. Without one we still
    collect measurements, but mark the report as state-isolated=false.

    Atom 当前没有像 Range 那样的统一 deploy/destroy wrapper，因此 CLI 要求
    调用者提供目标容器；`reset` 用来在模型之间恢复目标状态。
    """
    root = Path(atom_dir).resolve()
    atom = yaml.safe_load((root / "atom.yaml").read_text(encoding="utf-8")) or {}
    cve_id = str(atom.get("cve_id") or root.name)
    runtime = atom.get("runtime_spec") or {}
    ports = [int(p) for p in runtime.get("ports", [])]
    description = str(atom.get("description") or atom.get("vulnerability_type") or cve_id)
    writeup = ""
    for candidate in (root / "README.md", root / "exploit_guide.yaml"):
        if candidate.is_file():
            writeup = candidate.read_text(encoding="utf-8", errors="replace")
            break

    runs: list[EvaluationRun] = []
    # Agent 容器需要加入目标所在的 Docker network，而不是加入目标容器本身。
    inspect = subprocess.run(
        ["docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", container],
        capture_output=True,
        text=True,
        check=False,
    )
    if inspect.returncode != 0:
        raise RuntimeError(f"cannot inspect target container: {inspect.stderr.strip()}")
    import json
    networks = json.loads(inspect.stdout or "{}")
    network_name = next(iter(networks), "")
    if not network_name:
        raise RuntimeError("target container has no Docker network")
    workspace_root = Path(tempfile.mkdtemp(prefix="cvelab-difficulty-atom-"))
    try:
        trials = trial_specs(models, attempts_per_model)
        expected_flag = str(atom.get("flag_value") or "")
        for index, (model, attempt) in enumerate(trials, 1):
            # 没有 reset 时仍允许做探索性实验，但报告会明确标记隔离不完整。
            if reset:
                reset()
            workspace = workspace_root / f"run-{index}"
            workspace.mkdir()
            agent = SecurityResearcherAgent(max_turns=max_turns, agent_timeout=timeout)
            agent.start(network_name, str(workspace), api_key, base_url, model)
            try:
                output, elapsed = timed_run(
                    agent.run,
                    CVEInput(
                        cve_id=cve_id,
                        description=description,
                        target_ip=target_ip,
                        target_ports=ports,
                        writeup=writeup,
                    ),
                    str(workspace),
                )
                metrics = session_metrics(workspace / "session.json")
                captured_flag = str(output.captured_flag or "")
                verified = bool(expected_flag and captured_flag == expected_flag)
                runs.append(EvaluationRun(
                    model=model,
                    attempt=attempt,
                    success=verified,
                    turns=metrics["turns"],
                    tool_calls=metrics["tool_calls"],
                    wall_time_s=elapsed,
                    termination_reason="completed" if verified else "agent_failed",
                    status="valid" if expected_flag else "invalid_missing_flag_oracle",
                    verifier={
                        "environment_valid": bool(expected_flag),
                        "agent_reported_success": bool(output.success),
                        "flag_oracle_present": bool(expected_flag),
                        "flag_matched": verified,
                    },
                ))
            except Exception as exc:  # noqa: BLE001
                runs.append(EvaluationRun(
                    model=model,
                    attempt=attempt,
                    termination_reason="evaluator_exception",
                    status="invalid_evaluator",
                    error=str(exc),
                ))
            finally:
                agent.stop()
    finally:
        shutil.rmtree(workspace_root, ignore_errors=True)
    return runs, True, reset is not None
