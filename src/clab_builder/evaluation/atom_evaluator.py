"""Atom adapter for an already running single-CVE environment."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

import yaml

from clab_builder.atomizer.agent.researcher import CVEInput, SecurityResearcherAgent

from .difficulty import EvaluationRun, session_metrics, timed_run


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
    reset: Callable[[], None] | None = None,
) -> tuple[list[EvaluationRun], bool, bool]:
    """Run models against a supplied target container.

    A reset callback is required for strict isolation. Without one we still
    collect measurements, but mark the report as state-isolated=false.
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
        for index, model in enumerate(models, 1):
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
                runs.append(EvaluationRun(
                    model=model,
                    success=bool(output.success),
                    turns=metrics["turns"],
                    tool_calls=metrics["tool_calls"],
                    wall_time_s=elapsed,
                    termination_reason="completed" if output.success else "agent_failed",
                    verifier={"environment_valid": True, "agent_success": bool(output.success)},
                ))
            except Exception as exc:  # noqa: BLE001
                runs.append(EvaluationRun(model=model, error=str(exc)))
            finally:
                agent.stop()
    finally:
        shutil.rmtree(workspace_root, ignore_errors=True)
    return runs, True, reset is not None
