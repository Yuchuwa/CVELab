"""Range adapter for the independent difficulty evaluator."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from clab_builder.orchestrator.composer.verifier import ScenarioVerifier

from .difficulty import EvaluationRun, timed_run


def evaluate_range(
    scenario_dir: str,
    *,
    models: tuple[str, ...],
    api_key: str,
    base_url: str,
    max_turns: int,
    timeout: int,
    agent_context: str,
    keep_artifacts: bool = False,
) -> tuple[list[EvaluationRun], bool, bool]:
    source = Path(scenario_dir).resolve()
    runs: list[EvaluationRun] = []
    environment_valid = True
    state_isolated = True
    root = Path(tempfile.mkdtemp(prefix="cvelab-difficulty-range-"))
    try:
        for index, model in enumerate(models, 1):
            copy = root / f"run-{index}"
            shutil.copytree(source, copy)
            verifier = ScenarioVerifier(max_turns=max_turns, agent_timeout=timeout)
            try:
                result, elapsed = timed_run(
                    verifier.run_full,
                    scenario_dir=str(copy),
                    api_key=api_key,
                    base_url=base_url,
                    model=model,
                    agent_context=agent_context,
                    agent_runner="openai",
                )
                valid = bool(result.get("environment_success", False))
                environment_valid = environment_valid and valid
                success = bool(
                    valid
                    and result.get("agent_success", False)
                    and result.get("objective_achieved", True)
                )
                runs.append(EvaluationRun(
                    model=model,
                    success=success,
                    wall_time_s=elapsed,
                    termination_reason=str(result.get("failure_stage") or "completed"),
                    verifier={
                        "environment_valid": valid,
                        "environment_success": result.get("environment_success", False),
                        "agent_success": result.get("agent_success", False),
                        "objective_achieved": result.get("objective_achieved", True),
                    },
                    error=str(result.get("error", "")),
                ))
                session = copy / "agent_workspace" / "session.json"
                from .difficulty import session_metrics
                metrics = session_metrics(session)
                runs[-1].turns = metrics["turns"]
                runs[-1].tool_calls = metrics["tool_calls"]
            except Exception as exc:  # noqa: BLE001
                runs.append(EvaluationRun(model=model, wall_time_s=0, error=str(exc)))
                environment_valid = False
    finally:
        if not keep_artifacts:
            shutil.rmtree(root, ignore_errors=True)
    return runs, environment_valid, state_isolated
