"""Range adapter for the independent difficulty evaluator."""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from clab_builder.orchestrator.composer.verifier import ScenarioVerifier

from .difficulty import (
    EvaluationRun,
    sha256_file,
    timed_run,
    trial_specs,
    verifier_backed_success,
)


def _artifact_reference(path: Path) -> dict[str, str] | None:
    if not path.is_file():
        return None
    return {
        "path": str(path),
        "sha256": sha256_file(path),
    }


def evaluate_range(
    scenario_dir: str,
    *,
    models: tuple[str, ...],
    api_key: str,
    base_url: str,
    max_turns: int,
    timeout: int,
    agent_context: str,
    attempts_per_model: int = 1,
    keep_artifacts: bool = False,
) -> tuple[list[EvaluationRun], bool, bool]:
    """对同一个 Range 做模型 × attempt 次独立部署。

    关键点是每个模型都使用 scenario 的临时副本。ScenarioVerifier 会在
    副本内完成 deploy/setup/agent/objective verification/destroy，因此前一
    个模型不会把容器状态或运行结果写给下一个模型。
    """
    source = Path(scenario_dir).resolve()
    runs: list[EvaluationRun] = []
    environment_valid = False
    state_isolated = True
    root = Path(tempfile.mkdtemp(prefix="cvelab-difficulty-range-"))
    try:
        trials = trial_specs(models, attempts_per_model)
        for index, (model, attempt) in enumerate(trials, 1):
            # 不在 source 目录上直接运行，保证原始 Range artifact 只读。
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
                result_file = copy / "verify_result.json"
                if result_file.is_file():
                    result = json.loads(result_file.read_text(encoding="utf-8-sig"))
                # environment_success 是环境正确性，不等同于 Agent 成功。
                environment_ok = result.get("environment_success") is True
                environment_valid = environment_valid or environment_ok
                agent_evaluated_value = result.get("agent_evaluated")
                if not isinstance(agent_evaluated_value, bool):
                    agent_evaluated_value = result.get("guided_trial_evaluated")
                agent_evaluated = agent_evaluated_value is True
                contract_complete = all(
                    isinstance(result.get(field), bool)
                    for field in (
                        "environment_success",
                        "attack_graph_valid",
                        "attack_path_reachable",
                        "agent_success",
                        "objective_achieved",
                        "execution_complete",
                    )
                ) and isinstance(agent_evaluated_value, bool)
                cleanup_ok = result.get("execution_complete") is True
                state_isolated = state_isolated and cleanup_ok
                graph_valid = result.get("attack_graph_valid") is True
                path_reachable = result.get("attack_path_reachable") is True
                if not contract_complete:
                    status = "invalid_result_contract"
                elif not cleanup_ok:
                    status = "invalid_cleanup"
                elif not environment_ok:
                    status = "invalid_environment"
                elif not graph_valid:
                    status = "invalid_attack_graph"
                elif not path_reachable:
                    status = "invalid_attack_path"
                elif not agent_evaluated:
                    status = "invalid_agent_not_evaluated"
                else:
                    status = "valid"
                success = status == "valid" and verifier_backed_success(result)
                runs.append(EvaluationRun(
                    model=model,
                    attempt=attempt,
                    success=success,
                    wall_time_s=elapsed,
                    termination_reason=str(result.get("failure_stage") or "completed"),
                    status=status,
                    verifier={
                        "environment_valid": status == "valid",
                        "environment_success": result.get("environment_success", False),
                        "attack_graph_valid": result.get("attack_graph_valid", False),
                        "attack_path_reachable": result.get(
                            "attack_path_reachable", False
                        ),
                        "agent_evaluated": agent_evaluated,
                        "agent_success": result.get("agent_success", False),
                        "objective_achieved": result.get("objective_achieved", False),
                        "execution_complete": result.get("execution_complete", False),
                    },
                    error=str(result.get("error", "")),
                ))
                session = copy / "agent_workspace" / "session.json"
                from .difficulty import session_metrics
                metrics = session_metrics(session)
                runs[-1].turns = metrics["turns"]
                runs[-1].tool_calls = metrics["tool_calls"]
                if keep_artifacts:
                    runs[-1].artifacts = {
                        "run_dir": str(copy),
                        "verify_result": _artifact_reference(
                            result_file
                        ),
                        "session": _artifact_reference(session),
                    }
            except Exception as exc:  # noqa: BLE001
                failed_run = EvaluationRun(
                    model=model,
                    attempt=attempt,
                    wall_time_s=0,
                    termination_reason="evaluator_exception",
                    status="invalid_evaluator",
                    error=str(exc),
                )
                if keep_artifacts:
                    failed_run.artifacts = {"run_dir": str(copy)}
                runs.append(failed_run)
            finally:
                if not keep_artifacts:
                    shutil.rmtree(copy, ignore_errors=True)
    finally:
        if not keep_artifacts:
            shutil.rmtree(root, ignore_errors=True)
    return runs, environment_valid, state_isolated
