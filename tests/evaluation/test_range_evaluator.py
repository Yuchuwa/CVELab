from unittest.mock import patch

from clab_builder.evaluation.range_evaluator import evaluate_range


def test_range_evaluator_fails_closed_when_objective_field_is_missing(tmp_path):
    scenario = tmp_path / "scenario"
    scenario.mkdir()
    result = {
        "environment_success": True,
        "attack_graph_valid": True,
        "attack_path_reachable": True,
        "agent_evaluated": True,
        "agent_success": True,
        "execution_complete": True,
        "failure_stage": "",
    }

    with (
        patch(
            "clab_builder.evaluation.range_evaluator.ScenarioVerifier.run_full",
            return_value=result,
        ),
        patch(
            "clab_builder.evaluation.range_evaluator.timed_run",
            return_value=(result, 1.0),
        ),
    ):
        runs, environment_valid, state_isolated = evaluate_range(
            str(scenario),
            models=("model-a",),
            api_key="test",
            base_url="",
            max_turns=30,
            timeout=1800,
            agent_context="guided",
            attempts_per_model=2,
        )

    assert environment_valid is True
    assert state_isolated is True
    assert [run.attempt for run in runs] == [1, 2]
    assert all(run.success is False for run in runs)
    assert all(run.status == "invalid_result_contract" for run in runs)
    assert all(run.verifier["objective_achieved"] is False for run in runs)


def test_range_evaluator_excludes_agent_transport_abort(tmp_path):
    scenario = tmp_path / "scenario"
    scenario.mkdir()
    result = {
        "environment_success": True,
        "attack_graph_valid": True,
        "attack_path_reachable": True,
        "agent_evaluated": False,
        "agent_success": False,
        "objective_achieved": False,
        "execution_complete": True,
        "failure_stage": "agent_transport",
    }

    with patch(
        "clab_builder.evaluation.range_evaluator.timed_run",
        return_value=(result, 1.0),
    ):
        runs, environment_valid, _ = evaluate_range(
            str(scenario),
            models=("model-a",),
            api_key="test",
            base_url="",
            max_turns=30,
            timeout=1800,
            agent_context="guided",
        )

    assert environment_valid is True
    assert runs[0].status == "invalid_agent_not_evaluated"
    assert runs[0].verifier["environment_valid"] is False
