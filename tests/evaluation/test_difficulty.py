import json

from clab_builder.evaluation.difficulty import (
    EvaluationRun,
    aggregate_runs,
    classify_difficulty,
    session_metrics,
    wilson_interval,
    write_report,
)


def test_session_metrics_jsonl_counts_turns_and_tools(tmp_path):
    path = tmp_path / "session.json"
    path.write_text(
        "\n".join([
            json.dumps({"type": "assistant", "turn": 0, "message": {"role": "assistant", "tool_calls": [{"id": "1"}]}}),
            json.dumps({"type": "tool", "turn": 0}),
            json.dumps({"type": "assistant", "turn": 1, "message": {"role": "assistant"}}),
        ])
    )
    assert session_metrics(path) == {"turns": 2, "tool_calls": 1}


def test_session_metrics_supports_top_level_openai_events(tmp_path):
    path = tmp_path / "session.json"
    path.write_text(json.dumps([
        {
            "role": "assistant",
            "turn": 0,
            "tool_calls": [{"id": "1"}, {"id": "2"}],
        },
        {"role": "tool", "turn": 0},
        {"role": "tool", "turn": 0},
    ]))

    assert session_metrics(path) == {"turns": 1, "tool_calls": 2}


def test_invalid_environment_is_not_called_difficult():
    runs = [EvaluationRun(model="m", success=False)]
    result = classify_difficulty(runs, environment_valid=False)
    assert result["label"] == "invalid_environment"
    assert result["score"] is None


def test_aggregate_keeps_success_metrics_separate():
    runs = [
        EvaluationRun(model="a", success=True, turns=4, tool_calls=5, wall_time_s=2,
                      verifier={"environment_valid": True}),
        EvaluationRun(model="b", success=False, turns=30, tool_calls=40, wall_time_s=5,
                      verifier={"environment_valid": True}),
    ]
    result = aggregate_runs(runs, environment_valid=True, state_isolated=True)
    assert result["solution_rate"] == 0.5
    assert result["solution_rate_interval"]["lower"] == 0.0945
    assert result["successful_runs"]["turns"]["mean"] == 4.0
    assert result["failed_runs"]["turns"]["mean"] == 30.0
    assert result["failed_runs"]["count"] == 1


def test_zero_success_reports_uncertainty_and_failed_cost():
    runs = [
        EvaluationRun(
            model=f"m-{index}",
            turns=30,
            tool_calls=60,
            wall_time_s=1800,
            verifier={"environment_valid": True},
        )
        for index in range(4)
    ]

    result = classify_difficulty(runs, environment_valid=True)

    assert result["score"] == 80.0
    assert result["confidence"] == "tier_uncertain"
    assert result["plausible_labels"] == ["medium", "hard", "very_hard"]
    assert result["evidence"]["success_cost_factor"] is None
    assert result["evidence"]["failure_cost_factor"] == 1.0
    assert result["evidence"]["solution_rate_interval"]["upper"] == 0.4899


def test_invalid_runs_do_not_count_as_agent_failures():
    runs = [
        EvaluationRun(
            model="valid",
            success=True,
            verifier={"environment_valid": True},
        ),
        EvaluationRun(
            model="invalid",
            status="invalid_evaluator",
            termination_reason="evaluator_exception",
            error="boom",
        ),
    ]

    result = aggregate_runs(runs, environment_valid=True, state_isolated=True)

    assert result["solution_rate"] == 1.0
    assert result["valid_runs"] == 1
    assert result["invalid_runs"] == 1
    assert result["invalid_run_reasons"] == {"invalid_evaluator": 1}
    assert result["per_model"]["valid"]["solution_rate"] == 1.0


def test_no_valid_agent_runs_are_not_evaluable():
    result = classify_difficulty(
        [EvaluationRun(model="m", status="invalid_evaluator")],
        environment_valid=True,
    )

    assert result["label"] == "not_evaluable"
    assert result["score"] is None


def test_non_isolated_trials_are_not_evaluable():
    result = classify_difficulty(
        [
            EvaluationRun(
                model="m",
                success=True,
                verifier={"environment_valid": True},
            )
        ],
        environment_valid=True,
        state_isolated=False,
    )

    assert result["label"] == "not_evaluable"
    assert result["evidence"]["reason"] == "trial state was not isolated"


def test_wilson_interval_handles_boundary_and_empty_samples():
    assert wilson_interval(0, 4)["upper"] == 0.4899
    assert wilson_interval(4, 4)["lower"] == 0.5101
    assert wilson_interval(0, 0)["lower"] is None

    try:
        wilson_interval(2, 1)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid success count must be rejected")


def test_write_report_is_valid_json(tmp_path):
    output = tmp_path / "nested" / "report.json"
    write_report(output, {"schema_version": 1})
    assert json.loads(output.read_text())["schema_version"] == 1
