import json

from clab_builder.evaluation.difficulty import (
    EvaluationRun,
    aggregate_runs,
    classify_difficulty,
    session_metrics,
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
    assert result["successful_runs"]["turns"]["mean"] == 4.0


def test_write_report_is_valid_json(tmp_path):
    output = tmp_path / "nested" / "report.json"
    write_report(output, {"schema_version": 1})
    assert json.loads(output.read_text())["schema_version"] == 1
