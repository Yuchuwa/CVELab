from clab_builder.evaluation.kat import assess_case_kat


HASH = "a" * 64


def _result(*, success):
    return {
        "environment_success": True,
        "agent_success": success,
        "objective_achieved": success,
    }


def _control(result):
    return {"artifact_sha256": HASH, "result": result}


def _complete_evidence():
    return {
        "qualification": _control({
            "environment_success": True,
            "attack_graph_valid": True,
            "attack_path_reachable": True,
        }),
        "oracle": _control(_result(success=True)),
        "no_op": _control(_result(success=False)),
        "partial_solution": _control(_result(success=False)),
        "wrong_evidence": _control(_result(success=False)),
        "pre_agent": _control({
            "environment_success": True,
            "objective_achieved": False,
        }),
        "repeat_verdicts": [
            {
                "artifact_sha256": HASH,
                "terminal_state_sha256": "b" * 64,
                "verdict": True,
            },
            {
                "artifact_sha256": "c" * 64,
                "terminal_state_sha256": "b" * 64,
                "verdict": True,
            },
        ],
    }


def test_complete_known_answer_controls_are_eligible():
    result = assess_case_kat(_complete_evidence())

    assert result["eligible"] is True
    assert result["missing_controls"] == []
    assert result["failed_checks"] == []


def test_missing_or_false_positive_control_blocks_case():
    evidence = _complete_evidence()
    evidence["no_op"] = _control(_result(success=True))
    evidence.pop("repeat_verdicts")

    result = assess_case_kat(evidence)

    assert result["eligible"] is False
    assert result["missing_controls"] == ["repeat_verdicts"]
    assert result["failed_checks"] == ["no_op_rejected"]


def test_broken_environment_cannot_pass_as_negative_control():
    evidence = _complete_evidence()
    evidence["no_op"] = _control({
            "environment_success": False,
            "agent_success": False,
            "objective_achieved": False,
    })

    result = assess_case_kat(evidence)

    assert result["eligible"] is False
    assert result["failed_checks"] == ["no_op_rejected"]


def test_repeat_verdicts_require_same_hashed_terminal_state():
    evidence = _complete_evidence()
    evidence["repeat_verdicts"][1]["terminal_state_sha256"] = "d" * 64

    result = assess_case_kat(evidence)

    assert result["eligible"] is False
    assert result["failed_checks"] == ["repeat_verdict_stable"]
