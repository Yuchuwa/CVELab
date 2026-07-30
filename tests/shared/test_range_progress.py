import json

from clab_builder.shared.range_progress import (
    build_progress,
    discover_summaries,
    render_experiment_csv,
    render_range_csv,
)


def _result(case_id: str, *, environment_success: bool) -> dict:
    return {
        "case_id": case_id,
        "cves": ["CVE-A", "CVE-B", "CVE-C"],
        "scenario_dir": f"/tmp/{case_id}",
        "environment_verified": True,
        "environment_success": environment_success,
        "range_build_verified": environment_success,
        "attack_graph_valid": environment_success,
        "attack_path_reachable": environment_success,
        "agent_evaluated": True,
        "agent_success": False,
        "objective_achieved": False,
        "cleanup_failed": False,
        "execution_complete": True,
    }


def test_progress_separates_range_build_from_experiment_outcome(tmp_path):
    root = tmp_path / "project"
    batch = root / "data" / "guide_ablation" / "batch-one"
    batch.mkdir(parents=True)
    summary_path = batch / "summary.json"
    summary_path.write_text(json.dumps({
        "created_at": "2026-07-30T00:00:00+00:00",
        "run_id": "run-one",
        "template": "enterprise_3tier",
        "validation_mode": "guided_agent",
        "agent_context": "l2",
        "noise_level": "none",
        "model": "test-model",
        "agent_runner": "openai",
        "selected_cases": ["range-ok", "range-failed"],
        "results": [
            _result("range-ok", environment_success=True),
            _result("range-failed", environment_success=False),
        ],
    }))

    range_status, experiment_status = build_progress(
        discover_summaries(root / "data"),
        project_root=root,
        generated_at="2026-07-30T01:00:00+00:00",
    )

    assert range_status["summary"]["attempt_records"] == 2
    assert range_status["summary"]["unique_ranges"] == 2
    assert range_status["summary"]["latest_build_succeeded"] == 1
    assert range_status["summary"]["latest_build_failed"] == 1
    assert experiment_status["summary"]["agent_evaluated"] == 2
    assert experiment_status["summary"]["agent_succeeded"] == 0
    assert experiment_status["batches"][0]["model"] == "test-model"
    assert "range-ok" in render_range_csv(range_status)
    assert "test-model" in render_experiment_csv(experiment_status)


def test_legacy_range_build_is_inferred_only_from_all_deterministic_gates(
    tmp_path,
):
    root = tmp_path / "project"
    batch = root / "data" / "legacy"
    batch.mkdir(parents=True)
    (batch / "summary.json").write_text(json.dumps({
        "template": "enterprise_3tier",
        "results": [{
            "case_id": "legacy-ok",
            "cves": ["CVE-A"],
            "environment_success": True,
            "attack_graph_valid": True,
            "attack_path_reachable": True,
        }],
    }))

    range_status, _ = build_progress(
        discover_summaries(root / "data"),
        project_root=root,
    )

    attempt = range_status["attempts"][0]
    assert attempt["build_outcome"] == "succeeded"
    assert attempt["stages"]["range_build"] == {
        "status": "passed",
        "source": "legacy_inference",
    }
