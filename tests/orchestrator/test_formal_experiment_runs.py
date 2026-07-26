import json
import sys
from pathlib import Path

import pytest

EXPERIMENT_ROOT = Path(__file__).resolve().parents[2] / "data" / "experiments" / "stratified-50"
if str(EXPERIMENT_ROOT) not in sys.path:
    sys.path.insert(0, str(EXPERIMENT_ROOT))

from protocol.formal_run import (
    FormalRunConfig,
    create_formal_run,
    refresh_case_index,
)


def _write_case_manifest(path: Path) -> None:
    cases = [
        {
            "id": "matrix-case-a",
            "cves": ["CVE-2012-1823", "CVE-2018-16509", "CVE-2019-9193"],
            "purpose": "candidate A",
            "asset_variants": {"customer-records": "postgres"},
        },
        {
            "id": "matrix-case-b",
            "cves": ["CVE-2014-3120", "CVE-2019-17558", "CVE-2015-1427"],
            "purpose": "candidate B",
        },
    ]
    path.write_text(json.dumps({"cases": cases}, indent=2), encoding="utf-8")


def test_create_qualification_run_manifest_and_initial_index(tmp_path: Path):
    manifest_path = tmp_path / "stratified_50_ranges.json"
    _write_case_manifest(manifest_path)

    run = create_formal_run(
        FormalRunConfig(
            repo_root=tmp_path,
            experiment_root=tmp_path / "data/experiments/stratified-50",
            case_manifest_path=manifest_path,
            run_kind="qualification",
            run_id="qual-test-run",
            agent_context="l2",
            agent_runner="openai",
            model_id="gpt-test",
            base_url_label="quickrouter",
            max_cases=2,
            parallel=1,
            environment_only=True,
        )
    )

    manifest = json.loads((run.run_dir / "run_manifest.json").read_text())
    index = json.loads((run.run_dir / "case_index.json").read_text())

    assert manifest["schema_version"] == 1
    assert manifest["run_kind"] == "qualification"
    assert manifest["selected_case_ids"] == ["matrix-case-a", "matrix-case-b"]
    assert manifest["agent"]["context"] == "l2"
    assert manifest["agent"]["model_id"] == "gpt-test"
    assert manifest["agent"]["base_url_label"] == "quickrouter"
    assert "api_key" not in json.dumps(manifest).lower()
    assert manifest["batch_command"][0].endswith("python")
    assert "--environment-only" in manifest["batch_command"]
    assert "--case-manifest" in manifest["batch_command"]
    assert "--model" in manifest["batch_command"]
    assert "gpt-test" in manifest["batch_command"]
    assert index["totals"] == {
        "total": 2,
        "qualified": 0,
        "failed": 0,
        "not_started": 2,
        "agent_evaluated": 0,
        "agent_success": 0,
    }
    assert all(item["status"] == "not_started" for item in index["cases"])


def test_formal_manifest_is_immutable(tmp_path: Path):
    manifest_path = tmp_path / "stratified_50_ranges.json"
    _write_case_manifest(manifest_path)
    config = FormalRunConfig(
        repo_root=tmp_path,
        experiment_root=tmp_path / "data/experiments/stratified-50",
        case_manifest_path=manifest_path,
        run_kind="qualification",
        run_id="qual-test-run",
        max_cases=2,
    )

    create_formal_run(config)

    with pytest.raises(FileExistsError):
        create_formal_run(config)


def test_agent_trial_requires_parent_qualification_run(tmp_path: Path):
    manifest_path = tmp_path / "stratified_50_ranges.json"
    _write_case_manifest(manifest_path)

    with pytest.raises(ValueError, match="parent qualification"):
        create_formal_run(
            FormalRunConfig(
                repo_root=tmp_path,
                experiment_root=tmp_path / "data/experiments/stratified-50",
                case_manifest_path=manifest_path,
                run_kind="agent_trial",
                run_id="trial-test-run",
                max_cases=2,
                environment_only=False,
            )
        )


def test_refresh_case_index_separates_qualification_and_agent_outcome(tmp_path: Path):
    manifest_path = tmp_path / "stratified_50_ranges.json"
    _write_case_manifest(manifest_path)
    run = create_formal_run(
        FormalRunConfig(
            repo_root=tmp_path,
            experiment_root=tmp_path / "data/experiments/stratified-50",
            case_manifest_path=manifest_path,
            run_kind="qualification",
            run_id="qual-test-run",
            max_cases=2,
        )
    )
    batch_results = run.run_dir / "batch/.batch/results"
    batch_results.mkdir(parents=True)
    (batch_results / "matrix-case-a.json").write_text(
        json.dumps(
            {
                "case_id": "matrix-case-a",
                "success": True,
                "environment_success": True,
                "environment_verified": True,
                "agent_evaluated": False,
            }
        ),
        encoding="utf-8",
    )
    (batch_results / "matrix-case-b.json").write_text(
        json.dumps(
            {
                "case_id": "matrix-case-b",
                "success": False,
                "failure_stage": "runtime_materialization",
                "error": "runtime build inputs changed",
                "agent_evaluated": False,
            }
        ),
        encoding="utf-8",
    )

    index = refresh_case_index(run.run_dir)

    assert index["totals"]["qualified"] == 1
    assert index["totals"]["failed"] == 1
    by_id = {item["case_id"]: item for item in index["cases"]}
    assert by_id["matrix-case-a"]["qualification"] == {
        "eligible": True,
        "stage": "environment",
        "reason_code": "",
    }
    assert by_id["matrix-case-a"]["agent_trial"] == {
        "evaluated": False,
        "success": None,
    }
    assert by_id["matrix-case-b"]["failure_domain"] == "runtime"


def test_refresh_case_index_does_not_qualify_failed_environment_verification(tmp_path: Path):
    manifest_path = tmp_path / "stratified_50_ranges.json"
    _write_case_manifest(manifest_path)
    run = create_formal_run(
        FormalRunConfig(
            repo_root=tmp_path,
            experiment_root=tmp_path / "data/experiments/stratified-50",
            case_manifest_path=manifest_path,
            run_kind="qualification",
            run_id="qual-test-run",
            max_cases=2,
        )
    )
    batch_results = run.run_dir / "batch/.batch/results"
    batch_results.mkdir(parents=True)
    (batch_results / "matrix-case-a.json").write_text(
        json.dumps(
            {
                "case_id": "matrix-case-a",
                "success": False,
                "environment_verified": True,
                "environment_success": False,
                "failure_stage": "setup:base",
                "agent_evaluated": False,
            }
        ),
        encoding="utf-8",
    )

    index = refresh_case_index(run.run_dir)

    by_id = {item["case_id"]: item for item in index["cases"]}
    assert index["totals"]["qualified"] == 0
    assert index["totals"]["failed"] == 1
    assert by_id["matrix-case-a"]["status"] == "failed"
    assert by_id["matrix-case-a"]["failure_domain"] == "setup:base"
