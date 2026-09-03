import hashlib
import json

import pytest

from clab_builder.evaluation.difficulty import sha256_file
from clab_builder.evaluation.kat import REQUIRED_KAT_CONTROLS
from clab_builder.evaluation.study import (
    assess_manifest_qualification,
    build_frozen_run_plan,
    collect_trial_outcomes,
)


def _seal(payload):
    canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def _write(path, text="evidence"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return sha256_file(path)


def _manifest(tmp_path):
    matrix = tmp_path / "matrix.json"
    scorer = tmp_path / "scorer.py"
    template = tmp_path / "templates/demo/template.yaml"
    atom = tmp_path / "data/atoms/CVE-A/atom.yaml"
    guide = tmp_path / "data/atoms/CVE-A/exploit_guide.yaml"
    for path in (matrix, scorer, template, atom, guide):
        _write(path)
    cases = []
    for split in ("calibration", "test"):
        cases.append({
            "id": f"{split}-case",
            "split": split,
            "cves": ["CVE-A"],
            "predicted_success_probability": 0.5,
            "baselines": {"cve_count": 1},
            "eligibility": {"required_controls": list(REQUIRED_KAT_CONTROLS)},
            "dependency_hashes": {
                "template": {
                    "path": "templates/demo/template.yaml",
                    "sha256": sha256_file(template),
                },
                "atoms": {
                    "CVE-A": {
                        "atom_yaml_sha256": sha256_file(atom),
                        "guide_sha256": sha256_file(guide),
                    }
                },
            },
        })
    manifest = {
        "schema_version": 1,
        "protocol": {"max_turns": 30},
        "source": {
            "matrix": {"path": "matrix.json", "sha256": sha256_file(matrix)},
            "scorer": {"path": "scorer.py", "sha256": sha256_file(scorer)},
        },
        "cases": cases,
    }
    manifest["manifest_sha256"] = _seal(manifest)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest, path


def _case_evidence(evidence_dir, case_id):
    def control(name, result):
        path = evidence_dir / f"{case_id}-{name}.json"
        artifact = {
            "case_id": case_id,
            "control": name,
            "result": result,
        }
        path.write_text(json.dumps(artifact), encoding="utf-8")
        return {
            "artifact_path": path.name,
            "artifact_sha256": sha256_file(path),
            "result": result,
        }

    accepted = {
        "environment_success": True,
        "agent_success": True,
        "objective_achieved": True,
    }
    rejected = {
        "environment_success": True,
        "agent_success": False,
        "objective_achieved": False,
    }
    controls = {
        "qualification": control("qualification", {
            "environment_success": True,
            "attack_graph_valid": True,
            "attack_path_reachable": True,
        }),
        "oracle": control("oracle", accepted),
        "no_op": control("no_op", rejected),
        "partial_solution": control("partial_solution", rejected),
        "wrong_evidence": control("wrong_evidence", rejected),
        "pre_agent": control("pre_agent", {
            "environment_success": True,
            "objective_achieved": False,
        }),
    }
    repeats = []
    for number in (1, 2):
        path = evidence_dir / f"{case_id}-repeat-{number}.json"
        artifact = {
            "case_id": case_id,
            "control": "repeat_verdicts",
            "terminal_state_sha256": "b" * 64,
            "verdict": True,
        }
        path.write_text(json.dumps(artifact), encoding="utf-8")
        repeats.append({
            "artifact_path": path.name,
            "artifact_sha256": sha256_file(path),
            "terminal_state_sha256": "b" * 64,
            "verdict": True,
        })
    controls["repeat_verdicts"] = repeats
    evidence_path = evidence_dir / f"{case_id}.json"
    evidence_path.write_text(json.dumps({"controls": controls}), encoding="utf-8")


def _qualified_study(tmp_path):
    manifest, manifest_path = _manifest(tmp_path)
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    for case in manifest["cases"]:
        _case_evidence(evidence_dir, case["id"])
    qualification = assess_manifest_qualification(
        manifest,
        manifest_path=manifest_path,
        evidence_dir=evidence_dir,
        repo_root=tmp_path,
    )
    qualification_path = tmp_path / "qualification.json"
    qualification_path.write_text(json.dumps(qualification), encoding="utf-8")
    return manifest, manifest_path, qualification, qualification_path


def test_qualification_binds_controls_to_real_artifacts(tmp_path):
    manifest, manifest_path, qualification, qualification_path = (
        _qualified_study(tmp_path)
    )

    assert qualification["status"] == "qualified"
    assert qualification["summary"]["eligible_cases"] == 2

    artifact = tmp_path / "evidence/calibration-case-oracle.json"
    artifact.write_text("mutated", encoding="utf-8")
    with pytest.raises(ValueError, match="KAT .* changed"):
        build_frozen_run_plan(
            manifest,
            qualification,
            [
                {"id": "model-a", "family": "family-a"},
                {"id": "model-b", "family": "family-b"},
                {"id": "model-c", "family": "family-c"},
            ],
            repo_root=tmp_path,
            manifest_path=manifest_path,
            qualification_path=qualification_path,
            attempts_per_model=1,
            seed=7,
        )
    reassessed = assess_manifest_qualification(
        manifest,
        manifest_path=manifest_path,
        evidence_dir=tmp_path / "evidence",
        repo_root=tmp_path,
    )

    assert reassessed["status"] == "blocked"
    assert reassessed["summary"]["blocked_cases"] == 1


def test_freeze_randomizes_within_calibration_first_phases(tmp_path):
    manifest, manifest_path, qualification, qualification_path = (
        _qualified_study(tmp_path)
    )
    models = [
        {"id": "model-a", "family": "family-a"},
        {"id": "model-b", "family": "family-b"},
        {"id": "model-c", "family": "family-c"},
    ]

    plan = build_frozen_run_plan(
        manifest,
        qualification,
        models,
        repo_root=tmp_path,
        manifest_path=manifest_path,
        qualification_path=qualification_path,
        attempts_per_model=2,
        seed=7,
    )

    assert plan["summary"]["trial_count"] == 12
    assert [trial["phase"] for trial in plan["trials"]] == [1] * 6 + [2] * 6
    assert plan["summary"]["model_family_count"] == 3
    assert plan["plan_sha256"] == _seal(
        {key: value for key, value in plan.items() if key != "plan_sha256"}
    )


def test_freeze_rejects_related_models_as_independent_families(tmp_path):
    manifest, manifest_path, qualification, qualification_path = (
        _qualified_study(tmp_path)
    )

    with pytest.raises(ValueError, match="three model families"):
        build_frozen_run_plan(
            manifest,
            qualification,
            [
                {"id": "small", "family": "same"},
                {"id": "large", "family": "same"},
            ],
            repo_root=tmp_path,
            manifest_path=manifest_path,
            qualification_path=qualification_path,
            attempts_per_model=3,
            seed=7,
        )


def test_collect_is_fail_closed_and_excludes_invalid_trials(tmp_path):
    manifest, manifest_path, qualification, qualification_path = (
        _qualified_study(tmp_path)
    )
    plan = build_frozen_run_plan(
        manifest,
        qualification,
        [
            {"id": "model-a", "family": "family-a"},
            {"id": "model-b", "family": "family-b"},
            {"id": "model-c", "family": "family-c"},
        ],
        repo_root=tmp_path,
        manifest_path=manifest_path,
        qualification_path=qualification_path,
        attempts_per_model=1,
        seed=7,
    )
    results = tmp_path / "results"
    results.mkdir()
    trials = [trial for trial in plan["trials"] if trial["split"] == "calibration"]
    for index, trial in enumerate(trials):
        verifier = {
            "agent_evaluated": True,
            "environment_success": index != 0,
            "agent_success": True,
            "objective_achieved": index != 0,
        }
        if index == 1:
            verifier.pop("objective_achieved")
        payload = {
            **{
                key: trial[key]
                for key in (
                    "trial_id",
                    "case_id",
                    "model_id",
                    "model_family",
                    "attempt",
                    "sequence",
                    "split",
                    "runner",
                    "agent_context",
                    "max_turns",
                    "timeout_seconds",
                    "case_dependency_sha256",
                )
            },
            "plan_sha256": plan["plan_sha256"],
            "status": "valid",
            "verifier": verifier,
        }
        (results / f"{trial['trial_id']}.json").write_text(
            json.dumps(payload), encoding="utf-8"
        )

    collected = collect_trial_outcomes(
        plan, results_dir=results, split="calibration"
    )

    assert collected["complete"] is False
    assert collected["summary"]["valid_trials"] == 1
    assert collected["summary"]["invalid_trials"] == 2
    assert collected["summary"]["invalid_reasons"] == {
        "invalid_environment": 1,
        "invalid_result_contract": 1,
    }
    assert len(collected["cases"][0]["outcomes"]) == 1
