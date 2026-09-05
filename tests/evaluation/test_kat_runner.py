import importlib.util
import json
from pathlib import Path

from clab_builder.evaluation.kat import assess_case_kat

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "run_difficulty_kat", ROOT / "scripts" / "run_difficulty_kat.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _case():
    return {
        "id": "calibration-case",
        "split": "calibration",
        "template": "demo",
        "cves": ["CVE-A", "CVE-B"],
    }


def _manifest():
    return {
        "manifest_sha256": "a" * 64,
        "selection": {"seed": 7},
        "protocol": {
            "agent_context": "guided",
            "max_turns": 30,
            "timeout_seconds": 60,
        },
    }


class FakePipeline:
    def generate(self, **kwargs):
        scenario = Path(kwargs["output_dir"]) / kwargs["scenario_name"]
        scenario.mkdir(parents=True)
        ground_truth = {
            "attack_path": [
                {"target_node": "target-1", "target_ip": "10.0.0.2", "flag": "flag-a"},
                {"target_node": "target-2", "target_ip": "10.0.0.3", "flag": "flag-b"},
            ],
            "objectives": [
                {
                    "id": "objective-a",
                    "actor_node": "target-1",
                    "target_node": "target-2",
                    "evidence_field": "evidence",
                    "success_pattern": "expected-witness",
                }
            ],
        }
        (scenario / "ground_truth.json").write_text(json.dumps(ground_truth))
        (scenario / "scenario.yaml").write_text("name: calibration-case\n")
        return {"name": kwargs["scenario_name"]}


def _fake_run_full(self, *, scenario_dir, api_key, environment_only, **kwargs):
    assert api_key == ""
    assert environment_only is True
    result = {
        "environment_success": True,
        "attack_graph_valid": True,
        "attack_path_reachable": True,
        "execution_complete": True,
        "pre_agent_objective_verification": {
            "all_satisfied": False,
            "per_objective": {},
        },
    }
    Path(scenario_dir, "verify_result.json").write_text(json.dumps(result))
    return result


def test_runner_creates_bound_eligible_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(MODULE.ScenarioVerifier, "run_full", _fake_run_full)
    evidence = tmp_path / "evidence"

    result = MODULE.run_case(
        _case(),
        manifest=_manifest(),
        evidence_root=evidence,
        work_root=tmp_path / "work",
        pipeline=FakePipeline(),
    )

    assert result["status"] == "qualified"
    payload = json.loads((evidence / "calibration-case.json").read_text())
    assessment = assess_case_kat(
        payload["controls"], artifact_root=evidence, case_id="calibration-case"
    )
    assert assessment["eligible"] is True
    repeats = payload["controls"]["repeat_verdicts"]
    assert len(repeats) == 2
    assert repeats[0]["terminal_state_sha256"] == repeats[1]["terminal_state_sha256"]
    wrong = json.loads(
        (evidence / "calibration-case" / "wrong_evidence.json").read_text()
    )
    assert wrong["result"]["agent_success"] is True
    assert wrong["result"]["objective_achieved"] is False
    oracle = json.loads((evidence / "calibration-case" / "oracle.json").read_text())
    assert oracle["details"]["execution_witness"] == {"objective-a": True}
    assert not (tmp_path / "work" / "calibration-case").exists()


def test_runner_blocks_cleanup_failure(tmp_path, monkeypatch):
    def failed_cleanup(self, **kwargs):
        result = _fake_run_full(self, **kwargs)
        result["execution_complete"] = False
        Path(kwargs["scenario_dir"], "verify_result.json").write_text(json.dumps(result))
        return result

    monkeypatch.setattr(MODULE.ScenarioVerifier, "run_full", failed_cleanup)
    evidence = tmp_path / "evidence"

    result = MODULE.run_case(
        _case(),
        manifest=_manifest(),
        evidence_root=evidence,
        work_root=tmp_path / "work",
        pipeline=FakePipeline(),
    )

    assert result["status"] == "blocked_environment"
    payload = json.loads((evidence / "calibration-case.json").read_text())
    assessment = assess_case_kat(
        payload["controls"], artifact_root=evidence, case_id="calibration-case"
    )
    assert assessment["eligible"] is False
    assert assessment["checks"]["qualification_passed"] is False
    assert (tmp_path / "work" / "calibration-case").exists()


def test_pre_agent_rejects_pre_satisfied_objective():
    evidence = {
        "artifact_sha256": "a" * 64,
        "result": {
            "environment_success": True,
            "agent_success": False,
            "objective_achieved": True,
        },
    }
    controls = {"pre_agent": evidence}

    assessment = assess_case_kat(controls)

    assert assessment["checks"]["objective_not_pre_satisfied"] is False



def test_runner_rejects_cross_scenario_artifact_binding(tmp_path, monkeypatch):
    monkeypatch.setattr(MODULE.ScenarioVerifier, "run_full", _fake_run_full)
    evidence = tmp_path / "evidence"
    result = MODULE.run_case(
        _case(),
        manifest=_manifest(),
        evidence_root=evidence,
        work_root=tmp_path / "work",
        pipeline=FakePipeline(),
    )
    assert result["status"] == "qualified"

    oracle_path = evidence / "calibration-case" / "oracle.json"
    oracle = json.loads(oracle_path.read_text())
    oracle["bindings"]["ground_truth_sha256"] = "f" * 64
    oracle_path.write_text(json.dumps(oracle))
    payload = json.loads((evidence / "calibration-case.json").read_text())
    payload["controls"]["oracle"]["artifact_sha256"] = MODULE.sha256_file(
        oracle_path
    )
    assessment = assess_case_kat(
        payload["controls"],
        artifact_root=evidence,
        case_id="calibration-case",
        expected_bindings=payload["bindings"],
    )

    assert assessment["eligible"] is False
    assert assessment["checks"]["oracle_accepted"] is False


def test_generation_failure_removes_partial_artifacts(tmp_path):
    class BrokenPipeline:
        def generate(self, **kwargs):
            scenario = Path(kwargs["output_dir"]) / kwargs["scenario_name"]
            scenario.mkdir(parents=True)
            raise RuntimeError("generation failed")

    evidence = tmp_path / "evidence"
    work = tmp_path / "work"
    try:
        MODULE.run_case(
            _case(),
            manifest=_manifest(),
            evidence_root=evidence,
            work_root=work,
            pipeline=BrokenPipeline(),
        )
    except RuntimeError as exc:
        assert str(exc) == "generation failed"
    else:
        raise AssertionError("generation failure should propagate")

    assert not (evidence / "calibration-case").exists()
    assert not (evidence / "calibration-case.json").exists()
    assert not (work / "calibration-case").exists()

def test_objective_controls_are_not_applicable_without_objectives(
    tmp_path, monkeypatch
):
    class NoObjectivePipeline(FakePipeline):
        def generate(self, **kwargs):
            result = super().generate(**kwargs)
            scenario = Path(kwargs["output_dir"]) / kwargs["scenario_name"]
            ground_truth_path = scenario / "ground_truth.json"
            ground_truth = json.loads(ground_truth_path.read_text())
            ground_truth["objectives"] = []
            ground_truth_path.write_text(json.dumps(ground_truth))
            return result

    monkeypatch.setattr(MODULE.ScenarioVerifier, "run_full", _fake_run_full)
    result = MODULE.run_case(
        _case(),
        manifest=_manifest(),
        evidence_root=tmp_path / "evidence",
        work_root=tmp_path / "work",
        pipeline=NoObjectivePipeline(),
    )

    assert result["status"] == "qualified"


def test_runtime_rebuild_requires_explicit_opt_in(tmp_path, monkeypatch):
    calls = []
    repository = tmp_path / "repository"
    for atom_id in ("CVE-A", "CVE-B"):
        atom_dir = repository / "data" / "atoms" / atom_id
        atom_dir.mkdir(parents=True)
        (atom_dir / "atom.yaml").write_text(f"id: {atom_id}\n")
    monkeypatch.setattr(MODULE, "ROOT", repository)

    def prepare(self, scenario_dir, runtime_policy):
        calls.append((scenario_dir, runtime_policy, self.atoms_dir))
        return {"ok": True}

    monkeypatch.setattr(MODULE.ScenarioVerifier, "prepare_runtime_images", prepare)
    monkeypatch.setattr(MODULE.ScenarioVerifier, "run_full", _fake_run_full)

    MODULE.run_case(
        _case(),
        manifest=_manifest(),
        evidence_root=tmp_path / "evidence",
        work_root=tmp_path / "work",
        rebuild_missing_runtime_images=True,
        pipeline=FakePipeline(),
    )

    assert len(calls) == 1
    assert calls[0][1] == "rebuild_missing"
    assert str(calls[0][2]).endswith(".kat_atoms/calibration-case")
    assert not (tmp_path / "work" / ".kat_atoms" / "calibration-case").exists()
