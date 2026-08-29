import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "analyze_static_difficulty_pilot",
    ROOT / "scripts" / "analyze_static_difficulty_pilot.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _atom(method="single_request", complexity="simple", **kwargs):
    return {
        "cve_id": "CVE-TEST",
        "attack_method": method,
        "exploit_complexity": complexity,
        "network_requirements": kwargs.get("network_requirements", {}),
        "exploit_access": kwargs.get("exploit_access", {}),
        "source_bundle": kwargs.get("source_bundle", {}),
    }


def test_file_upload_relay_is_harder_than_direct_entry():
    atom = _atom(method="file_upload")
    entry = MODULE.atom_stage_score(atom, "entry")
    app = MODULE.atom_stage_score(atom, "app")

    assert app["success_probability"] < entry["success_probability"]
    assert any(item["name"] == "file_upload_relay" for item in app["factors"])


def test_declared_default_credentials_reduce_authentication_penalty():
    with_credentials = _atom(
        exploit_access={"required_service": {"authentication": "password"}},
    )
    with_credentials["default_credentials"] = {"username": "user", "password": "pass"}
    without_credentials = _atom(
        exploit_access={"required_service": {"authentication": "password"}},
    )

    declared = MODULE.atom_stage_score(with_credentials, "entry")
    unknown = MODULE.atom_stage_score(without_credentials, "entry")

    assert declared["success_probability"] > unknown["success_probability"]
    assert any(
        item["name"] == "declared_default_credentials" for item in declared["factors"]
    )


def test_chain_probability_is_multiplicative_and_exposes_bottleneck():
    stages = [
        {"cve_id": "A", "stage": "entry", "success_probability": 0.9, "cost_factor": 0.1},
        {"cve_id": "B", "stage": "app", "success_probability": 0.4, "cost_factor": 0.5},
    ]
    result = MODULE.score_chain(stages, 0.5)

    assert result["success_probability"] == 0.18
    assert result["score"] == 72.6
    assert result["bottleneck"]["cve_id"] == "B"
    assert result["label"] == "hard"


def test_report_declares_no_historical_or_evaluator_inputs():
    report = MODULE.build_report(
        ROOT / "data/range_matrices/enterprise_3tier_hetero.json",
        ROOT / "data/atoms",
    )

    assert report["uses_historical_agent_results"] is False
    assert report["uses_difficulty_evaluator"] is False
    assert len(report["atoms"]) == len(MODULE.PILOT_ATOMS)
    assert len(report["combinations"]) == len(MODULE.PILOT_CASES)
