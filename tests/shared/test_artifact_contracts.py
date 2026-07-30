import pytest
from pydantic import ValidationError

from clab_builder.shared.models.artifact_contracts import (
    LegacyScenarioManifest,
    LegacyVerificationResult,
    ScenarioManifestV1,
    VerificationResultV1,
    load_scenario_manifest,
    load_verification_result,
    normalize_verification_result,
)


def _scenario_payload() -> dict:
    return {
        "schema_version": 1,
        "name": "example-range",
        "hash": "abc123",
        "template": "enterprise_3tier",
        "injections": [{"ip_id": "dmz-web", "cve_id": "CVE-2012-1823"}],
    }


def test_scenario_manifest_v1_round_trip():
    model = load_scenario_manifest(_scenario_payload())

    assert isinstance(model, ScenarioManifestV1)
    assert model.model_dump(mode="json")["schema_version"] == 1


def test_scenario_manifest_v1_requires_identity():
    payload = _scenario_payload()
    payload.pop("hash")

    with pytest.raises(ValidationError):
        load_scenario_manifest(payload)


def test_unversioned_scenario_manifest_is_legacy_compatible():
    model = load_scenario_manifest({"name": "historical"})

    assert isinstance(model, LegacyScenarioManifest)
    assert model.schema_version == 0
    assert model.name == "historical"


def test_scenario_manifest_rejects_unknown_version():
    with pytest.raises(ValueError, match="unsupported scenario manifest"):
        load_scenario_manifest({**_scenario_payload(), "schema_version": 2})


@pytest.mark.parametrize(
    "overrides",
    [
        {"environment_success": True, "range_build_verified": True},
        {"failure_stage": "deploy"},
        {
            "environment_success": True,
            "attack_graph_valid": True,
            "attack_path_reachable": True,
            "agent_evaluated": True,
            "agent_success": False,
        },
        {"execution_complete": False, "cleanup_failed": True},
    ],
)
def test_verification_result_v1_serializes_independent_outcomes(overrides):
    result = normalize_verification_result(overrides)
    model = load_verification_result(result)

    assert isinstance(model, VerificationResultV1)
    for key, value in overrides.items():
        assert getattr(model, key) == value


def test_agent_failure_does_not_override_deterministic_gates():
    model = VerificationResultV1(
        environment_verified=True,
        environment_success=True,
        range_build_verified=True,
        attack_graph_valid=True,
        attack_path_reachable=True,
        agent_evaluated=True,
        agent_success=False,
        objective_achieved=False,
    )

    assert model.environment_success is True
    assert model.attack_graph_valid is True
    assert model.agent_success is False


def test_unversioned_verification_result_is_legacy_compatible():
    model = load_verification_result({"success": True, "historical_field": "kept"})

    assert isinstance(model, LegacyVerificationResult)
    assert model.schema_version == 0
    assert model.model_dump()["historical_field"] == "kept"
