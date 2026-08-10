import pytest
from pydantic import ValidationError

from clab_builder.shared.models.artifact_contracts import (
    AgentExposureProfile,
    AgentInputV1,
    AgentOutputV1,
    BatchStateV1,
    BatchSummaryV1,
    GroundTruthV1,
    MaterialAuditV1,
    LegacyScenarioManifest,
    LegacyVerificationResult,
    ScenarioManifestV1,
    VerificationResultV1,
    load_scenario_manifest,
    load_verification_result,
    normalize_verification_result,
    normalize_agent_input,
    normalize_agent_output,
    normalize_batch_state,
    normalize_batch_summary,
    normalize_ground_truth,
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


def test_agent_exposure_profile_normalizes_context_and_is_versioned():
    profile = AgentExposureProfile.model_validate({"context": "no-guide"})

    assert profile.schema_version == 1
    assert profile.context == "no_guide"
    assert profile.profile == "guide_removed"
    assert profile.hint_profile == "guide_removed"


def test_agent_exposure_profile_rejects_context_label_mismatch():
    with pytest.raises(ValidationError, match="does not match context"):
        AgentExposureProfile.model_validate({
            "context": "l1",
            "profile": "full_guide",
        })


def test_agent_exposure_profile_rejects_unknown_version():
    with pytest.raises(ValidationError, match="unsupported agent exposure profile"):
        AgentExposureProfile.model_validate({"schema_version": 2, "context": "guided"})


def test_manifest_profile_and_context_are_kept_in_lockstep():
    model = load_scenario_manifest({
        **_scenario_payload(),
        "agent_context": "no-hint",
    })

    assert model.agent_context == "no_hint"
    assert model.agent_exposure_profile.context == "no_hint"


def test_manifest_rejects_profile_context_mismatch():
    with pytest.raises(ValidationError, match="profile/context mismatch"):
        load_scenario_manifest({
            **_scenario_payload(),
            "agent_context": "guided",
            "agent_exposure_profile": {"context": "l2"},
        })


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


def test_private_ground_truth_and_agent_envelopes_are_versioned():
    ground_truth = normalize_ground_truth({
        "scenario": "range-1",
        "attack_path": [{"target_node": "target-1", "flag": "private"}],
    })
    agent_input = normalize_agent_input({
        "scenario_name": "range-1",
        "targets": [{"node_name": "target-1"}],
        "agent_context": "no-guide",
    })
    agent_output = normalize_agent_output({
        "scenario_name": "range-1",
        "agent_context": "no-guide",
        "agent_reported": {"success": True, "evidence": ["observed"]},
    })

    assert GroundTruthV1.model_validate(ground_truth).schema_version == 1
    assert AgentInputV1.model_validate(agent_input).agent_exposure_profile.context == "no_guide"
    assert AgentOutputV1.model_validate(agent_output).agent_reported.success is True


def test_material_audit_and_batch_envelopes_preserve_unknown_extensions():
    audit = MaterialAuditV1.model_validate({
        "agent_context": "guided",
        "items": [{"cve_id": "CVE-X", "material": "poc.py", "visible": True}],
        "future_field": "kept",
    })
    state = normalize_batch_state({
        "run_id": "run-1",
        "fingerprint": "f" * 64,
        "cases": {"case-1": {"status": "pending"}},
    })
    summary = normalize_batch_summary({
        "run_id": "run-1",
        "selected_cases": ["case-1"],
        "results": [],
    })

    assert audit.model_dump()["future_field"] == "kept"
    assert BatchStateV1.model_validate(state).cases["case-1"].status == "pending"
    assert BatchSummaryV1.model_validate(summary).schema_version == 1
