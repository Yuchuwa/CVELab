"""Versioned contracts for persisted Range artifacts."""

from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field


class _ArtifactModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class ScenarioManifestV1(_ArtifactModel):
    """Public scenario metadata persisted as ``scenario.yaml``."""

    schema_version: Literal[1] = 1
    name: str = Field(min_length=1)
    hash: str = Field(min_length=1)
    template: str = Field(min_length=1)
    injections: list[dict[str, Any]]
    ip_allocations: dict[str, Any] = Field(default_factory=dict)
    objectives: list[dict[str, Any]] = Field(default_factory=list)
    agent_objectives: list[dict[str, Any]] = Field(default_factory=list)
    assets: list[dict[str, Any]] = Field(default_factory=list)
    resolved_asset_bindings: dict[str, Any] = Field(default_factory=dict)
    network_subnets: list[Any] = Field(default_factory=list)
    match_report: list[dict[str, Any]] = Field(default_factory=list)
    runtime_builds: list[dict[str, Any]] = Field(default_factory=list)
    runtime_images: list[dict[str, Any]] = Field(default_factory=list)
    validation_mode: str = ""
    exploit_guides: list[Any] = Field(default_factory=list)
    guide_compatibility: dict[str, Any] = Field(default_factory=dict)
    guide_advisories: dict[str, Any] = Field(default_factory=dict)


class LegacyScenarioManifest(_ArtifactModel):
    """Compatibility reader for historical, unversioned scenario metadata."""

    schema_version: Literal[0] = 0
    name: str = ""
    hash: str = ""
    template: str = ""
    injections: list[dict[str, Any]] = Field(default_factory=list)


class VerificationResultV1(_ArtifactModel):
    """Independent deterministic, Agent and objective verification outcomes."""

    schema_version: Literal[1] = 1
    success: bool = False
    validation_mode: str = ""
    environment_verified: bool = False
    environment_success: bool = False
    range_build_verified: bool = False
    attack_graph_valid: bool = False
    attack_path_reachable: bool = False
    agent_evaluated: bool = False
    agent_success: bool = False
    guided_trial_evaluated: bool = False
    guided_trial_success: bool = False
    objective_achieved: bool = False
    failure_stage: str = ""
    execution_complete: bool = False
    cleanup_failed: bool = False


class LegacyVerificationResult(_ArtifactModel):
    """Compatibility reader for historical, unversioned verification output."""

    schema_version: Literal[0] = 0
    success: bool = False


def load_scenario_manifest(
    payload: Mapping[str, Any],
) -> ScenarioManifestV1 | LegacyScenarioManifest:
    """Validate a v1 manifest or preserve an unversioned legacy payload."""
    data = dict(payload)
    version = data.get("schema_version", 0)
    if version == 0:
        data["schema_version"] = 0
        return LegacyScenarioManifest.model_validate(data)
    if version == 1:
        return ScenarioManifestV1.model_validate(data)
    raise ValueError(f"unsupported scenario manifest schema_version: {version!r}")


def load_verification_result(
    payload: Mapping[str, Any],
) -> VerificationResultV1 | LegacyVerificationResult:
    """Validate a v1 result or preserve an unversioned legacy payload."""
    data = dict(payload)
    version = data.get("schema_version", 0)
    if version == 0:
        data["schema_version"] = 0
        return LegacyVerificationResult.model_validate(data)
    if version == 1:
        return VerificationResultV1.model_validate(data)
    raise ValueError(f"unsupported verification result schema_version: {version!r}")


def normalize_verification_result(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Apply v1 defaults at the single verifier persistence boundary."""
    data = dict(payload)
    data["schema_version"] = 1
    return VerificationResultV1.model_validate(data).model_dump(mode="json")
