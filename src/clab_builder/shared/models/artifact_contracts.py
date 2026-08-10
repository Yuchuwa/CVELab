"""Versioned contracts for persisted Range artifacts."""

from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, model_validator


class _ArtifactModel(BaseModel):
    model_config = ConfigDict(extra="allow")


AGENT_EXPOSURE_CONTEXTS = (
    "guided",
    "no_guide",
    "no_hint",
    "l0",
    "l1",
    "l2",
)

_AGENT_EXPOSURE_PROFILE_NAMES = {
    "guided": "full_guide",
    "no_guide": "guide_removed",
    "no_hint": "exploit_hints_removed",
    "l0": "level_l0_hints_removed",
    "l1": "level_l1_hints_removed",
    "l2": "level_l2_hints_removed",
}


def normalize_agent_context(value: str | None) -> str:
    """Normalize CLI spellings to the persisted Agent context contract."""
    context = str(value or "guided").strip().lower().replace("-", "_")
    if context not in AGENT_EXPOSURE_CONTEXTS:
        raise ValueError(
            "agent context must be one of "
            + ", ".join(AGENT_EXPOSURE_CONTEXTS)
        )
    return context


class AgentExposureProfile(_ArtifactModel):
    """Versioned, immutable description of what an Agent may see."""

    schema_version: Literal[1] = 1
    context: Literal["guided", "no_guide", "no_hint", "l0", "l1", "l2"] = "guided"
    profile: str = ""
    hint_profile: str = ""

    @model_validator(mode="before")
    @classmethod
    def _normalize_context(cls, value):
        if isinstance(value, str):
            value = {"context": value}
        if not isinstance(value, Mapping):
            return value
        data = dict(value)
        version = data.get("schema_version", 1)
        if version != 1:
            raise ValueError(
                f"unsupported agent exposure profile schema_version: {version!r}"
            )
        context = normalize_agent_context(data.get("context"))
        expected = _AGENT_EXPOSURE_PROFILE_NAMES[context]
        for key in ("profile", "hint_profile"):
            supplied = str(data.get(key) or "")
            if supplied and supplied != expected:
                raise ValueError(
                    f"agent exposure {key} does not match context {context!r}"
                )
            data[key] = expected
        data["context"] = context
        data["schema_version"] = 1
        return data

    @classmethod
    def from_context(cls, context: str | None = "guided") -> "AgentExposureProfile":
        return cls(context=normalize_agent_context(context))


def normalize_agent_exposure_profile(
    value: AgentExposureProfile | Mapping[str, Any] | str | None = None,
    *,
    context: str | None = None,
) -> AgentExposureProfile:
    """Validate a profile and optionally require a matching context."""
    normalized_context = normalize_agent_context(context) if context is not None else None
    if value is None:
        profile = AgentExposureProfile.from_context(normalized_context or "guided")
    elif isinstance(value, AgentExposureProfile):
        profile = value
    elif isinstance(value, str):
        profile = AgentExposureProfile.from_context(value)
    else:
        profile = AgentExposureProfile.model_validate(value)
    if normalized_context is not None and profile.context != normalized_context:
        raise ValueError(
            "agent exposure profile/context mismatch: "
            f"profile={profile.context!r}, context={normalized_context!r}"
        )
    return profile


def _normalize_model_exposure_fields(data: Mapping[str, Any]) -> dict[str, Any]:
    """Fill and validate the shared profile/context pair for artifact models."""
    normalized = dict(data)
    raw_profile = normalized.get("agent_exposure_profile")
    raw_context = normalized.get("agent_context")
    if raw_context is None or str(raw_context).strip() == "":
        if raw_profile is not None:
            raw_context = (
                raw_profile.context
                if isinstance(raw_profile, AgentExposureProfile)
                else raw_profile.get("context")
                if isinstance(raw_profile, Mapping)
                else raw_profile
            )
        else:
            raw_context = "guided"
    context = normalize_agent_context(raw_context)
    profile = normalize_agent_exposure_profile(raw_profile, context=context)
    normalized["agent_context"] = context
    normalized["agent_exposure_profile"] = profile.model_dump(mode="json")
    return normalized


class GroundTruthV1(_ArtifactModel):
    """Verifier-private scenario truth and objective assertions."""

    schema_version: Literal[1] = 1
    scenario: str = ""
    template: str = ""
    attack_path: list[dict[str, Any]] = Field(default_factory=list)
    objectives: list[dict[str, Any]] = Field(default_factory=list)


class MaterialAuditItemV1(_ArtifactModel):
    """One host-side material visibility and integrity decision."""

    cve_id: str = ""
    material: str = ""
    visible: bool = False
    role: str = ""
    visibility: str = ""
    source_path: str = ""
    mounted_path: str = ""
    declared_sha256: str = ""
    actual_sha256: str = ""
    hash_valid: bool | None = None
    reason: str = ""


class MaterialAuditV1(_ArtifactModel):
    """Persisted audit envelope for the material exposure boundary."""

    schema_version: Literal[1] = 1
    agent_context: str = "guided"
    agent_exposure_profile: AgentExposureProfile = Field(
        default_factory=AgentExposureProfile.from_context
    )
    policy: str = "source_bundle_selector_v1"
    ok: bool = True
    items: list[MaterialAuditItemV1] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _normalize_exposure(cls, value):
        if isinstance(value, Mapping):
            return _normalize_model_exposure_fields(value)
        return value


class AgentInputV1(_ArtifactModel):
    """Sanitized input envelope written before an Agent subprocess starts."""

    schema_version: Literal[1] = 1
    scenario_name: str = ""
    attacker_ip: str = ""
    targets: list[dict[str, Any]] = Field(default_factory=list)
    objectives: list[dict[str, Any]] = Field(default_factory=list)
    agent_context: str = "guided"
    agent_exposure_profile: AgentExposureProfile = Field(
        default_factory=AgentExposureProfile.from_context
    )

    @model_validator(mode="before")
    @classmethod
    def _normalize_exposure(cls, value):
        if isinstance(value, Mapping):
            return _normalize_model_exposure_fields(value)
        return value


class AgentReportedV1(_ArtifactModel):
    """Fields the model is allowed to claim in its structured report."""

    success: bool = False
    verified_flags: dict[str, str] = Field(default_factory=dict)
    objective_results: dict[str, Any] = Field(default_factory=dict)
    attack_log: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[Any] = Field(default_factory=list)
    failed_targets: list[Any] = Field(default_factory=list)


class AgentOutputV1(_ArtifactModel):
    """Runner-owned Agent result envelope with an isolated report payload."""

    schema_version: Literal[1] = 1
    scenario_name: str = ""
    success: bool = False
    agent_context: str = "guided"
    agent_exposure_profile: AgentExposureProfile = Field(
        default_factory=AgentExposureProfile.from_context
    )
    agent_reported: AgentReportedV1 = Field(default_factory=AgentReportedV1)
    prompt_hygiene: dict[str, Any] = Field(default_factory=dict)
    material_audit: MaterialAuditV1 | None = None
    agent_evaluated: bool = False
    termination_reason: str = ""

    @model_validator(mode="before")
    @classmethod
    def _normalize_exposure(cls, value):
        if isinstance(value, Mapping):
            return _normalize_model_exposure_fields(value)
        return value


class BatchCaseStateV1(_ArtifactModel):
    """One resumable case entry inside a batch state envelope."""

    case: dict[str, Any] = Field(default_factory=dict)
    status: str = "pending"
    attempts: int = 0
    scenario_dir: str = ""
    result_path: str = ""


class BatchStateV1(_ArtifactModel):
    """Coordinator state used for immutable resume decisions."""

    schema_version: Literal[1] = 1
    created_at: str = ""
    updated_at: str = ""
    run_id: str = ""
    fingerprint: str = ""
    agent_context: str = "guided"
    agent_exposure_profile: AgentExposureProfile = Field(
        default_factory=AgentExposureProfile.from_context
    )
    options: dict[str, Any] = Field(default_factory=dict)
    selected_case_ids: list[str] = Field(default_factory=list)
    cases: dict[str, BatchCaseStateV1] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _normalize_exposure(cls, value):
        if isinstance(value, Mapping):
            return _normalize_model_exposure_fields(value)
        return value


class BatchSummaryV1(_ArtifactModel):
    """Sanitized, versioned batch projection consumed by analysis tools."""

    schema_version: Literal[1] = 1
    created_at: str = ""
    run_id: str = ""
    template: str = ""
    validation_mode: str = "guided_agent"
    environment_only: bool = False
    agent_context: str = "guided"
    agent_exposure_profile: AgentExposureProfile = Field(
        default_factory=AgentExposureProfile.from_context
    )
    selected_cases: list[str] = Field(default_factory=list)
    results: list[dict[str, Any]] = Field(default_factory=list)
    case_states: dict[str, str] = Field(default_factory=dict)
    fingerprint: str = ""

    @model_validator(mode="before")
    @classmethod
    def _normalize_exposure(cls, value):
        if isinstance(value, Mapping):
            return _normalize_model_exposure_fields(value)
        return value


def _normalize_artifact(model_type, payload: Mapping[str, Any]) -> dict[str, Any]:
    data = dict(payload)
    return model_type.model_validate(data).model_dump(mode="json")


def _stamp_current_schema(data: dict[str, Any]) -> dict[str, Any]:
    version = data.get("schema_version")
    if version not in (None, 1):
        raise ValueError(f"unsupported artifact schema_version: {version!r}")
    data["schema_version"] = 1
    return data


def normalize_ground_truth(payload: Mapping[str, Any]) -> dict[str, Any]:
    return _normalize_artifact(GroundTruthV1, _stamp_current_schema(dict(payload)))


def load_ground_truth(payload: Mapping[str, Any]) -> GroundTruthV1:
    return GroundTruthV1.model_validate(normalize_ground_truth(payload))


def normalize_agent_input(payload: Mapping[str, Any]) -> dict[str, Any]:
    return _normalize_artifact(AgentInputV1, _stamp_current_schema(dict(payload)))


def normalize_agent_output(payload: Mapping[str, Any]) -> dict[str, Any]:
    return _normalize_artifact(AgentOutputV1, _stamp_current_schema(dict(payload)))


def normalize_material_audit(payload: Mapping[str, Any]) -> dict[str, Any]:
    return _normalize_artifact(MaterialAuditV1, _stamp_current_schema(dict(payload)))


def normalize_batch_state(payload: Mapping[str, Any]) -> dict[str, Any]:
    return _normalize_artifact(BatchStateV1, _stamp_current_schema(dict(payload)))


def normalize_batch_summary(payload: Mapping[str, Any]) -> dict[str, Any]:
    return _normalize_artifact(BatchSummaryV1, _stamp_current_schema(dict(payload)))


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
    agent_context: str = "guided"
    agent_exposure_profile: AgentExposureProfile = Field(
        default_factory=AgentExposureProfile.from_context
    )
    validation_mode: str = ""
    exploit_guides: list[Any] = Field(default_factory=list)
    guide_compatibility: dict[str, Any] = Field(default_factory=dict)
    guide_advisories: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _normalize_exposure(cls, value):
        if isinstance(value, Mapping):
            return _normalize_model_exposure_fields(value)
        return value


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
    agent_context: str = "guided"
    agent_exposure_profile: AgentExposureProfile = Field(
        default_factory=AgentExposureProfile.from_context
    )

    @model_validator(mode="before")
    @classmethod
    def _normalize_exposure(cls, value):
        if isinstance(value, Mapping):
            return _normalize_model_exposure_fields(value)
        return value


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
