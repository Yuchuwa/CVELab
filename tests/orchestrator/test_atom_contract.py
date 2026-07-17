"""Tests for atom v3 normalization and compatibility."""

from clab_builder.shared.models.atom import (
    AtomConfig,
    CapabilityType,
    EvidenceLevel,
)


def test_v2_atom_loads_with_v3_defaults():
    atom = AtomConfig(
        version=2,
        cve_id="CVE-TEST-0001",
        category="test",
        docker_image="test:latest",
        ports=[8080],
        services=[{"name": "web", "image": "test:latest", "is_target": True}],
        vuln_category="RCE",
        primary_mitre_phase="initial_access",
        service_role="web_application",
        exploit_complexity="simple",
        attack_method="single_request",
        verified=True,
    )

    assert atom.runtime_spec is not None
    assert atom.runtime_spec.ports == [8080]
    assert atom.flag_spec is not None
    assert atom.flag_spec.primary_path == "/flag.txt"
    assert atom.validation_spec is not None
    assert atom.validation_spec.readiness[0].probe_type.value == "container_state"
    assert atom.is_legacy is True


def test_v3_atom_requires_native_verification_for_verified_true():
    atom = AtomConfig(
        version=3,
        cve_id="CVE-TEST-0002",
        category="test",
        docker_image="test:latest",
        ports=[8080],
        services=[{"name": "web", "image": "test:latest", "is_target": True}],
        runtime_spec={"ports": [8080], "services": [{"name": "web", "image": "test:latest", "is_target": True}]},
        vuln_category="RCE",
        primary_mitre_phase="initial_access",
        service_role="web_application",
        exploit_complexity="simple",
        attack_method="single_request",
        verification={
            "native_verification": {"success": True, "mode": "native"},
            # Orchestrated rebuild failed; verified no longer tracks it.
            "orchestrated_verification": {"success": False, "mode": "orchestrated"},
            "environment_ready": False,
        },
        verified=True,
    )

    # Native success keeps verified even when orchestrated rebuild failed.
    assert atom.verified is True
    assert atom.is_legacy is False


def test_v3_atom_native_failure_downgrades_verified():
    atom = AtomConfig(
        version=3,
        cve_id="CVE-TEST-0002b",
        category="test",
        docker_image="test:latest",
        ports=[8080],
        services=[{"name": "web", "image": "test:latest", "is_target": True}],
        runtime_spec={"ports": [8080], "services": [{"name": "web", "image": "test:latest", "is_target": True}]},
        vuln_category="RCE",
        primary_mitre_phase="initial_access",
        service_role="web_application",
        exploit_complexity="simple",
        attack_method="single_request",
        verification={
            "native_verification": {"success": False, "mode": "native"},
            "orchestrated_verification": {"success": True, "mode": "orchestrated"},
            "environment_ready": True,
        },
        verified=True,
    )

    assert atom.verified is False


def test_capability_contract_parses_verified_grants():
    atom = AtomConfig(
        version=3,
        cve_id="CVE-TEST-0003",
        category="test",
        docker_image="test:latest",
        vuln_category="RCE",
        primary_mitre_phase="initial_access",
        service_role="web_application",
        exploit_complexity="simple",
        attack_method="single_request",
        exploit_access={
            "attack_vector": "network",
            "privileges_required": "none",
            "required_service": {"protocol": "http", "port": 80},
        },
        capability_grants=[
            {
                "type": "execute_command",
                "principal": "service_user",
                "evidence_level": "verified",
                "evidence_ref": "native-replay-01",
            },
            {
                "type": "network_vantage",
                "evidence_level": "inferred",
            },
        ],
    )

    assert atom.exploit_access.required_service["port"] == 80
    assert atom.has_verified_capability(CapabilityType.EXECUTE_COMMAND)
    assert not atom.has_verified_capability(CapabilityType.NETWORK_VANTAGE)
    assert atom.capability_grants[1].evidence_level == EvidenceLevel.INFERRED


def test_legacy_pivot_capability_is_compatibility_view():
    atom = AtomConfig(
        version=3,
        cve_id="CVE-TEST-0004",
        category="test",
        docker_image="test:latest",
        vuln_category="RCE",
        primary_mitre_phase="initial_access",
        service_role="web_application",
        exploit_complexity="simple",
        attack_method="single_request",
        post_exploit={"pivot_capability": "shell"},
    )

    assert atom.has_verified_capability(CapabilityType.EXECUTE_COMMAND)
    assert atom.has_verified_capability(CapabilityType.NETWORK_VANTAGE)


def test_explicit_unverified_grants_do_not_fallback_to_pivot():
    atom = AtomConfig(
        version=3,
        cve_id="CVE-TEST-0005",
        category="test",
        docker_image="test:latest",
        vuln_category="RCE",
        primary_mitre_phase="initial_access",
        service_role="web_application",
        exploit_complexity="simple",
        attack_method="single_request",
        post_exploit={"pivot_capability": "shell"},
        capability_grants=[
            {"type": "network_vantage", "evidence_level": "inferred"}
        ],
    )

    assert not atom.has_verified_capability(CapabilityType.NETWORK_VANTAGE)
