from clab_builder.orchestrator.composer.capability_closure import (
    close_capabilities,
    required_assets_satisfied,
    seed_capabilities,
)
from clab_builder.orchestrator.composer.cve_matcher import match_kill_chain
from clab_builder.orchestrator.composer.template_loader import TemplateLoader
from clab_builder.shared.models.atom import AtomConfig
from clab_builder.shared.models.template import InjectionPoint


def _rce_atom(principal: str = "service_user") -> AtomConfig:
    return AtomConfig(
        version=3,
        cve_id="CVE-CLOSURE-0001",
        category="test",
        docker_image="test:latest",
        vuln_category="RCE",
        primary_mitre_phase="initial_access",
        service_role="web_application",
        exploit_complexity="simple",
        attack_method="single_request",
        capability_grants=[
            {
                "type": "execute_command",
                "principal": principal,
                "evidence_level": "verified",
            },
            {
                "type": "network_vantage",
                "principal": principal,
                "evidence_level": "verified",
            }
        ],
    )


def test_execute_command_reads_app_db_credential():
    template = TemplateLoader().load("enterprise_3tier")
    result = close_capabilities(
        seed_capabilities(_rce_atom(), host_scope="app-service"),
        template.assets,
    )

    assert "app-db-credential" in result.assets
    assert "customer-records" not in result.assets
    assert required_assets_satisfied(["app-db-credential"], result.assets)


def test_unreadable_principal_cannot_acquire_credential():
    template = TemplateLoader().load("enterprise_3tier")
    result = close_capabilities(
        seed_capabilities(_rce_atom(principal="nobody"), host_scope="app-service"),
        template.assets,
    )

    assert "app-db-credential" not in result.assets


def test_injection_point_can_require_acquired_asset():
    atom = _rce_atom()
    point = InjectionPoint(
        id="data-store",
        zone="data",
        required_mitre=["initial_access"],
        required_vuln_category=["RCE"],
        required_assets=["app-db-credential"],
        kill_chain_phase="objective",
        depends_on=["app-service"],
    )
    upstream = {"app-service": atom}

    assert match_kill_chain(
        point,
        [atom],
        resolved_upstream=upstream,
        available_assets=set(),
    ) == []
    assert match_kill_chain(
        point,
        [atom],
        resolved_upstream=upstream,
        available_assets={"app-db-credential"},
    ) == [atom]
