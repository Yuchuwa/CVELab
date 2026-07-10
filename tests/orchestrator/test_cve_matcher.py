"""Tests for CVE matcher"""

import pytest

from clab_builder.shared.models.atom import (
    AtomConfig, VulnCategory, MitrePhase, ServiceRole,
    ExploitComplexity, AttackMethod, ServiceInfo,
)
from clab_builder.shared.models.template import InjectionPoint
from clab_builder.orchestrator.composer.cve_matcher import (
    match,
    pick_random,
    pick_orchestrated,
    score_for_chain_position,
)


def _make_atom(
    cve_id="CVE-TEST-0001",
    vuln_category=VulnCategory.RCE,
    mitre_phase=MitrePhase.INITIAL_ACCESS,
    service_role=ServiceRole.WEB_APPLICATION,
    exploit_complexity=ExploitComplexity.SIMPLE,
    attack_method=AttackMethod.SINGLE_REQUEST,
) -> AtomConfig:
    return AtomConfig(
        cve_id=cve_id,
        category="test",
        docker_image="test:latest",
        ports=[80],
        services=[ServiceInfo(name="web", image="test:latest")],
        vuln_category=vuln_category,
        primary_mitre_phase=mitre_phase,
        service_role=service_role,
        exploit_complexity=exploit_complexity,
        attack_method=attack_method,
        verified=True,
    )


def _make_ip(
    required_mitre=None,
    required_vuln_category=None,
    required_service_role=None,
) -> InjectionPoint:
    return InjectionPoint(
        id="test-ip-1",
        zone="dmz",
        required_mitre=required_mitre or ["initial_access"],
        required_vuln_category=required_vuln_category or ["RCE"],
        required_service_role=required_service_role,
    )


class TestMatch:
    def test_basic_match(self):
        atom = _make_atom()
        ip = _make_ip()
        result = match(ip, [atom])
        assert len(result) == 1
        assert result[0].cve_id == "CVE-TEST-0001"

    def test_mitre_mismatch(self):
        atom = _make_atom(mitre_phase=MitrePhase.PRIVILEGE_ESCALATION)
        ip = _make_ip(required_mitre=["initial_access"])
        result = match(ip, [atom])
        assert len(result) == 0

    def test_vuln_category_mismatch(self):
        atom = _make_atom(vuln_category=VulnCategory.LFI)
        ip = _make_ip(required_vuln_category=["RCE"])
        result = match(ip, [atom])
        assert len(result) == 0

    def test_service_role_match_when_required(self):
        atom = _make_atom(service_role=ServiceRole.WEB_APPLICATION)
        ip = _make_ip(required_service_role=["web_application", "middleware"])
        result = match(ip, [atom])
        assert len(result) == 1

    def test_service_role_mismatch_when_required(self):
        atom = _make_atom(service_role=ServiceRole.DATABASE)
        ip = _make_ip(required_service_role=["web_application"])
        result = match(ip, [atom])
        assert len(result) == 0

    def test_service_role_skipped_when_not_required(self):
        """injection_point 没有指定 required_service_role 时不检查"""
        atom = _make_atom(service_role=ServiceRole.DATABASE)
        ip = _make_ip(required_service_role=None)
        result = match(ip, [atom])
        assert len(result) == 1

    def test_exclude_list(self):
        atoms = [_make_atom(cve_id=f"CVE-TEST-{i:04d}") for i in range(5)]
        ip = _make_ip()
        result = match(ip, atoms, exclude=["CVE-TEST-0001", "CVE-TEST-0003"])
        assert len(result) == 3
        assert all(a.cve_id not in ["CVE-TEST-0001", "CVE-TEST-0003"] for a in result)

    def test_multiple_matching(self):
        atoms = [
            _make_atom(cve_id="CVE-001", vuln_category=VulnCategory.RCE),
            _make_atom(cve_id="CVE-002", vuln_category=VulnCategory.RCE),
            _make_atom(cve_id="CVE-003", vuln_category=VulnCategory.LFI),
        ]
        ip = _make_ip(required_vuln_category=["RCE"])
        result = match(ip, atoms)
        assert len(result) == 2

    def test_empty_atoms(self):
        ip = _make_ip()
        result = match(ip, [])
        assert result == []


class TestPickRandom:
    def test_pick_exact_count(self):
        atoms = [_make_atom(cve_id=f"CVE-{i}") for i in range(5)]
        picked = pick_random(atoms, count=3)
        assert len(picked) == 3
        assert len(set(a.cve_id for a in picked)) == 3  # unique

    def test_pick_more_than_available(self):
        atoms = [_make_atom(cve_id=f"CVE-{i}") for i in range(2)]
        picked = pick_random(atoms, count=5)
        assert len(picked) == 2  # can't pick more than available

    def test_pick_from_empty(self):
        picked = pick_random([], count=3)
        assert picked == []


class TestPickOrchestrated:
    def test_intermediate_hop_penalizes_heavy_tooling(self):
        ip = _make_ip(
            required_vuln_category=["RCE", "Deserialization"],
            required_service_role=["web_application"],
        )
        simple = _make_atom(
            "CVE-SIMPLE",
            vuln_category=VulnCategory.RCE,
            exploit_complexity=ExploitComplexity.SIMPLE,
        )
        heavy = _make_atom(
            "CVE-HEAVY",
            vuln_category=VulnCategory.DESERIALIZATION,
            exploit_complexity=ExploitComplexity.COMPLEX,
        )
        heavy.requirements = {
            "tools_needed": ["Java Runtime (JDK 8+)", "ysoserial-all.jar"]
        }

        assert score_for_chain_position(simple, ip, index=1, total=3) > (
            score_for_chain_position(heavy, ip, index=1, total=3)
        )
        assert pick_orchestrated([heavy, simple], ip, index=1, total=3)[0] == simple

    def test_last_hop_can_accept_information_leak_more_than_intermediate(self):
        ip = _make_ip(required_vuln_category=["Info_Leak"])
        atom = _make_atom("CVE-LEAK", vuln_category=VulnCategory.INFO_LEAK)

        assert score_for_chain_position(atom, ip, index=2, total=3) > (
            score_for_chain_position(atom, ip, index=1, total=3)
        )
