"""Tests for unified native verification structure (batch 6).

The Agent path and the CVE-Factory PoC path both write a
``verification.native_verification`` dict with the same shape. The Agent
path records provenance="native_agent"; the PoC backend records
provenance="cve_factory_poc" plus witnesses/source_hash/test_results.

This batch only adds the shared fields to the Agent path. The PoC backend
(batch 7-9) reuses the same structure.
"""
from pathlib import Path

import yaml

from clab_builder.shared.models.atom import AtomConfig


def _atom_with_native(native: dict, **overrides) -> AtomConfig:
    data = {
        "version": 3,
        "cve_id": "CVE-NV-0001",
        "category": "test",
        "docker_image": "test:latest",
        "ports": [80],
        "services": [{"name": "web", "image": "test:latest", "is_target": True}],
        "vuln_category": "RCE",
        "primary_mitre_phase": "initial_access",
        "service_role": "web_application",
        "exploit_complexity": "simple",
        "attack_method": "single_request",
        "exploit_access": {"attack_vector": "network",
                           "required_service": {"protocol": "http", "port": 80}},
        "capability_grants": [{"type": "execute_command",
                               "principal": "root",
                               "evidence_level": "verified",
                               "evidence_ref": "verification.native_verification.evidence"}],
        "verification": {
            "native_verification": native,
            "orchestrated_verification": {"success": True, "mode": "orchestrated"},
            "environment_ready": True,
        },
        "verified": True,
    }
    data.update(overrides)
    return AtomConfig(**data)


def test_agent_native_verification_has_provenance():
    """Agent-path native verification records provenance=native_agent."""
    atom = _atom_with_native({
        "success": True, "mode": "native", "provenance": "native_agent",
        "evidence": ["id output = uid=0(root)"],
        "captured_flag": "flag{x}", "flag_matched": True,
        "reason": "flag matched",
        "flag_recovery": {"attempted": True, "success": True, "method": "agent_captured_flag"},
        "timestamp": "2026-07-17T00:00:00",
    })
    nv = atom.verification["native_verification"]
    assert nv["provenance"] == "native_agent"
    assert nv["flag_recovery"]["success"] is True
    assert nv["flag_recovery"]["method"] == "agent_captured_flag"


def test_poc_native_verification_has_provenance():
    """PoC-path native verification records provenance=cve_factory_poc and
    the extra fields the PoC backend produces (witnesses/source_hash/test_results).
    These are written by the PoC backend (batch 7-9); this test pins the
    shared shape so both paths produce a loadable atom."""
    atom = _atom_with_native({
        "success": True, "mode": "native", "provenance": "cve_factory_poc",
        "evidence": ["test_vuln.py assertion failed as expected"],
        "captured_flag": "", "flag_matched": False,
        "reason": "vulnerability observed via pytest",
        "flag_recovery": {"attempted": True, "success": False, "method": "flag_not_recovered"},
        "witnesses": {"exec-01": {"capability": "execute_command",
                                  "command": "id", "output": "uid=0(root)"}},
        "source_hash": "sha256:abc",
        "test_results": {"test_func": {"passed": 2, "failed": 0},
                         "test_vuln": {"passed": 0, "failed": 3}},
        "timestamp": "2026-07-17T00:00:00",
    })
    nv = atom.verification["native_verification"]
    assert nv["provenance"] == "cve_factory_poc"
    assert nv["witnesses"]["exec-01"]["capability"] == "execute_command"
    assert nv["test_results"]["test_vuln"]["failed"] == 3
    # Both paths keep verified in sync with native success (v3 contract).
    assert atom.verified is True


def test_no_flag_bug_records_flag_recovery_not_attempted():
    """Objective-evidence bugs (Info_Leak/Auth_Bypass) do not plant a flag,
    so flag_recovery.attempted is False and verified is not gated on it."""
    atom = _atom_with_native({
        "success": True, "mode": "native", "provenance": "native_agent",
        "evidence": ["Heartbeat leaked 16384 bytes"],
        "captured_flag": "", "flag_matched": False,
        "reason": "objective evidence accepted",
        "flag_recovery": {"attempted": False, "success": False, "method": "no_flag_required"},
        "timestamp": "2026-07-17T00:00:00",
    })
    nv = atom.verification["native_verification"]
    assert nv["flag_recovery"]["attempted"] is False
    assert nv["flag_recovery"]["method"] == "no_flag_required"
    # v3 keeps verified even without a flag, because native success is True.
    assert atom.verified is True