"""Regression tests for the read-only Atom reconstruction audit."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import yaml

from clab_builder.shared.models.atom import AtomConfig


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "audit_atom_reconstruction.py"
SPEC = importlib.util.spec_from_file_location("reconstruction_audit", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def _ready_atom(atom_dir: Path) -> AtomConfig:
    bundle = atom_dir / "source_bundle"
    bundle.mkdir(parents=True)
    (bundle / "docker-compose.yml").write_text("services: {}\n")
    (bundle / "README.md").write_text("test\n")
    (atom_dir / "exploit_guide.yaml").write_text(
        yaml.safe_dump({
            "version": 2,
            "cve_id": "CVE-AUDIT-1",
            "steps": [{
                "id": "exploit", "action": "trigger", "procedure": "trigger exploit",
                "success_signal": "command succeeds",
                "execution": {"scope": "actor", "tools": [], "materials": []},
            }],
        })
    )
    return AtomConfig.model_validate({
        "version": 3,
        "cve_id": "CVE-AUDIT-1",
        "category": "test",
        "docker_image": "vulhub/test:1",
        "ports": [61616, 8161],
        "vuln_category": "RCE",
        "primary_mitre_phase": "initial_access",
        "service_role": "middleware",
        "exploit_complexity": "simple",
        "attack_method": "single_request",
        "source_bundle": {
            "compose_file": "source_bundle/docker-compose.yml",
            "readme_file": "source_bundle/README.md",
        },
        "exploit_access": {
            "required_service": {"protocol": "http", "port": 8161},
        },
        "capability_grants": [{
            "type": "execute_command", "evidence_level": "verified",
            "evidence_ref": "verification.native_verification.evidence",
        }],
        "exploit_guide": {"path": "exploit_guide.yaml", "format_version": 2, "status": "ready"},
        "verification": {
            "native_verification": {"success": True, "evidence": ["ok"]},
            "environment_ready": True,
            "runtime_verification": {"status": "ready", "service_ready": True},
        },
        "runtime_spec": {
            "ports": [61616, 8161], "runtime_image": "runtime:test",
            "runtime_status": "ready",
        },
        "validation_spec": {"readiness": [
            {"probe_type": "container_state"}, {"probe_type": "tcp", "target": "8161"},
        ]},
        "verified": True,
    })


def test_multiport_contract_is_range_ready_when_exploit_entry_is_probed(tmp_path, monkeypatch):
    atom = _ready_atom(tmp_path)
    monkeypatch.setattr(MODULE, "_local_image_state", lambda image: "unknown")

    classification, reasons, alignment = MODULE._classify(atom, tmp_path)

    assert classification == "range_ready"
    assert reasons == []
    assert alignment["aligned"] is True


def test_multiport_contract_requires_rebuild_when_probe_targets_other_port(tmp_path, monkeypatch):
    atom = _ready_atom(tmp_path)
    atom.validation_spec.readiness[-1].target = "61616"
    monkeypatch.setattr(MODULE, "_local_image_state", lambda image: "unknown")

    classification, reasons, alignment = MODULE._classify(atom, tmp_path)

    assert classification == "rebuild_runtime_or_bundle"
    assert alignment["aligned"] is False
    assert "multi-port readiness does not probe exploit entry" in reasons


def test_local_image_permission_denied_is_unknown_not_unavailable(monkeypatch):
    monkeypatch.setattr(
        MODULE.subprocess, "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1, stderr="permission denied while trying to connect to Docker"
        ),
    )

    assert MODULE._local_image_state("vulhub/test:1") == "unknown"
