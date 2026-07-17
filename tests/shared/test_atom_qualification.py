"""Tests for atom authoritative qualification (batch 1).

Covers the three levels (structure_healthy / template_candidate /
template_anchor) and the key design decisions:
  - native verified but bundle missing -> not candidate
  - bundle complete but service empty -> not candidate (network atom)
  - service complete but no verified capability -> not candidate
  - guide alignment mismatch does NOT affect candidate (advisory)
  - guide integrity failure DOES block candidate
  - environment_ready=false blocks anchor but not candidate
  - environment_ready=None (legacy) blocks anchor but not candidate
  - local-vector atom with empty service is allowed
"""
from pathlib import Path

import yaml

from clab_builder.shared.models.atom import AtomConfig
from clab_builder.shared.atom_qualification import qualify_atom, qualify_atom_dir


def _base_atom(**overrides) -> AtomConfig:
    data = {
        "version": 3,
        "cve_id": "CVE-QUAL-0001",
        "category": "test",
        "docker_image": "test:latest",
        "ports": [80],
        "services": [{"name": "web", "image": "test:latest", "is_target": True}],
        "runtime_spec": {
            "ports": [80],
            "services": [{"name": "web", "image": "test:latest", "is_target": True}],
        },
        "vuln_category": "RCE",
        "primary_mitre_phase": "initial_access",
        "service_role": "web_application",
        "exploit_complexity": "simple",
        "attack_method": "single_request",
        "exploit_access": {
            "attack_vector": "network",
            "privileges_required": "none",
            "required_service": {"protocol": "http", "port": 80},
        },
        "capability_grants": [
            {
                "type": "execute_command",
                "principal": "root",
                "evidence_level": "verified",
                "evidence_ref": "native-replay-01",
            }
        ],
        "verification": {
            "native_verification": {"success": True, "mode": "native"},
            "orchestrated_verification": {"success": True, "mode": "orchestrated"},
            "environment_ready": True,
        },
        "verified": True,
    }
    data.update(overrides)
    return AtomConfig(**data)


def test_full_qualified_atom_is_anchor(tmp_path):
    atom = _base_atom()
    # no source_bundle => bundle check fails without disk; add minimal bundle
    atom_dir = tmp_path / "CVE-QUAL-0001"
    atom_dir.mkdir()
    (atom_dir / "docker-compose.yml").write_text("services:\n  web:\n    image: test\n")
    (atom_dir / "README.md").write_text("ok")
    atom = _base_atom(source_bundle={
        "compose_file": "docker-compose.yml",
        "readme_file": "README.md",
        "dockerfiles": [],
        "init_files": [],
        "poc_materials": [],
        "hashes": {},
    })
    r = qualify_atom(atom, atom_dir)
    assert r.template_anchor, r.reasons
    assert r.structure_healthy
    assert r.template_candidate


def test_native_verified_but_bundle_missing_not_candidate(tmp_path):
    atom = _base_atom()
    r = qualify_atom(atom, tmp_path / "missing")
    assert not r.template_candidate
    assert not r.structure_healthy
    assert "no source_bundle" in r.reasons


def test_bundle_complete_but_service_empty_not_candidate(tmp_path):
    atom_dir = tmp_path / "CVE-X"
    atom_dir.mkdir()
    (atom_dir / "docker-compose.yml").write_text("x")
    (atom_dir / "README.md").write_text("x")
    atom = _base_atom(
        source_bundle={
            "compose_file": "docker-compose.yml",
            "readme_file": "README.md",
            "dockerfiles": [],
            "init_files": [],
            "poc_materials": [],
            "hashes": {},
        },
        exploit_access={
            "attack_vector": "network",
            "privileges_required": "none",
            "required_service": {},
        },
    )
    r = qualify_atom(atom, atom_dir)
    assert not r.template_candidate
    assert any("empty required_service" in x for x in r.reasons)


def test_local_vector_atom_with_empty_service_allowed(tmp_path):
    atom_dir = tmp_path / "CVE-LPE"
    atom_dir.mkdir()
    (atom_dir / "Dockerfile").write_text("FROM alpine\n")
    (atom_dir / "README.md").write_text("x")
    atom = _base_atom(
        cve_id="CVE-LPE-0001",
        source_bundle={
            "compose_file": None,
            "readme_file": "README.md",
            "dockerfiles": ["Dockerfile"],
            "init_files": [],
            "poc_materials": [],
            "hashes": {},
        },
        exploit_access={
            "attack_vector": "local",
            "privileges_required": "low",
            "required_service": {},
        },
    )
    r = qualify_atom(atom, atom_dir)
    assert r.checks["service"]["ok"]


def test_resolvable_evidence_ref_accepted(tmp_path):
    """An evidence_ref pointing at the real native evidence record is the
    post-batch-5 contract: opaque labels are gone, refs are resolvable."""
    atom_dir = tmp_path / "CVE-RES"
    atom_dir.mkdir()
    (atom_dir / "docker-compose.yml").write_text("x")
    (atom_dir / "README.md").write_text("x")
    atom = _base_atom(
        cve_id="CVE-RES",
        source_bundle={
            "compose_file": "docker-compose.yml",
            "readme_file": "README.md",
            "dockerfiles": [],
            "init_files": [],
            "poc_materials": [],
            "hashes": {},
        },
        capability_grants=[{
            "type": "execute_command",
            "principal": "root",
            "evidence_level": "verified",
            "evidence_ref": "verification.native_verification.evidence",
        }],
        verification={
            "native_verification": {"success": True, "mode": "native",
                                     "evidence": ["id output = uid=0(root)"]},
            "orchestrated_verification": {"success": True, "mode": "orchestrated"},
            "environment_ready": True,
        },
    )
    r = qualify_atom(atom, atom_dir)
    assert r.template_anchor, r.reasons


def test_no_verified_capability_not_candidate(tmp_path):
    atom_dir = tmp_path / "CVE-NOCAP"
    atom_dir.mkdir()
    (atom_dir / "docker-compose.yml").write_text("x")
    (atom_dir / "README.md").write_text("x")
    atom = _base_atom(
        cve_id="CVE-NOCAP",
        source_bundle={
            "compose_file": "docker-compose.yml",
            "readme_file": "README.md",
            "dockerfiles": [],
            "init_files": [],
            "poc_materials": [],
            "hashes": {},
        },
        capability_grants=[
            {"type": "execute_command", "evidence_level": "inferred"}
        ],
    )
    r = qualify_atom(atom, atom_dir)
    assert not r.template_candidate
    assert any("no verified capability" in x for x in r.reasons)


def test_guide_alignment_mismatch_does_not_affect_candidate(tmp_path):
    """Guide principal differs from atom, but this is advisory, not a gate."""
    atom_dir = tmp_path / "CVE-MISMATCH"
    atom_dir.mkdir()
    (atom_dir / "docker-compose.yml").write_text("x")
    (atom_dir / "README.md").write_text("x")
    guide_yaml = {
        "version": 2,
        "cve_id": "CVE-MISMATCH",
        "summary": "ok",
        "target": {"protocol": "http", "port": 80, "service_role": "web_application"},
        "steps": [{
            "id": "exploit", "action": "trigger", "procedure": "run",
            "depends_on": [], "success_signal": "ok",
            "execution": {"scope": "actor", "tools": [], "materials": [],
                          "external_download": False, "fallback_ids": []},
        }],
        "post_exploit": {
            "principal": "someone-else",
            "capabilities": ["read_file"],
            "command_channel": {"type": "none", "reusable": False,
                                "established_by": [], "invocation_hint": ""},
        },
    }
    (atom_dir / "exploit_guide.yaml").write_text(yaml.safe_dump(guide_yaml))
    atom = _base_atom(
        cve_id="CVE-MISMATCH",
        source_bundle={
            "compose_file": "docker-compose.yml",
            "readme_file": "README.md",
            "dockerfiles": [],
            "init_files": [],
            "poc_materials": [],
            "hashes": {},
        },
        exploit_guide={
            "path": "exploit_guide.yaml",
            "format_version": 2,
            "provenance": "native_agent",
            "status": "ready",
            "evidence_refs": [],
        },
    )
    r = qualify_atom(atom, atom_dir)
    # guide integrity is ok despite principal/capability mismatch
    assert r.checks["guide"]["ok"] is True
    assert r.template_candidate


def test_guide_integrity_failure_blocks_candidate(tmp_path):
    atom_dir = tmp_path / "CVE-BADGUIDE"
    atom_dir.mkdir()
    (atom_dir / "docker-compose.yml").write_text("x")
    (atom_dir / "README.md").write_text("x")
    # guide referencing a material that does not exist
    guide_yaml = {
        "version": 2,
        "cve_id": "CVE-BADGUIDE",
        "summary": "ok",
        "target": {"protocol": "http", "port": 80, "service_role": "web_application"},
        "steps": [{
            "id": "exploit", "action": "trigger", "procedure": "run",
            "depends_on": [], "success_signal": "ok",
            "execution": {"scope": "actor", "tools": [], "materials": [],
                          "external_download": False, "fallback_ids": []},
        }],
        "requirements": {"materials": ["source_bundle/missing.py"], "tools": [],
                          "authentication": "none", "callback": "none"},
        "post_exploit": {"principal": "root", "capabilities": [],
                         "command_channel": {"type": "none", "reusable": False,
                                             "established_by": [], "invocation_hint": ""}},
    }
    (atom_dir / "exploit_guide.yaml").write_text(yaml.safe_dump(guide_yaml))
    atom = _base_atom(
        cve_id="CVE-BADGUIDE",
        source_bundle={
            "compose_file": "docker-compose.yml",
            "readme_file": "README.md",
            "dockerfiles": [],
            "init_files": [],
            "poc_materials": [],
            "hashes": {},
        },
        exploit_guide={
            "path": "exploit_guide.yaml",
            "format_version": 2,
            "provenance": "native_agent",
            "status": "ready",
            "evidence_refs": [],
        },
    )
    r = qualify_atom(atom, atom_dir)
    assert not r.template_candidate
    assert r.checks["guide"]["ok"] is False


def test_environment_false_blocks_anchor_not_candidate(tmp_path):
    atom_dir = tmp_path / "CVE-ENVFALSE"
    atom_dir.mkdir()
    (atom_dir / "docker-compose.yml").write_text("x")
    (atom_dir / "README.md").write_text("x")
    atom = _base_atom(
        cve_id="CVE-ENVFALSE",
        source_bundle={
            "compose_file": "docker-compose.yml",
            "readme_file": "README.md",
            "dockerfiles": [],
            "init_files": [],
            "poc_materials": [],
            "hashes": {},
        },
        verification={
            "native_verification": {"success": True, "mode": "native"},
            "orchestrated_verification": {"success": False, "mode": "orchestrated"},
            "environment_ready": False,
        },
    )
    r = qualify_atom(atom, atom_dir)
    assert r.template_candidate
    assert not r.template_anchor
    assert any("environment_ready=false" in x for x in r.reasons)


def test_environment_none_legacy_blocks_anchor_not_candidate(tmp_path):
    """Legacy atoms without environment_ready stay candidate (not excluded),
    which preserves existing Range-test anchors."""
    atom_dir = tmp_path / "CVE-LEGACY"
    atom_dir.mkdir()
    (atom_dir / "docker-compose.yml").write_text("x")
    (atom_dir / "README.md").write_text("x")
    atom = _base_atom(
        cve_id="CVE-LEGACY",
        source_bundle={
            "compose_file": "docker-compose.yml",
            "readme_file": "README.md",
            "dockerfiles": [],
            "init_files": [],
            "poc_materials": [],
            "hashes": {},
        },
        verification={
            "native_verification": {"success": True, "mode": "native"},
            "orchestrated_verification": {"success": True, "mode": "orchestrated"},
            # no environment_ready key
        },
    )
    r = qualify_atom(atom, atom_dir)
    assert r.template_candidate
    assert not r.template_anchor


def test_poc_material_basename_collision_blocks_candidate(tmp_path):
    atom_dir = tmp_path / "CVE-COLLIDE"
    atom_dir.mkdir()
    sub1 = atom_dir / "source_bundle" / "a"
    sub2 = atom_dir / "source_bundle" / "b"
    sub1.mkdir(parents=True)
    sub2.mkdir(parents=True)
    (sub1 / "poc.py").write_text("x")
    (sub2 / "poc.py").write_text("x")
    (atom_dir / "docker-compose.yml").write_text("x")
    (atom_dir / "README.md").write_text("x")
    atom = _base_atom(
        cve_id="CVE-COLLIDE",
        source_bundle={
            "compose_file": "docker-compose.yml",
            "readme_file": "README.md",
            "dockerfiles": [],
            "init_files": [],
            "poc_materials": ["source_bundle/a/poc.py", "source_bundle/b/poc.py"],
            "hashes": {},
        },
    )
    r = qualify_atom(atom, atom_dir)
    assert not r.template_candidate
    assert any("basename collision" in x for x in r.reasons)


def test_qualify_atom_dir(tmp_path):
    atom_dir = tmp_path / "CVE-DIR"
    atom_dir.mkdir()
    (atom_dir / "docker-compose.yml").write_text("x")
    (atom_dir / "README.md").write_text("x")
    atom = _base_atom(
        cve_id="CVE-DIR",
        source_bundle={
            "compose_file": "docker-compose.yml",
            "readme_file": "README.md",
            "dockerfiles": [],
            "init_files": [],
            "poc_materials": [],
            "hashes": {},
        },
    )
    (atom_dir / "atom.yaml").write_text(yaml.safe_dump(
        atom.model_dump(exclude_none=True, mode="json")
    ))
    r = qualify_atom_dir(atom_dir)
    assert r.template_anchor