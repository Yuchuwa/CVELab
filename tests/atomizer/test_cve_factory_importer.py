"""Tests for the CVE-Factory atom importer (batch 9)."""
from pathlib import Path
from textwrap import dedent

import yaml

from clab_builder.atomizer.cve_factory_verifier import (
    CVEFactoryVerificationResult, TestSuiteResult,
)
from clab_builder.atomizer.cve_factory_importer import import_cve_factory_atom
from clab_builder.shared.atom_qualification import qualify_atom_dir


def _task_dir(tmp_path, observer="network"):
    d = tmp_path / "CVE-2021-TEST"
    d.mkdir()
    (d / "docker-compose.yml").write_text(
        "services:\n  client:\n    image: cve-cve-2021-test:vuln\n    expose: ['8080']\n"
    )
    (d / "Dockerfile").write_text("FROM python:3.10\nEXPOSE 8080\n")
    (d / "README.md").write_text("# test")
    (d / "task.yaml").write_text("cve_id: CVE-2021-TEST\n")
    tests = d / "tests"
    tests.mkdir()
    if observer == "network":
        (tests / "test_vuln.py").write_text(dedent("""
            import requests
            BASE_URL = 'http://localhost:8080'
            def test_lfi():
                r = requests.get(BASE_URL + '/?f=../../etc/passwd')
                assert 'root:' not in r.text, 'leaked /etc/passwd'
        """))
    else:
        (tests / "test_vuln.py").write_text(dedent("""
            import os, requests
            def test_rce():
                requests.get('http://localhost:8080/x', params={'c': 'touch /tmp/m'})
                assert not os.path.exists('/tmp/m'), 'command execution'
        """))
    (tests / "test_func.py").write_text("def test_ok(): assert True\n")
    return d


def _result(cve_id="CVE-2021-TEST"):
    func = TestSuiteResult("test_func.py", collected=1, passed=1, failed=0,
                           errors=0, skipped=0)
    vuln = TestSuiteResult("test_vuln.py", collected=1, passed=0, failed=1,
                           errors=0, skipped=0)
    return CVEFactoryVerificationResult(
        cve_id=cve_id, verified=True, build_ok=True, service_ready=True,
        func=func, vuln=vuln, observer_scope="network",
        pytest_location="cve_container", source_hash="sha:s",
        test_hash="sha:t", timestamp="2026-07-17T00:00:00",
    )


def test_import_produces_standard_atom(tmp_path):
    task = _task_dir(tmp_path)
    atoms = tmp_path / "atoms"
    config = import_cve_factory_atom(task, _result(), atoms)
    assert config.verified is True
    assert config.version == 3
    assert (atoms / "CVE-2021-TEST" / "atom.yaml").is_file()
    assert (atoms / "CVE-2021-TEST" / "source_bundle").is_dir()
    assert (atoms / "CVE-2021-TEST" / "exploit_guide.yaml").is_file()


def test_import_inferred_caps_are_not_verified(tmp_path):
    """Three-state: inferred capabilities stay INFERRED, never VERIFIED."""
    task = _task_dir(tmp_path)
    atoms = tmp_path / "atoms"
    config = import_cve_factory_atom(task, _result(), atoms)
    # read_file inferred from /etc/passwd assertion, but evidence_level inferred
    grants = config.capability_grants
    assert all(g.evidence_level.value == "inferred" for g in grants)
    assert config.verified_capability_types == set()


def test_import_guide_is_review_required(tmp_path):
    """A static recipe does not prove flag recovery; guide stays review_required."""
    task = _task_dir(tmp_path)
    atoms = tmp_path / "atoms"
    config = import_cve_factory_atom(task, _result(), atoms)
    assert config.exploit_guide is not None
    assert config.exploit_guide.status == "review_required"
    assert config.exploit_guide.provenance == "cve_factory_poc"


def test_import_service_contract_from_expose(tmp_path):
    task = _task_dir(tmp_path)
    atoms = tmp_path / "atoms"
    config = import_cve_factory_atom(task, _result(), atoms)
    assert config.exploit_access.required_service.get("port") == 8080
    assert config.ports == [8080]


def test_import_marker_atom_not_template_candidate(tmp_path):
    """A marker-based PoC atom is verified but not template_candidate (no
    verified capability, guide review_required, environment_ready=false)."""
    task = _task_dir(tmp_path, observer="target_local")
    atoms = tmp_path / "atoms"
    config = import_cve_factory_atom(task, _result(), atoms)
    assert config.verified is True
    r = qualify_atom_dir(atoms / "CVE-2021-TEST")
    # structure healthy + verified, but no verified capability grants and
    # environment_ready=false -> not candidate
    assert not r.template_candidate
    assert r.status in ("review_required", "excluded")


def test_import_native_verification_has_provenance(tmp_path):
    task = _task_dir(tmp_path)
    atoms = tmp_path / "atoms"
    config = import_cve_factory_atom(task, _result(), atoms)
    nv = config.verification["native_verification"]
    assert nv["provenance"] == "cve_factory_poc"
    assert nv["test_results"]["test_func"]["passed"] == 1
    assert nv["test_results"]["test_vuln"]["failed"] == 1
    assert nv["three_state"]["vulnerability_observed"] is True
    assert nv["three_state"]["range_flag_recovery_verified"] is False


def test_import_source_bundle_test_vuln_is_assisted(tmp_path):
    task = _task_dir(tmp_path)
    atoms = tmp_path / "atoms"
    import_cve_factory_atom(task, _result(), atoms)
    from clab_builder.shared.models.atom import AtomConfig, MaterialRole
    cfg = AtomConfig(**yaml.safe_load(
        (atoms / "CVE-2021-TEST" / "atom.yaml").read_text()
    ))
    md = cfg.source_bundle.material_metadata
    tv = "source_bundle/tests/test_vuln.py"
    assert tv in md
    assert md[tv].role == MaterialRole.EXPLOIT_REFERENCE