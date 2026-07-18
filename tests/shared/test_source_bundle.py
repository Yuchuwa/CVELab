"""Tests for shared source-bundle capture and material classification (batch 2).

Covers:
  - capture_source_bundle copies the source tree and produces a manifest
  - vulhub source: poc.png / id_rsa are exploit_material/always
  - cve_factory source: test_vuln.py is exploit_reference/assisted,
    test_func.py is verification/private, solution.sh is solution/private
  - runtime files (compose/Dockerfile/README/init) are NOT poc_materials
  - scan_source_bundle is backward compatible (loads old bundles)
  - material_metadata roles/visibilities are recorded
"""
from pathlib import Path

import yaml

from clab_builder.shared.source_bundle import (
    capture_source_bundle,
    scan_source_bundle,
    classify_material,
)
from clab_builder.shared.models.atom import (
    MaterialRole,
    MaterialVisibility,
)


def _write_vulhub_src(src: Path):
    src.mkdir(parents=True)
    (src / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: vulhub/test:latest\n    ports:\n      - '8080:80'\n"
    )
    (src / "Dockerfile").write_text("FROM php:7.0\nCOPY www /var/www/html\n")
    (src / "README.md").write_text("# Test\n![screenshot](1.png)\n")
    (src / "www").mkdir()
    (src / "www" / "index.php").write_text("<?php system($_GET['cmd']); ?>")
    (src / "poc.png").write_bytes(b"\x89PNG\r\n")
    (src / "id_rsa").write_text("PRIVATE KEY")


def _write_cve_factory_src(src: Path):
    src.mkdir(parents=True)
    (src / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: cve-test:vuln\n"
    )
    (src / "Dockerfile").write_text("FROM python:3.10\nCMD python app.py\n")
    (src / "README.md").write_text("# CVE-Factory task")
    (src / "task.yaml").write_text("cve_id: CVE-X\ncategory: web\n")
    (src / "run-tests.sh").write_text("pytest tests/\n")
    (src / "solution.sh").write_text("#!/bin/sh\n# full writeup")
    (src / "tests").mkdir()
    (src / "tests" / "test_vuln.py").write_text("def test_vuln(): assert False\n")
    (src / "tests" / "test_func.py").write_text("def test_func(): assert True\n")
    (src / "task-deps").mkdir()
    (src / "task-deps" / "entrypoint.sh").write_text("python app.py\n")


def test_capture_vulhub_source_classifies_materials(tmp_path):
    src = tmp_path / "src"
    _write_vulhub_src(src)
    atom_dir = tmp_path / "atom" / "CVE-TEST"
    atom_dir.mkdir(parents=True)

    bundle = capture_source_bundle(src, atom_dir, source_kind="vulhub")
    assert bundle is not None
    assert bundle.compose_file == "source_bundle/docker-compose.yml"
    assert bundle.readme_file == "source_bundle/README.md"
    assert "source_bundle/Dockerfile" in bundle.dockerfiles
    # poc.png and id_rsa are exploit materials; www/index.php too
    assert "source_bundle/poc.png" in bundle.poc_materials
    assert "source_bundle/id_rsa" in bundle.poc_materials
    assert "source_bundle/www/index.php" in bundle.poc_materials
    # 1.png is README-referenced screenshot -> NOT a poc material
    assert "source_bundle/1.png" not in bundle.poc_materials
    # hashes cover all captured files
    assert len(bundle.hashes) == len(bundle.poc_materials) + len(bundle.dockerfiles) + 2
    # metadata roles
    md = bundle.material_metadata
    assert md["source_bundle/docker-compose.yml"].role == MaterialRole.RUNTIME
    assert md["source_bundle/poc.png"].role == MaterialRole.EXPLOIT_MATERIAL
    assert md["source_bundle/poc.png"].visibility == MaterialVisibility.ALWAYS
    assert md["source_bundle/README.md"].visibility == MaterialVisibility.PRIVATE


def test_capture_cve_factory_source_test_vuln_is_assisted(tmp_path):
    src = tmp_path / "src"
    _write_cve_factory_src(src)
    atom_dir = tmp_path / "atom" / "CVE-FACTORY"
    atom_dir.mkdir(parents=True)

    bundle = capture_source_bundle(src, atom_dir, source_kind="cve_factory")
    assert bundle is not None
    md = bundle.material_metadata
    # test_vuln.py is an exploit reference, only visible under assisted profile
    assert md["source_bundle/tests/test_vuln.py"].role == MaterialRole.EXPLOIT_REFERENCE
    assert md["source_bundle/tests/test_vuln.py"].visibility == MaterialVisibility.ASSISTED
    # test_func.py is verification evidence, never agent-visible
    assert md["source_bundle/tests/test_func.py"].role == MaterialRole.VERIFICATION
    assert md["source_bundle/tests/test_func.py"].visibility == MaterialVisibility.PRIVATE
    # solution.sh is a full writeup, private
    assert md["source_bundle/solution.sh"].role == MaterialRole.SOLUTION
    assert md["source_bundle/solution.sh"].visibility == MaterialVisibility.PRIVATE
    # task.yaml / run-tests.sh are verification scaffolding
    assert md["source_bundle/task.yaml"].role == MaterialRole.VERIFICATION
    # test_vuln.py IS a poc_material (so Range can mount it under assisted profile)
    assert "source_bundle/tests/test_vuln.py" in bundle.poc_materials
    # test_func.py is also a poc_material by bucketing; its visibility gates it
    assert "source_bundle/tests/test_func.py" in bundle.poc_materials


def test_capture_creates_bundle_dir(tmp_path):
    src = tmp_path / "src"
    _write_vulhub_src(src)
    atom_dir = tmp_path / "atom" / "CVE-T"
    atom_dir.mkdir(parents=True)
    capture_source_bundle(src, atom_dir, source_kind="vulhub")
    assert (atom_dir / "source_bundle").is_dir()
    assert (atom_dir / "source_bundle" / "docker-compose.yml").is_file()


def test_capture_replaces_stale_directory_with_source_file(tmp_path):
    """A fresh capture must not retain a legacy directory where source has a file."""
    src = tmp_path / "src"
    _write_vulhub_src(src)
    (src / "index.php").write_text("<?php echo 'source'; ?>")
    atom_dir = tmp_path / "atom" / "CVE-T"
    stale = atom_dir / "source_bundle" / "index.php"
    stale.mkdir(parents=True)
    (stale / "obsolete").write_text("old")

    capture_source_bundle(src, atom_dir, source_kind="vulhub")

    materialized = atom_dir / "source_bundle" / "index.php"
    assert materialized.is_file()
    assert materialized.read_text() == "<?php echo 'source'; ?>"


def test_scan_is_backward_compatible_no_metadata(tmp_path):
    """An old bundle dir without material_metadata still scans into a valid
    SourceBundle (the field defaults to empty)."""
    atom_dir = tmp_path / "CVE-OLD"
    bdir = atom_dir / "source_bundle"
    bdir.mkdir(parents=True)
    (bdir / "docker-compose.yml").write_text("x")
    (bdir / "poc.py").write_text("y")
    bundle = scan_source_bundle(atom_dir, "vulhub")
    assert bundle.compose_file == "source_bundle/docker-compose.yml"
    assert "source_bundle/poc.py" in bundle.poc_materials
    # metadata is populated by the scanner even for old bundles
    assert len(bundle.material_metadata) >= 2


def test_classify_material_explicit():
    assert classify_material("x/test_vuln.py", "test_vuln.py", "cve_factory") == (
        MaterialRole.EXPLOIT_REFERENCE, MaterialVisibility.ASSISTED,
    )
    assert classify_material("x/test_func.py", "test_func.py", "cve_factory") == (
        MaterialRole.VERIFICATION, MaterialVisibility.PRIVATE,
    )
    assert classify_material("x/poc.png", "poc.png", "vulhub") == (
        MaterialRole.EXPLOIT_MATERIAL, MaterialVisibility.ALWAYS,
    )
    assert classify_material("x/docker-compose.yml", "docker-compose.yml", "vulhub") == (
        MaterialRole.RUNTIME, MaterialVisibility.PRIVATE,
    )
    # vulhub source does NOT treat test_vuln.py as exploit_reference
    assert classify_material("x/test_vuln.py", "test_vuln.py", "vulhub") == (
        MaterialRole.EXPLOIT_MATERIAL, MaterialVisibility.ALWAYS,
    )
