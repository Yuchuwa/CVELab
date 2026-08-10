"""Regression tests for generic legacy Atom contract backfill."""

import importlib.util
import shutil
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "backfill_atom_contracts.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("atom_contract_backfill", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_backfill_uses_existing_runtime_and_compose_evidence(tmp_path):
    module = _load_module()
    source = ROOT / "data" / "atoms" / "CVE-2024-27348"
    atom_dir = tmp_path / source.name
    shutil.copytree(source, atom_dir)

    atom_path = atom_dir / "atom.yaml"
    raw = yaml.safe_load(atom_path.read_text())
    raw["runtime_spec"]["runtime_build"].pop("context")
    raw["runtime_spec"]["runtime_build"].pop("dockerfile")
    raw["runtime_spec"]["runtime_build"].pop("install_script")
    raw["exploit_access"]["required_service"] = {}
    atom_path.write_text(yaml.safe_dump(raw, sort_keys=False, allow_unicode=True))

    changes = module.backfill_atom(atom_dir, write=True)
    assert changes == [
        "runtime_spec.runtime_build.context",
        "runtime_spec.runtime_build.dockerfile",
        "runtime_spec.runtime_build.install_script",
        "exploit_access.required_service",
    ]
    repaired = yaml.safe_load(atom_path.read_text())
    manifest = yaml.safe_load(
        (atom_dir / "runtime" / "manifest.yaml").read_text()
    )
    assert repaired["runtime_spec"]["runtime_build"]["generated_hash"] == manifest[
        "generated_hash"
    ]
    assert repaired["exploit_access"]["required_service"] == {
        "protocol": "http",
        "port": 8080,
    }
    assert module.backfill_atom(atom_dir, write=False) == []


def test_backfill_adds_metadata_for_declared_poc_material(tmp_path):
    module = _load_module()
    source = ROOT / "data" / "atoms" / "CVE-2018-16509"
    atom_dir = tmp_path / source.name
    shutil.copytree(source, atom_dir, ignore=shutil.ignore_patterns(".workspace"))
    atom_path = atom_dir / "atom.yaml"
    raw = yaml.safe_load(atom_path.read_text())
    raw["source_bundle"].pop("material_metadata", None)
    atom_path.write_text(yaml.safe_dump(raw, sort_keys=False, allow_unicode=True))

    changes = module.backfill_atom(atom_dir, write=True)

    assert "source_bundle.material_metadata.source_bundle/poc.png" in changes
    repaired = yaml.safe_load((atom_dir / "atom.yaml").read_text())
    assert repaired["source_bundle"]["material_metadata"]["source_bundle/poc.png"] == {
        "role": "exploit_material",
        "visibility": "always",
    }
