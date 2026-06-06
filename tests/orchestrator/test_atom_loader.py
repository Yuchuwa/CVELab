"""Tests for atom_loader — loading v2 AtomConfig from data/atoms/"""

import pytest
import yaml
from pathlib import Path

from clab_builder.shared.models.atom import AtomConfig
from clab_builder.orchestrator.composer.atom_loader import AtomLoader


class TestAtomLoaderLoad:
    @pytest.fixture
    def loader(self):
        return AtomLoader(atoms_dir="data/atoms")

    def test_load_known_atom(self, loader):
        atom = loader.load("CVE-2014-6271")
        assert atom.cve_id == "CVE-2014-6271"
        assert atom.version == 2
        assert atom.vuln_category.value == "RCE"
        assert atom.verified is True

    def test_load_nonexistent(self, loader):
        with pytest.raises(FileNotFoundError, match="Atom not found"):
            loader.load("CVE-9999-9999")

    def test_load_has_required_fields(self, loader):
        atom = loader.load("CVE-2014-6271")
        assert atom.docker_image
        assert atom.ports
        assert atom.primary_mitre_phase
        assert atom.service_role
        assert atom.exploit_complexity
        assert atom.attack_method


class TestAtomLoaderAllVerified:
    @pytest.fixture
    def loader(self):
        return AtomLoader(atoms_dir="data/atoms")

    def test_load_all_verified(self, loader):
        atoms = loader.load_all_verified()
        assert len(atoms) >= 10  # we have 18+ verified atoms
        for atom in atoms:
            assert atom.verified is True
            assert atom.version == 2

    def test_single_service_filter(self, loader):
        atoms = loader.load_all_verified(single_service_only=True)
        for atom in atoms:
            assert len(atom.services) <= 1

    def test_multi_service_excluded_by_default(self, loader):
        """单服务模式下，多服务 atom 被排除"""
        all_atoms = loader.load_all_verified(single_service_only=False)
        single_atoms = loader.load_all_verified(single_service_only=True)
        assert len(all_atoms) >= len(single_atoms)


class TestAtomLoaderList:
    @pytest.fixture
    def loader(self):
        return AtomLoader(atoms_dir="data/atoms")

    def test_list_available(self, loader):
        names = loader.list_available()
        assert "CVE-2014-6271" in names
        assert len(names) >= 15


class TestAtomLoaderRoundtrip:
    def test_create_and_load(self, tmp_path):
        """创建 atom 目录，然后加载验证"""
        atom_dir = tmp_path / "CVE-TEST-0001"
        atom_dir.mkdir()

        atom_data = {
            "version": 2,
            "cve_id": "CVE-TEST-0001",
            "category": "test",
            "docker_image": "test:latest",
            "ports": [80],
            "services": [{"name": "web", "image": "test:latest", "is_target": True}],
            "vuln_category": "RCE",
            "primary_mitre_phase": "initial_access",
            "service_role": "web_application",
            "exploit_complexity": "simple",
            "attack_method": "single_request",
            "verified": True,
        }
        (atom_dir / "atom.yaml").write_text(
            yaml.dump(atom_data, default_flow_style=False)
        )

        loader = AtomLoader(atoms_dir=str(tmp_path))
        atom = loader.load("CVE-TEST-0001")
        assert atom.cve_id == "CVE-TEST-0001"
        assert atom.vuln_category.value == "RCE"

    def test_load_all_includes_verified(self, tmp_path):
        """load_all_verified 包含已验证的 atom"""
        for i in range(3):
            d = tmp_path / f"CVE-TEST-{i:04d}"
            d.mkdir()
            atom_data = {
                "version": 2,
                "cve_id": f"CVE-TEST-{i:04d}",
                "category": "test",
                "docker_image": "test:latest",
                "ports": [80],
                "services": [{"name": "web", "image": "test:latest"}],
                "vuln_category": "RCE",
                "primary_mitre_phase": "initial_access",
                "service_role": "web_application",
                "exploit_complexity": "simple",
                "attack_method": "single_request",
                "verified": True,
            }
            (d / "atom.yaml").write_text(yaml.dump(atom_data, default_flow_style=False))

        # Add an unverified atom
        d = tmp_path / "CVE-UNVERIFIED"
        d.mkdir()
        atom_data = {
            "version": 2,
            "cve_id": "CVE-UNVERIFIED",
            "category": "test",
            "docker_image": "test:latest",
            "vuln_category": "LFI",
            "primary_mitre_phase": "initial_access",
            "service_role": "web_application",
            "exploit_complexity": "simple",
            "attack_method": "single_request",
            "verified": False,
        }
        (d / "atom.yaml").write_text(yaml.dump(atom_data, default_flow_style=False))

        loader = AtomLoader(atoms_dir=str(tmp_path))
        atoms = loader.load_all_verified()
        assert len(atoms) == 3
        assert all(a.verified for a in atoms)
