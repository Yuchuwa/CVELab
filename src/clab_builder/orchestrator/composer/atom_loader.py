"""Atom Loader — 从 data/atoms/ 加载 v2 AtomConfig"""

import yaml
from pathlib import Path
from typing import Optional

from clab_builder.shared.models.atom import AtomConfig


class AtomLoader:
    """从 data/atoms/ 目录加载已验证的 atom"""

    def __init__(self, atoms_dir: str = "data/atoms"):
        self.atoms_dir = Path(atoms_dir)

    def load(self, cve_id: str) -> AtomConfig:
        """加载指定 CVE 的 atom

        Args:
            cve_id: CVE ID 或目录名 (e.g. "CVE-2014-6271")

        Returns:
            AtomConfig 实例

        Raises:
            FileNotFoundError: atom 目录或 atom.yaml 不存在
            ValueError: atom.yaml 格式错误
        """
        atom_dir = self.atoms_dir / cve_id
        if not atom_dir.is_dir():
            raise FileNotFoundError(f"Atom not found: {atom_dir}")

        atom_yaml = atom_dir / "atom.yaml"
        if not atom_yaml.exists():
            raise FileNotFoundError(f"atom.yaml not found in {atom_dir}")

        data = yaml.safe_load(atom_yaml.read_text())
        try:
            return AtomConfig(**data)
        except Exception as e:
            raise ValueError(f"Invalid atom.yaml in {atom_dir}: {e}") from e

    def load_all_verified(self, single_service_only: bool = True) -> list[AtomConfig]:
        """加载所有已验证的 atom

        Args:
            single_service_only: 仅返回单服务 atom (len(services) <= 1)

        Returns:
            AtomConfig 列表
        """
        atoms = []
        if not self.atoms_dir.exists():
            return atoms

        for d in sorted(self.atoms_dir.iterdir()):
            if not d.is_dir():
                continue
            atom_yaml = d / "atom.yaml"
            if not atom_yaml.exists():
                continue

            data = yaml.safe_load(atom_yaml.read_text())
            try:
                atom = AtomConfig(**data)
            except Exception:
                continue

            if not atom.verified:
                continue
            if single_service_only and len(atom.services) > 1:
                continue

            atoms.append(atom)

        return atoms

    def list_available(self) -> list[str]:
        """列出所有有 atom.yaml 的目录名"""
        available = []
        if not self.atoms_dir.exists():
            return available
        for d in sorted(self.atoms_dir.iterdir()):
            if d.is_dir() and (d / "atom.yaml").exists():
                available.append(d.name)
        return available
