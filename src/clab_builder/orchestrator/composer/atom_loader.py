"""Atom Loader — loads Range-admitted AtomConfigs from the materialized index."""

import json
import yaml
from pathlib import Path

from clab_builder.shared.models.atom import AtomConfig


class AtomLoader:
    """从 data/atoms/ 目录加载已验证的 atom"""

    def __init__(self, atoms_dir: str = "data/atoms", dataset_path: str | None = None):
        self.atoms_dir = Path(atoms_dir)
        self.dataset_path = (
            Path(dataset_path)
            if dataset_path is not None
            else self.atoms_dir.parent / "atom_scale" / "dataset.jsonl"
        )

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
        """Load Range-admitted atoms, with a legacy directory fallback.

        Args:
            single_service_only: 仅返回单服务 atom (len(services) <= 1)

        Returns:
            AtomConfig 列表
        """
        indexed = self._load_admitted_index(single_service_only)
        if indexed is not None:
            return indexed

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

    def _load_admitted_index(self, single_service_only: bool) -> list[AtomConfig] | None:
        """Load only rows that passed the shared Range qualification gate.

        ``None`` means a legacy dataset is absent or has not yet been upgraded,
        so existing projects remain usable until ``atom scale --discover-only``
        backfills the materialized index.  Once a v1 admission row exists, the
        index is authoritative even when it contains zero admitted atoms.
        """
        if not self.dataset_path.is_file():
            return None
        rows = []
        has_admission_schema = False
        for line in self.dataset_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if int(row.get("admission_schema_version", 0) or 0) >= 1:
                has_admission_schema = True
                rows.append(row)
        if not has_admission_schema:
            return None

        atoms: list[AtomConfig] = []
        for row in sorted(rows, key=lambda item: str(item.get("cve_id", ""))):
            if not row.get("range_admitted"):
                continue
            atom_path = Path(str(row.get("atom_path") or self.atoms_dir / row.get("cve_id", "")))
            if not atom_path.is_absolute() and not atom_path.exists():
                atom_path = self.atoms_dir / str(row.get("cve_id", ""))
            atom_yaml = atom_path / "atom.yaml"
            if not atom_yaml.is_file():
                continue
            try:
                atom = AtomConfig.model_validate(yaml.safe_load(atom_yaml.read_text()) or {})
            except Exception:
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
