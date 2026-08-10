#!/usr/bin/env python3
"""Backfill missing v3 Atom contract metadata from existing local artifacts.

This migration only copies facts already evidenced by an Atom's runtime
manifest, source Compose file and recorded runtime verification. It never
changes native/orchestrated verification truth or lifecycle fields.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from clab_builder.atomizer.output.vulhub_converter import VulhubParser
from clab_builder.shared.models.atom import AtomConfig
from clab_builder.shared.service_resolver import resolve_service_contract
from clab_builder.shared.source_bundle import scan_source_bundle


def _load_yaml(path: Path) -> dict:
    value = yaml.safe_load(path.read_text()) or {}
    if not isinstance(value, dict):
        raise ValueError(f"expected mapping in {path}")
    return value


def _backfill_runtime_metadata(raw: dict, atom_dir: Path) -> list[str]:
    runtime = raw.get("runtime_spec")
    build = runtime.get("runtime_build") if isinstance(runtime, dict) else None
    manifest_path = atom_dir / "runtime" / "manifest.yaml"
    if not isinstance(build, dict) or not manifest_path.is_file():
        return []

    manifest = _load_yaml(manifest_path)
    generated_hash = str(build.get("generated_hash") or "")
    if not generated_hash or manifest.get("generated_hash") != generated_hash:
        return []

    changes: list[str] = []
    standard_paths = {
        "context": "runtime",
        "dockerfile": "runtime/Dockerfile",
        "install_script": "runtime/install-tools.sh",
    }
    for field, relative in standard_paths.items():
        if build.get(field) or not (atom_dir / relative).exists():
            continue
        build[field] = relative
        changes.append(f"runtime_spec.runtime_build.{field}")

    recorded = (
        (raw.get("verification") or {}).get("runtime_verification") or {}
    ).get("base_image_digest")
    if not build.get("base_image_digest") and recorded:
        build["base_image_digest"] = str(recorded)
        changes.append("runtime_spec.runtime_build.base_image_digest")
    return changes


def _backfill_service_contract(raw: dict, atom_dir: Path) -> list[str]:
    access = raw.get("exploit_access")
    if not isinstance(access, dict) or access.get("attack_vector", "network") != "network":
        return []
    current = access.get("required_service")
    if not isinstance(current, dict):
        current = {}
    if current.get("protocol") and current.get("port") is not None:
        return []

    bundle = raw.get("source_bundle") or {}
    compose = bundle.get("compose_file") if isinstance(bundle, dict) else None
    compose_path = atom_dir / str(compose or "")
    if not compose_path.is_file():
        return []
    environment = VulhubParser().parse(str(compose_path.parent))
    resolved = resolve_service_contract(environment, compose_path.parent)
    if resolved is None:
        return []

    protocol, port = resolved
    updated = dict(current)
    updated.setdefault("protocol", protocol)
    updated.setdefault("port", port)
    if updated == current:
        return []
    access["required_service"] = updated
    return ["exploit_access.required_service"]


def _source_kind(raw: dict) -> str:
    source = str(raw.get("source") or "").lower()
    category = str(raw.get("category") or "").lower()
    return (
        "cve_factory"
        if "cve_factory" in source or "cve_factory" in category
        else "vulhub"
    )


def _backfill_material_metadata(
    raw: dict,
    atom_dir: Path,
    *,
    refresh: bool = False,
) -> list[str]:
    bundle = raw.get("source_bundle")
    if not isinstance(bundle, dict) or not bundle.get("poc_materials"):
        return []
    if not (atom_dir / "source_bundle").is_dir():
        return []

    scanned = scan_source_bundle(atom_dir, source_kind=_source_kind(raw))
    if scanned is None:
        return []
    metadata = bundle.setdefault("material_metadata", {})
    changes: list[str] = []
    for material in bundle.get("poc_materials") or []:
        if material in metadata and not refresh:
            continue
        record = scanned.material_metadata.get(material)
        if record is None:
            continue
        rendered = record.model_dump(mode="json")
        if metadata.get(material) == rendered:
            continue
        metadata[material] = rendered
        changes.append(f"source_bundle.material_metadata.{material}")
    return changes


def backfill_atom(
    atom_dir: Path,
    *,
    write: bool,
    materials_only: bool = False,
    refresh_material_metadata: bool = False,
) -> list[str]:
    atom_path = atom_dir / "atom.yaml"
    raw = _load_yaml(atom_path)
    AtomConfig.model_validate(raw)
    changes = [
        *_backfill_material_metadata(
            raw,
            atom_dir,
            refresh=refresh_material_metadata,
        )
    ]
    if not materials_only:
        changes.extend(_backfill_runtime_metadata(raw, atom_dir))
        changes.extend(_backfill_service_contract(raw, atom_dir))
    if not changes:
        return []

    AtomConfig.model_validate(raw)
    if write:
        atom_path.write_text(
            yaml.safe_dump(raw, sort_keys=False, allow_unicode=True)
        )
    return changes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--atoms-dir", type=Path, default=ROOT / "data" / "atoms")
    parser.add_argument("--cve", action="append", default=[])
    parser.add_argument(
        "--write",
        action="store_true",
        help="Persist backfilled metadata; default is a read-only preview.",
    )
    parser.add_argument(
        "--materials-only",
        action="store_true",
        help="Only backfill source_bundle material metadata.",
    )
    parser.add_argument(
        "--refresh-material-metadata",
        action="store_true",
        help="Recompute existing PoC metadata with the shared classifier.",
    )
    args = parser.parse_args()
    targets = (
        [args.atoms_dir / cve for cve in args.cve]
        if args.cve
        else sorted(args.atoms_dir.iterdir())
    )
    for atom_dir in targets:
        if not atom_dir.is_dir() or not (atom_dir / "atom.yaml").is_file():
            continue
        changes = backfill_atom(
            atom_dir,
            write=args.write,
            materials_only=args.materials_only,
            refresh_material_metadata=args.refresh_material_metadata,
        )
        action = "updated" if args.write and changes else "would update" if changes else "unchanged"
        print(f"{atom_dir.name}: {action}{(': ' + ', '.join(changes)) if changes else ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
