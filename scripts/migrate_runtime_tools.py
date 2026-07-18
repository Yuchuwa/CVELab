#!/usr/bin/env python3
"""Idempotent migration: build runtime tool layer for existing atoms.

For each atom with a docker_image and no runtime_image yet, this generates
the runtime/Dockerfile + install-tools.sh (and optionally builds the image)
WITHOUT modifying source_bundle or any verification truth. Re-running is
safe: atoms that already have a runtime_image are skipped unless --force.

Usage:
    python scripts/migrate_runtime_tools.py [--build] [--cve CVE-XXXX]
    [--atoms-dir data/atoms]

Without --build: writes runtime/ artifacts and sets runtime_status=pending.
With --build: also builds the image and runs smoke/service checks, setting
runtime_status=ready/failed/unsupported. Failures never touch native verified.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from clab_builder.shared.models.atom import AtomConfig, RuntimeStatus
from clab_builder.atomizer.runtime_generator import generate_runtime_artifacts, write_runtime_dir


def migrate_one(atom_dir: Path, build: bool, force: bool) -> str:
    atom_path = atom_dir / "atom.yaml"
    try:
        raw = yaml.safe_load(atom_path.read_text()) or {}
        atom = AtomConfig(**raw)
    except Exception as exc:
        return f"skip (unreadable): {exc}"
    if not atom.docker_image:
        return "skip (no docker_image)"
    if atom.runtime_spec.runtime_image and not force:
        return f"skip (already has runtime_image: {atom.runtime_spec.runtime_image})"
    src = atom.runtime_spec.source_image or atom.docker_image
    arts = generate_runtime_artifacts(atom, src, atom_dir=atom_dir)
    if arts.unsupported_reason:
        atom.runtime_spec.runtime_status = RuntimeStatus.UNSUPPORTED
        atom.runtime_spec.runtime_failure_reason = arts.unsupported_reason
        _write_atom(atom, atom_path)
        return f"unsupported: {arts.unsupported_reason}"
    write_runtime_dir(atom_dir, arts)
    atom.runtime_spec.source_image = src
    atom.runtime_spec.tool_profile = ",".join(arts.tool_profiles) if arts.tool_profiles else None
    atom.runtime_spec.tool_profile_version = "1"
    from clab_builder.shared.models.atom import RuntimeBuildSpec
    atom.runtime_spec.runtime_build = RuntimeBuildSpec(
        context="runtime", dockerfile="runtime/Dockerfile",
        install_script="runtime/install-tools.sh", base_image_digest="",
        generated_hash=arts.manifest["generated_hash"],
        intermediate_image=arts.base_image_for_runtime,
        source_dockerfile=arts.source_dockerfile,
    )
    if not build:
        atom.runtime_spec.runtime_status = RuntimeStatus.PENDING
        atom.runtime_spec.runtime_image = None
        _write_atom(atom, atom_path)
        return "pending (artifacts written; build with --build)"
    # build
    from clab_builder.atomizer.runtime_builder import (
        build_runtime_image, runtime_verification_record,
    )
    rt = build_runtime_image(atom, atom_dir, source_image=src)
    if rt.status == RuntimeStatus.READY:
        atom.runtime_spec.runtime_image = rt.runtime_image
        atom.runtime_spec.runtime_status = RuntimeStatus.READY
        atom.runtime_spec.runtime_failure_reason = ""
        # backfill digests + resolved user from the build into runtime_build
        atom.runtime_spec.runtime_build.base_image_digest = rt.base_image_digest
        if rt.resolved_user:
            atom.runtime_spec.user = rt.resolved_user
    else:
        atom.runtime_spec.runtime_status = rt.status
        atom.runtime_spec.runtime_failure_reason = rt.failure_reason
    raw["runtime_spec"] = atom.runtime_spec.model_dump(exclude_none=True, mode="json")
    raw.setdefault("verification", {})["runtime_verification"] = runtime_verification_record(rt)
    atom_path.write_text(yaml.safe_dump(raw, sort_keys=False, allow_unicode=True))
    return f"{rt.status.value}"


def _write_atom(atom: AtomConfig, atom_path: Path):
    raw = yaml.safe_load(atom_path.read_text()) or {}
    raw["runtime_spec"] = atom.runtime_spec.model_dump(exclude_none=True, mode="json")
    atom_path.write_text(yaml.safe_dump(raw, sort_keys=False, allow_unicode=True))


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--atoms-dir", default="data/atoms")
    p.add_argument("--cve", action="append", default=[])
    p.add_argument("--build", action="store_true", help="Build the image too")
    p.add_argument("--force", action="store_true", help="Rebuild even if runtime_image exists")
    args = p.parse_args()

    atoms_dir = Path(args.atoms_dir)
    targets = sorted(atoms_dir.iterdir()) if not args.cve else [atoms_dir / c for c in args.cve]
    for d in targets:
        if not d.is_dir() or not (d / "atom.yaml").exists():
            continue
        status = migrate_one(d, args.build, args.force)
        print(f"{d.name}: {status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
