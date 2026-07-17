"""Shared source-bundle capture.

Both Agent-verified atoms (vulhub source) and CVE-Factory PoC atoms
(prepared staging source) use this to build a self-contained
``source_bundle/`` inside the atom directory. The captured bundle is the
single source of truth for environment rebuild and agent material delivery.

Design:
  - capture_source_bundle(src_dir, atom_dir, source_kind)
        copies the source tree into atom_dir/source_bundle/, excluding
        build/runtime noise, then scans + hashes it into a SourceBundle.
  - scan_source_bundle(atom_dir)
        scans an existing source_bundle/ dir into a SourceBundle manifest
        with material role/visibility metadata.
  - classify_material(rel, name, source_kind)
        assigns a MaterialRole + MaterialVisibility to a file.

source_kind drives classification differences:
  - "vulhub":   test/poc artifacts are poc.png, id_rsa, *.py; no test_vuln.py
  - "cve_factory": tests/test_vuln.py is the exploit reference (assisted);
                  test_func.py / solution.sh are verification/solution (private)

The bundle is NOT sanitized. test_vuln.py is captured verbatim so native
verification and assisted agent trials use the identical file. Exposure is
controlled at Range assembly time via the agent exposure profile, not by
rewriting the file.
"""
from __future__ import annotations

import hashlib
import re
import shutil
from pathlib import Path
from typing import Optional

from clab_builder.shared.models.atom import (
    SourceBundle,
    MaterialRole,
    MaterialVisibility,
    MaterialMetadata,
)

# Files/dirs never copied into source_bundle regardless of source kind.
# These are build/runtime noise or private ground-truth artifacts.
_EXCLUDE_NAMES = {
    ".workspace", ".claude_cache", ".git", "__pycache__",
    "agent_transcript.log", "session.json",
    ".orch-compose.yml", ".compose-no-ports.yml",
    "test_full_output.txt", "test_full_output2.txt",  # cve-factory run logs
}

# Regex for README-referenced documentation images (not attack PoCs).
_README_IMG_RE = re.compile(r"!\[.*?\]\(([^)]+)\)|<img[^>]+src=\"([^\"]+)\"")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _should_exclude(path: Path, src_root: Path) -> bool:
    parts = path.relative_to(src_root).parts
    for part in parts:
        if part in _EXCLUDE_NAMES:
            return True
        if part.startswith(".claude_cache") or part == "__pycache__":
            return True
    # atom.yaml / exploit_guide.yaml are outputs, not source
    if path.name == "atom.yaml":
        return True
    if path.name == "exploit_guide.yaml":
        return True
    return False


def classify_material(
    rel: str,
    name: str,
    source_kind: str,
) -> tuple[MaterialRole, MaterialVisibility]:
    """Return (role, visibility) for a bundle file.

    rel  — path relative to atom dir, e.g. 'source_bundle/tests/test_vuln.py'
    name — basename lowercased
    """
    rel_norm = rel.replace("\\", "/")
    # Runtime / build files
    if name in ("docker-compose.yml", "compose.yml", "docker-compose.yaml",
                "compose.yaml"):
        return MaterialRole.RUNTIME, MaterialVisibility.PRIVATE
    if name.startswith("readme"):
        return MaterialRole.RUNTIME, MaterialVisibility.PRIVATE
    if name == "dockerfile" or name.startswith("dockerfile."):
        return MaterialRole.RUNTIME, MaterialVisibility.PRIVATE
    if "/init/" in rel_norm:
        return MaterialRole.RUNTIME, MaterialVisibility.PRIVATE
    if name in ("entrypoint.sh",) or rel_norm.endswith("/task-deps/entrypoint.sh"):
        return MaterialRole.RUNTIME, MaterialVisibility.PRIVATE
    if name in ("task.yaml", "run-tests.sh"):
        # task.yaml is task metadata; run-tests.sh is the bench runner. Both
        # are runtime/verification scaffolding, not agent materials.
        return MaterialRole.VERIFICATION, MaterialVisibility.PRIVATE
    # CVE-Factory test artifacts
    if source_kind == "cve_factory":
        if name == "test_vuln.py":
            return MaterialRole.EXPLOIT_REFERENCE, MaterialVisibility.ASSISTED
        if name == "test_func.py":
            return MaterialRole.VERIFICATION, MaterialVisibility.PRIVATE
        if name == "solution.sh":
            return MaterialRole.SOLUTION, MaterialVisibility.PRIVATE
        if name.startswith("test_full_output"):
            return MaterialRole.VERIFICATION, MaterialVisibility.PRIVATE
    # Everything else: an exploit material (poc.png, id_rsa, payload.py, etc.)
    return MaterialRole.EXPLOIT_MATERIAL, MaterialVisibility.ALWAYS


def _readme_image_basenames(bundle_dir: Path) -> set[str]:
    imgs: set[str] = set()
    for entry in bundle_dir.glob("README*"):
        if not entry.is_file():
            continue
        try:
            text = entry.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _README_IMG_RE.finditer(text):
            for g in (m.group(1), m.group(2)):
                if g:
                    imgs.add(Path(g.split("/")[-1]).name)
    return imgs


def scan_source_bundle(atom_dir: Path, source_kind: str = "vulhub") -> Optional[SourceBundle]:
    """Scan atom_dir/source_bundle/ into a SourceBundle manifest with metadata.

    Replaces the old pipeline-only _build_source_bundle_manifest, adding
    material_metadata. Backward compatible: atoms without material_metadata
    in their YAML still load (the field defaults to empty).
    """
    bundle_dir = atom_dir / "source_bundle"
    if not bundle_dir.is_dir():
        return None

    readme_images = _readme_image_basenames(bundle_dir)

    compose_file: Optional[str] = None
    readme_file: Optional[str] = None
    dockerfiles: list[str] = []
    init_files: list[str] = []
    poc_materials: list[str] = []
    hashes: dict[str, str] = {}
    material_metadata: dict[str, MaterialMetadata] = {}

    for entry in sorted(bundle_dir.rglob("*")):
        if entry.is_dir():
            continue
        if entry.name.startswith("."):
            continue
        rel = str(entry.relative_to(atom_dir))
        name = entry.name.lower()

        # Bucket the build-source files first (these are NOT poc_materials).
        if name in ("docker-compose.yml", "compose.yml",
                    "docker-compose.yaml", "compose.yaml"):
            if compose_file is None:
                compose_file = rel
            role, vis = classify_material(rel, name, source_kind)
            material_metadata[rel] = MaterialMetadata(role=role, visibility=vis)
        elif name.startswith("readme"):
            if readme_file is None:
                readme_file = rel
            material_metadata[rel] = MaterialMetadata(
                role=MaterialRole.RUNTIME, visibility=MaterialVisibility.PRIVATE
            )
        elif name == "dockerfile" or name.startswith("dockerfile."):
            dockerfiles.append(rel)
            material_metadata[rel] = MaterialMetadata(
                role=MaterialRole.RUNTIME, visibility=MaterialVisibility.PRIVATE
            )
        elif "/init/" in rel.replace("\\", "/"):
            init_files.append(rel)
            material_metadata[rel] = MaterialMetadata(
                role=MaterialRole.RUNTIME, visibility=MaterialVisibility.PRIVATE
            )
        elif entry.name in readme_images:
            # README-referenced doc screenshot: skip (not a PoC).
            continue
        else:
            poc_materials.append(rel)
            role, vis = classify_material(rel, name, source_kind)
            material_metadata[rel] = MaterialMetadata(role=role, visibility=vis)

        try:
            hashes[rel] = _sha256_file(entry)
        except OSError:
            pass

    return SourceBundle(
        compose_file=compose_file,
        readme_file=readme_file,
        dockerfiles=dockerfiles,
        init_files=init_files,
        poc_materials=poc_materials,
        hashes=hashes,
        material_metadata=material_metadata,
    )


def capture_source_bundle(
    src_dir: Path,
    atom_dir: Path,
    source_kind: str = "vulhub",
) -> Optional[SourceBundle]:
    """Copy the source tree into atom_dir/source_bundle/ then scan it.

    src_dir:    vulhub CVE dir or prepared CVE-Factory staging dir
    atom_dir:   the atom output directory (source_bundle/ created inside)
    source_kind: "vulhub" | "cve_factory"
    """
    bundle_dir = atom_dir / "source_bundle"
    if bundle_dir.exists():
        shutil.rmtree(bundle_dir)
    bundle_dir.mkdir(parents=True)

    src_root = src_dir.resolve()

    def _copy(src: Path, dst: Path):
        if src.is_dir():
            dst.mkdir(parents=True, exist_ok=True)
            for child in sorted(src.iterdir()):
                if _should_exclude(child, src_root):
                    continue
                _copy(child, dst / child.name)
        else:
            if _should_exclude(src, src_root):
                return
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dst))

    _copy(src_root, bundle_dir)
    return scan_source_bundle(atom_dir, source_kind=source_kind)


__all__ = [
    "capture_source_bundle",
    "scan_source_bundle",
    "classify_material",
]