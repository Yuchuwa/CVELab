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

_CREDENTIAL_MATERIAL_PATTERNS = (
    "id_rsa", "id_dsa", "id_ed25519", "id_ecdsa",
    ".pem", ".key", ".p12", "id_rsa.pub",
)
_PAYLOAD_MATERIAL_PATTERNS = (
    "poc.py", "poc.sh", "poc.png", "poc.jpg", "poc.gif",
    "exploit.py", "exploit.sh", "exp.py", "exp.sh",
    "evil.py", "evil.sh",
)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_material_hash(atom_or_bundle, atom_dir: Path, material: str) -> bool:
    """Verify one declared bundle material before exposing or copying it."""
    bundle = getattr(atom_or_bundle, "source_bundle", atom_or_bundle)
    if isinstance(atom_or_bundle, dict) and "source_bundle" in atom_or_bundle:
        bundle = atom_or_bundle.get("source_bundle")
    if not bundle:
        return False
    hashes = (
        bundle.get("hashes", {})
        if isinstance(bundle, dict)
        else getattr(bundle, "hashes", {}) or {}
    )
    expected = hashes.get(material)
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        return False
    path = atom_dir / material
    if not path.is_file() or path.is_symlink():
        return False
    try:
        return _sha256_file(path) == expected
    except OSError:
        return False


def material_sha256(path: Path) -> str:
    """Return a material digest, or an empty value when it is unreadable."""
    try:
        return _sha256_file(path) if path.is_file() and not path.is_symlink() else ""
    except OSError:
        return ""


def missing_material_metadata(atom_or_bundle) -> list[str]:
    """Return declared PoC materials without an explicit metadata record."""
    bundle = getattr(atom_or_bundle, "source_bundle", atom_or_bundle)
    if isinstance(atom_or_bundle, dict) and "source_bundle" in atom_or_bundle:
        bundle = atom_or_bundle.get("source_bundle")
    if not bundle:
        return []

    if isinstance(bundle, dict):
        materials = list(bundle.get("poc_materials") or [])
        metadata = bundle.get("material_metadata") or {}
    else:
        materials = list(getattr(bundle, "poc_materials", []) or [])
        metadata = getattr(bundle, "material_metadata", {}) or {}
    return sorted(
        str(material)
        for material in materials
        if material not in metadata or metadata.get(material) is None
    )


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
        if name == "analyzer_summary.txt":
            return MaterialRole.VERIFICATION, MaterialVisibility.PRIVATE
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


def is_credential_material(material: str) -> bool:
    """Return whether a material is an existing Level-2 credential hint."""
    base = str(Path(material).name).lower()
    if any(base == pattern or base.endswith(pattern) for pattern in _PAYLOAD_MATERIAL_PATTERNS):
        return False
    return any(pattern in base for pattern in _CREDENTIAL_MATERIAL_PATTERNS)


def select_agent_materials(atom_or_bundle, agent_context: str = "guided") -> list[str]:
    """Select source-bundle files visible under one Agent exposure profile.

    Missing metadata remains a compatibility contract for pre-v3 atoms. v3
    atoms fail closed for unannotated materials. Explicit private metadata
    always wins, while assisted material is limited to the guided and no-guide
    profiles. Level restrictions are applied after visibility.
    """
    bundle = getattr(atom_or_bundle, "source_bundle", atom_or_bundle)
    if isinstance(atom_or_bundle, dict) and "source_bundle" in atom_or_bundle:
        bundle = atom_or_bundle.get("source_bundle")
    if not bundle:
        return []

    materials = list(getattr(bundle, "poc_materials", []) or [])
    if isinstance(bundle, dict):
        materials = list(bundle.get("poc_materials") or [])
        metadata = bundle.get("material_metadata") or {}
    else:
        metadata = getattr(bundle, "material_metadata", {}) or {}

    strict_metadata = (
        int(getattr(atom_or_bundle, "version", 0) or 0) >= 3
        if not isinstance(atom_or_bundle, dict)
        else int(atom_or_bundle.get("version", 0) or 0) >= 3
    )

    level = "l2" if agent_context in {"l2", "no_hint"} else ""
    if agent_context in {"l0", "l1"}:
        return []

    selected: list[str] = []
    for material in materials:
        record = metadata.get(material)
        if isinstance(record, dict):
            visibility = record.get("visibility")
        else:
            visibility = getattr(record, "visibility", None)
        visibility = getattr(visibility, "value", visibility)
        if visibility is None and strict_metadata:
            continue
        # An absent metadata entry is the compatibility contract for old
        # atoms; current v3 atoms take the fail-closed branch above.
        visibility = str(visibility or MaterialVisibility.ALWAYS.value)
        if visibility == "legacy":
            visibility = MaterialVisibility.ALWAYS.value
        if visibility == MaterialVisibility.PRIVATE.value:
            continue
        if visibility == MaterialVisibility.ASSISTED.value and agent_context not in {
            "guided", "no_guide",
        }:
            continue
        if visibility not in {
            MaterialVisibility.ASSISTED.value,
            MaterialVisibility.ALWAYS.value,
        }:
            continue
        if level == "l2" and not is_credential_material(material):
            continue
        selected.append(material)
    return selected


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
    "is_credential_material",
    "verify_material_hash",
    "material_sha256",
    "missing_material_metadata",
    "select_agent_materials",
]
