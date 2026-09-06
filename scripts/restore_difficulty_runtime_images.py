#!/usr/bin/env python3
"""Restore exact difficulty-study runtime images from sealed local archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tarfile
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from clab_builder.evaluation.study import load_sealed_json

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "data" / "difficulty_runtime_image_lock_2026-09-06.json"


def load_lock(path: Path) -> dict[str, Any]:
    payload, _ = load_sealed_json(path, seal_field="lock_sha256")
    images = payload.get("images")
    if not isinstance(images, dict) or not images:
        raise ValueError("runtime image lock has no images")
    return payload


def resolve_archive(archive_dir: Path, filename: Any) -> Path:
    if not isinstance(filename, str) or not filename:
        raise ValueError("archive_file must be a non-empty filename")
    root = archive_dir.resolve()
    path = (root / filename).resolve()
    if path.parent != root:
        raise ValueError("archive_file must not escape archive directory")
    return path


def inspect_image_id(image: str) -> str:
    result = subprocess.run(
        ["docker", "image", "inspect", image, "--format", "{{.Id}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def _read_archive_json(archive: tarfile.TarFile, name: str) -> Any:
    member = archive.getmember(name)
    if not member.isfile() or member.size > 1024 * 1024:
        raise ValueError(f"invalid Docker archive member: {name}")
    handle = archive.extractfile(member)
    if handle is None:
        raise ValueError(f"missing Docker archive member: {name}")
    return json.loads(handle.read().decode("utf-8"))


def preflight_archive(archive_path: Path, *, image: str, image_id: str) -> None:
    """Reject archives that would load any image or tag beyond the locked one."""
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            manifest = _read_archive_json(archive, "manifest.json")
            index = _read_archive_json(archive, "index.json")
    except (KeyError, OSError, tarfile.TarError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid Docker image archive") from exc
    if not isinstance(manifest, list) or len(manifest) != 1:
        raise ValueError("Docker archive must contain exactly one image")
    if manifest[0].get("RepoTags") != [image]:
        raise ValueError("Docker archive contains an unexpected image tag")
    index_entries = index.get("manifests") if isinstance(index, dict) else None
    if not isinstance(index_entries, list) or len(index_entries) != 1:
        raise ValueError("Docker archive index must contain exactly one image")
    if index_entries[0].get("digest") != image_id:
        raise ValueError("Docker archive image identity does not match the lock")


def stage_verified_archive(
    cve_id: str, record: Mapping[str, Any], archive_dir: Path
) -> Path:
    source = resolve_archive(archive_dir, record.get("archive_file"))
    expected_size = record.get("archive_size_bytes")
    if not isinstance(expected_size, int) or expected_size <= 0:
        raise ValueError(f"invalid runtime archive size for {cve_id}")
    if source.stat().st_size != expected_size:
        raise ValueError(f"runtime archive size mismatch for {cve_id}")
    expected_hash = str(record.get("archive_sha256") or "")
    digest = hashlib.sha256()
    staged_path: Path | None = None
    try:
        with source.open("rb") as source_handle, tempfile.NamedTemporaryFile(
            prefix=f"cvelab-{cve_id}-", suffix=".tar.gz", delete=False
        ) as staged:
            staged_path = Path(staged.name)
            copied = 0
            for chunk in iter(lambda: source_handle.read(1024 * 1024), b""):
                copied += len(chunk)
                digest.update(chunk)
                staged.write(chunk)
        if copied != expected_size or digest.hexdigest() != expected_hash:
            raise ValueError(f"runtime archive hash mismatch for {cve_id}")
        preflight_archive(
            staged_path,
            image=str(record.get("image") or ""),
            image_id=str(record.get("image_id") or ""),
        )
        return staged_path
    except Exception:
        if staged_path is not None:
            staged_path.unlink(missing_ok=True)
        raise


def restore_image(
    cve_id: str, record: Mapping[str, Any], archive_dir: Path
) -> dict[str, Any]:
    image = str(record.get("image") or "")
    expected_id = str(record.get("image_id") or "")
    if not image or len(expected_id) != 71 or not expected_id.startswith("sha256:"):
        raise ValueError(f"invalid image identity for {cve_id}")
    actual_id = inspect_image_id(image)
    if actual_id and actual_id != expected_id:
        raise RuntimeError(
            f"{image} exists with {actual_id}; expected {expected_id}; "
            "refusing to overwrite"
        )

    staged = stage_verified_archive(cve_id, record, archive_dir)
    try:
        if actual_id == expected_id:
            return {
                "cve_id": cve_id,
                "image": image,
                "status": "already_present",
                "image_id": actual_id,
            }
        loaded = subprocess.run(
            ["docker", "load", "--input", str(staged)],
            capture_output=True,
            text=True,
            check=False,
        )
        if loaded.returncode != 0:
            raise RuntimeError(
                f"docker load failed for {cve_id}: {loaded.stderr.strip()}"
            )
        actual_id = inspect_image_id(image)
        if actual_id != expected_id:
            subprocess.run(
                ["docker", "image", "rm", image],
                capture_output=True,
                text=True,
                check=False,
            )
            raise RuntimeError(
                f"loaded image identity mismatch for {cve_id}: "
                f"{actual_id or 'missing'}"
            )
        return {
            "cve_id": cve_id,
            "image": image,
            "status": "restored",
            "image_id": actual_id,
        }
    finally:
        staged.unlink(missing_ok=True)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--archive-dir", type=Path, required=True)
    parser.add_argument("--cve", action="append", default=[])
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    lock = load_lock(args.lock.resolve())
    images = lock["images"]
    selected = args.cve or sorted(images)
    unknown = sorted(set(selected) - set(images))
    if unknown:
        raise SystemExit("CVEs absent from runtime lock: " + ", ".join(unknown))
    results = [
        restore_image(cve_id, images[cve_id], args.archive_dir)
        for cve_id in selected
    ]
    print(
        json.dumps(
            {"lock_sha256": lock["lock_sha256"], "results": results}, indent=2
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())