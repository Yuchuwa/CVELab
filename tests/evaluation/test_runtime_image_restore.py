import hashlib
import importlib.util
import io
import json
import tarfile
from pathlib import Path

import pytest

from clab_builder.evaluation.study import canonical_sha256

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "restore_difficulty_runtime_images",
    ROOT / "scripts" / "restore_difficulty_runtime_images.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

IMAGE = "runtime-a:latest"
IMAGE_ID = "sha256:" + "a" * 64


def _sealed_lock():
    payload = {
        "schema_version": 1,
        "images": {
            "CVE-A": {
                "image": IMAGE,
                "image_id": IMAGE_ID,
                "archive_file": "runtime-a.tar.gz",
                "archive_sha256": "b" * 64,
                "archive_size_bytes": 7,
            }
        },
    }
    payload["lock_sha256"] = canonical_sha256(payload)
    return payload


def _add_json(archive, name, payload):
    raw = json.dumps(payload, separators=(",", ":")).encode()
    member = tarfile.TarInfo(name)
    member.size = len(raw)
    member.mtime = 0
    archive.addfile(member, io.BytesIO(raw))


def _write_archive(path, *, image=IMAGE, image_id=IMAGE_ID):
    with tarfile.open(path, "w:gz") as archive:
        _add_json(archive, "manifest.json", [{"RepoTags": [image]}])
        _add_json(archive, "index.json", {"manifests": [{"digest": image_id}]})
    return path.read_bytes()


def _archive_record(tmp_path, *, archived_image=IMAGE):
    record = _sealed_lock()["images"]["CVE-A"]
    archive = tmp_path / record["archive_file"]
    raw = _write_archive(archive, image=archived_image)
    record["archive_size_bytes"] = len(raw)
    record["archive_sha256"] = hashlib.sha256(raw).hexdigest()
    return record


def test_load_lock_rejects_tampering(tmp_path):
    path = tmp_path / "lock.json"
    payload = _sealed_lock()
    path.write_text(json.dumps(payload))
    assert MODULE.load_lock(path)["lock_sha256"] == payload["lock_sha256"]

    payload["images"]["CVE-A"]["image_id"] = "sha256:" + "c" * 64
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="seal"):
        MODULE.load_lock(path)


def test_resolve_archive_rejects_path_escape(tmp_path):
    with pytest.raises(ValueError, match="escape"):
        MODULE.resolve_archive(tmp_path, "../runtime.tar.gz")


def test_restore_validates_archive_when_exact_image_exists(tmp_path, monkeypatch):
    record = _archive_record(tmp_path)
    monkeypatch.setattr(MODULE, "inspect_image_id", lambda image: record["image_id"])

    result = MODULE.restore_image("CVE-A", record, tmp_path)

    assert result["status"] == "already_present"
    assert result["image_id"] == record["image_id"]


def test_restore_rejects_unexpected_archive_tag_before_noop(tmp_path, monkeypatch):
    record = _archive_record(tmp_path, archived_image="unrelated:latest")
    monkeypatch.setattr(MODULE, "inspect_image_id", lambda image: record["image_id"])

    with pytest.raises(ValueError, match="unexpected image tag"):
        MODULE.restore_image("CVE-A", record, tmp_path)