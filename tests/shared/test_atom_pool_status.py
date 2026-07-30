import csv
import hashlib
import io
import json
from pathlib import Path

import yaml

from clab_builder.shared.atom_pool_status import (
    build_snapshot,
    render_csv,
    render_markdown,
)


def _write_atom(
    root: Path,
    cve_id: str,
    *,
    parseable: bool = True,
    completed: bool = False,
) -> None:
    atom_dir = root / cve_id
    atom_dir.mkdir(parents=True)
    if not parseable:
        (atom_dir / "atom.yaml").write_text("version: invalid\n")
        return

    (atom_dir / "source_bundle").mkdir()
    (atom_dir / "source_bundle" / "docker-compose.yml").write_text(
        "services: {}\n"
    )
    compose_hash = hashlib.sha256(
        (atom_dir / "source_bundle" / "docker-compose.yml").read_bytes()
    ).hexdigest()
    if completed:
        (atom_dir / "runtime").mkdir()
        (atom_dir / "runtime" / "Dockerfile").write_text(
            "FROM example/service:1\n"
        )
        (atom_dir / "runtime" / "install-tools.sh").write_text("#!/bin/sh\n")
        (atom_dir / "exploit_guide.yaml").write_text(
            yaml.safe_dump(
                {
                    "version": 1,
                    "cve_id": cve_id,
                    "steps": [
                        {
                            "id": "exploit",
                            "action": "exploit",
                            "procedure": "send the verified request",
                            "success_signal": "command output",
                        }
                    ],
                }
            )
        )

    atom = {
        "version": 3,
        "cve_id": cve_id,
        "category": "test",
        "verified": completed,
        "docker_image": "example/service:1",
        "ports": [80],
        "services": [
            {"name": "web", "image": "example/service:1", "is_target": True}
        ],
        "runtime_spec": {
            "ports": [80],
            "services": [
                {"name": "web", "image": "example/service:1", "is_target": True}
            ],
            "source_image": "example/service:1",
            "runtime_image": "example/service-runtime:1",
            "runtime_status": "ready" if completed else "pending",
            "runtime_build": {
                "context": "runtime",
                "dockerfile": "runtime/Dockerfile",
                "install_script": "runtime/install-tools.sh",
                "base_image_digest": "sha256:base",
                "generated_hash": "sha256:runtime",
            } if completed else None,
        },
        "vuln_category": "RCE",
        "primary_mitre_phase": "initial_access",
        "service_role": "web_application",
        "exploit_complexity": "simple",
        "attack_method": "single_request",
        "source_bundle": {
            "compose_file": "source_bundle/docker-compose.yml",
            "hashes": {
                "source_bundle/docker-compose.yml": compose_hash,
            },
        },
        "flag_spec": {
            "primary_path": "/flag.txt",
            "injection": {"method": "file"},
        },
        "validation_spec": {"readiness": [{"probe_type": "tcp"}]},
        "exploit_access": {
            "attack_vector": "network",
            "required_service": {"protocol": "http", "port": 80},
        },
        "capability_grants": [
            {
                "type": "execute_command",
                "principal": "root",
                "evidence_level": "verified",
                "evidence_ref": "native-result",
            }
        ],
        "verification": {
            "native_verification": {"success": completed},
            "orchestrated_verification": {
                "success": completed,
                "mode": "orchestrated",
                "evidence": ["container and readiness checks passed"],
                "timestamp": "2026-07-30T00:00:00+00:00",
            },
            "environment_ready": completed,
        },
    }
    if completed:
        atom["exploit_guide"] = {
            "path": "exploit_guide.yaml",
            "status": "ready",
        }
    (atom_dir / "atom.yaml").write_text(yaml.safe_dump(atom))


def test_snapshot_has_only_three_lifecycle_states_and_strict_completion(tmp_path):
    _write_atom(tmp_path, "CVE-COMPLETE-0001", completed=True)
    _write_atom(tmp_path, "CVE-BUILDING-0002")
    _write_atom(tmp_path, "CVE-BROKEN-0003", parseable=False)

    snapshot = build_snapshot(
        tmp_path,
        planned_ids=["CVE-PLANNED-0004", "CVE-BUILDING-0002"],
        generated_at="2026-07-30T00:00:00+00:00",
    )
    rows = {row["cve_id"]: row for row in snapshot["atoms"]}

    assert snapshot["schema_version"] == 2
    assert snapshot["summary"] == {
        "total": 4,
        "planned": 1,
        "building": 2,
        "completed": 1,
    }
    assert {row["build_status"] for row in rows.values()} == {
        "planned",
        "building",
        "completed",
    }
    assert rows["CVE-COMPLETE-0001"]["blockers"] == []
    assert all(rows["CVE-COMPLETE-0001"]["completion_checks"].values())
    assert "runtime_ready" in rows["CVE-BUILDING-0002"]["blockers"]
    assert rows["CVE-BROKEN-0003"]["blockers"] == ["atom_schema_parse"]


def test_generated_views_share_snapshot_identity(tmp_path):
    _write_atom(tmp_path, "CVE-BUILDING-0001")
    snapshot = build_snapshot(
        tmp_path,
        generated_at="2026-07-30T00:00:00+00:00",
    )
    csv_text = render_csv(snapshot)
    markdown = render_markdown(snapshot)
    csv_rows = list(csv.DictReader(io.StringIO(csv_text)))

    assert all(row["snapshot_hash"] == snapshot["snapshot_hash"] for row in csv_rows)
    assert snapshot["generated_at"] in csv_text
    assert snapshot["generated_at"] in markdown
    assert snapshot["snapshot_hash"] in markdown
    assert "matrix_eligible" not in csv_text
    assert json.loads(json.dumps(snapshot))["summary"] == snapshot["summary"]


def test_structured_orchestrated_evidence_not_legacy_mirror_is_gate(tmp_path):
    _write_atom(tmp_path, "CVE-STRUCTURED-0001", completed=True)
    atom_path = tmp_path / "CVE-STRUCTURED-0001" / "atom.yaml"
    raw = yaml.safe_load(atom_path.read_text())
    raw["verification"].pop("environment_ready")
    atom_path.write_text(yaml.safe_dump(raw))

    snapshot = build_snapshot(tmp_path)

    assert snapshot["atoms"][0]["build_status"] == "completed"
    assert snapshot["atoms"][0]["completion_checks"][
        "orchestrated_environment_verified"
    ] is True


def test_legacy_environment_mirror_cannot_replace_structured_evidence(tmp_path):
    _write_atom(tmp_path, "CVE-MIRROR-0001", completed=True)
    atom_path = tmp_path / "CVE-MIRROR-0001" / "atom.yaml"
    raw = yaml.safe_load(atom_path.read_text())
    raw["verification"].pop("orchestrated_verification")
    raw["verification"]["environment_ready"] = True
    atom_path.write_text(yaml.safe_dump(raw))

    snapshot = build_snapshot(tmp_path)

    assert snapshot["atoms"][0]["build_status"] == "building"
    assert "orchestrated_environment_verified" in snapshot["atoms"][0][
        "blockers"
    ]
