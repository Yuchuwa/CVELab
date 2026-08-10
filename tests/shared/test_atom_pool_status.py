import csv
import hashlib
import io
import json
import subprocess
import sys
from pathlib import Path

import yaml

from clab_builder.shared.atom_pool_status import (
    build_snapshot,
    check_snapshot_files,
    render_csv,
    render_markdown,
    snapshot_semantic_identity,
    write_snapshot,
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
        runtime_hash = hashlib.sha256(b"runtime").hexdigest()
        (atom_dir / "runtime" / "manifest.yaml").write_text(
            yaml.safe_dump({"generated_hash": runtime_hash})
        )
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
                "generated_hash": runtime_hash,
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


def test_nonempty_directory_without_atom_yaml_needs_ledger(tmp_path):
    partial = tmp_path / "CVE-PARTIAL-0001"
    partial.mkdir()
    (partial / "agent_transcript.log").write_text("interrupted\n")
    empty = tmp_path / "CVE-PLANNED-0002"
    empty.mkdir()

    snapshot = build_snapshot(
        tmp_path,
        planned_ids=["CVE-PARTIAL-0001", "CVE-PLANNED-0002"],
    )
    rows = {row["cve_id"]: row for row in snapshot["atoms"]}

    assert rows["CVE-PARTIAL-0001"]["build_status"] == "planned"
    assert rows["CVE-PARTIAL-0001"]["blockers"] == ["atom_not_started"]
    assert rows["CVE-PLANNED-0002"]["build_status"] == "planned"


def test_directory_identity_wins_over_declared_cve_id(tmp_path):
    _write_atom(tmp_path, "CVE-DIRECTORY-0001")
    atom_path = tmp_path / "CVE-DIRECTORY-0001" / "atom.yaml"
    atom = yaml.safe_load(atom_path.read_text())
    atom["cve_id"] = "CVE-YAML-0002"
    atom_path.write_text(yaml.safe_dump(atom))

    row = build_snapshot(tmp_path)["atoms"][0]
    assert row["cve_id"] == "CVE-DIRECTORY-0001"
    assert row["declared_cve_id"] == "CVE-YAML-0002"
    assert row["build_status"] == "building"
    assert "atom_directory_id_mismatch" in row["blockers"]


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


def test_semantic_identity_ignores_generated_at(tmp_path):
    _write_atom(tmp_path, "CVE-BUILDING-0001")
    first = build_snapshot(tmp_path, generated_at="2026-07-30T00:00:00+00:00")
    second = build_snapshot(tmp_path, generated_at="2026-08-09T00:00:00+00:00")

    assert snapshot_semantic_identity(first) == snapshot_semantic_identity(second)
    assert first["snapshot_hash"] == second["snapshot_hash"]


def test_check_detects_stale_snapshot_and_does_not_write(tmp_path):
    atoms_dir = tmp_path / "atoms"
    output_prefix = tmp_path / "status" / "atom_pool_status"
    _write_atom(atoms_dir, "CVE-BUILDING-0001")
    write_snapshot(build_snapshot(atoms_dir), output_prefix)
    before = {
        suffix: output_prefix.with_suffix(suffix).read_bytes()
        for suffix in (".json", ".csv", ".md")
    }
    script = Path(__file__).resolve().parents[2] / "scripts" / "generate_atom_pool_status.py"
    check_command = [
        sys.executable,
        str(script),
        "--atoms-dir",
        str(atoms_dir),
        "--output-prefix",
        str(output_prefix),
        "--build-plan",
        str(tmp_path / "missing-plan.json"),
        "--check",
    ]
    current = subprocess.run(
        check_command,
        capture_output=True,
        text=True,
        check=False,
    )
    atom_path = atoms_dir / "CVE-BUILDING-0001" / "atom.yaml"
    raw = yaml.safe_load(atom_path.read_text())
    raw["runtime_spec"]["runtime_status"] = "ready"
    atom_path.write_text(yaml.safe_dump(raw))

    errors = check_snapshot_files(build_snapshot(atoms_dir), output_prefix)
    result = subprocess.run(
        check_command,
        capture_output=True,
        text=True,
        check=False,
    )

    assert current.returncode == 0, current.stderr
    assert "stored Atom lifecycle snapshot is stale" in errors
    assert result.returncode == 1
    assert "stored Atom lifecycle snapshot is stale" in result.stderr
    assert before == {
        suffix: output_prefix.with_suffix(suffix).read_bytes()
        for suffix in (".json", ".csv", ".md")
    }


def test_generator_check_exits_nonzero_when_view_is_missing(tmp_path):
    atoms_dir = tmp_path / "atoms"
    atoms_dir.mkdir()
    output_prefix = tmp_path / "status" / "atom_pool_status"
    script = Path(__file__).resolve().parents[2] / "scripts" / "generate_atom_pool_status.py"

    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--atoms-dir",
            str(atoms_dir),
            "--output-prefix",
            str(output_prefix),
            "--build-plan",
            str(tmp_path / "missing-plan.json"),
            "--check",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "missing JSON snapshot" in result.stderr
    assert not output_prefix.parent.exists()


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


def test_v3_poc_material_metadata_is_a_completion_gate(tmp_path):
    _write_atom(tmp_path, "CVE-MATERIAL-GATE-0001", completed=True)
    atom_dir = tmp_path / "CVE-MATERIAL-GATE-0001"
    material = atom_dir / "source_bundle" / "poc.py"
    material.write_text("print('poc')\n")
    atom_path = atom_dir / "atom.yaml"
    raw = yaml.safe_load(atom_path.read_text())
    raw["source_bundle"]["poc_materials"] = ["source_bundle/poc.py"]
    raw["source_bundle"]["hashes"]["source_bundle/poc.py"] = hashlib.sha256(
        material.read_bytes()
    ).hexdigest()
    atom_path.write_text(yaml.safe_dump(raw))

    row = build_snapshot(tmp_path)["atoms"][0]

    assert row["build_status"] == "building"
    assert row["completion_checks"][
        "source_bundle_material_metadata_complete"
    ] is False
    assert "source_bundle_material_metadata_complete" in row["blockers"]


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
