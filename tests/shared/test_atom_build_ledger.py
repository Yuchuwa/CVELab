"""Contract tests for tracked Atom build attempts and clean-clone projection."""

import json

from clab_builder.shared.atom_build_ledger import (
    finish_attempt,
    latest_attempts,
    start_attempt,
)
from clab_builder.shared.atom_pool_status import build_lifecycle_index, build_snapshot


def test_attempt_lifecycle_is_appendable_and_latest_is_projected(tmp_path):
    ledger = tmp_path / "atom_build_attempts.json"
    attempt_id = start_attempt(
        ledger,
        "CVE-TEST-0001",
        attempt_id="attempt-1",
        started_at="2026-08-10T00:00:00+00:00",
    )
    finish_attempt(
        ledger,
        attempt_id,
        state="deferred",
        failure_class="atom_yaml_missing",
        updated_at="2026-08-10T00:01:00+00:00",
    )

    latest = latest_attempts(ledger)
    assert latest["CVE-TEST-0001"]["state"] == "deferred"
    assert latest["CVE-TEST-0001"]["attempt_count"] == 1
    assert json.loads(ledger.read_text())["schema_version"] == 1


def test_orphan_workspace_requires_tracked_ledger(tmp_path):
    atoms_dir = tmp_path / "atoms"
    orphan = atoms_dir / "CVE-TEST-0002" / ".workspace"
    orphan.mkdir(parents=True)
    (orphan / "session.json").write_text("private")

    assert build_lifecycle_index(atoms_dir) == {}
    attempts = {
        "CVE-TEST-0002": {
            "attempt_id": "legacy-test-0002",
            "cve_id": "CVE-TEST-0002",
            "state": "deferred",
            "started_at": "2026-08-10T00:00:00+00:00",
            "updated_at": "2026-08-10T00:00:00+00:00",
            "owner": "atomizer",
            "phase": "construction",
            "failure_class": "atom_yaml_missing",
            "source_kind": "legacy-local-evidence",
            "attempt_count": 1,
        }
    }
    local = build_snapshot(atoms_dir, build_attempts=attempts, generated_at="fixed")

    clean_atoms = tmp_path / "clean-atoms"
    clean = build_snapshot(clean_atoms, build_attempts=attempts, generated_at="fixed")
    assert local["atoms"] == clean["atoms"]
    assert local["summary"] == {"total": 1, "planned": 0, "building": 1, "completed": 0}
