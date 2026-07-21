"""Batch scheduler identity and parallelism guards."""

import importlib.util
import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "verify_enterprise3_guided_batch.py"
SPEC = importlib.util.spec_from_file_location("enterprise3_batch_runner", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


@pytest.mark.parametrize("parallel", [1, 2, 4, 8])
def test_batch_runner_allows_adjustable_process_parallelism(parallel):
    MODULE.validate_parallelism(parallel)


@pytest.mark.parametrize("parallel", [0, -1])
def test_batch_runner_rejects_non_positive_parallelism(parallel):
    with pytest.raises(ValueError, match="at least 1"):
        MODULE.validate_parallelism(parallel)


def test_physical_lab_name_is_batch_unique_and_case_stable():
    first = MODULE.physical_lab_name("a" * 24, "case-a")
    second = MODULE.physical_lab_name("b" * 24, "case-a")
    assert first != second
    assert first == MODULE.physical_lab_name("a" * 24, "case-a")
    assert first.startswith("e3-aaaaaaaa-")


def test_case_validation_rejects_duplicate_or_unsafe_ids():
    with pytest.raises(SystemExit, match="Duplicate"):
        MODULE.validate_cases([
            {"id": "duplicate", "cves": []},
            {"id": "duplicate", "cves": []},
        ])
    with pytest.raises(SystemExit, match="Illegal"):
        MODULE.validate_cases([{"id": "../escape", "cves": []}])


def test_worker_spec_is_unique_and_does_not_persist_api_key(tmp_path):
    state = {"run_id": "a" * 24}
    case_state = {
        "case": {"id": "case-a", "cves": ["CVE-1"], "purpose": "test"},
        "lab_name": MODULE.physical_lab_name(state["run_id"], "case-a"),
        "scenario_dir": str(tmp_path / "scenario"),
        "result_path": str(tmp_path / ".batch" / "results" / "case-a.json"),
        "attempts": 1,
    }
    args = type("Args", (), {
        "atoms_dir": "data/atoms", "max_turns": 2, "agent_timeout": 3,
        "environment_only": True, "strict_guide_compatibility": False,
    })()
    spec_path = MODULE._worker_spec(
        state, case_state, args, tmp_path, 1, {"name": "cvelab-range-mgmt", "subnet": "172.30.240.0/24"}
    )
    content = spec_path.read_text()
    spec = json.loads(content)
    assert "LLM_API_KEY" not in content
    assert spec["lab_name"] == case_state["lab_name"]
    assert Path(spec["ansible_paths"]["ANSIBLE_LOCAL_TEMP"]).parent.name == "case-a"


def test_atomic_json_never_leaves_temporary_file(tmp_path):
    destination = tmp_path / "state.json"
    MODULE.atomic_json(destination, {"ok": True})
    assert json.loads(destination.read_text()) == {"ok": True}
    assert destination.stat().st_mode & 0o777 == 0o644
    assert not list(tmp_path.glob(".state.json.*"))


def test_control_lease_uses_scoped_bridge_network():
    completed = subprocess.CompletedProcess([], 0, "network-id\n", "")
    with patch.object(MODULE, "_docker_network_subnets", return_value=set()), \
         patch.object(MODULE.subprocess, "run", return_value=completed) as run:
        lease = MODULE.control_lease("a" * 24, "case-a", [])

    assert lease["network_name"].startswith("cvelab-agent-")
    create = run.call_args.args[0]
    assert create[:5] == ["docker", "network", "create", "--driver", "bridge"]
    assert "--internal" not in create


def test_live_output_streams_new_worker_log_lines(tmp_path, capsys):
    log_path = tmp_path / "worker.log"
    log_path.write_text("[1/5] Deploying...\npartial", encoding="utf-8")
    active = {"case-a": (None, 0.0, log_path)}
    positions = {}
    pending = {}

    MODULE._stream_log_updates(active, positions, pending)
    assert "[case-a] [1/5] Deploying..." in capsys.readouterr().out
    assert pending["case-a"] == "partial"

    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(" done\n")
    MODULE._stream_log_updates(active, positions, pending)
    assert "[case-a] partial done" in capsys.readouterr().out
