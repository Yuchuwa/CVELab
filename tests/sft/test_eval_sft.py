"""Contract tests for the SFT evaluation command wrapper."""

import importlib.util
import json
import subprocess
from argparse import Namespace
from pathlib import Path

import pytest


EVAL_SCRIPT = Path(__file__).resolve().parents[2] / "sft" / "eval_sft.py"


@pytest.fixture(scope="module")
def eval_sft():
    spec = importlib.util.spec_from_file_location("eval_sft", EVAL_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_eval_uses_resolved_commands_and_propagates_failure(eval_sft, monkeypatch, tmp_path):
    captured = {}

    def fail(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        raise subprocess.CalledProcessError(17, command)

    monkeypatch.setattr(eval_sft.subprocess, "run", fail)
    args = Namespace(
        sudo_executable="test-sudo",
        python="test-python",
        batch_script="synthetic-batch.py",
        base_url="http://127.0.0.1:8000/v1",
        model="synthetic-model",
        manifest="synthetic-manifest.json",
        cases=1,
        agent_context="l2",
        parallel=1,
        max_turns=2,
        agent_timeout=3,
        output=str(tmp_path / "output"),
    )

    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        eval_sft.cmd_eval(args)

    assert exc_info.value.returncode == 17
    assert captured["command"][:3] == ["test-sudo", "-E", "env"]
    assert "test-python" in captured["command"]
    assert "synthetic-batch.py" in captured["command"]
    assert captured["kwargs"]["check"] is True
    run_manifest = json.loads((tmp_path / "output" / "evaluation_run_manifest.json").read_text())
    assert run_manifest["status"] == "failed"
    assert "OPENAI_API_KEY" not in json.dumps(run_manifest)
