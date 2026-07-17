from pathlib import Path

import yaml

from clab_builder.orchestrator.composer.sysfield_runner import SysFieldRunner


def _scenario(tmp_path: Path) -> Path:
    scenario = tmp_path / "scenario"
    scenario.mkdir()
    (scenario / "clab.yaml").write_text(
        yaml.safe_dump({"name": "demo", "topology": {"nodes": {}}})
    )
    playbook = scenario / "sysfield" / "playbook.yaml"
    playbook.parent.mkdir()
    playbook.write_text(
        "playbook: {id: demo}\n"
        "steps: [{id: objective, executor: {command: 'true'}}]\n"
        "reference_objective: {step: objective}\n"
    )
    return scenario


def test_runner_reuses_deployed_topology(monkeypatch, tmp_path):
    scenario = _scenario(tmp_path)
    calls = []

    class Result:
        returncode = 0
        stdout = '{"step_id":"objective","status":"PASS","exit_code":0}\nSteps: 1/1 succeeded'
        stderr = ""

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return Result()

    monkeypatch.setattr(
        "clab_builder.orchestrator.composer.sysfield_runner.subprocess.run",
        fake_run,
    )
    result = SysFieldRunner(binary="sysfield-test").run(str(scenario))

    assert result["ok"] is True
    command = calls[0][0]
    assert command[:2] == ["sysfield-test", "run"]
    assert "--topology-name" in command
    assert "demo" in command
    assert "--no-monitor" in command
    assert "--keep-topology" in command


def test_runner_fails_when_playbook_missing(tmp_path):
    scenario = tmp_path / "scenario"
    scenario.mkdir()
    (scenario / "clab.yaml").write_text(
        yaml.safe_dump({"name": "demo", "topology": {"nodes": {}}})
    )

    result = SysFieldRunner(binary="sysfield-test").run(str(scenario))

    assert result["ok"] is False
    assert "playbook" in result["error"]
