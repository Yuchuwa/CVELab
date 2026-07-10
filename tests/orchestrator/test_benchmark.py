"""Tests for benchmark runner components."""

import json
import importlib.util
from pathlib import Path

import yaml

from clab_builder.orchestrator.benchmark import AgentSpec, BenchmarkRunner, score_agent_result


def _write_scenario(path: Path):
    path.mkdir(parents=True)
    (path / "clab.yaml").write_text(
        yaml.dump({
            "name": "bench-test",
            "topology": {
                "nodes": {
                    "attacker": {"kind": "linux", "image": "clab-agent:latest"},
                    "target-1": {"kind": "linux", "image": "vulhub/test:latest"},
                },
                "links": [{"endpoints": ["attacker:eth1", "target-1:eth1"]}],
            },
        })
    )
    (path / "ground_truth.json").write_text(json.dumps({
        "scenario": "bench-test",
        "attack_path": [
            {
                "target_node": "target-1",
                "target_ip": "192.168.1.2",
                "flag": "flag{abc}",
                "cve_id": "CVE-TEST-0001",
            }
        ],
    }))
    (path / "scenario.yaml").write_text(yaml.dump({
        "ip_allocations": {
            "attacker": {"eth1": "192.168.1.1/24"},
            "target-1": {"eth1": "192.168.1.2/24"},
        }
    }))
    (path / "ansible").mkdir()


def test_agent_spec_loads_wrapped_yaml(tmp_path):
    spec_path = tmp_path / "agent.yaml"
    spec_path.write_text(yaml.dump({
        "agent": {
            "name": "unit-agent",
            "command": "python run.py",
            "env": {"MODEL": "test"},
            "timeout_seconds": 60,
        }
    }))

    spec = AgentSpec.load(spec_path)
    assert spec.name == "unit-agent"
    assert spec.command == "python run.py"
    assert spec.env["MODEL"] == "test"
    assert spec.output_contract.path == "/tmp/cvelab_agent_output.json"


def test_agent_spec_loads_env_from_host():
    spec = AgentSpec.load("examples/agents/claude-sdk-agent.yaml")
    assert spec.name == "claude-sdk-agent"
    assert spec.task_view == "entry_ip"
    assert "ANTHROPIC_AUTH_TOKEN" in spec.env_from_host
    assert "ANTHROPIC_API_KEY" in spec.env_from_host
    assert spec.files[0].target == "/workspace/claude-sdk-benchmark-agent.py"


def test_score_agent_result_accepts_verified_flags():
    result = score_agent_result(
        {"verified_flags": {"target-1": "flag{abc}"}},
        {"attack_path": [{"target_node": "target-1", "flag": "flag{abc}"}]},
    )
    assert result["all_captured"] is True
    assert result["score"] == 1.0


def test_score_agent_result_partial_capture():
    result = score_agent_result(
        {"flags": {"target-1": "flag{abc}"}},
        {
            "attack_path": [
                {"target_node": "target-1", "flag": "flag{abc}"},
                {"target_node": "target-2", "flag": "flag{def}"},
            ]
        },
    )
    assert result["all_captured"] is False
    assert result["captured"] == 1
    assert result["total"] == 2


class _FakeRunner(BenchmarkRunner):
    def _deploy(self):
        self.deployed = True

    def _destroy(self):
        self.destroyed = True

    def _run_ansible(self, playbook: str):
        return None

    def _run_agent(self):
        return {"verified_flags": {"target-1": "flag{abc}"}, "success": True}


def test_benchmark_runner_writes_result(tmp_path):
    scenario_dir = tmp_path / "scenario"
    _write_scenario(scenario_dir)
    spec = AgentSpec(name="fake", command="true")

    runner = _FakeRunner(
        scenario_dir=str(scenario_dir),
        agent_spec=spec,
        runs_dir=str(tmp_path / "runs"),
        skip_runtime_validation=True,
    )
    result = runner.run()

    assert result["success"] is True
    assert result["score"]["captured"] == 1
    assert Path(result["run_dir"], "benchmark_result.json").exists()
    assert Path(result["run_dir"], "agent_spec.yaml").exists()


def test_runner_extracts_json_from_stdout(tmp_path):
    scenario_dir = tmp_path / "scenario"
    _write_scenario(scenario_dir)
    runner = BenchmarkRunner(
        scenario_dir=str(scenario_dir),
        agent_spec=AgentSpec(name="fake", command="true"),
        runs_dir=str(tmp_path / "runs"),
        skip_deploy=True,
        skip_runtime_validation=True,
    )

    data = runner._extract_json('noise\n```json\n{"verified_flags": {"target-1": "flag{abc}"}}\n```')
    assert data["verified_flags"]["target-1"] == "flag{abc}"


def test_runner_public_task_does_not_expose_flags(tmp_path):
    scenario_dir = tmp_path / "scenario"
    _write_scenario(scenario_dir)
    runner = BenchmarkRunner(
        scenario_dir=str(scenario_dir),
        agent_spec=AgentSpec(name="fake", command="true"),
        runs_dir=str(tmp_path / "runs"),
        skip_deploy=True,
        skip_runtime_validation=True,
    )

    task = runner._public_attack_path()
    assert task[0]["target_node"] == "target-1"
    assert "flag" not in task[0]


def test_entry_ip_task_view_only_exposes_ip(tmp_path):
    scenario_dir = tmp_path / "scenario"
    _write_scenario(scenario_dir)
    runner = BenchmarkRunner(
        scenario_dir=str(scenario_dir),
        agent_spec=AgentSpec(name="fake", command="true", task_view="entry_ip"),
        runs_dir=str(tmp_path / "runs"),
        skip_deploy=True,
        skip_runtime_validation=True,
    )

    assert runner._task_input() == {"ip": "192.168.1.2"}


def test_agent_env_passes_host_values(tmp_path, monkeypatch):
    scenario_dir = tmp_path / "scenario"
    _write_scenario(scenario_dir)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    spec = AgentSpec(
        name="fake",
        command="true",
        env={"STATIC": "1"},
        env_from_host=["ANTHROPIC_API_KEY", "MISSING_ENV"],
    )
    runner = BenchmarkRunner(
        scenario_dir=str(scenario_dir),
        agent_spec=spec,
        runs_dir=str(tmp_path / "runs"),
        skip_deploy=True,
        skip_runtime_validation=True,
    )

    env = runner._agent_env()
    assert env["STATIC"] == "1"
    assert env["ANTHROPIC_API_KEY"] == "test-key"
    assert "MISSING_ENV" not in env
    assert "CVELAB_SCENARIO" not in env


def test_agent_env_maps_llm_env_to_anthropic(tmp_path, monkeypatch):
    scenario_dir = tmp_path / "scenario"
    _write_scenario(scenario_dir)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("LLM_API_KEY", "llm-key")
    monkeypatch.setenv("LLM_BASE_URL", "https://llm.example")
    monkeypatch.setenv("LLM_MODEL", "test-model")
    runner = BenchmarkRunner(
        scenario_dir=str(scenario_dir),
        agent_spec=AgentSpec(name="fake", command="true"),
        runs_dir=str(tmp_path / "runs"),
        skip_deploy=True,
        skip_runtime_validation=True,
    )
    runner._claude_settings_env = lambda: {}

    env = runner._agent_env()
    assert env["ANTHROPIC_API_KEY"] == "llm-key"
    assert env["ANTHROPIC_BASE_URL"] == "https://llm.example"
    assert env["MODEL"] == "test-model"


def test_agent_env_prefers_claude_settings_auth_token(tmp_path, monkeypatch):
    scenario_dir = tmp_path / "scenario"
    _write_scenario(scenario_dir)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
    monkeypatch.setenv("LLM_API_KEY", "openai-style-key")
    monkeypatch.setenv("LLM_BASE_URL", "https://openai-compatible.example")
    runner = BenchmarkRunner(
        scenario_dir=str(scenario_dir),
        agent_spec=AgentSpec(name="fake", command="true"),
        runs_dir=str(tmp_path / "runs"),
        skip_deploy=True,
        skip_runtime_validation=True,
    )
    runner._claude_settings_env = lambda: {
        "ANTHROPIC_AUTH_TOKEN": "claude-token",
        "ANTHROPIC_BASE_URL": "https://anthropic-compatible.example",
        "ANTHROPIC_DEFAULT_SONNET_MODEL": "claude-model",
    }

    env = runner._agent_env()

    assert env["ANTHROPIC_AUTH_TOKEN"] == "claude-token"
    assert env["ANTHROPIC_BASE_URL"] == "https://anthropic-compatible.example"
    assert env["MODEL"] == "claude-model"
    assert "ANTHROPIC_API_KEY" not in env


def test_claude_sdk_agent_extract_json():
    module_path = Path("examples/agents/claude-sdk-benchmark-agent.py")
    spec = importlib.util.spec_from_file_location("claude_sdk_benchmark_agent", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    data = module.extract_json(
        'notes\n```json\n{"success": true, "verified_flags": {"target-1": "flag{abc}"}}\n```'
    )
    assert data["verified_flags"]["target-1"] == "flag{abc}"


def test_claude_sdk_agent_entry_ip_prompt_is_minimal():
    module_path = Path("examples/agents/claude-sdk-benchmark-agent.py")
    spec = importlib.util.spec_from_file_location("claude_sdk_benchmark_agent", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    prompt = module.build_prompt({"ip": "192.168.1.2"})
    assert "192.168.1.2" in prompt
    assert "CVE-" not in prompt
    assert "attack_path" not in prompt
    assert "flag{" not in prompt


def test_claude_sdk_agent_disables_external_and_task_tools():
    module_path = Path("examples/agents/claude-sdk-benchmark-agent.py")
    spec = importlib.util.spec_from_file_location("claude_sdk_benchmark_agent", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert "WebSearch" in module.DISALLOWED_TOOLS
    assert "WebFetch" in module.DISALLOWED_TOOLS
    assert "TaskCreate" in module.DISALLOWED_TOOLS
    assert "TaskUpdate" in module.DISALLOWED_TOOLS
    assert "TaskOutput" in module.DISALLOWED_TOOLS


class _ArtifactRunner(BenchmarkRunner):
    def _copy_from_container(self, container: str, src: str, dst: Path) -> bool:
        self.copied.append((container, src, dst.name))
        return True


def test_runner_collects_partial_claude_artifacts(tmp_path):
    scenario_dir = tmp_path / "scenario"
    _write_scenario(scenario_dir)
    spec = AgentSpec(
        name="fake",
        command="true",
        env={"CLAUDE_CONFIG_DIR": "/workspace/.claude"},
    )
    runner = _ArtifactRunner(
        scenario_dir=str(scenario_dir),
        agent_spec=spec,
        runs_dir=str(tmp_path / "runs"),
        skip_deploy=True,
        skip_runtime_validation=True,
    )
    runner.copied = []

    runner._collect_agent_artifacts("attacker")

    copied_sources = {src for _, src, _ in runner.copied}
    assert "/tmp/cvelab_agent_session.json" in copied_sources
    assert "/workspace/.claude/projects" in copied_sources
    assert "/tmp/claude-1000" in copied_sources
