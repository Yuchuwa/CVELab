"""Researcher 容器管理单元测试

测试 SecurityResearcherAgent 的容器生命周期逻辑（mock docker）。
"""

import pytest
import json
import os
import subprocess as real_subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

from clab_builder.atomizer.agent.researcher import (
    SecurityResearcherAgent,
    CVEInput,
    AgentOutput,
    AGENT_RUNNER_SRC,
)


@pytest.mark.unit
class TestCVEInput:
    """CVEInput 数据类测试"""

    def test_defaults(self):
        inp = CVEInput(cve_id="CVE-2021-TEST", description="test",
                       target_ip="10.0.0.1", target_ports=[80])
        assert inp.writeup == ""
        assert inp.exploit_files == {}
        assert inp.environment_context == {}
        assert inp.exploit_guidance == ""

    def test_with_exploit_files(self):
        inp = CVEInput(cve_id="CVE-2021-TEST", description="test",
                       target_ip="10.0.0.1", target_ports=[80],
                       exploit_files={"poc.py": "code"})
        assert inp.exploit_files["poc.py"] == "code"


@pytest.mark.unit
class TestAgentRunnerSrc:
    """验证 agent_runner.py 源文件路径"""

    def test_exists(self):
        assert AGENT_RUNNER_SRC.exists()
        assert AGENT_RUNNER_SRC.name == "agent_runner.py"


@pytest.mark.unit
class TestSecurityResearcherAgent:
    """容器生命周期管理测试（mock subprocess）"""

    @patch("clab_builder.atomizer.agent.researcher.subprocess")
    def test_start_basic(self, mock_subprocess):
        """基本启动"""
        mock_subprocess.run.return_value = MagicMock(returncode=0, stdout="abc123\n")

        agent = SecurityResearcherAgent()
        assert agent.max_turns == 80
        cid = agent.start("cve-network", "/tmp/workspace", "sk-test-key")

        assert cid == "abc123"
        assert agent.container_id == "abc123"

        # 验证 docker run 命令
        call_args = mock_subprocess.run.call_args_list[-1]
        cmd = call_args[0][0]
        assert "docker" in cmd
        assert "run" in cmd
        assert "--network=cve-network" in cmd
        assert "--user" not in cmd
        assert "HOME=/home/agent" in cmd
        assert "--cap-add" in cmd
        assert "NET_RAW" in cmd
        assert "NET_ADMIN" in cmd
        # agent_runner.py 挂载到 /opt/agent_runner.py
        assert any("/opt/agent_runner.py:ro" in arg for arg in cmd)
        # API key 作为 ANTHROPIC_API_KEY
        assert "ANTHROPIC_API_KEY=sk-test-key" in cmd

    @patch("clab_builder.atomizer.agent.researcher.subprocess")
    def test_custom_max_turns(self, mock_subprocess):
        """自定义 max_turns 传递到 docker exec 命令"""
        agent = SecurityResearcherAgent(max_turns=10)
        assert agent.max_turns == 10

        # 验证参数构建（不实际执行 run）
        expected_args = [
            "docker", "exec", agent.container_name,
            "python3", "/opt/agent_runner.py",
            "--input", "/workspace/input.json",
            "--output", "/workspace/output.json",
            "--max-turns", "10",
        ]
        import subprocess as real_subprocess
        # 检查参数格式正确
        assert expected_args[-1] == "10"
        assert expected_args[-2] == "--max-turns"

    @patch("clab_builder.atomizer.agent.researcher.subprocess")
    def test_start_with_base_url_and_model(self, mock_subprocess):
        """带 base_url 和 model 启动"""
        mock_subprocess.run.return_value = MagicMock(returncode=0, stdout="abc\n")

        agent = SecurityResearcherAgent()
        agent.start("net", "/tmp/ws", "key",
                    base_url="https://api.example.com", model="gpt-4")

        call_args = mock_subprocess.run.call_args_list[-1]
        cmd = call_args[0][0]
        assert "ANTHROPIC_BASE_URL=https://api.example.com" in cmd
        assert "MODEL=gpt-4" in cmd

    @patch("clab_builder.atomizer.agent.researcher.time.sleep")
    @patch("clab_builder.atomizer.agent.researcher.subprocess")
    def test_start_retries_docker_run_timeout(self, mock_subprocess, mock_sleep, tmp_path):
        """A transient Docker daemon timeout should not fail the task immediately."""
        mock_subprocess.TimeoutExpired = real_subprocess.TimeoutExpired
        mock_subprocess.run.side_effect = [
            MagicMock(returncode=0, stdout="", stderr=""),  # initial stale removal
            real_subprocess.TimeoutExpired(["docker", "run"], 60),
            MagicMock(returncode=1, stdout="", stderr="not found"),  # inspect 1
            MagicMock(returncode=1, stdout="", stderr="not found"),  # inspect 2
            MagicMock(returncode=1, stdout="", stderr="not found"),  # inspect 3
            MagicMock(returncode=0, stdout="", stderr=""),  # retry cleanup
            MagicMock(returncode=0, stdout="abc123\n", stderr=""),
        ]

        agent = SecurityResearcherAgent()
        cid = agent.start("net", str(tmp_path), "key")

        assert cid == "abc123"
        assert mock_sleep.call_count == 3

    @patch("clab_builder.atomizer.agent.researcher.subprocess")
    def test_start_adopts_container_created_during_timeout(self, mock_subprocess, tmp_path):
        """Do not rerun docker run when the timed-out call actually created the container."""
        mock_subprocess.TimeoutExpired = real_subprocess.TimeoutExpired
        mock_subprocess.run.side_effect = [
            MagicMock(returncode=0, stdout="", stderr=""),  # initial stale removal
            real_subprocess.TimeoutExpired(["docker", "run"], 60),
            MagicMock(returncode=0, stdout="abc123\tcreated\n", stderr=""),
            MagicMock(returncode=0, stdout="agent-name\n", stderr=""),
        ]

        agent = SecurityResearcherAgent()
        cid = agent.start("net", str(tmp_path), "key")

        assert cid == "abc123"
        assert agent.container_id == "abc123"
        commands = [call.args[0] for call in mock_subprocess.run.call_args_list]
        assert sum(cmd[:2] == ["docker", "run"] for cmd in commands) == 1
        assert ["docker", "start", agent.container_name] in commands

    @patch("clab_builder.atomizer.agent.researcher.subprocess")
    def test_run_success(self, mock_subprocess, tmp_path):
        """Agent 执行成功"""
        # docker exec 成功
        mock_subprocess.run.return_value = MagicMock(returncode=0, stderr="")

        agent = SecurityResearcherAgent()
        agent.container_name = "test-container"
        agent.container_id = "fake"

        # 写 output.json
        output = {
            "success": True,
            "evidence": ["proof"],
            "exploit_steps": [{"name": "step1", "command": "cmd"}],
            "mitre_mapping": {"initial_access": ["T1190"]},
        }
        (tmp_path / "output.json").write_text(json.dumps(output))

        cve_input = CVEInput(
            cve_id="CVE-2021-TEST", description="test",
            target_ip="10.0.0.1", target_ports=[80],
        )
        result = agent.run(cve_input, str(tmp_path))

        assert result.success is True
        assert result.cve_id == "CVE-2021-TEST"
        assert len(result.exploit_steps) == 1
        assert result.evidence == ["proof"]

        # 验证 input.json 被写入
        input_data = json.loads((tmp_path / "input.json").read_text())
        assert input_data["cve_id"] == "CVE-2021-TEST"
        assert input_data["environment_context"] == {}
        assert input_data["exploit_guidance"] == ""

    @patch("clab_builder.atomizer.agent.researcher.subprocess")
    def test_run_agent_failure(self, mock_subprocess, tmp_path):
        """Agent 执行失败"""
        mock_subprocess.run.return_value = MagicMock(
            returncode=1, stderr="Error: something failed"
        )

        agent = SecurityResearcherAgent()
        agent.container_name = "test-container"
        agent.container_id = "fake"

        cve_input = CVEInput(
            cve_id="CVE-2021-TEST", description="test",
            target_ip="10.0.0.1", target_ports=[80],
        )
        result = agent.run(cve_input, str(tmp_path))

        assert result.success is False
        assert "failed" in result.evidence[0].lower()

    @patch("clab_builder.atomizer.agent.researcher.subprocess")
    def test_stop(self, mock_subprocess):
        """停止容器"""
        mock_subprocess.run.return_value = MagicMock(returncode=0, stderr="")

        agent = SecurityResearcherAgent()
        agent.container_id = "fake123"

        agent.stop()
        assert agent.container_id is None
        mock_subprocess.run.assert_called()

    @patch("clab_builder.atomizer.agent.researcher.subprocess")
    def test_stop_timeout_is_best_effort(self, mock_subprocess):
        """docker rm timeout should not mask the original agent failure."""
        mock_subprocess.TimeoutExpired = real_subprocess.TimeoutExpired
        mock_subprocess.run.side_effect = real_subprocess.TimeoutExpired(
            ["docker", "rm", "-f", "test-container"], 30
        )

        agent = SecurityResearcherAgent()
        agent.container_name = "test-container"
        agent.container_id = "fake123"

        assert agent.stop(timeout=30) is False
        assert agent.container_id == "fake123"

    @patch("clab_builder.atomizer.agent.researcher.subprocess")
    def test_stop_removes_container_even_without_container_id(self, mock_subprocess):
        """A docker run timeout may create a named container before returning its id."""
        mock_subprocess.run.return_value = MagicMock(returncode=0, stdout="removed\n", stderr="")
        agent = SecurityResearcherAgent()
        agent.container_name = "agent-created-only"
        agent.container_id = None

        assert agent.stop() is True
        mock_subprocess.run.assert_called_with(
            ["docker", "rm", "-f", "agent-created-only"],
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_recover_native_session_from_workspace_cache(self, tmp_path):
        """A killed runner should not lose the SDK session already on the host."""
        older = tmp_path / ".claude_cache" / "projects" / "old.jsonl"
        newer = tmp_path / ".claude_cache" / "projects" / "nested" / "new.jsonl"
        older.parent.mkdir(parents=True)
        newer.parent.mkdir(parents=True)
        older.write_text('{"session":"old"}\n')
        newer.write_text('{"session":"new"}\n')
        older.touch()
        newer.touch()
        os.utime(older, (1, 1))
        os.utime(newer, (2, 2))

        recovered = SecurityResearcherAgent._recover_native_session(tmp_path)

        assert recovered == tmp_path / "session.json"
        assert recovered.read_text() == '{"session":"new"}\n'
