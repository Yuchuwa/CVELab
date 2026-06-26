"""Atomizer Pipeline 集成测试

测试完整的 atomizer 流程:
1. skip-agent 模式 (不需要 Docker/Agent)
2. 真实 vulhub 目录解析
3. 完整 Agent 模式 (需要 Docker + API key)

用法:
    # 单元测试
    uv run pytest tests/atomizer/test_pipeline.py -v -m unit

    # skip-agent 集成 (需要 vulhub 数据)
    uv run pytest tests/atomizer/test_pipeline.py -v -m integration

    # 完整 Agent 集成 (需要 Docker + .env)
    uv run pytest tests/atomizer/test_pipeline.py -v -m "integration and docker"
"""

import pytest
import yaml
import json
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

from clab_builder.atomizer.pipeline import AtomizerPipeline, AtomMeta
from clab_builder.atomizer.output.vulhub_converter import VulhubParser, container_port_from_spec

# 项目根目录
PROJECT_ROOT = Path(__file__).parent.parent.parent
VULHUB_DIR = PROJECT_ROOT / "data" / "vulhub"


# ── 单元测试 ────────────────────────────────────────────────────────


@pytest.mark.unit
class TestAtomMeta:
    """Atom 元数据测试"""

    def test_defaults(self):
        meta = AtomMeta(
            cve_id="CVE-2021-TEST",
            category="test",
            docker_image="test:latest",
            ports=[8080],
        )
        assert meta.verified is False
        assert meta.services == []
        assert meta.mitre_mapping == {}


@pytest.mark.unit
def test_save_init_files_copies_directory_volume_without_shutil_scope_error(tmp_path):
    """Directory volumes used to hit UnboundLocalError from a local shutil import."""
    cve_dir = tmp_path / "vulhub" / "test" / "CVE-2024-0001"
    www_dir = cve_dir / "www"
    www_dir.mkdir(parents=True)
    (www_dir / "index.php").write_text("ok")
    (cve_dir / "docker-compose.yml").write_text(
        yaml.dump({
            "services": {
                "web": {
                    "image": "vulhub/test:latest",
                    "ports": ["8080:80"],
                    "volumes": ["./www:/var/www/html"],
                }
            }
        })
    )
    (cve_dir / "README.md").write_text("# CVE-2024-0001\n")

    pipeline = AtomizerPipeline(vulhub_dir=str(cve_dir), output_dir=str(tmp_path / "atoms"))
    mapping = pipeline._save_init_files(tmp_path / "atoms" / "CVE-2024-0001")

    assert mapping["/var/www/html"] == "www"
    assert (tmp_path / "atoms" / "CVE-2024-0001" / "init" / "www" / "index.php").read_text() == "ok"


@pytest.mark.unit
def test_cleanup_compose_project_removes_orphans_and_project_networks(tmp_path):
    """Cleanup should target only the current compose project instead of global prune."""
    cve_dir = tmp_path / "vulhub" / "test" / "CVE-2024-0002"
    cve_dir.mkdir(parents=True)
    (cve_dir / "docker-compose.yml").write_text(
        yaml.dump({"services": {"web": {"image": "vulhub/test:latest", "ports": ["8080:80"]}}})
    )
    (cve_dir / "README.md").write_text("# CVE-2024-0002\n")
    pipeline = AtomizerPipeline(vulhub_dir=str(cve_dir), output_dir=str(tmp_path / "atoms"))

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:3] == ["docker", "ps", "-aq"]:
            return MagicMock(returncode=0, stdout="container-a\n", stderr="")
        if cmd[:3] == ["docker", "network", "ls"]:
            return MagicMock(returncode=0, stdout="net-a\nnet-b\n", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("clab_builder.atomizer.pipeline.subprocess.run", side_effect=fake_run):
        pipeline._cleanup_compose_project(cve_dir, "docker-compose.yml", "cve-2024-0002")

    assert [
        "docker", "compose", "-p", "cve-2024-0002", "-f", "docker-compose.yml",
        "down", "-v", "--remove-orphans",
    ] in calls
    assert [
        "docker", "network", "ls", "-q",
        "--filter", "label=com.docker.compose.project=cve-2024-0002",
    ] in calls
    assert ["docker", "rm", "-f", "container-a"] in calls
    assert ["docker", "network", "rm", "net-a"] in calls
    assert ["docker", "network", "rm", "net-b"] in calls


@pytest.mark.unit
def test_cleanup_stops_agent_before_removing_compose_network(tmp_path, monkeypatch):
    """The Agent must disconnect before Compose can remove its project network."""
    cve_dir = tmp_path / "vulhub" / "test" / "CVE-2024-0007"
    cve_dir.mkdir(parents=True)
    (cve_dir / "docker-compose.yml").write_text(
        yaml.dump({"services": {"web": {"image": "vulhub/test:latest"}}})
    )
    (cve_dir / "README.md").write_text("# CVE-2024-0007\n")
    pipeline = AtomizerPipeline(vulhub_dir=str(cve_dir), output_dir=str(tmp_path / "atoms"))
    events = []

    class FakeAgent:
        def stop(self):
            events.append("agent-stop")
            return True

    pipeline._agent = FakeAgent()
    monkeypatch.setattr(
        pipeline,
        "_cleanup_compose_project",
        lambda *args, **kwargs: events.append("compose-cleanup"),
    )
    monkeypatch.setattr(
        "clab_builder.atomizer.pipeline.subprocess.run",
        lambda *args, **kwargs: MagicMock(returncode=0, stdout="", stderr=""),
    )

    pipeline._cleanup()

    assert events == ["agent-stop", "compose-cleanup"]


@pytest.mark.unit
def test_cleanup_preserves_raw_record_local_image(tmp_path, monkeypatch):
    """Verified raw-record images are local artefacts and must never be auto-removed."""
    cve_dir = tmp_path / "generated" / "raw_records" / "CVE-2024-0010"
    cve_dir.mkdir(parents=True)
    (cve_dir / "docker-compose.yml").write_text(
        yaml.dump({"services": {"target": {"image": "cve-2024-0010:vuln"}}})
    )
    (cve_dir / "README.md").write_text("# CVE-2024-0010\n")
    pipeline = AtomizerPipeline(vulhub_dir=str(cve_dir), output_dir=str(tmp_path / "atoms"))
    calls = []
    monkeypatch.setattr(pipeline, "_cleanup_compose_project", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        "clab_builder.atomizer.pipeline.subprocess.run",
        lambda cmd, **kwargs: calls.append(cmd) or MagicMock(returncode=0, stdout="", stderr=""),
    )

    pipeline._cleanup()

    assert not any(cmd[:2] == ["docker", "rmi"] for cmd in calls)


@pytest.mark.unit
def test_start_environment_cleans_project_when_compose_up_fails(tmp_path):
    """A failed compose up can leave a network; clean it before surfacing the error."""
    cve_dir = tmp_path / "vulhub" / "test" / "CVE-2024-0004"
    cve_dir.mkdir(parents=True)
    (cve_dir / "docker-compose.yml").write_text(
        yaml.dump({"services": {"web": {"image": "vulhub/test:latest", "ports": ["8080:80"]}}})
    )
    (cve_dir / "README.md").write_text("# CVE-2024-0004\n")
    pipeline = AtomizerPipeline(vulhub_dir=str(cve_dir), output_dir=str(tmp_path / "atoms"))

    def fake_run(cmd, **kwargs):
        if cmd[:3] == ["docker", "image", "inspect"]:
            return MagicMock(returncode=0, stdout="", stderr="")
        if cmd[:5] == ["docker", "compose", "-p", "cve-2024-0004", "-f"]:
            return MagicMock(returncode=1, stdout="", stderr="network pool exhausted")
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch.object(pipeline, "_pull_image_with_retry"), \
         patch.object(pipeline, "_cleanup_compose_project") as cleanup, \
         patch("clab_builder.atomizer.pipeline.subprocess.run", side_effect=fake_run):
        with pytest.raises(RuntimeError, match="docker compose up failed"):
            pipeline._start_cve_environment()

    cleanup.assert_any_call(cve_dir.resolve(), ".compose-no-ports.yml", "cve-2024-0004",
                            context="pre-start")
    cleanup.assert_any_call(cve_dir.resolve(), ".compose-no-ports.yml", "cve-2024-0004",
                            context="compose-up-failed")


@pytest.mark.unit
def test_inspect_compose_services_retries_timeout(tmp_path, monkeypatch):
    """A transient Docker inspect timeout should be retried."""
    import subprocess as real_subprocess

    cve_dir = tmp_path / "vulhub" / "test" / "CVE-2024-0008"
    cve_dir.mkdir(parents=True)
    (cve_dir / "docker-compose.yml").write_text(
        yaml.dump({"services": {"web": {"image": "vulhub/test:latest"}}})
    )
    (cve_dir / "README.md").write_text("# CVE-2024-0008\n")
    pipeline = AtomizerPipeline(vulhub_dir=str(cve_dir), output_dir=str(tmp_path / "atoms"))
    inspect_payload = [{
        "Id": "abc123",
        "Name": "/web",
        "Config": {
            "Image": "vulhub/test:latest",
            "Labels": {"com.docker.compose.service": "web"},
        },
        "State": {"Running": True, "Status": "running", "ExitCode": 0},
        "NetworkSettings": {"Networks": {}, "Ports": {}},
    }]
    calls = {"inspect": 0}

    def fake_run(cmd, **kwargs):
        if cmd[:3] == ["docker", "ps", "-a"]:
            return MagicMock(returncode=0, stdout="abc123\n", stderr="")
        if cmd[:2] == ["docker", "inspect"]:
            calls["inspect"] += 1
            if calls["inspect"] == 1:
                raise real_subprocess.TimeoutExpired(cmd, 20)
            return MagicMock(returncode=0, stdout=json.dumps(inspect_payload), stderr="")
        raise AssertionError(cmd)

    monkeypatch.setattr("clab_builder.atomizer.pipeline.subprocess.run", fake_run)
    monkeypatch.setattr("clab_builder.atomizer.pipeline.time.sleep", lambda _: None)

    services = pipeline._inspect_compose_services("cve-2024-0008")

    assert calls["inspect"] == 2
    assert services[0]["running"] is True


@pytest.mark.unit
def test_validate_compose_services_accepts_successful_init_container(tmp_path, monkeypatch):
    """A named one-shot init dependency exiting 0 is a successful service state."""
    cve_dir = tmp_path / "vulhub" / "test" / "CVE-2024-0009"
    cve_dir.mkdir(parents=True)
    (cve_dir / "docker-compose.yml").write_text(
        yaml.dump({"services": {"web": {"image": "vulhub/test:latest"}}})
    )
    (cve_dir / "README.md").write_text("# CVE-2024-0009\n")
    pipeline = AtomizerPipeline(vulhub_dir=str(cve_dir), output_dir=str(tmp_path / "atoms"))
    monkeypatch.setattr(
        pipeline,
        "_inspect_compose_services",
        lambda _: [
            {
                "service": "web",
                "container_name": "app-web-1",
                "is_target": True,
                "running": True,
                "status": "running",
                "exit_code": 0,
                "health": "none",
            },
            {
                "service": "airflow-init",
                "container_name": "app-airflow-init-1",
                "is_target": False,
                "running": False,
                "status": "exited",
                "exit_code": 0,
                "health": "none",
            },
        ],
    )

    services = pipeline._validate_compose_services("app")

    assert len(services) == 2


@pytest.mark.unit
def test_container_port_from_compose_spec_accepts_protocol_suffixes():
    assert container_port_from_spec("2379/tcp") == 2379
    assert container_port_from_spec("127.0.0.1:8080:80/tcp") == 80
    assert container_port_from_spec({"target": 7001, "published": 17001}) == 7001
    assert container_port_from_spec("not-a-port") is None


@pytest.mark.unit
def test_run_agent_recreates_workspace_before_start(tmp_path, monkeypatch):
    """An interrupted run's output/session/cache must not leak into a retry."""
    from clab_builder.atomizer.agent.researcher import AgentOutput
    from clab_builder.atomizer.environment.container import ContainerInfo

    cve_dir = tmp_path / "vulhub" / "test" / "CVE-2024-0006"
    cve_dir.mkdir(parents=True)
    (cve_dir / "docker-compose.yml").write_text(
        yaml.dump({"services": {"web": {"image": "vulhub/test:latest", "ports": ["8080:80"]}}})
    )
    (cve_dir / "README.md").write_text("# CVE-2024-0006\n")
    workspace = tmp_path / "atoms" / "CVE-2024-0006" / ".workspace"
    (workspace / ".claude_cache").mkdir(parents=True)
    (workspace / "output.json").write_text('{"success": true}')
    (workspace / "session.json").write_text('{"old": true}\n')
    (workspace / ".claude_cache" / "old.jsonl").write_text('{"old": true}\n')

    class FakeAgent:
        def __init__(self, **kwargs):
            pass

        def start(self, **kwargs):
            assert not (workspace / "output.json").exists()
            assert not (workspace / "session.json").exists()
            assert not (workspace / ".claude_cache" / "old.jsonl").exists()

        def run(self, cve_input, workspace_dir):
            return AgentOutput(
                cve_id=cve_input.cve_id,
                success=False,
                exploit_steps=[],
                evidence=["new run"],
                mitre_mapping={},
            )

        def stop(self):
            return True

    monkeypatch.setattr("clab_builder.atomizer.pipeline.SecurityResearcherAgent", FakeAgent)
    pipeline = AtomizerPipeline(vulhub_dir=str(cve_dir), output_dir=str(tmp_path / "atoms"))
    info = ContainerInfo(
        container_id="fake",
        container_name="fake",
        container_ip="172.18.0.2",
        image_name="vulhub/test:latest",
        ports=[80],
        status="running",
        created_time="now",
    )

    result = pipeline._run_agent(info, workspace, api_key="key", base_url="", model="model")

    assert result.evidence == ["new run"]


@pytest.mark.unit
def test_missing_env_file_is_materialized_from_readme(tmp_path):
    """Vulhub samples that require manual .env should not fail compose parsing."""
    cve_dir = tmp_path / "vulhub" / "phpmailer" / "CVE-2024-0003"
    cve_dir.mkdir(parents=True)
    (cve_dir / "docker-compose.yml").write_text(
        yaml.dump({
            "services": {
                "web": {
                    "image": "vulhub/phpmailer:test",
                    "ports": ["8080:80"],
                    "env_file": [".env"],
                }
            }
        })
    )
    (cve_dir / "README.md").write_text(
        "# CVE-2024-0003\n\n"
        "```env\n"
        "SMTP_SERVER=smtp.example.com\n"
        "SMTP_PORT=587\n"
        "SMTP_EMAIL=your_email@example.com\n"
        "SMTP_PASSWORD=secret\n"
        "```\n"
    )
    pipeline = AtomizerPipeline(vulhub_dir=str(cve_dir), output_dir=str(tmp_path / "atoms"))
    svc = {"env_file": [".env"]}

    pipeline._materialize_missing_env_files("web", svc, cve_dir)

    generated = Path(svc["env_file"][0])
    assert generated.exists()
    assert generated.parent.name == ".atomizer-env"
    assert "SMTP_SERVER=smtp.example.com" in generated.read_text()


# ── 集成测试: skip-agent 模式 ──────────────────────────────────────


@pytest.mark.integration
class TestPipelineSkipAgent:
    """Pipeline skip-agent 模式测试 (不需要 Docker)"""

    @pytest.fixture
    def log4j_dir(self):
        """Log4j CVE 目录"""
        path = VULHUB_DIR / "log4j" / "CVE-2021-44228"
        if not path.exists():
            pytest.skip("vulhub data not found")
        return str(path)

    @pytest.fixture
    def phpmyadmin_dir(self):
        """phpMyAdmin CVE 目录"""
        path = VULHUB_DIR / "phpmyadmin" / "CVE-2018-12613"
        if not path.exists():
            pytest.skip("vulhub data not found")
        return str(path)

    def test_parse_log4j(self, log4j_dir):
        """解析 Log4j vulhub 目录"""
        env = VulhubParser().parse(log4j_dir)
        assert env.cve_id == "CVE-2021-44228"
        assert env.category == "log4j"
        assert len(env.services) >= 1
        assert env.main_image.startswith("vulhub/")
        assert len(env.main_ports) >= 1
        assert env.readme_content  # 应该有 README

    def test_parse_phpmyadmin(self, phpmyadmin_dir):
        """解析 phpMyAdmin vulhub 目录（多服务）"""
        env = VulhubParser().parse(phpmyadmin_dir)
        assert env.cve_id == "CVE-2018-12613"
        assert len(env.services) == 2  # mysql + web
        assert env.main_service.name == "web"

    def test_skip_agent_generates_atom(self, log4j_dir, tmp_path):
        """skip-agent 模式生成完整 atom 目录"""
        output_dir = tmp_path / "atoms"
        pipeline = AtomizerPipeline(
            vulhub_dir=log4j_dir,
            output_dir=str(output_dir),
        )

        # Mock _start_cve_environment 返回假容器信息
        from clab_builder.atomizer.environment.container import ContainerInfo
        fake_info = ContainerInfo(
            container_id="fake123",
            container_name="fake-solr",
            container_ip="172.18.0.2",
            image_name="vulhub/log4j:2.14.1",
            ports=[8983],
            status="running",
            created_time="2026-01-01 00:00:00",
        )

        with patch.object(pipeline, "_start_cve_environment", return_value=(fake_info, "cve-network")), \
             patch.object(pipeline, "_cleanup"):
            result = pipeline.run(skip_agent=True)

        assert result["success"] is True
        assert result["agent_skipped"] is True
        assert result["cve_id"] == "CVE-2021-44228"

        # 检查生成的文件
        atom_dir = output_dir / "CVE-2021-44228"
        assert (atom_dir / "atom.yaml").exists()
        assert (atom_dir / "ansible" / "deploy.yaml").exists()

        # 验证 atom.yaml
        atom_data = yaml.safe_load((atom_dir / "atom.yaml").read_text())
        assert atom_data["cve_id"] == "CVE-2021-44228"
        assert atom_data["verified"] is False

        # 验证 ansible/deploy.yaml 是合法 YAML
        playbook = yaml.safe_load((atom_dir / "ansible" / "deploy.yaml").read_text())
        assert len(playbook) == 1
        assert playbook[0]["name"] == "Deploy CVE-2021-44228"
        assert len(playbook[0]["tasks"]) >= 2  # 网络 + 容器

    def test_skip_agent_multi_service(self, phpmyadmin_dir, tmp_path):
        """skip-agent 模式处理多服务环境"""
        output_dir = tmp_path / "atoms"

        pipeline = AtomizerPipeline(
            vulhub_dir=phpmyadmin_dir,
            output_dir=str(output_dir),
        )

        from clab_builder.atomizer.environment.container import ContainerInfo
        fake_info = ContainerInfo(
            container_id="fake456",
            container_name="fake-web",
            container_ip="172.18.0.3",
            image_name="vulhub/phpmyadmin:4.8.1",
            ports=[8080],
            status="running",
            created_time="2026-01-01 00:00:00",
        )

        with patch.object(pipeline, "_start_cve_environment", return_value=(fake_info, "cve-network")), \
             patch.object(pipeline, "_cleanup"):
            result = pipeline.run(skip_agent=True)

        assert result["success"] is True

        # 多服务 ansible
        playbook = yaml.safe_load(
            (output_dir / "CVE-2018-12613" / "ansible" / "deploy.yaml").read_text()
        )
        task_names = [t["name"] for t in playbook[0]["tasks"]]
        assert any("mysql" in n for n in task_names)
        assert any("web" in n for n in task_names)


# ── 集成测试: 完整 Agent 模式 ──────────────────────────────────────


@pytest.mark.integration
@pytest.mark.docker
class TestPipelineFullAgent:
    """完整 Agent 流程测试 (需要 Docker + API key + clab-agent 镜像)"""

    @pytest.fixture(autouse=True)
    def check_docker(self):
        """检查 Docker 和 clab-agent 镜像"""
        import subprocess
        try:
            subprocess.run(["docker", "--version"], capture_output=True, check=True, timeout=5)
        except Exception:
            pytest.skip("Docker not available")

        result = subprocess.run(
            ["docker", "images", "-q", "clab-agent:latest"],
            capture_output=True, text=True,
        )
        if not result.stdout.strip():
            pytest.skip("clab-agent image not built. Run: cd docker && bash build.sh")

    @pytest.fixture
    def log4j_dir(self):
        path = VULHUB_DIR / "log4j" / "CVE-2021-44228"
        if not path.exists():
            pytest.skip("vulhub data not found")
        return str(path)

    @pytest.fixture
    def api_key(self):
        """从 .env 文件读取 API key"""
        env_file = PROJECT_ROOT / ".env"
        if env_file.exists():
            for line in env_file.read_text().splitlines():
                if line.startswith("API_KEY="):
                    return line.split("=", 1)[1].strip()
        key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("LLM_API_KEY")
        if not key:
            pytest.skip("No API key found. Set API_KEY in .env")
        return key

    def test_full_agent_flow(self, log4j_dir, api_key, tmp_path):
        """完整 Agent 流程: vulhub → ansible → agent → SysField playbook"""
        output_dir = tmp_path / "atoms"

        pipeline = AtomizerPipeline(
            vulhub_dir=log4j_dir,
            output_dir=str(output_dir),
        )

        result = pipeline.run(
            api_key=api_key,
            model="claude-sonnet-4-20250514",
        )

        # Agent 可能成功也可能失败，但流程应该完整
        assert "cve_id" in result
        assert result["cve_id"] == "CVE-2021-44228"

        atom_dir = output_dir / "CVE-2021-44228"
        assert (atom_dir / "atom.yaml").exists()
        assert (atom_dir / "ansible" / "deploy.yaml").exists()

        if result["success"]:
            # Agent 成功 → 应有 SysField playbook
            assert (atom_dir / "playbook" / "sysfield.yaml").exists()
            atom_data = yaml.safe_load((atom_dir / "atom.yaml").read_text())
            assert atom_data["verified"] is True

            # 验证 SysField playbook 结构
            playbook = yaml.safe_load(
                (atom_dir / "playbook" / "sysfield.yaml").read_text()
            )
            assert "playbook" in playbook
            assert "steps" in playbook
