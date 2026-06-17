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
from clab_builder.atomizer.output.vulhub_converter import VulhubParser

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
