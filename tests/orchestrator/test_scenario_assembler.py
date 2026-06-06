"""Tests for Scenario Assembler"""

import json
import pytest
import yaml
from pathlib import Path

from clab_builder.shared.models.atom import (
    AtomConfig, VulnCategory, MitrePhase, ServiceRole,
    ExploitComplexity, AttackMethod, ServiceInfo, FlagInjection,
    ServiceStartup, NetworkRequirements,
)
from clab_builder.shared.models.template import InjectionPoint
from clab_builder.orchestrator.composer.scenario_assembler import (
    ScenarioAssembler, _generate_flag, _generate_scenario_hash,
)
from clab_builder.orchestrator.composer.template_loader import TemplateLoader


def _make_atom(cve_id="CVE-TEST-0001", ports=None) -> AtomConfig:
    return AtomConfig(
        cve_id=cve_id,
        category="test",
        docker_image="vulhub/test:latest",
        ports=ports or [8080],
        services=[ServiceInfo(name="web", image="vulhub/test:latest")],
        vuln_category=VulnCategory.RCE,
        primary_mitre_phase=MitrePhase.INITIAL_ACCESS,
        service_role=ServiceRole.WEB_APPLICATION,
        exploit_complexity=ExploitComplexity.SIMPLE,
        attack_method=AttackMethod.SINGLE_REQUEST,
        flag_injection=FlagInjection(method="env_var", env_var_name="FLAG"),
        service_startup=ServiceStartup(wait_seconds=5),
        verified=True,
    )


class TestHelpers:
    def test_generate_flag_format(self):
        flag = _generate_flag()
        assert flag.startswith("flag{")
        assert flag.endswith("}")
        # 16 bytes hex = 32 chars + 5 for "flag{" + 1 for "}" = 38
        assert len(flag) == 38

    def test_generate_flag_unique(self):
        flags = {_generate_flag() for _ in range(20)}
        assert len(flags) == 20

    def test_scenario_hash_deterministic(self):
        h1 = _generate_scenario_hash("test", ["CVE-001", "CVE-002"])
        h2 = _generate_scenario_hash("test", ["CVE-002", "CVE-001"])  # order-independent
        assert h1 == h2

    def test_scenario_hash_different_scenarios(self):
        h1 = _generate_scenario_hash("test1", ["CVE-001"])
        h2 = _generate_scenario_hash("test2", ["CVE-001"])
        assert h1 != h2


class TestAssemblerDMZSimple:
    """用真实的 dmz_simple 模板测试"""

    @pytest.fixture
    def assembler(self):
        loader = TemplateLoader(templates_dir="templates")
        return ScenarioAssembler(loader)

    def test_assemble_single_cve(self, assembler):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom])

        assert result["template"] == "dmz_simple"
        assert "target-1" in result["clab"]["topology"]["nodes"]
        assert len(result["injections"]) == 1
        assert result["injections"][0]["cve_id"] == "CVE-TEST-0001"
        assert result["injections"][0]["flag"].startswith("flag{")

    def test_clab_has_attacker_and_target(self, assembler):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom])
        nodes = result["clab"]["topology"]["nodes"]
        assert "attacker" in nodes
        assert "edge-router" in nodes
        assert "target-1" in nodes

    def test_target_linked_to_router(self, assembler):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom])
        links = result["clab"]["topology"]["links"]
        # Should have at least the base link + 1 target link
        assert len(links) >= 2
        target_links = [l for l in links if "target-1" in str(l)]
        assert len(target_links) == 1

    def test_target_has_flag_env(self, assembler):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom])
        target = result["clab"]["topology"]["nodes"]["target-1"]
        assert "FLAG" in target["env"]
        assert target["env"]["FLAG"].startswith("flag{")

    def test_target_has_docker_image(self, assembler):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom])
        target = result["clab"]["topology"]["nodes"]["target-1"]
        assert target["image"] == "vulhub/test:latest"

    def test_target_has_binds_for_flag(self, assembler):
        """Target should have CLab binds including flag file"""
        atom = _make_atom(ports=[8080, 8443])
        result = assembler.assemble("dmz_simple", [atom])
        target = result["clab"]["topology"]["nodes"]["target-1"]
        # No host port mapping — everything internal
        assert "ports" not in target
        # FLAG file should be bind-mounted
        assert "binds" in target
        flag_bind = [b for b in target["binds"] if b.endswith(":/flag.txt")]
        assert len(flag_bind) == 1

    def test_cve_setup_generated(self, assembler):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom])
        assert len(result["cve_setup"]) == 1
        setup = result["cve_setup"][0]
        # cve-setup runs on localhost (init files already mounted via CLab binds)
        assert setup["hosts"] == "localhost"
        assert len(setup["tasks"]) >= 1  # at least the wait task

    def test_ground_truth_structure(self, assembler):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom])
        gt = result["ground_truth"]
        assert gt["scenario"]
        assert gt["template"] == "dmz_simple"
        assert len(gt["attack_path"]) == 1
        step = gt["attack_path"][0]
        assert step["step"] == 1
        assert step["cve_id"] == "CVE-TEST-0001"
        assert step["flag"].startswith("flag{")

    def test_scenario_hash_present(self, assembler):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom])
        assert len(result["hash"]) == 16

    def test_custom_scenario_name(self, assembler):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom], scenario_name="my-scenario")
        assert result["name"] == "my-scenario"
        assert result["clab"]["name"] == "my-scenario"


class TestAssemblerOutput:
    """测试 write_output"""

    @pytest.fixture
    def assembler(self):
        loader = TemplateLoader(templates_dir="templates")
        return ScenarioAssembler(loader)

    def test_write_output_creates_files(self, assembler, tmp_path):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom], scenario_name="test-output")
        out_dir = assembler.write_output(result, str(tmp_path))

        assert Path(out_dir, "clab.yaml").exists()
        assert Path(out_dir, "ground_truth.json").exists()
        assert Path(out_dir, "scenario.yaml").exists()
        assert Path(out_dir, "ansible", "base.yaml").exists()
        assert Path(out_dir, "ansible", "cve-setup.yaml").exists()

    def test_written_clab_is_valid_yaml(self, assembler, tmp_path):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom], scenario_name="test-yaml")
        out_dir = assembler.write_output(result, str(tmp_path))

        clab = yaml.safe_load(Path(out_dir, "clab.yaml").read_text())
        assert "topology" in clab
        assert "target-1" in clab["topology"]["nodes"]

    def test_written_ground_truth_is_valid_json(self, assembler, tmp_path):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom], scenario_name="test-gt")
        out_dir = assembler.write_output(result, str(tmp_path))

        gt = json.loads(Path(out_dir, "ground_truth.json").read_text())
        assert gt["template"] == "dmz_simple"
        assert len(gt["attack_path"]) == 1

    def test_written_scenario_metadata(self, assembler, tmp_path):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom], scenario_name="test-meta")
        out_dir = assembler.write_output(result, str(tmp_path))

        meta = yaml.safe_load(Path(out_dir, "scenario.yaml").read_text())
        assert meta["name"] == "test-meta"
        assert meta["template"] == "dmz_simple"
        assert len(meta["injections"]) == 1
