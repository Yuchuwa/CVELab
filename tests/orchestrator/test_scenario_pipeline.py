"""Tests for Scenario pipeline (main entry point)"""

import pytest
import yaml
from pathlib import Path

from clab_builder.orchestrator.composer.scenario import ScenarioPipeline


def _write_pipeline_atom(
    atoms_dir: Path,
    cve_id: str,
    *,
    requires_pivot_host: bool = False,
):
    atom_dir = atoms_dir / cve_id
    atom_dir.mkdir(parents=True)
    (atom_dir / "atom.yaml").write_text(
        yaml.dump(
            {
                "cve_id": cve_id,
                "category": "test",
                "description": "test atom",
                "docker_image": "vulhub/test:latest",
                "ports": [8080],
                "services": [{"name": "web", "image": "vulhub/test:latest"}],
                "vuln_category": "RCE",
                "primary_mitre_phase": "initial_access",
                "mitre_mapping": {"initial_access": ["T1190"]},
                "service_role": "web_application",
                "exploit_complexity": "simple",
                "attack_method": "single_request",
                "flag_injection": {"method": "env_var", "env_var_name": "FLAG"},
                "flag_verify_command": "echo $FLAG",
                "service_startup": {"wait_seconds": 5},
                "post_exploit": {
                    "pivot_capability": (
                        "full_toolbox" if requires_pivot_host else "none"
                    ),
                    "requires_pivot_host": requires_pivot_host,
                },
                "verified": True,
            },
            sort_keys=False,
        )
    )
    playbook_dir = atom_dir / "playbook"
    playbook_dir.mkdir()
    (playbook_dir / "sysfield.yaml").write_text(
        yaml.dump(
            {
                "steps": [
                    {
                        "id": "trigger",
                        "stage": "initial_access",
                        "description": "Trigger test exploit",
                        "mitre": {"tactic": "initial_access", "technique": "T1190"},
                        "executor": {
                            "command": "curl http://{{ target_ip }}:{{ target_port }}/poc",
                        },
                    }
                ]
            },
            sort_keys=False,
        )
    )


class TestScenarioPipelineGenerate:
    @pytest.fixture
    def pipeline(self):
        return ScenarioPipeline(
            templates_dir="templates",
            atoms_dir="data/atoms",
        )

    def test_generate_auto_match(self, pipeline, tmp_path):
        """Auto-match CVEs from atom library"""
        result = pipeline.generate(
            template_name="dmz_simple",
            output_dir=str(tmp_path),
            seed=42,
        )
        assert result["template"] == "dmz_simple"
        assert len(result["injections"]) == 1
        assert result["injections"][0]["cve_id"]

        # Verify output files exist
        out = Path(tmp_path) / result["name"]
        assert (out / "clab.yaml").exists()
        assert (out / "ground_truth.json").exists()
        assert (out / "sysfield" / "playbook.yaml").exists()
        assert result["sysfield_playbook"] == str(out / "sysfield" / "playbook.yaml")

    def test_generate_with_specific_cve(self, pipeline, tmp_path):
        """指定 CVE 生成"""
        result = pipeline.generate(
            template_name="dmz_simple",
            cve_ids=["CVE-2014-6271"],
            output_dir=str(tmp_path),
        )
        assert result["injections"][0]["cve_id"] == "CVE-2014-6271"

    def test_generate_custom_name(self, pipeline, tmp_path):
        result = pipeline.generate(
            template_name="dmz_simple",
            scenario_name="my-test",
            output_dir=str(tmp_path),
            seed=1,
        )
        assert result["name"] == "my-test"

    def test_generate_reproducible_with_seed(self, pipeline, tmp_path):
        """相同 seed 生成相同 CVE 选择"""
        r1 = pipeline.generate(
            template_name="dmz_simple",
            output_dir=str(tmp_path / "a"),
            seed=123,
        )
        r2 = pipeline.generate(
            template_name="dmz_simple",
            output_dir=str(tmp_path / "b"),
            seed=123,
        )
        assert r1["injections"][0]["cve_id"] == r2["injections"][0]["cve_id"]

    def test_generate_nonexistent_template(self, pipeline, tmp_path):
        with pytest.raises(FileNotFoundError):
            pipeline.generate(
                template_name="nonexistent",
                output_dir=str(tmp_path),
            )

    def test_generate_nonexistent_cve(self, pipeline, tmp_path):
        with pytest.raises(FileNotFoundError):
            pipeline.generate(
                template_name="dmz_simple",
                cve_ids=["CVE-9999-9999"],
                output_dir=str(tmp_path),
            )


class TestScenarioPipelineBatch:
    @pytest.fixture
    def pipeline(self):
        return ScenarioPipeline(
            templates_dir="templates",
            atoms_dir="data/atoms",
        )

    def test_batch_generates_multiple(self, pipeline, tmp_path):
        results = pipeline.batch(
            template_name="dmz_simple",
            count=3,
            output_dir=str(tmp_path),
            seed=42,
        )
        assert len(results) >= 1  # at least 1, may have dedup

    def test_batch_dedup_by_hash(self, pipeline, tmp_path):
        """相同 CVE 组合不会重复"""
        results = pipeline.batch(
            template_name="dmz_simple",
            count=10,
            output_dir=str(tmp_path),
            seed=42,
        )
        hashes = [r["hash"] for r in results]
        assert len(hashes) == len(set(hashes))


class TestScenarioPipelineMultiTemplate:
    """测试多个模板的场景生成"""

    @pytest.fixture
    def pipeline(self):
        return ScenarioPipeline(
            templates_dir="templates",
            atoms_dir="data/atoms",
        )

    def test_dmz_dual_generates_two_targets(self, pipeline, tmp_path):
        result = pipeline.generate(
            template_name="dmz_dual",
            output_dir=str(tmp_path),
            seed=42,
        )
        assert len(result["injections"]) == 2
        assert result["injections"][0]["cve_id"] != result["injections"][1]["cve_id"]
        # Both in dmz zone
        assert result["injections"][0]["zone"] == "dmz"
        assert result["injections"][1]["zone"] == "dmz"
        # Two target nodes
        assert "target-1" in result["clab"]["topology"]["nodes"]
        assert "target-2" in result["clab"]["topology"]["nodes"]

    def test_dmz_dual_two_flags(self, pipeline, tmp_path):
        result = pipeline.generate(
            template_name="dmz_dual",
            output_dir=str(tmp_path),
            seed=42,
        )
        flags = [inj["flag"] for inj in result["injections"]]
        assert len(set(flags)) == 2  # unique flags

    def test_dmz_dual_ground_truth_two_steps(self, pipeline, tmp_path):
        result = pipeline.generate(
            template_name="dmz_dual",
            output_dir=str(tmp_path),
            seed=42,
        )
        gt = result["ground_truth"]
        assert len(gt["attack_path"]) == 2
        assert gt["attack_path"][0]["step"] == 1
        assert gt["attack_path"][1]["step"] == 2

    def test_enterprise_3tier_three_targets(self, pipeline, tmp_path):
        result = pipeline.generate(
            template_name="enterprise_3tier",
            output_dir=str(tmp_path),
            seed=42,
        )
        assert len(result["injections"]) == 3
        zones = [inj["zone"] for inj in result["injections"]]
        assert zones == ["dmz", "app", "data"]

    def test_enterprise_3tier_three_links(self, pipeline, tmp_path):
        result = pipeline.generate(
            template_name="enterprise_3tier",
            output_dir=str(tmp_path),
            seed=42,
        )
        # 3 base links + 3 target links
        links = result["clab"]["topology"]["links"]
        assert len(links) == 6

    def test_enterprise_3tier_cve_setup_three_playbooks(self, pipeline, tmp_path):
        result = pipeline.generate(
            template_name="enterprise_3tier",
            output_dir=str(tmp_path),
            seed=42,
        )
        assert len(result["cve_setup"]) == 3
        # All cve-setup tasks run on localhost (init files mounted via CLab binds)
        for cs in result["cve_setup"]:
            assert cs["hosts"] == "localhost"

    def test_enterprise_3tier_output_files(self, pipeline, tmp_path):
        result = pipeline.generate(
            template_name="enterprise_3tier",
            output_dir=str(tmp_path),
        )
        out = Path(tmp_path) / result["name"]
        assert (out / "clab.yaml").exists()
        assert (out / "ground_truth.json").exists()
        assert (out / "scenario.yaml").exists()
        assert (out / "ansible" / "base.yaml").exists()
        assert (out / "ansible" / "cve-setup.yaml").exists()
        assert (out / "sysfield" / "playbook.yaml").exists()

    def test_enterprise_3tier_three_unique_cves(self, pipeline, tmp_path):
        result = pipeline.generate(
            template_name="enterprise_3tier",
            output_dir=str(tmp_path),
            seed=42,
        )
        cve_ids = [inj["cve_id"] for inj in result["injections"]]
        assert len(set(cve_ids)) == 3  # all unique

    def test_dmz_simple_pivot_atom_writes_sysfield_playbook(self, tmp_path):
        atoms_dir = tmp_path / "atoms"
        _write_pipeline_atom(
            atoms_dir,
            "CVE-PIVOT-0001",
            requires_pivot_host=True,
        )
        pipeline = ScenarioPipeline(
            templates_dir="templates",
            atoms_dir=str(atoms_dir),
        )

        result = pipeline.generate(
            template_name="dmz_simple",
            cve_ids=["CVE-PIVOT-0001"],
            scenario_name="pivot-sysfield",
            output_dir=str(tmp_path / "scenarios"),
        )

        out = Path(result["sysfield_playbook"])
        playbook = yaml.safe_load(out.read_text())
        nodes = result["clab"]["topology"]["nodes"]

        assert nodes["target-1"]["image"] == "cvelab-pivot-base:latest"
        assert nodes["target-1-service"]["network-mode"] == (
            "container:clab-pivot-sysfield-target-1"
        )
        assert result["ground_truth"]["attack_path"][0]["service_node"] == (
            "target-1-service"
        )
        assert playbook["steps"][0]["id"].endswith("cve-pivot-0001-target-1-trigger")
        assert "curl http://" in playbook["steps"][0]["executor"]["command"]
        assert "echo $FLAG" not in playbook["steps"][0]["executor"]["command"]


class TestCLIIntegration:
    """CLI command integration tests"""

    def test_cli_scenario_generate(self, tmp_path):
        """Test CLI scenario generate command"""
        from click.testing import CliRunner
        from clab_builder.cli import main

        runner = CliRunner()
        result = runner.invoke(main, [
            "generate", "dmz_simple",
            "--cve", "CVE-2014-6271",
            "--name", "cli-test",
            "--output", str(tmp_path),
        ])
        assert result.exit_code == 0, result.output
        assert "cli-test" in result.output
        assert "CVE-2014-6271" in result.output

    def test_cli_scenario_batch(self, tmp_path):
        """Test CLI scenario batch command"""
        from click.testing import CliRunner
        from clab_builder.cli import main

        runner = CliRunner()
        result = runner.invoke(main, [
            "batch", "dmz_simple",
            "--count", "2",
            "--output", str(tmp_path),
            "--seed", "42",
        ])
        assert result.exit_code == 0, result.output
        assert "Generated" in result.output
