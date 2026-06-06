"""Tests for Scenario pipeline (main entry point)"""

import pytest
import yaml
from pathlib import Path

from clab_builder.orchestrator.composer.scenario import ScenarioPipeline


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

    def test_enterprise_3tier_three_unique_cves(self, pipeline, tmp_path):
        result = pipeline.generate(
            template_name="enterprise_3tier",
            output_dir=str(tmp_path),
            seed=42,
        )
        cve_ids = [inj["cve_id"] for inj in result["injections"]]
        assert len(set(cve_ids)) == 3  # all unique


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
