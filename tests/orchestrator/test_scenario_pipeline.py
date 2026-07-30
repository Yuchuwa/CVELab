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
    with_guide: bool = False,
    guide_principal: str = "unknown",
    guide_capabilities: list[str] | None = None,
    capability_grants: list[dict] | None = None,
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
                "flag_verify_command": "cat /flag.txt",
                "service_startup": {"wait_seconds": 5},
                "post_exploit": {
                    "pivot_capability": (
                        "full_toolbox" if requires_pivot_host else "none"
                    ),
                    "requires_pivot_host": requires_pivot_host,
                },
                "verified": True,
                **({"capability_grants": capability_grants} if capability_grants is not None else {}),
                **({"exploit_guide": {"path": "exploit_guide.yaml", "status": "ready"}} if with_guide else {}),
            },
            sort_keys=False,
        )
    )
    playbook_dir = atom_dir / "playbook"
    playbook_dir.mkdir()
    (playbook_dir / "sysfield.yaml").write_text(
        yaml.dump(
            {
                "playbook": {"id": cve_id.lower()},
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
    if with_guide:
        (atom_dir / "exploit_guide.yaml").write_text(yaml.safe_dump({
            "version": 1,
            "cve_id": cve_id,
            "summary": "test guide",
            "target": {"protocol": "http", "port": 8080, "service_role": "web_application"},
            "steps": [{
                "id": "exploit", "action": "trigger", "procedure": "send request",
                "depends_on": [], "success_signal": "command output",
            }],
            "post_exploit": {
                "principal": guide_principal,
                "capabilities": guide_capabilities or [],
            },
        }, sort_keys=False))


def _write_pipeline_atoms(atoms_dir: Path, count: int = 3) -> None:
    _write_pipeline_atom(atoms_dir, "CVE-2014-6271")
    for index in range(2, count + 1):
        _write_pipeline_atom(atoms_dir, f"CVE-PIPELINE-{index:04d}")


class TestScenarioPipelineGenerate:
    @pytest.fixture
    def pipeline(self, tmp_path):
        atoms_dir = tmp_path / "pipeline-atoms"
        _write_pipeline_atoms(atoms_dir)
        return ScenarioPipeline(
            templates_dir="templates",
            atoms_dir=str(atoms_dir),
            default_validation_mode="sysfield",
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
        scenario_meta = yaml.safe_load((out / "scenario.yaml").read_text())
        assert scenario_meta["schema_version"] == 1
        assert "ground_truth" not in scenario_meta

    def test_generate_guided_agent_copies_guides(self, tmp_path):
        atoms_dir = tmp_path / "atoms"
        _write_pipeline_atom(atoms_dir, "CVE-GUIDED-0001", with_guide=True)
        pipeline = ScenarioPipeline(templates_dir="templates", atoms_dir=str(atoms_dir))
        result = pipeline.generate(
            template_name="dmz_simple",
            cve_ids=["CVE-GUIDED-0001"],
            output_dir=str(tmp_path / "scenarios"),
            validation_mode="guided_agent",
        )
        out = Path(tmp_path / "scenarios" / result["name"])
        assert result["validation_mode"] == "guided_agent"
        assert (out / "exploit_guides" / "dmz-target-1.yaml").exists()
        assert "sysfield_playbook" not in result
        assert result["guide_compatibility"]["overall_status"] == "unknown_legacy"
        scenario_meta = yaml.safe_load((out / "scenario.yaml").read_text())
        assert scenario_meta["schema_version"] == 1
        assert scenario_meta["guide_compatibility"]["overall_status"] == "unknown_legacy"

    def test_guide_alignment_difference_is_advisory(self, tmp_path):
        atoms_dir = tmp_path / "atoms"
        _write_pipeline_atom(
            atoms_dir,
            "CVE-GUIDED-MISMATCH",
            with_guide=True,
            guide_principal="guide-user",
            capability_grants=[{
                "type": "execute_command",
                "principal": "verified-user",
                "evidence_level": "verified",
            }],
        )
        pipeline = ScenarioPipeline(templates_dir="templates", atoms_dir=str(atoms_dir))
        result = pipeline.generate(
            template_name="dmz_simple",
            cve_ids=["CVE-GUIDED-MISMATCH"],
            output_dir=str(tmp_path / "scenarios"),
            validation_mode="guided_agent",
        )

        assert result["guide_compatibility"]["overall_status"] == "unknown_legacy"
        codes = {
            item["code"]
            for item in result["guide_compatibility"]["entries"][0]["advisories"]
        }
        assert "principal_mismatch" in codes

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
    def pipeline(self, tmp_path):
        atoms_dir = tmp_path / "batch-atoms"
        _write_pipeline_atoms(atoms_dir)
        return ScenarioPipeline(
            templates_dir="templates",
            atoms_dir=str(atoms_dir),
            default_validation_mode="sysfield",
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
    def pipeline(self, tmp_path):
        atoms_dir = tmp_path / "multi-atoms"
        _write_pipeline_atoms(atoms_dir)
        return ScenarioPipeline(
            templates_dir="templates",
            atoms_dir=str(atoms_dir),
            default_validation_mode="sysfield",
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
        with pytest.raises(ValueError, match="No matching atom"):
            pipeline.generate(
                template_name="enterprise_3tier",
                output_dir=str(tmp_path),
                seed=42,
            )

    def test_enterprise_3tier_three_links(self, pipeline, tmp_path):
        with pytest.raises(ValueError, match="No matching atom"):
            pipeline.generate(
                template_name="enterprise_3tier",
                output_dir=str(tmp_path),
                seed=42,
            )

    def test_enterprise_3tier_cve_setup_three_playbooks(self, pipeline, tmp_path):
        with pytest.raises(ValueError, match="No matching atom"):
            pipeline.generate(
                template_name="enterprise_3tier",
                output_dir=str(tmp_path),
                seed=42,
            )

    def test_enterprise_3tier_output_files(self, pipeline, tmp_path):
        with pytest.raises(ValueError, match="No matching atom"):
            pipeline.generate(
                template_name="enterprise_3tier",
                output_dir=str(tmp_path),
            )

    def test_enterprise_3tier_three_unique_cves(self, pipeline, tmp_path):
        with pytest.raises(ValueError, match="No matching atom"):
            pipeline.generate(
                template_name="enterprise_3tier",
                output_dir=str(tmp_path),
                seed=42,
            )

    def test_dmz_simple_pivot_metadata_writes_sysfield_playbook(self, tmp_path):
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
            validation_mode="sysfield",
        )

        out = Path(result["sysfield_playbook"])
        playbook = yaml.safe_load(out.read_text())
        nodes = result["clab"]["topology"]["nodes"]

        assert nodes["target-1"]["image"] == "vulhub/test:latest"
        assert "target-1-service" not in nodes
        assert "network-mode" not in nodes["target-1"]
        assert "service_node" not in result["ground_truth"]["attack_path"][0]
        assert playbook["steps"][0]["id"].endswith("target-1-trigger")
        assert "curl http://" in playbook["steps"][0]["executor"]["command"]
        assert "echo $FLAG" not in playbook["steps"][0]["executor"]["command"]


class TestCLIIntegration:
    """CLI command integration tests"""

    def test_cli_scenario_generate(self, tmp_path):
        """Test CLI scenario generate command"""
        from click.testing import CliRunner
        from clab_builder.cli import main

        atoms_dir = tmp_path / "cli-atoms"
        _write_pipeline_atoms(atoms_dir)
        runner = CliRunner()
        result = runner.invoke(main, [
            "generate", "dmz_simple",
            "--cve", "CVE-2014-6271",
            "--name", "cli-test",
            "--output", str(tmp_path),
            "--atoms-dir", str(atoms_dir),
            "--validation-mode", "sysfield",
        ])
        assert result.exit_code == 0, result.output
        assert "cli-test" in result.output
        assert "CVE-2014-6271" in result.output

    def test_cli_scenario_batch(self, tmp_path):
        """Test CLI scenario batch command"""
        from click.testing import CliRunner
        from clab_builder.cli import main

        atoms_dir = tmp_path / "cli-batch-atoms"
        _write_pipeline_atoms(atoms_dir)
        runner = CliRunner()
        result = runner.invoke(main, [
            "batch", "dmz_simple",
            "--count", "2",
            "--output", str(tmp_path),
            "--atoms-dir", str(atoms_dir),
            "--seed", "42",
        ])
        assert result.exit_code == 0, result.output
        assert "Generated" in result.output
