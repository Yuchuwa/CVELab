"""Tests for SysField playbook export."""

import json
from pathlib import Path

import yaml
import pytest
from click.testing import CliRunner

from clab_builder.cli import main
from clab_builder.orchestrator.composer.sysfield_exporter import SysFieldExporter


def _write_atom(atoms_dir: Path, cve_id: str = "CVE-TEST-0001"):
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
                "flag_verify_command": "curl -s http://{{target_ip}}:{{target_port}}/health",
                "service_startup": {"wait_seconds": 5},
                "verified": True,
            },
            sort_keys=False,
        )
    )
    playbook_dir = atom_dir / "playbook"
    playbook_dir.mkdir()
    (playbook_dir / "sysfield.yaml").write_text(yaml.dump({
        "playbook": {"id": cve_id.lower()},
        "steps": [{
            "id": "verify-flag-command",
            "stage": "initial_access",
            "executor": {"command": "curl -s http://{{ target_ip }}:{{ target_port }}/health"},
        }],
    }, sort_keys=False))


def _write_scenario(scenario_dir: Path, cve_id: str = "CVE-TEST-0001"):
    scenario_dir.mkdir(parents=True)
    (scenario_dir / "ground_truth.json").write_text(
        json.dumps(
            {
                "scenario": "sysfield-test",
                "template": "dmz_simple",
                "attack_path": [
                    {
                        "step": 1,
                        "injection_point": "dmz-target-1",
                        "target_node": "target-1",
                        "cve_id": cve_id,
                        "zone": "dmz",
                        "flag": "flag{abc}",
                        "target_ip": "192.168.100.2",
                    }
                ],
            }
        )
    )
    (scenario_dir / "scenario.yaml").write_text(yaml.safe_dump({
        "objectives": [{
            "validation": "reference",
            "reference_command": "printf 'CVELAB-REFERENCE'",
            "success_pattern": "CVELAB-REFERENCE",
        }],
    }))


def test_export_sysfield_playbook(tmp_path):
    atoms_dir = tmp_path / "atoms"
    scenario_dir = tmp_path / "scenario"
    _write_atom(atoms_dir)
    _write_scenario(scenario_dir)

    out = SysFieldExporter(atoms_dir=str(atoms_dir)).export(str(scenario_dir))
    playbook = yaml.safe_load(Path(out).read_text())

    assert playbook["playbook"]["id"] == "sysfield-test"
    assert playbook["actors"]["attacker"]["node"] == "attacker"
    assert len(playbook["steps"]) == 2

    step = playbook["steps"][0]
    assert step["id"] == "01-01-cve-test-0001-target-1-verify-flag-command"
    assert step["stage"] == "initial_access"
    assert step["mitre"]["technique"] == "T1190"
    assert step["executor"]["command"] == "curl -s http://192.168.100.2:8080/health"
    assert "postconditions" not in step


def test_export_prefers_atom_sysfield_steps_over_local_flag_probe(tmp_path):
    atoms_dir = tmp_path / "atoms"
    scenario_dir = tmp_path / "scenario"
    _write_atom(atoms_dir)
    atom_playbook = atoms_dir / "CVE-TEST-0001" / "playbook" / "sysfield.yaml"
    atom_playbook.parent.mkdir(parents=True, exist_ok=True)
    atom_playbook.write_text(
        yaml.dump(
            {
                "playbook": {"id": "custom"},
                "steps": [
                    {
                        "id": "trigger-rce",
                        "stage": "initial_access",
                        "description": "Trigger remote command execution",
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
    _write_scenario(scenario_dir)

    out = SysFieldExporter(atoms_dir=str(atoms_dir)).export(str(scenario_dir))
    playbook = yaml.safe_load(Path(out).read_text())

    command = playbook["steps"][0]["executor"]["command"]
    assert "curl http://192.168.100.2:8080/poc" in command
    assert "echo $FLAG" not in command


def test_export_runs_later_steps_from_previous_target_node(tmp_path):
    atoms_dir = tmp_path / "atoms"
    scenario_dir = tmp_path / "scenario"
    _write_atom(atoms_dir, "CVE-TEST-0001")
    _write_atom(atoms_dir, "CVE-TEST-0002")
    atom_playbook = atoms_dir / "CVE-TEST-0002" / "playbook" / "sysfield.yaml"
    atom_playbook.parent.mkdir(parents=True, exist_ok=True)
    atom_playbook.write_text(
        yaml.dump(
            {
                "playbook": {"id": "custom"},
                "steps": [
                    {
                        "id": "callback-from-pivot",
                        "stage": "initial_access",
                        "description": "Trigger callback to current execution node",
                        "mitre": {"tactic": "initial_access", "technique": "T1190"},
                        "executor": {
                            "command": (
                                "curl http://{{ target_ip }}:{{ target_port }}/"
                                "?cb={{ attacker_ip }}:1389"
                            ),
                        },
                    }
                ]
            },
            sort_keys=False,
        )
    )
    scenario_dir.mkdir(parents=True)
    (scenario_dir / "ground_truth.json").write_text(
        json.dumps(
            {
                "scenario": "pivot-chain",
                "template": "dmz_dual",
                "attack_path": [
                    {
                        "step": 1,
                        "target_node": "target-1",
                        "cve_id": "CVE-TEST-0001",
                        "target_ip": "192.168.100.2",
                    },
                    {
                        "step": 2,
                        "target_node": "target-2",
                        "cve_id": "CVE-TEST-0002",
                        "target_ip": "10.10.1.2",
                        "execution_host": "target-1",
                        "execution_adapter": {
                            "mode": "stateless",
                            "command_template": "sh -c {{command}}",
                            "verified": True,
                        },
                    },
                ],
            }
        )
    )
    (scenario_dir / "scenario.yaml").write_text(
        yaml.dump(
            {
                "ip_allocations": {
                    "attacker": {"eth1": "10.255.255.1/30"},
                    "target-1": {"eth1": "192.168.100.2/24"},
                    "target-2": {"eth1": "10.10.1.2/24"},
                },
                "objectives": [{
                    "validation": "reference",
                    "reference_command": "printf 'CVELAB-REFERENCE'",
                    "success_pattern": "CVELAB-REFERENCE",
                }],
            },
            sort_keys=False,
        )
    )

    out = SysFieldExporter(atoms_dir=str(atoms_dir)).export(str(scenario_dir))
    playbook = yaml.safe_load(Path(out).read_text())

    assert playbook["steps"][0]["actor"] == "attacker"
    assert playbook["steps"][1]["actor"] == "target-1"
    assert playbook["actors"]["target-1"]["node"] == "target-1"
    assert "cb=10.255.255.1:1389" in playbook["steps"][1]["executor"]["command"]
    assert playbook["steps"][1]["executor"]["command"].startswith("sh -c ")
    assert playbook["steps"][1]["dependencies"] == [playbook["steps"][0]["id"]]


def test_sysfield_export_cli(tmp_path):
    atoms_dir = tmp_path / "atoms"
    scenario_dir = tmp_path / "scenario"
    output = tmp_path / "playbook.yaml"
    _write_atom(atoms_dir)
    _write_scenario(scenario_dir)

    result = CliRunner().invoke(
        main,
        [
            "sysfield",
            "export",
            str(scenario_dir),
            "--atoms-dir",
            str(atoms_dir),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    assert output.exists()
    assert "SysField playbook:" in result.output


def test_export_requires_atom_sysfield_playbook(tmp_path):
    atoms_dir = tmp_path / "atoms"
    scenario_dir = tmp_path / "scenario"
    _write_atom(atoms_dir)
    (atoms_dir / "CVE-TEST-0001" / "playbook" / "sysfield.yaml").unlink()
    _write_scenario(scenario_dir)

    with pytest.raises(ValueError, match="missing playbook/sysfield.yaml"):
        SysFieldExporter(atoms_dir=str(atoms_dir)).export(str(scenario_dir))


def test_export_emits_executable_objective_assertion(tmp_path):
    atoms_dir = tmp_path / "atoms"
    scenario_dir = tmp_path / "scenario"
    _write_atom(atoms_dir)
    _write_scenario(scenario_dir)
    (scenario_dir / "scenario.yaml").write_text(yaml.safe_dump({
        "objectives": [{
            "asset": "customer-records",
            "validation": "canary_row_read",
            "reference_command": "printf 'CVELAB-CANARY'",
            "success_pattern": "CVELAB-CANARY",
        }],
    }))

    out = SysFieldExporter(atoms_dir=str(atoms_dir)).export(str(scenario_dir))
    playbook = yaml.safe_load(Path(out).read_text())
    objective = playbook["steps"][-1]
    assert objective["stage"] == "objective"
    assert "grep -F" in objective["executor"]["command"]
    assert playbook["reference_objective"]["step"] == objective["id"]
