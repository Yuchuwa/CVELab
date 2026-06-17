"""Tests for atom-level SysField playbook generation."""

import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from clab_builder.atomizer.output.sysfield_playbook import SysFieldPlaybookGenerator
from clab_builder.cli import main


def test_generate_sysfield_playbook_from_exploit_steps():
    text = SysFieldPlaybookGenerator().generate(
        cve_id="CVE-TEST-0001",
        exploit_steps=[
            {
                "name": "Trigger bug",
                "description": "Send exploit request",
                "command": "curl http://{{target_ip}}:{{target_port}}/poc",
                "mitre_technique_id": "T1190",
            }
        ],
        mitre_mapping={"initial_access": ["T1190"]},
        target_ip="{{ target_ip }}",
        target_port=8080,
        vulnerability_type="RCE",
    )
    data = yaml.safe_load(text)

    assert data["playbook"]["id"] == "cve-test-0001"
    assert data["actors"]["attacker"]["node"] == "attacker"
    step = data["steps"][0]
    assert step["stage"] == "initial_access"
    assert step["mitre"]["technique"] == "T1190"
    assert "curl http://{{ target_ip }}:8080/poc" in step["executor"]["command"]
    assert step["postconditions"]["files"][0]["op"] == "write"


def test_steps_from_session_generalizes_target_ip(tmp_path):
    session = [
        {
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "name": "Bash",
                        "input": {
                            "command": "curl -s http://172.25.0.2:80/",
                            "description": "Probe target",
                        },
                    }
                ]
            },
        }
    ]
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session))

    steps = SysFieldPlaybookGenerator().steps_from_session(str(session_path))

    assert steps[0]["name"] == "Probe target"
    assert steps[0]["command"] == "curl -s http://{{ target_ip }}:80/"


def test_atom_sysfield_cli_generates_existing_atom_playbook(tmp_path):
    atom_dir = tmp_path / "atoms" / "CVE-TEST-0001"
    atom_dir.mkdir(parents=True)
    (atom_dir / "atom.yaml").write_text(
        yaml.dump(
            {
                "cve_id": "CVE-TEST-0001",
                "ports": [8080],
                "mitre_mapping": {"initial_access": ["T1190"]},
                "vulnerability_type": "RCE",
                "requirements": {},
            }
        )
    )
    (atom_dir / "session.json").write_text(
        json.dumps(
            [
                {
                    "message": {
                        "content": [
                            {
                                "type": "tool_use",
                                "name": "Bash",
                                "input": {"command": "curl http://10.0.0.2/"},
                            }
                        ]
                    }
                }
            ]
        )
    )

    result = CliRunner().invoke(
        main,
        ["atom", "sysfield", "CVE-TEST-0001", "--output", str(tmp_path / "atoms")],
    )

    assert result.exit_code == 0
    assert (atom_dir / "playbook" / "sysfield.yaml").exists()
