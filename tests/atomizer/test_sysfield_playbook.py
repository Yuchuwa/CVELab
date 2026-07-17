"""Tests for atom-level SysField playbook generation."""

import json

import yaml
import pytest
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
    assert step["id"] == "01-trigger-bug"
    assert step["stage"] == "initial_access"
    assert step["mitre"]["technique"] == "T1190"
    assert step["executor"]["command"] == "curl http://{{ target_ip }}:8080/poc"
    assert "postconditions" not in step


def test_generate_rejects_empty_exploit_steps():
    with pytest.raises(ValueError, match="no usable exploit steps"):
        SysFieldPlaybookGenerator().generate(
            cve_id="CVE-TEST-EMPTY",
            exploit_steps=[],
            mitre_mapping={},
        )


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


def test_steps_from_raw_sdk_session_shape(tmp_path):
    session = [
        {
            "type": "assistant",
            "content": [
                {
                    "type": "tool_use",
                    "name": "Bash",
                    "input": {
                        "command": "curl http://172.18.0.2:8080/",
                        "description": "Probe target",
                    },
                }
            ],
            "sdk_extra": {"kept": True},
        }
    ]
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session))

    steps = SysFieldPlaybookGenerator().steps_from_session(str(session_path))

    assert steps == [
        {
            "name": "Probe target",
            "description": "Probe target",
            "command": "curl http://{{ target_ip }}:8080/",
        }
    ]


def test_steps_from_transcript_extracts_and_generalizes(tmp_path):
    """transcript 的 [Tool] Bash 行应被提取，IP 模板化，探索命令过滤掉。"""
    transcript = tmp_path / "agent_transcript.log"
    transcript.write_text(
        '[Tool] Bash: {"command": "ls /vulhub", "description": "list"}\n'
        '[Tool] Bash: {"command": "nmap -sV -p 80 192.168.1.2", "description": "scan"}\n'
        '[Tool] Bash: {"command": "curl -s http://192.168.1.2:80/exploit", "description": "attack"}\n'
        '[Tool] Bash: {"command": "transport._send_message(m)", "description": "frag"}\n'
    )
    steps = SysFieldPlaybookGenerator().steps_from_transcript(str(transcript))
    # 只保留 curl 攻击命令；ls/nmap 被过滤；代码片段被过滤
    assert len(steps) == 1
    assert "192.168.1.2" not in steps[0]["command"]
    assert "{{ target_ip }}" in steps[0]["command"]


def test_generate_falls_back_to_transcript_when_agent_steps_empty(tmp_path):
    """agent 自报 exploit_steps 为空时，应回退 transcript 实际命令。"""
    transcript = tmp_path / "agent_transcript.log"
    transcript.write_text(
        '[Tool] Bash: {"command": "curl -s http://10.0.0.2:80/rce?cmd=id", "description": "exploit"}\n'
    )
    gen = SysFieldPlaybookGenerator()
    result = gen.generate(
        cve_id="CVE-TEST-FB",
        exploit_steps=[],  # agent 自报空
        mitre_mapping={"initial_access": ["T1190"]},
        transcript_path=str(transcript),
    )
    import yaml as _yaml
    data = _yaml.safe_load(result)
    assert "source=transcript" in data["playbook"]["description"]
    assert len(data["steps"]) >= 1
    assert "{{ target_ip }}" in data["steps"][0]["executor"]["command"]


def test_generate_filters_code_fragment_and_non_allowed_vars():
    """agent 自报步骤含代码片段或非白名单变量时，应被过滤。"""
    gen = SysFieldPlaybookGenerator()
    steps = [
        {"name": "good", "command": "curl -s http://{{ target_ip }}:80/"},
        {"name": "frag", "command": "transport._send_message(msg); client.exec_command(cmd)"},
        {"name": "badvar", "command": "curl -s http://{{ target_ip }}/{{ weird_var }}"},
        {"name": "recon", "command": "nmap -sV -p 80 {{ target_ip }}"},
    ]
    filtered = gen._filter_quality_steps(steps, "CVE-X", set())
    assert len(filtered) == 1
    assert filtered[0]["name"] == "good"


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
