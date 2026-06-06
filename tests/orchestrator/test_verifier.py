"""Tests for Scenario Verifier"""

import json
import pytest
import yaml
from pathlib import Path
from unittest.mock import patch, MagicMock

from clab_builder.orchestrator.composer.verifier import ScenarioVerifier


class TestVerifyFlags:
    """Flag 比对逻辑测试（不需要 Docker/CLab）"""

    @pytest.fixture
    def verifier(self):
        return ScenarioVerifier()

    def test_all_flags_captured(self, verifier):
        agent_result = {
            "success": True,
            "verified_flags": {
                "target-1": "flag{abc123}",
            },
        }
        ground_truth = {
            "attack_path": [
                {"target_node": "target-1", "flag": "flag{abc123}", "cve_id": "CVE-TEST"},
            ],
        }
        result = verifier.verify_flags(agent_result, ground_truth)
        assert result["all_captured"] is True
        assert result["per_target"]["target-1"]["match"] is True

    def test_flag_mismatch(self, verifier):
        agent_result = {
            "success": True,
            "verified_flags": {
                "target-1": "flag{wrong}",
            },
        }
        ground_truth = {
            "attack_path": [
                {"target_node": "target-1", "flag": "flag{abc123}", "cve_id": "CVE-TEST"},
            ],
        }
        result = verifier.verify_flags(agent_result, ground_truth)
        assert result["all_captured"] is False
        assert result["per_target"]["target-1"]["match"] is False

    def test_missing_flag(self, verifier):
        agent_result = {
            "success": False,
            "verified_flags": {},
        }
        ground_truth = {
            "attack_path": [
                {"target_node": "target-1", "flag": "flag{abc123}", "cve_id": "CVE-TEST"},
            ],
        }
        result = verifier.verify_flags(agent_result, ground_truth)
        assert result["all_captured"] is False
        assert result["per_target"]["target-1"]["captured"] == ""

    def test_multiple_targets_all_captured(self, verifier):
        agent_result = {
            "success": True,
            "verified_flags": {
                "target-1": "flag{aaa}",
                "target-2": "flag{bbb}",
            },
        }
        ground_truth = {
            "attack_path": [
                {"target_node": "target-1", "flag": "flag{aaa}", "cve_id": "CVE-1"},
                {"target_node": "target-2", "flag": "flag{bbb}", "cve_id": "CVE-2"},
            ],
        }
        result = verifier.verify_flags(agent_result, ground_truth)
        assert result["all_captured"] is True
        assert len(result["per_target"]) == 2

    def test_multiple_targets_partial(self, verifier):
        agent_result = {
            "success": True,
            "verified_flags": {
                "target-1": "flag{aaa}",
            },
        }
        ground_truth = {
            "attack_path": [
                {"target_node": "target-1", "flag": "flag{aaa}", "cve_id": "CVE-1"},
                {"target_node": "target-2", "flag": "flag{bbb}", "cve_id": "CVE-2"},
            ],
        }
        result = verifier.verify_flags(agent_result, ground_truth)
        assert result["all_captured"] is False


class TestGetNodePorts:
    """从 clab.yaml 提取端口"""

    @pytest.fixture
    def verifier(self):
        return ScenarioVerifier()

    def test_extract_ports(self, verifier):
        clab_data = {
            "topology": {
                "nodes": {
                    "target-1": {
                        "kind": "linux",
                        "image": "test:latest",
                        "ports": [8080, 8443],
                    }
                }
            }
        }
        ports = verifier._get_node_ports(clab_data, "target-1")
        assert ports == [8080, 8443]

    def test_no_ports(self, verifier):
        clab_data = {
            "topology": {
                "nodes": {
                    "target-1": {"kind": "linux", "image": "test:latest"}
                }
            }
        }
        ports = verifier._get_node_ports(clab_data, "target-1")
        assert ports == []


class TestRunnerPrompt:
    """scenario_runner.py 的 prompt 构建"""

    def test_build_prompt(self):
        from clab_builder.orchestrator.composer.scenario_runner import build_prompt

        input_data = {
            "scenario_name": "test-scenario",
            "attacker_ip": "172.20.1.1",
            "targets": [
                {
                    "node_name": "target-1",
                    "cve_id": "CVE-2014-6271",
                    "ip": "172.20.1.2",
                    "ports": [8080],
                    "zone": "dmz",
                    "flag_hint": "env:FLAG",
                }
            ],
        }
        prompt = build_prompt(input_data)
        assert "test-scenario" in prompt
        assert "CVE-2014-6271" in prompt
        assert "172.20.1.2" in prompt
        assert "8080" in prompt


class TestRunnerExtractJson:
    """JSON 提取逻辑"""

    def test_extract_from_code_block(self):
        from clab_builder.orchestrator.composer.scenario_runner import extract_json

        text = 'Some output\n```json\n{"success": true, "verified_flags": {"t-1": "flag{abc}"}}\n```\nMore text'
        result = extract_json(text)
        assert result is not None
        assert result["success"] is True
        assert result["verified_flags"]["t-1"] == "flag{abc}"

    def test_extract_bare_json(self):
        from clab_builder.orchestrator.composer.scenario_runner import extract_json

        text = 'Result: {"success": false, "verified_flags": {}}'
        result = extract_json(text)
        assert result is not None
        assert result["success"] is False

    def test_no_json(self):
        from clab_builder.orchestrator.composer.scenario_runner import extract_json

        result = extract_json("No JSON here")
        assert result is None


class TestVerifierDefaults:
    """Verifier 默认值"""

    def test_default_max_turns(self):
        from clab_builder.orchestrator.composer.scenario_runner import DEFAULT_MAX_TURNS
        verifier = ScenarioVerifier()
        assert verifier.max_turns == 80
        assert DEFAULT_MAX_TURNS == 80

    def test_custom_max_turns(self):
        verifier = ScenarioVerifier(max_turns=120)
        assert verifier.max_turns == 120

    def test_default_agent_image(self):
        verifier = ScenarioVerifier()
        assert verifier.agent_image == "clab-agent:latest"
