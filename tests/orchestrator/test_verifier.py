"""Tests for Scenario Verifier"""

import json
import subprocess
from types import SimpleNamespace
import pytest
import yaml
from pathlib import Path
from unittest.mock import patch, MagicMock

from clab_builder.orchestrator.composer.verifier import ScenarioVerifier
from clab_builder.orchestrator.composer.scenario_runner import build_prompt


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


class TestObjectiveVerification:
    @pytest.fixture
    def verifier(self):
        return ScenarioVerifier()

    @staticmethod
    def _objective():
        return {
            "id": "read-customer-records",
            "asset": "customer-records",
            "validation": "canary_row_read",
            "evidence_field": "evidence",
            "success_pattern": "CVELAB-CANARY",
            "actor_node": "target-2",
            "target_node": "target-3",
        }

    def test_structured_objective_evidence_passes(self, verifier):
        result = verifier._verify_objectives({
            "objective_results": {
                "read-customer-records": {
                    "achieved": True,
                    "actor_node": "target-2",
                    "target_node": "target-3",
                    "evidence": "marker=CVELAB-CANARY",
                }
            }
        }, [self._objective()])
        assert result["all_satisfied"] is True
        assert result["per_objective"]["read-customer-records"]["matched"] is True

    def test_unrelated_agent_text_cannot_satisfy_objective(self, verifier):
        result = verifier._verify_objectives({
            "evidence": ["CVELAB-CANARY"],
            "objective_results": {
                "read-customer-records": {
                    "achieved": True,
                    "actor_node": "target-2",
                    "target_node": "target-3",
                    "evidence": "database query failed",
                }
            }
        }, [self._objective()])
        assert result["all_satisfied"] is False
        assert result["per_objective"]["read-customer-records"]["failure_reason"] == "evidence_mismatch"

    def test_missing_objective_result_is_reported(self, verifier):
        result = verifier._verify_objectives({"objective_results": {}}, [self._objective()])
        item = result["per_objective"]["read-customer-records"]
        assert result["all_satisfied"] is False
        assert item["failure_reason"] == "missing_objective_result"


class TestGuidedObjectivePrompt:
    def test_prompt_contains_execution_context(self):
        prompt = build_prompt({
            "scenario_name": "context-contract",
            "attacker_ip": "10.0.0.2",
            "targets": [{
                "node_name": "target-1",
                "cve_id": "CVE-TEST",
                "ip": "10.0.0.3",
                "ports": [5432],
                "zone": "data",
                "execution_context": {
                    "execution_host": "target-2",
                    "required_tools": ["python3", "psycopg2-binary"],
                    "guide_suggested_tools": ["curl"],
                    "tool_policy": "inspect_first",
                },
            }],
        })
        assert "environment_tools=['python3', 'psycopg2-binary']" in prompt
        assert "Guide-suggested tools" in prompt
        assert "python3" in prompt
        assert "psycopg2-binary" in prompt
        assert "inspect_first" in prompt
        assert "Formal tool precondition" in prompt

    def test_prompt_contains_guide_preflight_status(self):
        prompt = build_prompt({
            "scenario_name": "preflight-contract",
            "attacker_ip": "10.0.0.2",
            "targets": [],
            "guide_preflight": {
                "overall_status": "repairable",
                "entries": [{
                    "injection_point": "data-store",
                    "status": "repairable",
                    "actor_node": "target-2",
                    "checks": [{
                        "status": "failed",
                        "ok": False,
                        "kind": "python_module",
                        "tool": "psycopg2",
                        "error": "tool check failed",
                    }],
                    "adaptations": [{
                        "artifact": "source_bundle/tools/client.py",
                        "actor_node": "target-2",
                    }],
                }],
            },
        })
        assert "Overall status: repairable" in prompt
        assert "psycopg2" in prompt
        assert "source_bundle/tools/client.py" in prompt

    def test_prompt_contains_public_goal_but_not_private_assertion(self):
        prompt = build_prompt({
            "scenario_name": "objective-contract",
            "attacker_ip": "10.0.0.2",
            "targets": [],
            "objectives": [{
                "id": "read-customer-records",
                "asset": "customer-records",
                "goal": "读取客户记录并提交 marker",
                "target_node": "target-3",
                "actor_node": "target-2",
                "evidence_field": "evidence",
                "reference_command": "PRIVATE-COMMAND-MUST-NOT-LEAK",
                "success_pattern": "PRIVATE-PATTERN-MUST-NOT-LEAK",
            }],
        })
        assert "读取客户记录并提交 marker" in prompt
        assert "target-2" in prompt
        assert "PRIVATE-COMMAND-MUST-NOT-LEAK" not in prompt
        assert "PRIVATE-PATTERN-MUST-NOT-LEAK" not in prompt

    def test_legacy_meta_gets_oracle_free_objective_view(self):
        view = ScenarioVerifier._public_objectives({
            "objectives": [{
                "asset": "customer-records",
                "validation": "canary_row_read",
                "reference_command": "PRIVATE",
                "success_pattern": "PRIVATE",
            }],
            "assets": [{
                "id": "customer-records",
                "location": {"node_ref": "data-store"},
            }],
            "injections": [
                {
                    "ip_id": "app-service",
                    "node_name": "target-2",
                    "service_node": "target-2",
                    "execution_host": "dmz-web",
                },
                {
                    "ip_id": "data-store",
                    "node_name": "target-3",
                    "service_node": "target-3",
                    "execution_host": "app-service",
                },
            ],
            "ip_allocations": {"target-3": {"eth1": "10.10.2.2/24"}},
        })
        assert view[0]["target_node"] == "target-3"
        assert view[0]["actor_node"] == "target-2"
        assert "reference_command" not in view[0]
        assert "success_pattern" not in view[0]


class TestReferencePathVerification:
    def test_reference_path_is_a_hard_gate(self, tmp_path):
        scenario_dir = tmp_path / "scenario"
        scenario_dir.mkdir()
        verifier = ScenarioVerifier()
        ground_truth = {"attack_path": [{"target_node": "target-1"}]}

        with patch.object(verifier, "_load_scenario_context", return_value=(ground_truth, {}, {})), \
             patch.object(verifier, "_deploy", return_value=True), \
             patch.object(verifier, "_run_ansible", return_value={"ok": True, "skipped": True}), \
             patch.object(verifier, "_verify_environment", return_value={"all_targets_verified": True}), \
             patch.object(verifier, "_verify_attack_path_reachability", return_value={"all_edges_verified": True}), \
             patch.object(verifier, "_run_reference_path", return_value={"ok": False, "error": "step failed"}), \
             patch.object(verifier, "_destroy"), \
             patch.object(verifier, "_save_result", side_effect=lambda _path, result: result):
            result = verifier.run_environment(str(scenario_dir))

        assert result["environment_success"] is True
        assert result["reference_path_verified"] is False
        assert result["success"] is False

    def test_guided_agent_is_reference_without_sysfield(self, tmp_path):
        scenario_dir = tmp_path / "scenario"
        scenario_dir.mkdir()
        (scenario_dir / "ground_truth.json").write_text(json.dumps({
            "scenario": "guided",
            "attack_path": [{
                "injection_point": "dmz-target-1",
                "target_node": "target-1",
                "cve_id": "CVE-TEST",
                "flag": "flag{abc}",
                "depends_on": [],
            }],
        }))
        (scenario_dir / "scenario.yaml").write_text("name: guided\n")
        verifier = ScenarioVerifier(validation_mode="guided_agent")
        with patch.object(verifier, "_deploy", return_value=True), \
             patch.object(verifier, "_run_ansible", return_value={"ok": True, "skipped": True}), \
             patch.object(verifier, "_verify_environment", return_value={"all_targets_verified": True}), \
             patch.object(verifier, "_verify_attack_path_reachability", return_value={"all_edges_verified": True}), \
             patch.object(verifier, "_run_guide_runtime_preflight", return_value={
                 "evaluated": True, "overall_status": "compatible",
                 "integrity_valid": True, "agent_allowed": True, "entries": [],
             }), \
             patch.object(verifier, "_prepare_agent_transport", return_value={"ok": True}), \
             patch.object(verifier, "_run_agent", return_value={
                 "success": True, "verified_flags": {"target-1": "flag{abc}"},
             }), \
             patch.object(verifier, "_destroy"), \
             patch.object(verifier, "_save_result", side_effect=lambda _path, result: result):
            result = verifier.run_full(str(scenario_dir), api_key="test")

        assert result["validation_mode"] == "guided_agent"
        assert result["range_build_verified"] is True
        assert result["guided_trial_evaluated"] is True
        assert result["guided_trial_success"] is True
        assert result["objective_achieved"] is True
        assert result["failure_stage"] == ""
        assert result["guided_reference_evaluated"] is True
        assert result["guided_reference_success"] is True
        assert result["reference_path_verified"] is None
        assert result["success"] is True

    def test_environment_only_succeeds_without_agent_evaluation(self, tmp_path):
        scenario_dir = tmp_path / "scenario"
        scenario_dir.mkdir()
        ground_truth = {"attack_path": [{"target_node": "target-1"}]}
        verifier = ScenarioVerifier(validation_mode="guided_agent")

        with patch.object(verifier, "_load_scenario_context", return_value=(ground_truth, {}, {})), \
             patch.object(verifier, "_deploy", return_value=True), \
             patch.object(verifier, "_run_ansible", return_value={"ok": True, "skipped": True}), \
             patch.object(verifier, "_verify_environment", return_value={"all_targets_verified": True}), \
             patch.object(verifier, "_verify_attack_path_reachability", return_value={"all_edges_verified": True}), \
             patch.object(verifier, "_run_guide_runtime_preflight") as guide_preflight, \
             patch.object(verifier, "_prepare_agent_transport") as prepare_transport, \
             patch.object(verifier, "_run_agent") as run_agent, \
             patch.object(verifier, "_destroy"), \
             patch.object(verifier, "_save_result", side_effect=lambda _path, result: result):
            result = verifier.run_full(
                str(scenario_dir), api_key="", environment_only=True
            )

        guide_preflight.assert_not_called()
        prepare_transport.assert_not_called()
        run_agent.assert_not_called()
        assert result["environment_only"] is True
        assert result["range_build_verified"] is True
        assert result["guided_trial_evaluated"] is False
        assert result["agent_evaluated"] is False
        assert result["failure_stage"] == ""
        assert result["success"] is True

    def test_environment_only_summary_uses_range_build_status(self, tmp_path, capsys):
        verifier = ScenarioVerifier()

        verifier._save_result(tmp_path, {
            "environment_only": True,
            "range_build_verified": True,
            "flag_verification": {"all_captured": False, "per_target": {}},
        })

        assert "Result: PASS" in capsys.readouterr().out

    def test_guided_agent_transport_failure_is_distinct(self, tmp_path):
        scenario_dir = tmp_path / "scenario"
        scenario_dir.mkdir()
        (scenario_dir / "ground_truth.json").write_text(json.dumps({
            "scenario": "guided",
            "attack_path": [{
                "injection_point": "dmz-target-1",
                "target_node": "target-1",
                "cve_id": "CVE-TEST",
                "flag": "flag{abc}",
                "depends_on": [],
            }],
        }))
        (scenario_dir / "scenario.yaml").write_text("name: guided\n")
        verifier = ScenarioVerifier(validation_mode="guided_agent")
        with patch.object(verifier, "_deploy", return_value=True), \
             patch.object(verifier, "_run_ansible", return_value={"ok": True, "skipped": True}), \
             patch.object(verifier, "_verify_environment", return_value={"all_targets_verified": True}), \
             patch.object(verifier, "_verify_attack_path_reachability", return_value={"all_edges_verified": True}), \
             patch.object(verifier, "_run_guide_runtime_preflight", return_value={
                 "evaluated": True, "overall_status": "compatible",
                 "integrity_valid": True, "agent_allowed": True, "entries": [],
             }), \
             patch.object(verifier, "_prepare_agent_transport", return_value={
                 "ok": False, "stage": "network_prepare", "error": "unreachable"
             }), \
             patch.object(verifier, "_run_agent") as run_agent, \
             patch.object(verifier, "_destroy"), \
             patch.object(verifier, "_save_result", side_effect=lambda _path, result: result):
            result = verifier.run_full(str(scenario_dir), api_key="test")

        run_agent.assert_not_called()
        assert result["agent_evaluated"] is False
        assert result["failure_stage"] == "agent_transport"
        assert result["agent_transport"]["error"] == "unreachable"

    def test_guided_agent_is_not_started_when_service_readiness_fails(self, tmp_path):
        scenario_dir = tmp_path / "scenario"
        scenario_dir.mkdir()
        (scenario_dir / "ground_truth.json").write_text(json.dumps({
            "scenario": "guided-readiness",
            "attack_path": [{
                "injection_point": "dmz-target-1",
                "target_node": "target-1",
                "service_node": "target-1",
                "cve_id": "CVE-TEST",
                "flag": "flag{abc}",
                "depends_on": [],
                "readiness_probes": [{"probe_type": "tcp", "target": "8080"}],
            }],
        }))
        (scenario_dir / "scenario.yaml").write_text("name: guided-readiness\n")
        verifier = ScenarioVerifier(validation_mode="guided_agent")
        with patch.object(verifier, "_deploy", return_value=True), \
             patch.object(verifier, "_run_ansible", return_value={"ok": True, "skipped": True}), \
             patch.object(verifier, "_verify_environment", return_value={
                 "all_targets_verified": False,
                 "targets": {"target-1": False},
                 "target_details": {"target-1": {"running": True, "probes": [{"ok": False}]}},
             }), \
             patch.object(verifier, "_prepare_agent_transport") as prepare_transport, \
             patch.object(verifier, "_run_agent") as run_agent, \
             patch.object(verifier, "_destroy"), \
             patch.object(verifier, "_save_result", side_effect=lambda _path, result: result):
            result = verifier.run_full(str(scenario_dir), api_key="test")

        prepare_transport.assert_not_called()
        run_agent.assert_not_called()
        assert result["environment_verified"] is False
        assert result["attack_graph_valid"] is True
        assert result["agent_evaluated"] is False
        assert result["failure_stage"] == "readiness"

    def test_guided_agent_is_not_started_when_attack_edge_is_unreachable(self, tmp_path):
        scenario_dir = tmp_path / "scenario"
        scenario_dir.mkdir()
        (scenario_dir / "ground_truth.json").write_text(json.dumps({
            "scenario": "guided-path",
            "attack_path": [{
                "injection_point": "dmz-target-1",
                "target_node": "target-1",
                "cve_id": "CVE-TEST",
                "flag": "flag{abc}",
                "depends_on": [],
            }],
        }))
        (scenario_dir / "scenario.yaml").write_text("name: guided-path\n")
        verifier = ScenarioVerifier(validation_mode="guided_agent")
        with patch.object(verifier, "_deploy", return_value=True), \
             patch.object(verifier, "_run_ansible", return_value={"ok": True, "skipped": True}), \
             patch.object(verifier, "_verify_environment", return_value={"all_targets_verified": True}), \
             patch.object(verifier, "_verify_attack_path_reachability", return_value={
                 "all_edges_verified": False,
                 "edges": [{"source_node": "attacker", "target_node": "target-1", "ok": False}],
             }), \
             patch.object(verifier, "_prepare_agent_transport") as prepare_transport, \
             patch.object(verifier, "_run_agent") as run_agent, \
             patch.object(verifier, "_destroy"), \
             patch.object(verifier, "_save_result", side_effect=lambda _path, result: result):
            result = verifier.run_full(str(scenario_dir), api_key="test")

        prepare_transport.assert_not_called()
        run_agent.assert_not_called()
        assert result["environment_verified"] is True
        assert result["attack_graph_valid"] is True
        assert result["attack_path_reachable"] is False
        assert result["failure_stage"] == "attack_path_reachability"


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


class TestAgentTransport:
    @staticmethod
    def _write_runtime_atom(atoms_dir: Path) -> None:
        atom_dir = atoms_dir / "CVE-RUNTIME-0001"
        atom_dir.mkdir(parents=True)
        (atom_dir / "atom.yaml").write_text(yaml.safe_dump({
            "version": 3,
            "cve_id": "CVE-RUNTIME-0001",
            "category": "test",
            "docker_image": "vulhub/test:latest",
            "ports": [8080],
            "vuln_category": "RCE",
            "primary_mitre_phase": "initial_access",
            "service_role": "web_application",
            "exploit_complexity": "simple",
            "attack_method": "single_request",
            "runtime_spec": {
                "ports": [8080],
                "source_image": "vulhub/test:latest",
                "runtime_image": "cvelab-runtime-test:abc",
                "runtime_status": "ready",
                "runtime_build": {
                    "base_image_digest": "sha256:base",
                    "generated_hash": "runtime-build-hash",
                },
            },
            "verification": {
                "runtime_verification": {
                    "status": "ready",
                    "runtime_image_digest": "sha256:expected",
                },
            },
        }, sort_keys=False))

    def test_endpoint_defaults_to_anthropic(self):
        assert ScenarioVerifier._agent_endpoint("") == ("api.anthropic.com", 443)
        assert ScenarioVerifier._agent_endpoint("http://10.0.0.5:3000") == (
            "10.0.0.5", 3000
        )

    def test_resolve_literal_ipv4_without_dns(self):
        assert ScenarioVerifier._resolve_endpoint("10.0.0.5", 3000) == ["10.0.0.5"]

    def test_control_network_uses_non_eth_interface_prefix(self, tmp_path):
        scenario_dir = tmp_path / "scenario"
        scenario_dir.mkdir()
        (scenario_dir / "clab.yaml").write_text("name: pilot\n")
        verifier = ScenarioVerifier()
        calls = []
        network_name = ""

        def fake_run(command, timeout=30):
            nonlocal network_name
            calls.append(command)
            if command[:3] == ["docker", "network", "create"]:
                network_name = command[-1]
                return subprocess.CompletedProcess(command, 0, "id\n", "")
            if command[:3] == ["docker", "network", "connect"]:
                return subprocess.CompletedProcess(command, 0, "", "")
            if command[:2] == ["docker", "inspect"]:
                payload = [{
                    "State": {"Pid": 1234},
                    "NetworkSettings": {"Networks": {
                        network_name: {"Gateway": "172.30.0.1", "IPAddress": "172.30.0.2"}
                    }},
                }]
                return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
            if command[:7] == ["docker", "exec", "-u", "0", "clab-pilot-attacker", "ip", "route"]:
                return subprocess.CompletedProcess(command, 1, "", "RTNETLINK answers: Operation not permitted")
            if command[:6] == ["docker", "exec", "-u", "0", "clab-pilot-attacker", "ip"]:
                output = "3: ctl0@if4: <UP> inet 172.30.0.2/16 scope global ctl0\n"
                return subprocess.CompletedProcess(command, 0, output, "")
            if command[:1] == ["nsenter"]:
                return subprocess.CompletedProcess(command, 0, "", "")
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch.object(verifier, "_run_command", side_effect=fake_run):
            result = verifier._prepare_agent_transport(
                str(scenario_dir), "http://10.0.0.5:3000"
            )

        assert result["ok"] is True
        create_command = calls[0]
        assert "com.docker.network.container_iface_prefix=ctl" in create_command
        assert "--subnet" in create_command
        assert create_command[create_command.index("--subnet") + 1].startswith("172.31.")
        route_command = ["docker", "exec", "-u", "0", "clab-pilot-attacker", "ip", "route", "replace",
                         "10.0.0.5/32", "via", "172.30.0.1", "dev", "ctl0"]
        assert route_command in calls
        assert ["nsenter", "-t", "1234", "-n", "ip", "route", "replace",
                "10.0.0.5/32", "via", "172.30.0.1", "dev", "ctl0"] in calls

    def test_runtime_build_manifest_is_materialized_before_deploy(self, tmp_path):
        scenario_dir = tmp_path / "scenario"
        context = tmp_path / "bundle"
        context.mkdir()
        dockerfile = context / "Dockerfile"
        dockerfile.write_text("FROM test:latest\n")
        scenario_dir.mkdir()
        (scenario_dir / "scenario.yaml").write_text(yaml.safe_dump({
            "runtime_builds": [{
                "cve_id": "CVE-BUILD-0001",
                "image": "cvelab-atom-test:abc",
                "context": str(context),
                "dockerfile": str(dockerfile),
            }],
        }))
        verifier = ScenarioVerifier()
        calls = []

        def fake_run(command, timeout=30):
            calls.append((command, timeout))
            return subprocess.CompletedProcess(command, 0, "built", "")

        with patch.object(verifier, "_run_command", side_effect=fake_run):
            result = verifier._materialize_runtime_images(str(scenario_dir))

        assert result["ok"] is True
        assert calls[0][0][:4] == ["docker", "build", "--file", str(dockerfile)]
        assert calls[0][1] == 900

    def test_selected_runtime_image_is_checked_before_deploy(self, tmp_path):
        scenario_dir = tmp_path / "scenario"
        scenario_dir.mkdir()
        (scenario_dir / "scenario.yaml").write_text(yaml.safe_dump({
            "runtime_images": [{
                "cve_id": "CVE-RUNTIME-0001",
                "selected_image": "cvelab-runtime-test:abc",
                "selection": "runtime_image",
                "runtime_image_digest": "sha256:expected",
            }],
        }))
        verifier = ScenarioVerifier()
        calls = []

        def fake_run(command, timeout=30):
            calls.append((command, timeout))
            return subprocess.CompletedProcess(command, 0, json.dumps([{
                "Id": "sha256:expected", "RepoDigests": [],
            }]), "")

        with patch.object(verifier, "_run_command", side_effect=fake_run):
            result = verifier._materialize_runtime_images(str(scenario_dir))

        assert result["ok"] is True
        assert result["builds"] == []
        assert result["runtime_images"][0]["ok"] is True
        assert result["runtime_images"][0]["action"] == "verified_local_image"
        assert calls == [(["docker", "image", "inspect", "cvelab-runtime-test:abc"], 30)]

    def test_mismatched_runtime_image_is_rebuilt_not_deployed(self, tmp_path):
        scenario_dir = tmp_path / "scenario"
        scenario_dir.mkdir()
        selection = {
            "cve_id": "CVE-RUNTIME-0001",
            "selected_image": "cvelab-runtime-test:abc",
            "selection": "runtime_image",
            "runtime_image_digest": "sha256:expected",
        }
        (scenario_dir / "scenario.yaml").write_text(yaml.safe_dump({
            "runtime_images": [selection],
        }))
        verifier = ScenarioVerifier()

        with patch.object(
            verifier, "_run_command",
            return_value=subprocess.CompletedProcess([], 0, json.dumps([
                {"Id": "sha256:wrong", "RepoDigests": []},
            ]), ""),
        ), patch.object(
            verifier, "_rebuild_runtime_image",
            return_value={"ok": True, "action": "rebuilt_and_reverified"},
        ) as rebuild:
            result = verifier._materialize_runtime_images(str(scenario_dir))

        assert result["ok"] is True
        assert result["runtime_images"][0]["action"] == "rebuilt_and_reverified"
        rebuild.assert_called_once_with(selection)

    def test_missing_runtime_image_is_rebuilt_with_shared_builder(self, tmp_path):
        scenario_dir = tmp_path / "scenario"
        scenario_dir.mkdir()
        atoms_dir = tmp_path / "atoms"
        self._write_runtime_atom(atoms_dir)
        selection = {
            "cve_id": "CVE-RUNTIME-0001",
            "source_image": "vulhub/test:latest",
            "selected_image": "cvelab-runtime-test:abc",
            "selection": "runtime_image",
            "base_image_digest": "sha256:base",
            "runtime_image_digest": "sha256:expected",
            "runtime_build_generated_hash": "runtime-build-hash",
        }
        (scenario_dir / "scenario.yaml").write_text(yaml.safe_dump({
            "runtime_images": [selection],
        }))
        verifier = ScenarioVerifier(atoms_dir=str(atoms_dir))
        from clab_builder.atomizer.runtime_builder import RuntimeBuildResult
        from clab_builder.shared.models.atom import RuntimeStatus

        missing = subprocess.CompletedProcess([], 1, "", "not found")
        rebuilt = RuntimeBuildResult(
            status=RuntimeStatus.READY,
            runtime_image="cvelab-runtime-test:abc",
            base_image_digest="sha256:base",
            runtime_image_digest="sha256:rebuilt",
        )
        with patch.object(verifier, "_run_command", return_value=missing), patch(
            "clab_builder.atomizer.runtime_generator.generate_runtime_artifacts",
            return_value=SimpleNamespace(
                unsupported_reason="",
                manifest={"generated_hash": "runtime-build-hash"},
            ),
        ), patch(
            "clab_builder.atomizer.runtime_builder.build_runtime_image",
            return_value=rebuilt,
        ) as build:
            result = verifier._materialize_runtime_images(str(scenario_dir))

        assert result["ok"] is True
        check = result["runtime_images"][0]
        assert check["action"] == "rebuilt_and_reverified"
        assert check["runtime_digest_changed"] is True
        build.assert_called_once()


class TestServiceReadiness:
    def test_proc_tcp_listening_is_detected_without_nc(self):
        verifier = ScenarioVerifier()
        proc = "  sl  local_address rem_address   st\n  1: 00000000:1F90 00000000:0000 0A\n"

        def fake_run(command, timeout=30):
            return subprocess.CompletedProcess(command, 0, proc, "")

        with patch.object(verifier, "_run_command", side_effect=fake_run):
            ok, detail = verifier._container_port_listening("target", 8080)

        assert ok is True
        assert detail == "listening"

    def test_proc_tcp_closed_is_not_ready(self):
        verifier = ScenarioVerifier()
        proc = "  sl  local_address rem_address   st\n  1: 00000000:1F90 00000000:0000 01\n"

        def fake_run(command, timeout=30):
            return subprocess.CompletedProcess(command, 0, proc, "")

        with patch.object(verifier, "_run_command", side_effect=fake_run):
            ok, detail = verifier._container_port_listening("target", 8080)

        assert ok is False
        assert "not listening" in detail

    def test_environment_reports_readiness_separately_from_container_state(self, tmp_path):
        scenario_dir = tmp_path / "scenario"
        scenario_dir.mkdir()
        (scenario_dir / "clab.yaml").write_text("name: readiness\n")
        gt = {"attack_path": [{
            "target_node": "target-1",
            "service_node": "target-1",
            "ports": [8080],
            "readiness_probes": [{"probe_type": "tcp", "target": "8080"}],
        }]}
        verifier = ScenarioVerifier()

        def fake_state(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, "true\n", "")

        with patch("clab_builder.orchestrator.composer.verifier.subprocess.run", side_effect=fake_state), \
             patch.object(verifier, "_run_command", side_effect=lambda command, timeout=30: subprocess.CompletedProcess(command, 0, "header\n", "")):
            result = verifier._verify_environment(gt, str(scenario_dir))

        assert result["targets"]["target-1"] is False
        assert result["all_targets_verified"] is False
        assert result["target_details"]["target-1"]["running"] is True


class TestAttackPathReachability:
    def test_allowed_and_denied_edges_are_checked_from_source_namespaces(self, tmp_path):
        (tmp_path / "clab.yaml").write_text("name: path-test\n")
        verifier = ScenarioVerifier()
        ground_truth = {
            "attack_path": [
                {
                    "target_node": "target-1",
                    "execution_host_node": "attacker",
                    "target_ip": "192.168.100.2",
                    "ports": [80],
                },
                {
                    "target_node": "target-2",
                    "execution_host_node": "target-1",
                    "target_ip": "10.10.1.2",
                    "ports": [8080],
                },
            ],
            "network_policy_checks": [{
                "source_node": "attacker",
                "target_node": "target-2",
                "target_ip": "10.10.1.2",
                "ports": [8080],
                "expected_reachable": False,
            }],
        }
        def fake_run(command, timeout=30):
            if command[:4] == ["docker", "exec", "-u", "0"] and command[5:7] == ["sh", "-c"]:
                return subprocess.CompletedProcess(command, 0, "/usr/bin/python3\n", "")
            source = command[4]
            target_ip = command[-2]
            reachable = (
                (source, target_ip) in {
                    ("clab-path-test-attacker", "192.168.100.2"),
                    ("clab-path-test-target-1", "10.10.1.2"),
                }
            )
            return subprocess.CompletedProcess(
                command, 0 if reachable else 1, "", "connection refused"
            )

        with patch.object(verifier, "_run_command", side_effect=fake_run):
            result = verifier._verify_attack_path_reachability(
                ground_truth,
                str(tmp_path),
                {
                    "target-1": {"eth1": "192.168.100.2/24"},
                    "target-2": {"eth1": "10.10.1.2/24"},
                },
            )

        assert result["all_edges_verified"] is True
        assert len(result["edges"]) == 3
        assert any(
            edge["expected_reachable"] is False and edge["ok"] is True
            for edge in result["edges"]
        )

    def test_denied_policy_fails_when_any_declared_port_is_reachable(self, tmp_path):
        (tmp_path / "clab.yaml").write_text("name: deny-test\n")
        verifier = ScenarioVerifier()
        ground_truth = {
            "attack_path": [],
            "network_policy_checks": [{
                "source_node": "attacker",
                "target_node": "target-1",
                "target_ip": "10.10.1.2",
                "ports": [8080, 8443],
                "expected_reachable": False,
            }],
        }

        def fake_run(command, timeout=30):
            if command[5:7] == ["sh", "-c"]:
                return subprocess.CompletedProcess(command, 0, "/usr/bin/python3\n", "")
            port = command[-1]
            return subprocess.CompletedProcess(
                command, 0 if port == "8080" else 1, "", "connection refused"
            )

        with patch.object(verifier, "_run_command", side_effect=fake_run):
            result = verifier._verify_attack_path_reachability(
                ground_truth, str(tmp_path), {}
            )

        assert result["all_edges_verified"] is False
        assert result["edges"][0]["ok"] is False

    def test_probe_falls_back_to_nsenter_without_source_python(self):
        verifier = ScenarioVerifier()
        calls = []

        def fake_run(command, timeout=30):
            calls.append(command)
            if command[:5] == ["docker", "exec", "-u", "0", "clab-path-test-attacker"]:
                return subprocess.CompletedProcess(command, 1, "", "python unavailable")
            if command[:3] == ["docker", "inspect", "-f"]:
                return subprocess.CompletedProcess(command, 0, "100\n", "")
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch.object(verifier, "_run_command", side_effect=fake_run):
            result = verifier._probe_network_edge(
                "path-test", "attacker", "192.168.100.2", 8080
            )

        assert result["reachable"] is True
        assert any(command[0] == "nsenter" for command in calls)


class TestGuideRuntimePreflight:
    def test_legacy_guide_is_explicitly_unknown(self, tmp_path):
        scenario_dir = tmp_path / "scenario"
        (scenario_dir / "exploit_guides").mkdir(parents=True)
        (scenario_dir / "clab.yaml").write_text("name: preflight-test\n")
        (scenario_dir / "exploit_guides" / "dmz-target-1.yaml").write_text(
            yaml.safe_dump({
                "version": 1,
                "cve_id": "CVE-TEST",
                "steps": [{
                    "id": "exploit", "action": "trigger",
                    "procedure": "run", "depends_on": [],
                    "success_signal": "ok",
                }],
            })
        )
        verifier = ScenarioVerifier(strict_guide_compatibility=True)
        result = verifier._run_guide_runtime_preflight(str(scenario_dir), {
            "attack_path": [{
                "injection_point": "dmz-target-1",
                "target_node": "target-1",
                "cve_id": "CVE-TEST",
                "execution_host_node": "attacker",
            }],
        })
        assert result["overall_status"] == "unknown_legacy"
        assert result["integrity_valid"] is True
        assert result["agent_allowed"] is True

    @staticmethod
    def _write_v2_guide(path: Path, *, tool: dict | None = None, execution=None):
        step_execution = execution if execution is not None else {
            "scope": "actor",
            "tools": [tool] if tool else [],
            "materials": [],
        }
        path.write_text(yaml.safe_dump({
            "version": 2,
            "cve_id": "CVE-TEST",
            "steps": [{
                "id": "exploit", "action": "trigger", "procedure": "run",
                "depends_on": [], "success_signal": "ok",
                "execution": step_execution,
            }],
        }))

    def _scenario_for_v2(self, tmp_path, execution):
        scenario_dir = tmp_path / "scenario"
        guide_dir = scenario_dir / "exploit_guides"
        guide_dir.mkdir(parents=True)
        (scenario_dir / "clab.yaml").write_text("name: preflight-v2\n")
        self._write_v2_guide(guide_dir / "dmz-target-1.yaml", execution=execution)
        ground_truth = {
            "attack_path": [{
                "injection_point": "dmz-target-1",
                "target_node": "target-1",
                "cve_id": "CVE-TEST",
                "execution_host_node": "attacker",
            }],
        }
        return scenario_dir, ground_truth

    def test_v2_tool_available_is_compatible(self, tmp_path):
        scenario_dir, ground_truth = self._scenario_for_v2(tmp_path, {
            "id": "curl", "kind": "executable", "name": "curl",
        })
        verifier = ScenarioVerifier(strict_guide_compatibility=True)
        completed = subprocess.CompletedProcess([], 0, "/usr/bin/curl\n", "")
        with patch("clab_builder.orchestrator.composer.verifier.subprocess.run", return_value=completed):
            result = verifier._run_guide_runtime_preflight(str(scenario_dir), ground_truth)
        assert result["overall_status"] == "compatible"
        assert result["agent_allowed"] is True

    def test_v2_missing_tool_with_offline_material_is_repairable(self, tmp_path):
        scenario_dir, ground_truth = self._scenario_for_v2(tmp_path, {
            "id": "exploit.py", "kind": "executable", "name": "python3",
            "artifact": "source_bundle/exploit.py",
        })
        verifier = ScenarioVerifier(strict_guide_compatibility=True)
        missing = subprocess.CompletedProcess([], 1, "", "not found")
        with patch("clab_builder.orchestrator.composer.verifier.subprocess.run", return_value=missing), \
             patch.object(verifier, "_guide_artifact_exists", return_value=True):
            # The transfer declaration is the explicit permission to adapt a
            # missing attacker-side executable into the foothold context.
            guide_path = scenario_dir / "exploit_guides" / "dmz-target-1.yaml"
            self._write_v2_guide(
                guide_path,
                execution={
                    "scope": "actor",
                    "tools": [{
                        "id": "exploit", "kind": "executable", "name": "python3",
                        "artifact": "source_bundle/exploit.py",
                    }],
                    "materials": [{
                        "ref": "source_bundle/exploit.py", "scope": "actor",
                        "delivery": "channel_transfer",
                    }],
                },
            )
            result = verifier._run_guide_runtime_preflight(str(scenario_dir), ground_truth)
        assert result["overall_status"] == "warnings"
        assert result["integrity_valid"] is True
        assert result["agent_allowed"] is True
        assert result["entries"][0]["adaptations"][0]["strategy"] == "channel_transfer"

    def test_v2_missing_tool_without_adaptation_is_incompatible(self, tmp_path):
        scenario_dir, ground_truth = self._scenario_for_v2(tmp_path, {
            "scope": "actor",
            "tools": [{"id": "psql", "kind": "executable", "name": "psql"}],
            "materials": [],
        })
        verifier = ScenarioVerifier(strict_guide_compatibility=True)
        missing = subprocess.CompletedProcess([], 1, "", "not found")
        with patch("clab_builder.orchestrator.composer.verifier.subprocess.run", return_value=missing):
            result = verifier._run_guide_runtime_preflight(str(scenario_dir), ground_truth)
        assert result["overall_status"] == "warnings"
        assert result["integrity_valid"] is True
        assert result["agent_allowed"] is True

    def test_v2_missing_execution_context_is_incompatible(self, tmp_path):
        scenario_dir = tmp_path / "scenario"
        guide_dir = scenario_dir / "exploit_guides"
        guide_dir.mkdir(parents=True)
        (scenario_dir / "clab.yaml").write_text("name: preflight-invalid\n")
        (guide_dir / "dmz-target-1.yaml").write_text(yaml.safe_dump({
            "version": 2, "cve_id": "CVE-TEST",
            "steps": [{"id": "exploit", "action": "trigger",
                       "procedure": "run", "depends_on": [],
                       "success_signal": "ok"}],
        }))
        verifier = ScenarioVerifier(strict_guide_compatibility=True)
        result = verifier._run_guide_runtime_preflight(str(scenario_dir), {
            "attack_path": [{"injection_point": "dmz-target-1",
                              "target_node": "target-1", "cve_id": "CVE-TEST"}],
        })
        assert result["overall_status"] == "invalid"
        assert result["integrity_valid"] is False
        assert result["agent_allowed"] is False

    def test_v2_mounted_material_must_exist_on_execution_host(self, tmp_path):
        scenario_dir, ground_truth = self._scenario_for_v2(tmp_path, {
            "scope": "actor",
            "tools": [],
            "materials": [{
                "ref": "source_bundle/client.py",
                "scope": "actor",
                "delivery": "mounted",
            }],
        })
        ground_truth["attack_path"][0]["execution_host_node"] = "target-1"
        verifier = ScenarioVerifier(strict_guide_compatibility=True)
        with patch.object(verifier, "_guide_artifact_exists", return_value=True):
            result = verifier._run_guide_runtime_preflight(str(scenario_dir), ground_truth)
        assert result["overall_status"] == "warnings"
        assert result["integrity_valid"] is True
        assert result["entries"][0]["checks"][0]["kind"] == "material"

    def test_v2_channel_transfer_material_is_repairable(self, tmp_path):
        scenario_dir, ground_truth = self._scenario_for_v2(tmp_path, {
            "scope": "actor",
            "tools": [],
            "materials": [{
                "ref": "source_bundle/client.py",
                "scope": "actor",
                "delivery": "channel_transfer",
            }],
        })
        ground_truth["attack_path"][0]["execution_host_node"] = "target-1"
        verifier = ScenarioVerifier(strict_guide_compatibility=True)
        with patch.object(verifier, "_guide_artifact_exists", return_value=True):
            result = verifier._run_guide_runtime_preflight(str(scenario_dir), ground_truth)
        assert result["overall_status"] == "warnings"
        assert result["integrity_valid"] is True
        assert result["entries"][0]["adaptations"][0]["strategy"] == "channel_transfer_material"


class TestAgentArtifactRecovery:
    def test_stale_artifacts_are_removed_before_trial(self, tmp_path):
        for name in ("output.json", "session.json", "agent_stream.log"):
            (tmp_path / name).write_text("stale")
        (tmp_path / "input.json").write_text("current")

        ScenarioVerifier._reset_agent_artifacts(tmp_path)

        assert (tmp_path / "input.json").read_text() == "current"
        assert not (tmp_path / "output.json").exists()
        assert not (tmp_path / "session.json").exists()
        assert not (tmp_path / "agent_stream.log").exists()

    def test_timeout_recovery_keeps_partial_claim_without_verifying_it(self):
        stream = (
            "[Agent] Target-1 RCE confirmed\n"
            "[Tool] Bash: cat /flag\n"
            "[Agent] Target-1 flag captured: flag{abc123}\n"
            "Agent timed out after 1800s\n"
        )

        result = ScenarioVerifier._recover_partial_agent_result(
            stream,
            [{"node_name": "target-1"}, {"node_name": "target-2"}],
            "agent_timeout",
        )

        assert result["termination_reason"] == "agent_timeout"
        assert result["verified_flags"] == {}
        assert result["claimed_flags"] == [{
            "target": "target-1",
            "reported_flag": "flag{abc123}",
            "source": "assistant_text",
        }]
        assert result["attack_log"][0]["flag_claimed"] is True
        assert "flag_captured" not in result["attack_log"][0]
        assert result["failed_targets"] == ["target-2"]
        assert result["partial_result"] is True
        assert result["observed_progress"]["targets_with_claimed_flags"] == ["target-1"]
        assert result["structured_result"] is False

    def test_partial_claims_never_satisfy_flag_gate(self):
        verifier = ScenarioVerifier()
        result = verifier.verify_flags(
            {"verified_flags": {}, "claimed_flags": [{
                "target": "target-1", "reported_flag": "flag{abc123}",
            }]},
            {"attack_path": [{"target_node": "target-1", "flag": "flag{abc123}"}]},
        )
        assert result["all_captured"] is False
        assert result["per_target"]["target-1"]["captured"] == ""

    def test_failure_stage_preserves_timeout_and_api_categories(self):
        common = {
            "environment_success": True,
            "setup_results": {},
            "environment": {"all_targets_verified": True},
            "validation_mode": "guided_agent",
            "reference_verified": False,
            "agent_transport": {"ok": True},
            "agent_evaluated": True,
            "attack_graph_valid": True,
            "attack_path_reachable": True,
            "guided_trial_success": False,
            "objective_achieved": False,
        }
        assert ScenarioVerifier._failure_stage(
            **common, agent_termination_reason="agent_timeout"
        ) == "agent_timeout"
        assert ScenarioVerifier._failure_stage(
            **common, agent_termination_reason="max_turns_reached"
        ) == "agent_turn_limit"
        assert ScenarioVerifier._failure_stage(
            **common, agent_termination_reason="agent_api_protocol"
        ) == "agent_api_protocol"


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

    def test_build_prompt_includes_guide_and_dag_without_flag_value(self):
        from clab_builder.orchestrator.composer.scenario_runner import build_prompt

        prompt = build_prompt({
            "scenario_name": "guided-test",
            "attacker_ip": "172.20.1.1",
            "targets": [{
                "node_name": "target-2",
                "cve_id": "CVE-TEST",
                "ip": "10.10.1.2",
                "ports": [8080],
                "zone": "app",
                "depends_on_nodes": ["target-1"],
                "execution_host": "target-1",
                "exploit_guide": "steps:\n- id: exploit\n  success_signal: command output",
            }],
        })
        assert "Exploit Guide" in prompt
        assert "target-1" in prompt
        assert "same CLab network" not in prompt
        assert "flag{secret}" not in prompt


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

    def test_observed_progress_is_separate_from_verified_flags(self):
        from clab_builder.orchestrator.composer.scenario_runner import (
            extract_observed_progress,
        )

        progress = extract_observed_progress(
            "Target-1 flag captured: `flag{aaa}`. "
            "Target-2 flag retrieved: flag{bbb}.",
            [{"node_name": "target-1"}, {"node_name": "target-2"}],
        )
        assert progress["targets_with_claimed_flags"] == ["target-1", "target-2"]
        assert {item["target"] for item in progress["flag_claims"]} == {
            "target-1", "target-2"
        }
        assert progress["flag_claims"][0]["source"] == "assistant_text"

    def test_turn_limit_is_distinguished_from_completed_output(self):
        from clab_builder.orchestrator.composer.scenario_runner import (
            classify_termination,
        )

        assert classify_termination("Reached maximum number of turns (80)") == (
            "max_turns_reached"
        )
        assert classify_termination(
            "Reached maximum number of turns (80)", structured_result=True
        ) == "completed"


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

    def test_agent_timeout_is_configurable(self):
        assert ScenarioVerifier().agent_timeout == 1800
        assert ScenarioVerifier(agent_timeout=600).agent_timeout == 600

    def test_default_agent_image(self):
        verifier = ScenarioVerifier()
        assert verifier.agent_image == "clab-agent:latest"

    def test_ansible_timeout_is_reported_as_setup_failure(self, tmp_path):
        (tmp_path / "clab.yaml").write_text("name: timeout-test\n")
        ansible_dir = tmp_path / "ansible"
        ansible_dir.mkdir()
        (ansible_dir / "cve-setup.yaml").write_text("- hosts: localhost\n  tasks: []\n")
        verifier = ScenarioVerifier()
        with patch(
            "clab_builder.orchestrator.composer.verifier.subprocess.run",
            side_effect=subprocess.TimeoutExpired(["ansible-playbook"], 300),
        ):
            result = verifier._run_ansible(str(tmp_path), "cve-setup.yaml")

        assert result["ok"] is False
        assert result["timed_out"] is True
        assert result["termination_reason"] == "ansible_timeout"
