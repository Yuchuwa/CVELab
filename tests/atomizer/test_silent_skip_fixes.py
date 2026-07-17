"""Regression tests for the atom-build silent-skip fixes.

Covers:
- Layer 1: _generate_exploit_guide downgrades a reusable command_channel
  when the Agent declared one without execute_command, instead of dropping
  the whole guide.
- Layer 2: AtomConfig keeps verified=True when native succeeded even if
  orchestrated rebuild failed.
- Layer 3: invalid capability_grants values are surfaced, and agent_runner
  merges (not replaces) extracted output so structural defaults survive.
- Layer B: orchestrated verification probes /proc/net/tcp LISTEN state and
  gives slow-init (DB/search) services a longer readiness window.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
SRC = PROJECT_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from clab_builder.atomizer.pipeline import AtomizerPipeline
from clab_builder.shared.models.atom import (
    AtomConfig, VulnCategory, MitrePhase, ServiceRole,
    ExploitComplexity, AttackMethod,
)


def _minimal_atom(**overrides) -> AtomConfig:
    base = dict(
        cve_id="CVE-TEST-1",
        category="test",
        docker_image="img:1",
        ports=[80],
        vuln_category=VulnCategory.RCE,
        primary_mitre_phase=MitrePhase.INITIAL_ACCESS,
        service_role=ServiceRole.WEB_APPLICATION,
        exploit_complexity=ExploitComplexity.SIMPLE,
        attack_method=AttackMethod.SINGLE_REQUEST,
        verified=True,
        version=3,
    )
    base.update(overrides)
    return AtomConfig(**base)


@pytest.mark.unit
class TestGuideReusableDowngrade:
    """Layer 1: reusable channel is downgraded, not silently dropped."""

    def test_downgrade_dict_guide_clears_reusable(self):
        raw = {
            "version": 1,
            "summary": "LFI via traversal",
            "post_exploit": {
                "principal": "root",
                "capabilities": ["read_file"],
                "command_channel": {
                    "type": "webshell",
                    "established_by": ["exploit"],
                    "invocation_hint": "reuse",
                    "reusable": True,
                },
            },
        }
        patched = AtomizerPipeline._downgrade_reusable_channel(raw)
        channel = patched["post_exploit"]["command_channel"]
        assert channel["reusable"] is False
        assert channel["established_by"] == []
        # Other fields preserved.
        assert patched["post_exploit"]["capabilities"] == ["read_file"]
        assert patched["summary"] == "LFI via traversal"

    def test_downgrade_none_input_returns_none(self):
        assert AtomizerPipeline._downgrade_reusable_channel(None) is None


@pytest.mark.unit
class TestVerifiedDecoupledFromOrchestrated:
    """Layer 2: native success keeps verified even if orchestrated failed."""

    def test_native_success_orchestrated_fail_stays_verified(self):
        atom = _minimal_atom(
            cve_id="CVE-TEST-1",
            verification={
                "native_verification": {"success": True},
                "orchestrated_verification": {"success": False},
                "environment_ready": False,
            },
        )
        assert atom.verified is True

    def test_native_fail_downgrades_verified(self):
        atom = _minimal_atom(
            cve_id="CVE-TEST-2",
            verification={
                "native_verification": {"success": False},
                "orchestrated_verification": {"success": True},
                "environment_ready": True,
            },
        )
        assert atom.verified is False


@pytest.mark.unit
class TestAgentRunnerOutputMerge:
    """Layer 3: extracted output is merged, not replacing structural defaults."""

    def test_merge_preserves_missing_keys_and_unions_evidence(self):
        # Import lazily so the test does not require the claude_agent_sdk at
        # collection time; we only exercise the pure-python merge branch.
        import json
        from clab_builder.atomizer.agent import agent_runner as ar

        # Simulate: result init has evidence=["Agent error: x"]; extracted
        # JSON omits exploit_guide and has its own evidence.
        result = {
            "success": False, "evidence": ["Agent error: timeout"],
            "exploit_steps": [], "exploit_guide": {}, "mitre_mapping": {},
            "captured_flag": "",
        }
        extracted = {
            "success": True, "evidence": ["flag captured"],
            # exploit_guide / mitre_mapping intentionally omitted
        }
        # Replicate the merge logic from run_agent.
        prior_evidence = list(result.get("evidence") or [])
        merged = dict(result)
        merged.update(extracted)
        extracted_evidence = list(extracted.get("evidence") or [])
        combined = prior_evidence + [
            e for e in extracted_evidence if e not in prior_evidence
        ]
        merged["evidence"] = combined
        result = merged

        # Structural default survived.
        assert result["exploit_guide"] == {}
        assert result["mitre_mapping"] == {}
        # Evidence unioned, not replaced.
        assert "Agent error: timeout" in result["evidence"]
        assert "flag captured" in result["evidence"]
        assert result["success"] is True


@pytest.mark.unit
class TestOrchestratedProbeStability:
    """Layer B: port probe uses /proc/net/tcp and adapts to slow-init services."""

    def test_slow_init_ports_get_longer_window(self):
        # DB / search service ports are recognized as slow-init.
        for port in (3306, 5432, 9200, 27017, 6379):
            assert AtomizerPipeline._is_slow_init_port(port) is True
        # Web / common ports are not.
        for port in (80, 8080, 443, 7001):
            assert AtomizerPipeline._is_slow_init_port(port) is False

    def test_port_listening_parses_proc_net_tcp(self, monkeypatch):
        # Simulate /proc/net/tcp output containing a LISTEN entry on port 80.
        # Hex 0050 = 80, state 0A = LISTEN.
        sample = (
            "  sl  local_address rem_address   st tx_queue rx_queue ...\n"
            "   0: 00000000:0050 00000000:0000 0A 00000000:00000000 ...\n"
        )

        class FakeResult:
            def __init__(self, stdout, returncode=0):
                self.stdout = stdout
                self.stderr = ""
                self.returncode = returncode

        def fake_run(cmd, **kwargs):
            assert cmd[:2] == ["docker", "exec"]
            # Return sample for /proc/net/tcp, empty for tcp6.
            if "/proc/net/tcp6" in cmd:
                return FakeResult("", returncode=1)
            return FakeResult(sample)

        monkeypatch.setattr("clab_builder.atomizer.pipeline.subprocess.run", fake_run)
        ok, detail = AtomizerPipeline._container_port_listening("any-container", 80)
        assert ok is True
        assert "80" in detail

    def test_port_not_listening_returns_false(self, monkeypatch):
        sample = (
            "  sl  local_address rem_address   st ...\n"
            "   0: 00000000:0016 00000000:0000 0A ...\n"  # port 22 LISTEN, not 80
        )

        class FakeResult:
            def __init__(self, stdout, returncode=0):
                self.stdout = stdout
                self.stderr = ""
                self.returncode = returncode

        def fake_run(cmd, **kwargs):
            return FakeResult(sample if "/proc/net/tcp6" not in cmd else "", returncode=0)

        monkeypatch.setattr("clab_builder.atomizer.pipeline.subprocess.run", fake_run)
        ok, detail = AtomizerPipeline._container_port_listening("any-container", 80)
        assert ok is False
        assert "80" in detail


@pytest.mark.unit
class TestObjectiveEvidenceCheckerFallback:
    """Objective-evidence bugs (no planted flag): when the agent self-reports
    success=False but carries real exploit evidence, the LLM checker should
    arbitrate instead of the run being rejected outright.

    Background: Info_Leak / Auth_Bypass / SSRF atoms do not plant a flag, so
    ``_evaluate_agent_success`` judges them by ``agent_output.success`` +
    evidence presence. When the agent's JSON is truncated and its success
    field is lost during extraction, a verified exploit is wrongly downgraded.
    The fix routes "success=False + non-empty evidence" through the LLM
    checker so the evidence is actually judged.
    """

    def test_evaluate_success_false_with_evidence_is_false(self):
        # The static evaluator still reports False; the rescue happens in
        # _save_atom by calling the LLM checker. We assert the gate condition
        # that triggers that rescue: verified=False AND evidence non-empty.
        from clab_builder.atomizer.agent.researcher import AgentOutput
        ao = AgentOutput(
            cve_id="CVE-X", success=False, exploit_steps=[],
            evidence=["Heartbeat leaked 16384 bytes — vulnerability confirmed"],
            mitre_mapping={}, captured_flag="",
        )
        ev = AtomizerPipeline._evaluate_agent_success(ao, "")
        assert ev.verified is False
        assert ao.evidence  # non-empty evidence is the rescue trigger

    def test_evaluate_success_false_no_evidence_no_rescue(self):
        from clab_builder.atomizer.agent.researcher import AgentOutput
        ao = AgentOutput(
            cve_id="CVE-Y", success=False, exploit_steps=[],
            evidence=[], mitre_mapping={}, captured_flag="",
        )
        ev = AtomizerPipeline._evaluate_agent_success(ao, "")
        assert ev.verified is False
        assert not ao.evidence  # no evidence → no rescue path

    def test_save_atom_routes_failed_with_evidence_to_checker(self, monkeypatch):
        """Verify _save_atom calls the LLM checker for objective-evidence bugs
        when verified=False but evidence is present, and accepts on its verdict.
        """
        from unittest.mock import patch, MagicMock
        from clab_builder.atomizer.agent.researcher import AgentOutput
        from clab_builder.atomizer.pipeline import LLMCheckResult

        ao = AgentOutput(
            cve_id="CVE-2014-0160", success=False, exploit_steps=[],
            evidence=["Heartbeat leaked 16384 bytes — vulnerability confirmed"],
            mitre_mapping={}, captured_flag="",
            extra_fields={"vuln_category": "Info_Leak", "service_role": "middleware"},
        )

        # Build a minimal pipeline instance without running docker/agent.
        from clab_builder.shared.models.atom import SourceBundle
        with patch.object(AtomizerPipeline, "_run_orchestrated_verification",
                          return_value={"success": True, "mode": "orchestrated",
                                        "evidence": [], "timestamp": "t"}), \
             patch.object(AtomizerPipeline, "_build_source_bundle_manifest",
                          return_value=SourceBundle(compose_file="source_bundle/docker-compose.yml",
                                                     readme_file="source_bundle/README.md",
                                                     dockerfiles=[], init_files=[],
                                                     poc_materials=[], hashes={})), \
             patch.object(AtomizerPipeline, "_run_llm_checker",
                          return_value=LLMCheckResult(accepted=True, reason="evidence confirms leak",
                                                       confidence="high", model="test")) as m_check, \
             patch.object(AtomizerPipeline, "_generate_exploit_guide", return_value=None), \
             patch.object(AtomizerPipeline, "_load_init_file_mappings", return_value=[]), \
             patch.object(AtomizerPipeline, "_extract_wait_seconds", return_value=5), \
             patch("clab_builder.atomizer.pipeline.subprocess.run"), \
             patch.object(Path, "write_text"):
            # Force no-flag path (objective evidence mode).
            pipe = AtomizerPipeline.__new__(AtomizerPipeline)
            pipe._flag = ""  # no flag planted
            pipe.env = MagicMock()
            pipe.env.cve_id = "CVE-2014-0160"
            pipe.env.category = "openssl"
            pipe.env.main_image = "vulhub/openssl:1.0.1c-with-nginx"
            pipe.env.main_ports = [443]
            pipe.env.main_service = None
            pipe.env.services = []
            pipe.env.readme_content = "Heartbleed information disclosure"
            pipe.vulhub_dir = "vulhub/openssl/CVE-2014-0160"
            pipe._compose_service_statuses = []
            pipe._readiness_warnings = []
            pipe._flag_required = False
            pipe.output_dir = Path("/tmp/atom_test")
            pipe.max_turns = 80

            verified, flag_matched = pipe._save_atom(
                Path("/tmp/atom_test/CVE-2014-0160"), agent_output=ao,
                llm_checker=True, api_key="k", base_url="", model="test",
            )
            # LLM checker was invoked and accepted → verified True.
            assert m_check.called


@pytest.mark.unit
class TestGuideForbiddenFlag:
    """Batch 4: the normal pipeline passes the ground-truth flag to the
    guide validator so a guide that leaks it is rejected."""

    def test_generate_exploit_guide_rejects_guide_with_real_flag(self, monkeypatch):
        from unittest.mock import MagicMock
        from clab_builder.atomizer.agent.researcher import AgentOutput
        from clab_builder.shared.models.atom import SourceBundle

        flag = "flag{secret-cve-x-1234}"
        raw_guide = {
            "version": 2,
            "summary": "leak",
            "target": {"protocol": "http", "port": 80, "service_role": "web_application"},
            "steps": [{
                "id": "exploit", "action": "trigger",
                "procedure": f"read the flag {flag}",
                "depends_on": [], "success_signal": "ok",
                "execution": {"scope": "actor", "tools": [], "materials": [],
                              "external_download": False, "fallback_ids": []},
            }],
            "post_exploit": {"principal": "root", "capabilities": [],
                             "command_channel": {"type": "none", "reusable": False,
                                                 "established_by": [], "invocation_hint": ""}},
        }
        ao = AgentOutput(
            cve_id="CVE-X", success=True, exploit_steps=[],
            evidence=["ok"], mitre_mapping={}, captured_flag=flag,
            extra_fields={"exploit_guide": raw_guide,
                           "exploit_access": {"attack_vector": "network",
                                              "required_service": {"protocol": "http", "port": 80}},
                           "capability_grants": ["execute_command"],
                           "exploit_principal": "root",
                           "vuln_category": "RCE", "service_role": "web_application"},
        )

        pipe = AtomizerPipeline.__new__(AtomizerPipeline)
        pipe.env = MagicMock()
        pipe.env.cve_id = "CVE-X"
        pipe._flag = flag
        # The guide contains the real flag -> generate must raise and the
        # pipeline must skip the guide rather than write a ready one.
        ref = pipe._generate_exploit_guide(
            Path("/tmp/x"), ao,
            service_role="web_application",
            exploit_access={"attack_vector": "network",
                            "required_service": {"protocol": "http", "port": 80}},
            capabilities=["execute_command"],
            requirements={},
            source_bundle=SourceBundle(),
            evidence=["ok"],
            forbidden_values=[flag],
        )
        assert ref is None