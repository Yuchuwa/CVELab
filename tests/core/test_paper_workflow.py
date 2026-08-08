from pathlib import Path

from clab_builder.core.paper_workflow import (
    AgentArtifact,
    AgentRole,
    DependencyPlanner,
    Diagnoser,
    FailureClass,
    Generator,
    IncompatibilityRecord,
    IncompatibilityStore,
    RangeFactoryWorkflow,
)
from clab_builder.shared.models.atom import (
    AttackMethod,
    AtomConfig,
    CapabilityGrant,
    CapabilityType,
    EvidenceLevel,
    ExploitAccess,
    ExploitComplexity,
    MitrePhase,
    ServiceRole,
    VulnCategory,
)
from clab_builder.shared.models.template import InjectionPoint, IsolationRule, TopologyTemplate


def atom(cve: str, port: int, caps: list[CapabilityType], *, verified: bool = True):
    return AtomConfig(
        cve_id=cve,
        category="test",
        docker_image="local/test:latest",
        vuln_category=VulnCategory.RCE,
        primary_mitre_phase=MitrePhase.INITIAL_ACCESS,
        service_role=ServiceRole.WEB_APPLICATION,
        exploit_complexity=ExploitComplexity.SIMPLE,
        attack_method=AttackMethod.SINGLE_REQUEST,
        verified=verified,
        verification={"native_verification": {"success": verified}},
        exploit_access=ExploitAccess(
            attack_vector="network",
            privileges_required="none",
            required_service={"protocol": "http", "port": port},
        ),
        capability_grants=[
            CapabilityGrant(
                type=cap,
                principal="service_user",
                evidence_level=EvidenceLevel.VERIFIED,
                evidence_ref=f"probe:{cve}:{cap.value}",
            )
            for cap in caps
        ],
    )


def template():
    return TopologyTemplate(
        name="fixture",
        zones={},
        routers={},
        isolation_rules=[IsolationRule(**{"from": "dmz", "to": "app", "action": "accept"})],
        injection_points=[
            InjectionPoint(id="dmz", zone="dmz"),
            InjectionPoint(id="app", zone="app", depends_on=["dmz"]),
        ],
    )


def test_composer_backtracks_and_emits_attack_chain():
    planner = DependencyPlanner()
    result = planner.compose(
        template(),
        [
            atom("CVE-DEAD", 80, [CapabilityType.READ_FILE]),
            atom("CVE-ENTRY", 80, [CapabilityType.EXECUTE_COMMAND]),
            atom("CVE-NEXT", 8080, [CapabilityType.EXECUTE_COMMAND]),
        ],
    )
    assert result
    assert any(item.bindings["dmz"] == "CVE-ENTRY" for item in result)
    assert all(len(item.attack_chain) == 1 for item in result)


def test_known_incompatibility_is_pruned(tmp_path: Path):
    store = IncompatibilityStore(tmp_path / "memory.json")
    store.add(IncompatibilityRecord("fixture", "dmz", "app", "CVE-ENTRY", "CVE-NEXT", "runtime"))
    result = DependencyPlanner(incompatibilities=store).compose(
        template(), [atom("CVE-ENTRY", 80, [CapabilityType.EXECUTE_COMMAND]), atom("CVE-NEXT", 8080, [CapabilityType.EXECUTE_COMMAND])]
    )
    assert all(
        not (item.bindings.get("dmz") == "CVE-ENTRY" and item.bindings.get("app") == "CVE-NEXT")
        for item in result
    )


def test_diagnoser_routes_execution_and_composition_failures():
    diagnosis = Diagnoser().diagnose({"failure_stage": "agent_turn_limit"})
    assert diagnosis.failure_class == FailureClass.ATTACK_EXECUTION
    assert diagnosis.retryable

    diagnosis = Diagnoser().diagnose(
        {"runtime_conflict": "callback route blocked", "source_slot": "dmz", "target_slot": "app", "evidence_refs": ["edge:1"]},
        template="fixture",
        bindings={"dmz": "CVE-ENTRY", "app": "CVE-NEXT"},
    )
    assert diagnosis.failure_class == FailureClass.CHAIN_COMPOSITION
    assert diagnosis.incompatibility is not None


def test_generator_rejects_unknown_dependency():
    invalid = TopologyTemplate(
        name="bad", zones={}, routers={},
        injection_points=[InjectionPoint(id="slot", zone="dmz", depends_on=["missing"])],
    )
    assert Generator.validate(invalid)


class ScriptedBackend:
    def run(self, role, task, *, budget):
        return AgentArtifact(f"{role.value}_artifact", {"role": role.value})

    def resume(self, session_id, feedback, *, budget):
        return AgentArtifact("resumed", {"session_id": session_id})


def test_workflow_exposes_all_six_agent_handoffs(tmp_path: Path):
    workflow = RangeFactoryWorkflow(ScriptedBackend(), incompatibility_store=IncompatibilityStore(tmp_path / "memory.json"))
    exploit, explore = workflow.atomize({"environment": {"id": "fixture"}})
    assert exploit.kind == "exploiter_artifact"
    assert explore.kind == "explorer_artifact"
    assert workflow.composer.role == AgentRole.COMPOSER
    assert workflow.executor.role == AgentRole.EXECUTOR
    assert workflow.diagnoser.role == AgentRole.DIAGNOSER


class RetryBackend:
    def __init__(self):
        self.resumes = 0

    def run(self, role, task, *, budget):
        return AgentArtifact("executor_artifact", {
            "failure_stage": "agent_turn_limit",
            "session_id": "session-1",
        })

    def resume(self, session_id, feedback, *, budget):
        self.resumes += 1
        return AgentArtifact("executor_retry", {"success": True})


def test_workflow_routes_retryable_execution_failure_to_executor():
    backend = RetryBackend()
    workflow = RangeFactoryWorkflow(backend)
    artifact, diagnosis = workflow.validate({"bindings": {}}, max_retries=1)
    assert artifact.kind == "executor_retry"
    assert diagnosis.failure_class == FailureClass.UNRESOLVED
    assert backend.resumes == 1
