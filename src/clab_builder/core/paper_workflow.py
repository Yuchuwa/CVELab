"""Paper-faithful, provider-independent RangeFactory workflow primitives.

This module is the small orchestration kernel shared by the operational
pipeline and the review-safe code supplement.  It deliberately contains no
exploit payloads and no model-provider code.  Providers implement
``AgentBackend`` while the dependency gate, evidence rules, and failure
routing remain deterministic.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, Protocol, Sequence

from clab_builder.orchestrator.composer.capability_closure import (
    CapabilityFact,
    close_capabilities,
    seed_capabilities,
)
from clab_builder.orchestrator.composer.cve_matcher import (
    effective_service_role,
    service_access_matches,
)
from clab_builder.shared.models.atom import (
    AtomConfig,
    CapabilityType,
    EvidenceLevel,
)
from clab_builder.shared.models.template import InjectionPoint, TopologyTemplate


class AgentRole(str, Enum):
    EXPLOITER = "exploiter"
    EXPLORER = "explorer"
    GENERATOR = "generator"
    COMPOSER = "composer"
    EXECUTOR = "executor"
    DIAGNOSER = "diagnoser"


class FailureClass(str, Enum):
    INFRASTRUCTURE = "infrastructure"
    ATTACK_EXECUTION = "attack_execution"
    CHAIN_COMPOSITION = "chain_composition"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class AgentArtifact:
    """Versioned hand-off between agents."""

    kind: str
    payload: dict[str, Any]
    evidence_refs: tuple[str, ...] = ()
    schema_version: int = 1


class AgentBackend(Protocol):
    """Provider-neutral agent interface.

    The production runners adapt Claude/OpenAI endpoints to this interface;
    tests use a scripted implementation.  ``resume`` is important for the
    Diagnoser -> Executor bounded retry described in the paper.
    """

    def run(self, role: AgentRole, task: dict[str, Any], *, budget: dict[str, Any]) -> AgentArtifact: ...

    def resume(self, session_id: str, feedback: dict[str, Any], *, budget: dict[str, Any]) -> AgentArtifact: ...


@dataclass
class CapabilityProbeEvidence:
    probe_id: str
    capability: CapabilityType
    principal: str
    scope: str
    passed: bool
    evidence_ref: str
    observation: str = ""


class CapabilityProbeRegistry:
    """Registry for capability-specific, local-lab verification adapters."""

    def __init__(self) -> None:
        self._probes: dict[CapabilityType, Callable[..., CapabilityProbeEvidence]] = {}

    def register(self, capability: CapabilityType, verifier: Callable[..., CapabilityProbeEvidence]) -> None:
        self._probes[capability] = verifier

    def confirm(self, capability: CapabilityType, **kwargs: Any) -> CapabilityProbeEvidence:
        if capability not in self._probes:
            raise KeyError(f"no probe registered for {capability.value}")
        evidence = self._probes[capability](**kwargs)
        if evidence.capability != capability:
            raise ValueError("probe returned a different capability")
        return evidence


@dataclass
class ExplorerResult:
    """Only probe-confirmed grants can be consumed by Composer."""

    grants: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[CapabilityProbeEvidence] = field(default_factory=list)

    @classmethod
    def from_probe_evidence(cls, evidence: Iterable[CapabilityProbeEvidence]) -> "ExplorerResult":
        items = list(evidence)
        grants = [
            {
                "type": item.capability.value,
                "principal": item.principal,
                "scope": item.scope,
                "evidence_level": EvidenceLevel.VERIFIED.value,
                "evidence_ref": item.evidence_ref,
            }
            for item in items
            if item.passed
        ]
        return cls(grants=grants, evidence=items)


@dataclass(frozen=True)
class PrefixState:
    footholds: frozenset[str] = frozenset()
    capabilities: frozenset[CapabilityFact] = frozenset()
    assets: frozenset[str] = frozenset()
    reachable_services: frozenset[tuple[str, str, int | None]] = frozenset()


@dataclass(frozen=True)
class AttackEdge:
    source_slot: str
    target_slot: str
    supporting_capabilities: tuple[str, ...]
    service: dict[str, Any]


@dataclass
class CandidateRange:
    template: str
    bindings: dict[str, str]
    attack_chain: list[AttackEdge]
    state: PrefixState
    deployment: dict[str, Any] = field(default_factory=dict)


@dataclass
class IncompatibilityRecord:
    template: str
    source_slot: str
    target_slot: str
    source_atom: str
    target_atom: str
    condition: str
    evidence_refs: list[str] = field(default_factory=list)
    schema_version: int = 1

    @property
    def key(self) -> str:
        raw = "|".join((self.template, self.source_slot, self.target_slot,
                         self.source_atom, self.target_atom, self.condition))
        return hashlib.sha256(raw.encode()).hexdigest()


class IncompatibilityStore:
    """Small append-only JSON store for confirmed, binding-specific conflicts."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"schema_version": 1, "records": {}}
        return json.loads(self.path.read_text())

    def contains(self, record: IncompatibilityRecord) -> bool:
        with self._lock:
            return record.key in self._read().get("records", {})

    def add(self, record: IncompatibilityRecord) -> None:
        with self._lock:
            payload = self._read()
            payload.setdefault("schema_version", 1)
            payload.setdefault("records", {})[record.key] = {
                "template": record.template,
                "source_slot": record.source_slot,
                "target_slot": record.target_slot,
                "source_atom": record.source_atom,
                "target_atom": record.target_atom,
                "condition": record.condition,
                "evidence_refs": list(record.evidence_refs),
                "schema_version": record.schema_version,
            }
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


class DependencyPlanner:
    """Dependency-constrained DFS used by the Composer agent."""

    def __init__(self, *, incompatibilities: IncompatibilityStore | None = None) -> None:
        self.incompatibilities = incompatibilities

    @staticmethod
    def _topological_slots(template: TopologyTemplate) -> list[InjectionPoint]:
        slots = {slot.id: slot for slot in template.injection_points}
        order: list[InjectionPoint] = []
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(slot_id: str) -> None:
            if slot_id in visited:
                return
            if slot_id in visiting or slot_id not in slots:
                raise ValueError(f"invalid attack-chain dependency at {slot_id}")
            visiting.add(slot_id)
            for dependency in slots[slot_id].depends_on:
                visit(dependency)
            visiting.remove(slot_id)
            visited.add(slot_id)
            order.append(slots[slot_id])

        for slot in template.injection_points:
            visit(slot.id)
        return order

    @staticmethod
    def _network_allowed(template: TopologyTemplate, source_zone: str, target_zone: str) -> bool:
        if source_zone == target_zone:
            return True
        for rule in template.isolation_rules:
            if rule.from_zone == source_zone and rule.to_zone == target_zone:
                return rule.action in {"accept", "allow"}
        return False

    def _compatible(
        self,
        template: TopologyTemplate,
        slot: InjectionPoint,
        atom: AtomConfig,
        state: PrefixState,
        bindings: dict[str, AtomConfig],
    ) -> tuple[bool, str, tuple[str, ...]]:
        if not atom.verified:
            return False, "atom_not_verified", ()
        if atom.cve_id in {item.cve_id for item in bindings.values()}:
            return False, "duplicate_atom", ()
        if slot.required_service_role and effective_service_role(atom) not in slot.required_service_role:
            return False, "service_role", ()
        if slot.required_service_access and not service_access_matches(
            slot.required_service_access, atom.exploit_access.required_service
        ):
            return False, "service_access", ()
        if not set(slot.required_assets).issubset(state.assets):
            return False, "required_asset", ()

        access = atom.exploit_access
        supported: list[str] = []
        if slot.depends_on:
            for predecessor in slot.depends_on:
                if predecessor not in bindings:
                    return False, "predecessor_unresolved", ()
                predecessor_facts = [
                    fact for fact in state.capabilities
                    if fact.host_scope == predecessor
                ]
                if access.attack_vector == "network":
                    if not any(fact.type == CapabilityType.NETWORK_VANTAGE for fact in predecessor_facts):
                        return False, "missing_network_vantage", ()
                elif not any(fact.type == CapabilityType.EXECUTE_COMMAND for fact in predecessor_facts):
                    return False, "missing_command_execution", ()
                source_zone = next((s.zone for s in template.injection_points if s.id == predecessor), "")
                if not self._network_allowed(template, source_zone, slot.zone):
                    return False, "network_policy", ()
                supported.append(f"{predecessor}:network_vantage")

        if access.privileges_required == "high" and not any(
            fact.principal in {"root", "application_admin"} for fact in state.capabilities
        ) and slot.depends_on:
            return False, "privilege", ()

        if self.incompatibilities:
            for predecessor in slot.depends_on:
                previous = bindings[predecessor]
                record = IncompatibilityRecord(
                    template=template.name,
                    source_slot=predecessor,
                    target_slot=slot.id,
                    source_atom=previous.cve_id,
                    target_atom=atom.cve_id,
                    condition="runtime",
                )
                if self.incompatibilities.contains(record):
                    return False, "known_incompatibility", ()
        return True, "", tuple(supported)

    @staticmethod
    def _advance_state(template: TopologyTemplate, slot: InjectionPoint, atom: AtomConfig,
                       state: PrefixState) -> PrefixState:
        facts = set(state.capabilities)
        facts.update(seed_capabilities(atom, host_scope=slot.id))
        closed = close_capabilities(facts, template.assets)
        footholds = set(state.footholds)
        footholds.add(slot.id)
        services = set(state.reachable_services)
        service = atom.exploit_access.required_service or {}
        services.add((slot.id, str(service.get("protocol", "")), service.get("port")))
        return PrefixState(
            footholds=frozenset(footholds),
            capabilities=frozenset(closed.capabilities),
            assets=frozenset(set(state.assets) | closed.assets),
            reachable_services=frozenset(services),
        )

    def compose(self, template: TopologyTemplate, atoms: Sequence[AtomConfig], *, max_candidates: int = 0) -> list[CandidateRange]:
        slots = self._topological_slots(template)
        candidates: list[CandidateRange] = []

        def expand(index: int, bindings: dict[str, AtomConfig], state: PrefixState,
                   edges: list[AttackEdge]) -> None:
            if max_candidates and len(candidates) >= max_candidates:
                return
            if index == len(slots):
                candidates.append(CandidateRange(
                    template=template.name,
                    bindings={key: value.cve_id for key, value in bindings.items()},
                    attack_chain=list(edges),
                    state=state,
                    deployment={"template": template.name},
                ))
                return
            slot = slots[index]
            for atom in sorted(atoms, key=lambda item: item.cve_id):
                ok, reason, support = self._compatible(template, slot, atom, state, bindings)
                if not ok:
                    continue
                next_state = self._advance_state(template, slot, atom, state)
                for predecessor in slot.depends_on:
                    edges.append(AttackEdge(
                        source_slot=predecessor,
                        target_slot=slot.id,
                        supporting_capabilities=support,
                        service=atom.exploit_access.required_service or {},
                    ))
                bindings[slot.id] = atom
                expand(index + 1, bindings, next_state, edges)
                bindings.pop(slot.id, None)
                for _ in slot.depends_on:
                    if edges:
                        edges.pop()

        expand(0, {}, PrefixState(), [])
        return candidates


@dataclass
class Diagnosis:
    failure_class: FailureClass
    failed_slot: str = ""
    reason: str = ""
    retryable: bool = False
    incompatibility: IncompatibilityRecord | None = None
    evidence_refs: list[str] = field(default_factory=list)


class Diagnoser:
    """Evidence-bounded failure routing for Executor feedback."""

    def diagnose(self, result: dict[str, Any], *, template: str = "",
                 bindings: dict[str, str] | None = None) -> Diagnosis:
        stage = str(result.get("failure_stage", ""))
        evidence = list(result.get("evidence_refs", []))
        if stage.startswith(("deploy", "setup", "readiness", "runtime_materialization", "noise")):
            return Diagnosis(FailureClass.INFRASTRUCTURE, reason=stage, evidence_refs=evidence)
        if stage in {"attack_graph", "attack_path_reachability"}:
            return Diagnosis(FailureClass.CHAIN_COMPOSITION, reason=stage,
                             evidence_refs=evidence)
        if stage in {"reference_path", "objective"}:
            return Diagnosis(FailureClass.ATTACK_EXECUTION, reason=stage,
                             retryable=True, evidence_refs=evidence)
        if result.get("runtime_conflict") and bindings:
            source_slot = str(result.get("source_slot", ""))
            target_slot = str(result.get("target_slot", ""))
            record = IncompatibilityRecord(
                template=template,
                source_slot=source_slot,
                target_slot=target_slot,
                source_atom=str(bindings.get(source_slot, "")),
                target_atom=str(bindings.get(target_slot, "")),
                condition=str(result.get("runtime_conflict")),
                evidence_refs=evidence,
            )
            return Diagnosis(FailureClass.CHAIN_COMPOSITION, target_slot,
                             record.condition, False, record, evidence)
        if stage in {"agent", "objective", "agent_timeout", "agent_turn_limit"}:
            return Diagnosis(FailureClass.ATTACK_EXECUTION, reason=stage,
                             retryable=True, evidence_refs=evidence)
        return Diagnosis(FailureClass.UNRESOLVED, reason=stage or "insufficient evidence",
                         evidence_refs=evidence)


class Generator:
    """Schema and graph gate for an Agent-produced topology template."""

    @staticmethod
    def validate(template: TopologyTemplate) -> list[str]:
        errors: list[str] = []
        try:
            DependencyPlanner._topological_slots(template)
        except ValueError as exc:
            errors.append(str(exc))
        slot_ids = {slot.id for slot in template.injection_points}
        for slot in template.injection_points:
            errors.extend(f"{slot.id}: unknown dependency {d}" for d in slot.depends_on if d not in slot_ids)
        objective_assets = {obj.asset for obj in template.objectives}
        known_assets = {asset.id for asset in template.assets}
        errors.extend(f"objective references unknown asset {asset}" for asset in objective_assets - known_assets)
        return errors


class StageAgent:
    """Thin role-specific wrapper around the provider-neutral backend."""

    role: AgentRole

    def __init__(self, backend: AgentBackend) -> None:
        self.backend = backend

    def run(self, task: dict[str, Any], *, budget: dict[str, Any] | None = None) -> AgentArtifact:
        return self.backend.run(self.role, task, budget=budget or {})


class ExploiterAgent(StageAgent):
    role = AgentRole.EXPLOITER


class ExplorerAgent(StageAgent):
    role = AgentRole.EXPLORER


class GeneratorAgent(StageAgent):
    role = AgentRole.GENERATOR

    def run_template(self, task: dict[str, Any], *, budget: dict[str, Any] | None = None) -> AgentArtifact:
        artifact = self.run(task, budget=budget)
        template = TopologyTemplate.model_validate(artifact.payload.get("template", artifact.payload))
        errors = Generator.validate(template)
        if errors:
            raise ValueError("Generator template rejected: " + "; ".join(errors))
        return AgentArtifact("scenario_template", template.model_dump(mode="json"), artifact.evidence_refs)


class ComposerAgent(StageAgent):
    role = AgentRole.COMPOSER

    def __init__(self, backend: AgentBackend | None = None, *, planner: DependencyPlanner | None = None) -> None:
        if backend is not None:
            super().__init__(backend)
        self.planner = planner or DependencyPlanner()

    def compose(self, template: TopologyTemplate, atoms: Sequence[AtomConfig], *, max_candidates: int = 0) -> list[CandidateRange]:
        # The Agent may rank or request a search policy through the backend;
        # every returned binding still passes this deterministic planner.
        return self.planner.compose(template, atoms, max_candidates=max_candidates)


class ExecutorAgent(StageAgent):
    role = AgentRole.EXECUTOR


class DiagnoserAgent(StageAgent):
    role = AgentRole.DIAGNOSER

    def __init__(self, backend: AgentBackend | None = None) -> None:
        if backend is not None:
            super().__init__(backend)
        self.rule_diagnoser = Diagnoser()

    def classify(self, result: dict[str, Any], *, template: str = "",
                 bindings: dict[str, str] | None = None) -> Diagnosis:
        # LLM explanations can be attached as evidence, but cannot override
        # deterministic infrastructure and reproducible-conflict gates.
        return self.rule_diagnoser.diagnose(result, template=template, bindings=bindings)


class RangeFactoryWorkflow:
    """Explicit hand-off points for the six-agent construction workflow."""

    def __init__(self, backend: AgentBackend, *, incompatibility_store: IncompatibilityStore | None = None) -> None:
        self.backend = backend
        self.exploiter = ExploiterAgent(backend)
        self.explorer = ExplorerAgent(backend)
        self.generator = GeneratorAgent(backend)
        self.composer = ComposerAgent(backend, planner=DependencyPlanner(incompatibilities=incompatibility_store))
        self.executor = ExecutorAgent(backend)
        self.diagnoser = DiagnoserAgent(backend)
        self.incompatibility_store = incompatibility_store

    def atomize(self, task: dict[str, Any], *, budget: dict[str, Any] | None = None) -> tuple[AgentArtifact, AgentArtifact]:
        exploit = self.exploiter.run(task, budget=budget)
        explorer_task = {"exploitation": exploit.payload, "environment": task.get("environment", {})}
        exploration = self.explorer.run(explorer_task, budget=budget)
        return exploit, exploration

    def compose(self, template: TopologyTemplate, atoms: Sequence[AtomConfig], *, max_candidates: int = 0) -> list[CandidateRange]:
        return self.composer.compose(template, atoms, max_candidates=max_candidates)

    def diagnose(self, result: dict[str, Any], *, template: str = "",
                 bindings: dict[str, str] | None = None) -> Diagnosis:
        diagnosis = self.diagnoser.classify(result, template=template, bindings=bindings)
        if diagnosis.incompatibility and self.incompatibility_store:
            self.incompatibility_store.add(diagnosis.incompatibility)
        return diagnosis

    def validate(self, candidate: CandidateRange | dict[str, Any], *,
                 budget: dict[str, Any] | None = None, max_retries: int = 1,
                 template: str = "", bindings: dict[str, str] | None = None,
                 ) -> tuple[AgentArtifact, Diagnosis]:
        """Execute a candidate and route bounded retries through Diagnoser."""
        if isinstance(candidate, CandidateRange):
            task = {
                "template": candidate.template,
                "bindings": candidate.bindings,
                "attack_chain": [edge.__dict__ for edge in candidate.attack_chain],
            }
        else:
            task = dict(candidate)
        artifact = self.executor.run(task, budget=budget or {})
        attempts = 0
        while True:
            diagnosis = self.diagnose(
                artifact.payload, template=template,
                bindings=bindings or task.get("bindings"),
            )
            if not diagnosis.retryable or attempts >= max_retries:
                return artifact, diagnosis
            session_id = str(artifact.payload.get("session_id", ""))
            if not session_id:
                return artifact, diagnosis
            attempts += 1
            artifact = self.backend.resume(
                session_id,
                {"diagnosis": diagnosis.reason, "evidence_refs": diagnosis.evidence_refs},
                budget=budget or {},
            )


__all__ = [
    "AgentArtifact", "AgentBackend", "AgentRole", "AttackEdge", "CandidateRange",
    "CapabilityProbeEvidence", "CapabilityProbeRegistry", "DependencyPlanner",
    "Diagnoser", "Diagnosis", "ExplorerResult", "FailureClass", "Generator",
    "IncompatibilityRecord", "IncompatibilityStore", "PrefixState", "StageAgent",
    "ExploiterAgent", "ExplorerAgent", "GeneratorAgent", "ComposerAgent",
    "ExecutorAgent", "DiagnoserAgent", "RangeFactoryWorkflow",
]
