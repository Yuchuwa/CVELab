"""Deterministic capability-to-asset closure for scenario planning.

This module deliberately models only the small set of effects needed by the
first asset-chain slice. It does not execute commands or infer security
semantics with an LLM.
"""

from dataclasses import dataclass, field
from typing import Iterable

from clab_builder.shared.models.atom import (
    AtomConfig,
    CapabilityType,
    EvidenceLevel,
)
from clab_builder.shared.models.template import ScenarioAsset


@dataclass(frozen=True)
class CapabilityFact:
    """A capability with an explicit host, principal and scope."""

    type: CapabilityType
    host_scope: str
    principal: str = "unknown"
    scope: str = ""


@dataclass
class ClosureResult:
    """Fixed point of capability propagation and asset access."""

    capabilities: set[CapabilityFact] = field(default_factory=set)
    assets: set[str] = field(default_factory=set)


def seed_capabilities(atom: AtomConfig, host_scope: str) -> set[CapabilityFact]:
    """Convert verified atom grants into initial facts for a target host."""
    grants = [
        grant
        for grant in atom.capability_grants
        if grant.evidence_level == EvidenceLevel.VERIFIED
    ]
    if grants:
        return {
            CapabilityFact(
                type=grant.type,
                host_scope=host_scope,
                principal=grant.principal,
            )
            for grant in grants
        }

    # Compatibility for atoms that have not yet migrated from pivot_capability.
    principal = "service_user"
    return {
        CapabilityFact(
            type=capability,
            host_scope=host_scope,
            principal=principal,
        )
        for capability in atom.verified_capability_types
    }


def close_capabilities(
    initial_capabilities: Iterable[CapabilityFact],
    scenario_assets: Iterable[ScenarioAsset],
) -> ClosureResult:
    """Compute the explicit capability → asset closure.

    The first rules are intentionally small:

    ``execute_command`` → ``read_file`` and ``network_vantage``;
    a file-read fact acquires a file asset when its node and principal match.
    """
    result = ClosureResult(capabilities=set(initial_capabilities))
    assets = list(scenario_assets)

    changed = True
    while changed:
        changed = False
        for fact in list(result.capabilities):
            if fact.type == CapabilityType.EXECUTE_COMMAND:
                changed |= _add_capability(
                    result,
                    CapabilityFact(
                        type=CapabilityType.READ_FILE,
                        host_scope=fact.host_scope,
                        principal=fact.principal,
                        scope="readable_files",
                    ),
                )
                changed |= _add_capability(
                    result,
                    CapabilityFact(
                        type=CapabilityType.NETWORK_VANTAGE,
                        host_scope=fact.host_scope,
                        principal=fact.principal,
                        scope="attached_networks",
                    ),
                )

            if fact.type != CapabilityType.READ_FILE:
                continue

            for asset in assets:
                location = asset.location or {}
                if location.get("kind") != "file":
                    continue
                if location.get("node_ref") != fact.host_scope:
                    continue
                if fact.principal not in asset.readable_by and fact.principal != "root":
                    continue
                if asset.id not in result.assets:
                    result.assets.add(asset.id)
                    changed = True

    return result


def required_assets_satisfied(
    required_assets: Iterable[str],
    available_assets: Iterable[str],
) -> bool:
    """Return whether all declared injection-point assets are available."""
    return set(required_assets).issubset(set(available_assets))


def _add_capability(result: ClosureResult, capability: CapabilityFact) -> bool:
    if capability in result.capabilities:
        return False
    result.capabilities.add(capability)
    return True
