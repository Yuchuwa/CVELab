"""Import a CVE-Factory PoC verification into a standard atom (batch 9).

Turns a CVEFactoryVerificationResult + PoCRecipe into the same atom.yaml /
source_bundle / exploit_guide.yaml layout the Agent path produces, so Range
consumes it through the existing AtomLoader without a second schema.

Rules from the three-state model (batch 8):
  - vulnerability_observed -> atom.verified = True (native truth)
  - capability_verified   -> currently False; inferred capabilities stay
                              INFERRED, never VERIFIED. Range cannot use this
                              atom as a required-capability slot or a chain
                              pivot until a runtime witness layer proves them.
  - range_flag_recovery_verified -> currently False; guide.status is left as
                              review_required (NOT ready), so the atom does not
                              enter Guided Range as a template_candidate.

This is deliberately conservative: a marker-based PoC atom is
structure_healthy + verified (native truth) but NOT template_candidate,
matching the batch-0 audit's classification.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

from clab_builder.atomizer.cve_factory_verifier import CVEFactoryVerificationResult
from clab_builder.atomizer.poc_recipe import (
    PoCRecipe,
    ThreeStateVerification,
    extract_recipe,
    judge_three_state,
)
from clab_builder.shared.models.atom import (
    AtomConfig,
    ExploitAccess,
    EvidenceLevel,
    FlagInjection,
    FlagMethod,
    ReadinessProbe,
    ProbeType,
    RuntimeSpec,
    ServiceInfo,
    ServiceRole,
    SourceBundle,
    ValidationSpec,
    VulnCategory,
    MitrePhase,
    ExploitComplexity,
    AttackMethod,
    CapabilityGrant,
    CapabilityType,
)
from clab_builder.shared.service_resolver import resolve_service_contract
from clab_builder.shared.source_bundle import capture_source_bundle


def _infer_category(recipe: Optional[PoCRecipe]) -> tuple[str, str, str]:
    """Return (vuln_category, primary_mitre_phase, service_role)."""
    caps = recipe.inferred_capabilities if recipe else []
    text = (recipe.expected_outcome if recipe else "").lower()
    if "execute_command" in caps or "command execution" in text:
        cat = "RCE"
    elif "read_file" in caps or "/etc/passwd" in text or "leak" in text:
        cat = "LFI"
    elif "network_vantage" in caps or "ssrf" in text:
        cat = "SSRF"
    elif "read_credential" in caps or "credential" in text:
        cat = "Auth_Bypass"
    elif "write_file" in caps or "upload" in text:
        cat = "RCE"
    else:
        cat = "RCE"
    return cat, "initial_access", "web_application"


def _build_recipe_guide_data(
    recipe: PoCRecipe,
    cve_id: str,
    target_port,
) -> dict:
    """Build an ExploitGuide-compatible dict from the recipe (advisory)."""
    port_repr = target_port if target_port is not None else None
    steps = []
    if recipe.endpoint:
        steps.append({
            "id": "exploit",
            "action": "trigger vulnerability",
            "procedure": recipe.expected_outcome or "Trigger the vulnerable endpoint",
            "command_hint": f"{recipe.method.upper()} {recipe.endpoint}" if recipe.method else "",
            "depends_on": [],
            "success_signal": recipe.expected_outcome[:120] if recipe.expected_outcome else "vulnerability triggered",
            "materials": [],
            "execution": {
                "scope": "actor",
                "tools": [{"id": "curl", "kind": "executable", "name": "curl", "required": True}],
                "materials": [],
                "external_download": False,
                "fallback_ids": [],
            },
        })
    if not steps:
        steps.append({
            "id": "exploit",
            "action": "trigger vulnerability",
            "procedure": "See test_vuln.py for the native exploit sequence",
            "depends_on": [],
            "success_signal": "native test_vuln.py assertion failed as expected",
            "materials": [],
            "execution": {
                "scope": "actor", "tools": [], "materials": [],
                "external_download": False, "fallback_ids": [],
            },
        })
    return {
        "version": 2,
        "cve_id": cve_id,
        "summary": f"PoC-derived advisory guide from test_vuln.py (observer={recipe.observer_scope})",
        "target": {
            "protocol": "http",
            "port": port_repr,
            "service_role": "web_application",
            "endpoints": [],
        },
        "preconditions": {
            "attack_vector": "network",
            "privileges_required": "none",
            "required_service": {"protocol": "http", "port": target_port} if target_port else {},
        },
        "steps": steps,
        "post_exploit": {
            "principal": "unknown",
            "capabilities": list(recipe.inferred_capabilities),
            "command_channel": {"type": "none", "reusable": False,
                                 "established_by": [], "invocation_hint": ""},
        },
        "requirements": {"tools": ["curl"], "materials": [],
                         "authentication": recipe.auth or "none", "callback": "none"},
        "evidence_refs": ["verification.native_verification.evidence"],
    }


def import_cve_factory_atom(
    task_dir: Path,
    result: CVEFactoryVerificationResult,
    atoms_dir: Path,
    *,
    guide_status: str = "review_required",
) -> AtomConfig:
    """Build a standard atom from a CVE-Factory PoC verification.

    The atom is written to atoms_dir/<cve_id>/. The source bundle is captured
    from task_dir (cve_factory classification: test_vuln.py is an
    exploit_reference, test_func.py/solution.sh are private).

    guide_status defaults to review_required because the three-state model
    (batch 8) does not grant range_flag_recovery_verified from a static recipe.
    A future runtime recovery layer may pass guide_status="ready".
    """
    cve_id = result.cve_id
    atom_dir = atoms_dir / cve_id
    atom_dir.mkdir(parents=True, exist_ok=True)

    # 1. source bundle
    source_bundle = capture_source_bundle(task_dir, atom_dir, source_kind="cve_factory")

    # 2. recipe (static extraction)
    test_vuln = task_dir / "tests" / "test_vuln.py"
    recipe = extract_recipe(test_vuln) if test_vuln.is_file() else None

    # 3. three-state judgement
    ts = judge_three_state(result, recipe)

    # 4. service contract from the prepared source (compose/expose/Dockerfile)
    #    Reuse the shared resolver by parsing the prepared compose.
    from clab_builder.atomizer.output.vulhub_converter import VulhubParser
    env = None
    try:
        env = VulhubParser().parse(str(task_dir))
    except Exception:
        env = None
    resolved = resolve_service_contract(env, task_dir)
    protocol = resolved[0] if resolved else "http"
    port = resolved[1] if resolved else None

    # 5. native verification (batch 6 shape)
    nv = result.to_native_verification()
    overlay = ts.to_native_verification_overlay()
    nv.update(overlay)

    # 6. atom config
    cat, phase, role = _infer_category(recipe)
    vuln_cat = VulnCategory(cat) if cat in [c.value for c in VulnCategory] else VulnCategory.RCE
    mitre = MitrePhase(phase) if phase in [m.value for m in MitrePhase] else MitrePhase.INITIAL_ACCESS
    svc_role = ServiceRole(role) if role in [s.value for s in ServiceRole] else ServiceRole.WEB_APPLICATION

    exploit_access = ExploitAccess(
        attack_vector="network",
        privileges_required="none",
        required_service={"protocol": protocol, "port": port} if port else {},
    )

    # capability grants: inferred only (three-state: not verified)
    capability_grants = [
        CapabilityGrant(
            type=CapabilityType(c),
            principal="unknown",
            evidence_level=EvidenceLevel.INFERRED,
            evidence_ref="verification.native_verification.evidence",
        )
        for c in ts.inferred_capabilities
        if c in [t.value for t in CapabilityType]
    ]

    runtime_spec = RuntimeSpec(
        ports=[port] if port else [],
        services=[{"name": "client", "image": "", "is_target": True}],
    )
    validation_spec = ValidationSpec(
        readiness=[
            ReadinessProbe(probe_type=ProbeType.CONTAINER_STATE),
            ReadinessProbe(probe_type=ProbeType.TCP, target=str(port)) if port
            else ReadinessProbe(probe_type=ProbeType.CONTAINER_STATE),
        ],
    )

    # 7. guide (advisory, from recipe)
    guide_ref = None
    if recipe is not None:
        guide_data = _build_recipe_guide_data(recipe, cve_id, port)
        guide_path = atom_dir / "exploit_guide.yaml"
        guide_path.write_text(yaml.safe_dump(guide_data, sort_keys=False,
                                              allow_unicode=True))
        from clab_builder.shared.models.exploit_guide import ExploitGuideRef
        guide_ref = ExploitGuideRef(
            path="exploit_guide.yaml",
            format_version=2,
            provenance="cve_factory_poc",
            status=guide_status,
            evidence_refs=["verification.native_verification.evidence"],
        )

    config = AtomConfig(
        version=3,
        cve_id=cve_id,
        category="cve_factory",
        description=f"CVE-Factory PoC atom ({result.observer_scope})",
        docker_image=f"cve-{cve_id.lower()}:vuln",
        ports=[port] if port else [],
        services=[ServiceInfo(name="client", image=f"cve-{cve_id.lower()}:vuln",
                              is_target=True)],
        vuln_category=vuln_cat,
        primary_mitre_phase=mitre,
        service_role=svc_role,
        exploit_complexity=ExploitComplexity.SIMPLE,
        attack_method=AttackMethod.SINGLE_REQUEST,
        exploit_access=exploit_access,
        capability_grants=capability_grants,
        flag_injection=FlagInjection(method=FlagMethod.FILE, file_path="/flag"),
        runtime_spec=runtime_spec,
        validation_spec=validation_spec,
        verified=result.verified,
        verification={
            "native_verification": nv,
            "orchestrated_verification": {
                "success": False, "mode": "orchestrated",
                "evidence": ["not yet run"], "timestamp": nv.get("timestamp", ""),
            },
            "environment_ready": False,
        },
        source_bundle=source_bundle,
        exploit_guide=guide_ref,
        timestamp=datetime.now(timezone.utc).isoformat(),
        source=str(task_dir),
    )

    # 8. write atom.yaml
    (atom_dir / "atom.yaml").write_text(yaml.safe_dump(
        config.model_dump(exclude_none=True, mode="json"),
        sort_keys=False, allow_unicode=True,
    ))
    return config


__all__ = ["import_cve_factory_atom"]