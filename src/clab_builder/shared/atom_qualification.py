"""Atom authoritative qualification.

A single, side-effect-free function that classifies an atom against the Range
authoritative contract. It checks ONLY the atom's formal fields:

  - native verification truth
  - source bundle completeness
  - runtime / service contract
  - verified capability grants (with resolvable evidence)
  - flag injection contract
  - guide integrity (file exists, parseable, safe, no native IP/flag)
  - environment readiness (three-state: True pass / False fail / None legacy)

It does NOT check guide<->atom alignment (principal, capability, port, role).
Those are advisory in the Range layer and belong to guide_advisories, not to
qualification. This separation is deliberate and matches the codex contract:
the atom is the authoritative source of matching facts; the guide is advisory.

Used by:
  - pipeline._save_atom (so fresh builds are gated)
  - AtomLoader / ScenarioPipeline selection (so Range only picks candidates)
  - audit scripts (so the pool report is consistent)

Three levels:
  structure_healthy    schema + bundle + runtime metadata present
  template_candidate   + verified + service + capability + guide integrity
  template_anchor      + environment_ready is True
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from clab_builder.shared.models.atom import AtomConfig, EvidenceLevel
from clab_builder.shared.models.exploit_guide import (
    ExploitGuide,
    validate_exploit_guide,
)
from clab_builder.shared.source_bundle import (
    missing_material_metadata,
    select_agent_materials,
)


@dataclass
class QualificationResult:
    structure_healthy: bool = False
    template_candidate: bool = False
    template_anchor: bool = False
    status: str = "excluded"  # template_anchor | template_candidate | review_required | excluded
    checks: dict[str, Any] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "structure_healthy": self.structure_healthy,
            "template_candidate": self.template_candidate,
            "template_anchor": self.template_anchor,
            "status": self.status,
            "checks": self.checks,
            "reasons": self.reasons,
        }


def _bundle_check(atom: AtomConfig, atom_dir: Optional[Path]) -> dict:
    bundle = atom.source_bundle
    if bundle is None:
        return {
            "present": False,
            "ok": False,
            "reasons": ["no source_bundle"],
            "material_metadata": {"ok": False, "missing": []},
        }
    reasons: list[str] = []
    if atom_dir is None:
        # cannot verify file existence; report structural only
        ok = bool(bundle.compose_file or bundle.dockerfiles)
        missing_metadata = missing_material_metadata(bundle)
        return {
            "present": True,
            "ok": ok,
            "reasons": [] if ok else ["no build source"],
            "material_metadata": {
                "ok": not missing_metadata,
                "missing": missing_metadata,
            },
        }
    # compose or dockerfile must exist to rebuild
    compose_ok = bool(bundle.compose_file and (atom_dir / bundle.compose_file).is_file())
    df_ok = any((atom_dir / df).is_file() for df in (bundle.dockerfiles or []))
    if not (compose_ok or df_ok):
        reasons.append("no build source (compose/dockerfile) on disk")
    # declared poc materials must exist
    missing_mats = [
        m for m in (bundle.poc_materials or [])
        if not (atom_dir / m).is_file()
    ]
    if missing_mats:
        reasons.append(f"missing poc_materials: {','.join(missing_mats)}")
    # basename collision check (Range mounts /vulhub/<CVE>__<basename>)
    basenames: dict[str, int] = {}
    collisions: list[str] = []
    for m in (bundle.poc_materials or []):
        bn = Path(m).name
        basenames[bn] = basenames.get(bn, 0) + 1
        if basenames[bn] == 2:
            collisions.append(bn)
    if collisions:
        reasons.append(f"poc_material basename collision: {','.join(collisions)}")
    # hash verification
    hash_bad = 0
    for rel, expected in (bundle.hashes or {}).items():
        fp = atom_dir / rel
        if not fp.is_file():
            hash_bad += 1
            continue
        import hashlib
        if hashlib.sha256(fp.read_bytes()).hexdigest() != expected:
            hash_bad += 1
    if hash_bad:
        reasons.append(f"{hash_bad} hash mismatch")
    missing_metadata = missing_material_metadata(bundle)
    return {
        "present": True,
        "ok": not reasons,
        "reasons": reasons,
        "material_metadata": {
            "ok": not missing_metadata,
            "missing": missing_metadata,
        },
    }


def _guide_materials(guide: ExploitGuide) -> set[str]:
    materials = set(guide.requirements.materials)
    for step in guide.steps:
        materials.update(step.materials)
        if step.execution:
            materials.update(material.ref for material in step.execution.materials)
    return materials


def _service_check(atom: AtomConfig) -> dict:
    rs = atom.exploit_access.required_service or {}
    protocol = str(rs.get("protocol", "")).strip()
    port = rs.get("port")
    complete = bool(protocol and port is not None)
    empty = not rs
    reasons: list[str] = []
    # A network atom with empty required_service cannot satisfy service slots.
    # Local-vector atoms (attack_vector != network) are exempt: they do not
    # expose a network service and the matcher does not require one.
    is_network = atom.exploit_access.attack_vector == "network"
    if is_network and empty:
        reasons.append("network atom has empty required_service")
    elif is_network and not complete:
        reasons.append("network atom service contract incomplete")
    return {
        "complete": complete,
        "empty": empty,
        "is_network": is_network,
        "ok": not reasons,
        "reasons": reasons,
        "protocol": protocol,
        "port": port,
    }


def _capability_check(atom: AtomConfig) -> dict:
    verified = [
        g for g in (atom.capability_grants or [])
        if g.evidence_level == EvidenceLevel.VERIFIED
    ]
    inferred = [
        g for g in (atom.capability_grants or [])
        if g.evidence_level == EvidenceLevel.INFERRED
    ]
    reasons: list[str] = []
    if not verified:
        reasons.append("no verified capability grants")
    return {
        "verified_types": sorted({g.type.value for g in verified}),
        "verified_principals": sorted({g.principal for g in verified}),
        "inferred_count": len(inferred),
        "ok": bool(verified),
        "reasons": reasons,
    }


def _guide_integrity_check(atom: AtomConfig, atom_dir: Optional[Path]) -> dict:
    ref = atom.exploit_guide
    if ref is None:
        return {"present": False, "ready": False, "ok": True, "reasons": [],
                "advisory": []}
    if ref.status != "ready":
        return {"present": True, "ready": False, "ok": True, "reasons": [],
                "advisory": []}
    if atom_dir is None:
        return {"present": True, "ready": True, "ok": True,
                "reasons": ["cannot verify file without atom_dir"],
                "advisory": []}
    gp = atom_dir / ref.path
    if not gp.is_file():
        return {"present": True, "ready": True, "ok": False,
                "reasons": [f"guide file missing: {ref.path}"], "advisory": []}
    try:
        guide = ExploitGuide.model_validate(yaml.safe_load(gp.read_text()) or {})
    except Exception as exc:
        return {"present": True, "ready": True, "ok": False,
                "reasons": [f"guide parse failed: {exc}"], "advisory": []}
    if guide.cve_id != atom.cve_id:
        return {"present": True, "ready": True, "ok": False,
                "reasons": ["guide cve_id mismatch"], "advisory": []}
    bundle = atom.source_bundle
    mats = set(bundle.poc_materials or []) if bundle else set()
    forbidden = [str(atom.flag_value or "")]
    try:
        validate_exploit_guide(
            guide,
            source_bundle_materials=mats,
            forbidden_values=forbidden,
        )
        not_visible = sorted(
            _guide_materials(guide) - set(select_agent_materials(atom, "guided"))
        )
        if not_visible:
            return {
                "present": True,
                "ready": True,
                "ok": False,
                "reasons": [
                    "guide references materials excluded by guided profile: "
                    + ", ".join(not_visible)
                ],
                "advisory": [],
            }
    except (ValueError, TypeError) as exc:
        return {"present": True, "ready": True, "ok": False,
                "reasons": [f"guide integrity: {exc}"], "advisory": []}
    return {"present": True, "ready": True, "ok": True, "reasons": [], "advisory": []}


def _environment_check(atom: AtomConfig) -> dict:
    """Three-state: True pass / False fail / None legacy (not yet verified).

    A legacy atom without environment_ready is NOT excluded from candidate —
    it simply cannot reach template_anchor. This preserves existing verified
    atoms that predate the environment_ready field without erasing native
    truth, and avoids breaking Range tests that depend on those anchors.
    """
    env_ready = (atom.verification or {}).get("environment_ready")
    return {"environment_ready": env_ready, "ok": env_ready is not False,
            "reasons": [] if env_ready is not False else ["environment_ready=false"]}


def qualify_atom(
    atom: AtomConfig,
    atom_dir: Optional[Path] = None,
    *,
    require_environment_for_anchor: bool = True,
) -> QualificationResult:
    """Classify an atom. Pure function; does not read or write files beyond
    what is needed to verify declared bundle/guide paths exist.

    Args:
        atom: parsed AtomConfig
        atom_dir: directory containing the atom files (None = skip disk checks)
        require_environment_for_anchor: if False, candidate with a ready guide
            is also treated as anchor (used by tests that stub environment)
    """
    r = QualificationResult()

    # structure
    struct_reasons: list[str] = []
    if atom.version < 3:
        struct_reasons.append("version<3")
    bundle = _bundle_check(atom, atom_dir)
    if not bundle["ok"]:
        struct_reasons.extend(bundle["reasons"])
    metadata_ok = atom.version < 3 or bundle["material_metadata"]["ok"]
    if atom.version >= 3 and not metadata_ok:
        struct_reasons.append(
            "missing material_metadata: "
            + ",".join(bundle["material_metadata"]["missing"])
        )
    r.checks["source_bundle"] = bundle
    r.structure_healthy = (
        atom.version >= 3
        and bundle["ok"]
        and metadata_ok
    )

    # native truth
    native = (atom.verification or {}).get("native_verification") or {}
    native_ok = bool(native.get("success"))
    r.checks["native"] = {"success": native_ok}
    if not atom.verified:
        struct_reasons.append("verified=false")
    if atom.version >= 3 and atom.verified and not native_ok:
        # AtomConfig validator already downgrades verified in this case, but
        # be explicit so the reason is recorded.
        struct_reasons.append("v3 verified but native not success")

    # service
    service = _service_check(atom)
    r.checks["service"] = service

    # capability
    cap = _capability_check(atom)
    r.checks["capability"] = cap

    # guide integrity
    guide = _guide_integrity_check(atom, atom_dir)
    r.checks["guide"] = guide

    # environment
    env = _environment_check(atom)
    r.checks["environment"] = env

    # candidate
    cand_reasons = list(struct_reasons)
    if not native_ok:
        cand_reasons.append("native not success")
    cand_reasons.extend(service["reasons"])
    cand_reasons.extend(cap["reasons"])
    if guide["present"] and guide["ready"] and not guide["ok"]:
        cand_reasons.extend(guide["reasons"])
    r.template_candidate = (
        r.structure_healthy
        and native_ok
        and service["ok"]
        and cap["ok"]
        and not (guide["present"] and guide["ready"] and not guide["ok"])
    )
    if not r.template_candidate:
        cand_reasons = [x for x in cand_reasons if x]

    # anchor
    if r.template_candidate:
        if require_environment_for_anchor:
            if env["environment_ready"] is True:
                r.template_anchor = True
            elif env["environment_ready"] is False:
                r.reasons.append("environment_ready=false")
            else:
                # legacy: candidate but not anchor
                r.reasons.append("environment_ready missing (legacy)")
        else:
            r.template_anchor = True
    else:
        r.reasons.extend(cand_reasons)

    if r.template_anchor:
        r.status = "template_anchor"
    elif r.template_candidate:
        r.status = "template_candidate"
    elif r.structure_healthy:
        r.status = "review_required"
        r.reasons = cand_reasons if cand_reasons else r.reasons
    else:
        r.status = "excluded"
        r.reasons = cand_reasons if cand_reasons else r.reasons
    return r


def qualify_atom_dir(atom_dir: Path) -> QualificationResult:
    """Load and qualify an atom from its directory."""
    atom_path = atom_dir / "atom.yaml"
    data = yaml.safe_load(atom_path.read_text()) or {}
    atom = AtomConfig(**data)
    return qualify_atom(atom, atom_dir)


__all__ = ["QualificationResult", "qualify_atom", "qualify_atom_dir"]
