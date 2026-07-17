#!/usr/bin/env python3
"""Batch 0: read-only authoritative audit of the atom pool.

Produces data/atom_authoritative_audit.{json,csv,md} recording, per atom:
  - version / verified / native success / environment_ready
  - source_bundle existence + compose/readme/dockerfiles/init/hash completeness
  - runtime_spec completeness (ports/command/services)
  - exploit_access.required_service completeness (protocol+port)
  - capability_grants evidence (verified count, resolvable evidence_ref)
  - guide integrity (ready ref, version match, file exists, cve match)
  - structure_healthy / template_candidate / template_anchor classification
  - advisory diagnostics (principal/capability/port/role mismatch against guide)

This script only READS. It does not modify any atom or guide file.
The classification here is the baseline for all later batches; later batches
must move atoms toward template_candidate/anchor, not paper over the gaps.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from clab_builder.shared.models.atom import AtomConfig, EvidenceLevel
from clab_builder.shared.models.exploit_guide import ExploitGuide, validate_exploit_guide


def _safe_load_atom(atom_dir: Path) -> dict | None:
    p = atom_dir / "atom.yaml"
    if not p.exists():
        return None
    try:
        return yaml.safe_load(p.read_text()) or {}
    except Exception:
        return None


def _bundle_completeness(atom_dir: Path, raw: dict) -> dict:
    bundle = raw.get("source_bundle") or {}
    if not bundle:
        return {"present": False}
    checks = {"present": True}
    for key in ("compose_file", "readme_file"):
        rel = bundle.get(key)
        checks[key] = bool(rel and (atom_dir / rel).is_file())
    checks["dockerfiles"] = []
    for df in bundle.get("dockerfiles") or []:
        checks["dockerfiles"].append({"path": df, "exists": (atom_dir / df).is_file()})
    checks["init_files"] = []
    for f in bundle.get("init_files") or []:
        if isinstance(f, dict):
            rel = f.get("filename") or f.get("path") or ""
        else:
            rel = str(f)
        checks["init_files"].append({"path": rel, "exists": bool(rel and (atom_dir / rel).exists())})
    # hash verification
    hashes = bundle.get("hashes") or {}
    hash_ok = 0
    hash_bad = 0
    for rel, expected in hashes.items():
        fp = atom_dir / rel
        if not fp.is_file():
            hash_bad += 1
            continue
        import hashlib
        actual = hashlib.sha256(fp.read_bytes()).hexdigest()
        if actual == expected:
            hash_ok += 1
        else:
            hash_bad += 1
    checks["hash_ok"] = hash_ok
    checks["hash_bad"] = hash_bad
    checks["hash_total"] = len(hashes)
    # poc_materials existence + basename collision
    mats = bundle.get("poc_materials") or []
    missing = []
    basenames = {}
    collisions = []
    for m in mats:
        if not (atom_dir / m).is_file():
            missing.append(m)
        bn = Path(m).name
        basenames[bn] = basenames.get(bn, 0) + 1
        if basenames[bn] == 2:
            collisions.append(bn)
    checks["poc_materials_total"] = len(mats)
    checks["poc_materials_missing"] = missing
    checks["poc_materials_basename_collisions"] = collisions
    return checks


def _service_contract(atom: AtomConfig, raw: dict) -> dict:
    rs = atom.exploit_access.required_service or {}
    protocol = str(rs.get("protocol", "")).strip()
    port = rs.get("port")
    complete = bool(protocol and port is not None)
    return {
        "protocol": protocol,
        "port": port,
        "complete": complete,
        "empty": not rs,
        "ports_field": list(atom.ports),
        "runtime_spec_ports": list(atom.runtime_spec.ports) if atom.runtime_spec else [],
    }


def _capability_contract(atom: AtomConfig, raw: dict) -> dict:
    grants = atom.capability_grants or []
    verified = [g for g in grants if g.evidence_level == EvidenceLevel.VERIFIED]
    inferred = [g for g in grants if g.evidence_level == EvidenceLevel.INFERRED]
    # resolvable evidence_ref: must point at a real native evidence record.
    verification = raw.get("verification") or {}
    native = verification.get("native_verification") or {}
    native_evidence = native.get("evidence") or []
    witnesses = native.get("witnesses") or {}
    resolvable = []
    unresolvable = []
    for g in verified:
        ref = g.evidence_ref or ""
        if ref == "verification.native_verification.evidence":
            (resolvable if native_evidence else unresolvable).append(ref)
        elif ref.startswith("verification.native_verification.witnesses."):
            wid = ref.rsplit(".", 1)[-1]
            (resolvable if wid in witnesses else unresolvable).append(ref)
        else:
            unresolvable.append(ref or "<empty>")
    return {
        "total": len(grants),
        "verified": [g.type.value for g in verified],
        "inferred": [g.type.value for g in inferred],
        "verified_principals": sorted({g.principal for g in verified}),
        "resolvable_evidence_refs": resolvable,
        "unresolvable_evidence_refs": unresolvable,
    }


def _guide_integrity(atom_dir: Path, raw: dict) -> dict:
    ref = raw.get("exploit_guide")
    if not ref or not isinstance(ref, dict):
        return {"present": False, "ready": False}
    present = True
    ready = ref.get("status") == "ready"
    fv = ref.get("format_version")
    path = ref.get("path", "exploit_guide.yaml")
    gp = atom_dir / path
    file_exists = gp.is_file()
    cve_match = False
    version_match = False
    integrity_ok = None
    advisory_reasons = []
    if file_exists:
        try:
            guide = ExploitGuide.model_validate(yaml.safe_load(gp.read_text()) or {})
            cve_match = guide.cve_id == raw.get("cve_id")
            version_match = (fv == guide.version)
            bundle = raw.get("source_bundle") or {}
            mats = set(bundle.get("poc_materials") or [])
            for m in mats:
                if not (atom_dir / m).is_file():
                    advisory_reasons.append(f"missing material: {m}")
            try:
                validate_exploit_guide(
                    guide,
                    source_bundle_materials=mats,
                    forbidden_values=[str(raw.get("flag_value") or "")],
                )
                integrity_ok = True
            except (ValueError, TypeError) as exc:
                integrity_ok = False
                advisory_reasons.append(f"validate_exploit_guide: {exc}")
        except Exception as exc:
            integrity_ok = False
            advisory_reasons.append(f"guide parse: {exc}")
    return {
        "present": present,
        "ready": ready,
        "format_version": fv,
        "file_exists": file_exists,
        "cve_match": cve_match,
        "version_match": version_match,
        "integrity_ok": integrity_ok,
        "advisory_reasons": advisory_reasons,
    }


def _classify(atom: AtomConfig, raw: dict, bundle: dict, service: dict,
              cap: dict, guide: dict) -> tuple[str, list[str]]:
    reasons: list[str] = []
    # structure_healthy
    structure_ok = True
    if atom.version < 3:
        structure_ok = False
        reasons.append("version<3")
    if not bundle.get("present"):
        structure_ok = False
        reasons.append("no source_bundle")
    else:
        if not bundle.get("compose_file"):
            reasons.append("bundle: no compose_file")
            structure_ok = False
        if not bundle.get("readme_file"):
            reasons.append("bundle: no readme_file")
        if bundle.get("poc_materials_missing"):
            reasons.append("bundle: missing poc_materials")
            structure_ok = False
        if bundle.get("hash_bad"):
            reasons.append(f"bundle: {bundle['hash_bad']} hash mismatch")
            structure_ok = False
    # template_candidate
    candidate = structure_ok
    if not atom.verified:
        candidate = False
        reasons.append("not verified")
    native = (raw.get("verification") or {}).get("native_verification") or {}
    if not native.get("success"):
        candidate = False
        reasons.append("native not success")
    if not service.get("complete") and not service.get("empty"):
        candidate = False
        reasons.append("service contract incomplete")
    if service.get("empty"):
        # network atom with empty required_service cannot match service slots
        reasons.append("required_service empty")
        candidate = False
    if not cap.get("verified"):
        # no verified capability means cannot satisfy required_capabilities slots
        reasons.append("no verified capability grants")
        candidate = False
    if bundle.get("poc_materials_basename_collisions"):
        candidate = False
        reasons.append("poc_material basename collision")
    if guide.get("present") and guide.get("ready"):
        if guide.get("integrity_ok") is False:
            candidate = False
            reasons.append("guide integrity failed")
    # template_anchor (superset): needs environment_ready
    anchor = candidate
    env_ready = (raw.get("verification") or {}).get("environment_ready")
    if env_ready is True:
        pass
    elif env_ready is False:
        anchor = False
        reasons.append("environment_ready=false")
    else:
        # legacy atoms without the field: not anchor yet, but not excluded
        anchor = False
        reasons.append("environment_ready missing (legacy)")
    if not (guide.get("present") and guide.get("ready")):
        anchor = False
        if not reasons or "guide not ready" not in reasons:
            reasons.append("guide not ready")
    status = "excluded"
    if anchor:
        status = "template_anchor"
    elif candidate:
        status = "template_candidate"
    elif structure_ok:
        status = "review_required"
    return status, reasons


def audit_one(atom_dir: Path) -> dict:
    raw = _safe_load_atom(atom_dir)
    if raw is None:
        return {"cve_id": atom_dir.name, "parseable": False}
    try:
        atom = AtomConfig(**raw)
    except Exception as exc:
        return {"cve_id": atom_dir.name, "parseable": False, "parse_error": str(exc)}
    bundle = _bundle_completeness(atom_dir, raw)
    service = _service_contract(atom, raw)
    cap = _capability_contract(atom, raw)
    guide = _guide_integrity(atom_dir, raw)
    status, reasons = _classify(atom, raw, bundle, service, cap, guide)
    env_ready = (raw.get("verification") or {}).get("environment_ready")
    native_success = (raw.get("verification") or {}).get("native_verification", {}).get("success")
    return {
        "cve_id": atom.cve_id,
        "category": atom.category,
        "parseable": True,
        "version": atom.version,
        "verified": atom.verified,
        "native_success": native_success,
        "environment_ready": env_ready,
        "service_role": atom.service_role.value,
        "vuln_category": atom.vuln_category.value,
        "source_bundle": bundle,
        "service_contract": service,
        "capability_contract": cap,
        "guide": guide,
        "status": status,
        "reasons": reasons,
    }


def main() -> int:
    atoms_dir = ROOT / "data" / "atoms"
    rows = []
    for d in sorted(atoms_dir.iterdir()):
        if not d.is_dir() or not (d / "atom.yaml").exists():
            continue
        rows.append(audit_one(d))

    # write json
    out_json = ROOT / "data" / "atom_authoritative_audit.json"
    out_json.write_text(json.dumps(rows, indent=2, ensure_ascii=False))

    # write csv (flat key fields)
    out_csv = ROOT / "data" / "atom_authoritative_audit.csv"
    fields = [
        "cve_id", "category", "version", "verified", "native_success",
        "environment_ready", "status",
        "bundle_present", "bundle_compose", "bundle_readme",
        "poc_materials_total", "poc_materials_missing_count",
        "poc_basename_collisions", "hash_ok", "hash_bad",
        "service_complete", "service_empty", "service_protocol", "service_port",
        "cap_verified_count", "cap_inferred_count",
        "cap_unresolvable_refs",
        "guide_present", "guide_ready", "guide_integrity_ok",
        "reasons",
    ]
    with out_csv.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(fields)
        for r in rows:
            if not r.get("parseable"):
                w.writerow([r.get("cve_id", ""), "", "", "", "", "", "excluded", "", "", "",
                            "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", ""])
                continue
            b = r["source_bundle"]
            s = r["service_contract"]
            c = r["capability_contract"]
            g = r["guide"]
            w.writerow([
                r["cve_id"], r["category"], r["version"], r["verified"],
                r["native_success"], r["environment_ready"], r["status"],
                b.get("present", False), b.get("compose_file", False),
                b.get("readme_file", False),
                b.get("poc_materials_total", 0), len(b.get("poc_materials_missing", [])),
                len(b.get("poc_materials_basename_collisions", [])),
                b.get("hash_ok", 0), b.get("hash_bad", 0),
                s["complete"], s["empty"], s["protocol"], s["port"],
                len(c["verified"]), len(c["inferred"]),
                len(c["unresolvable_evidence_refs"]),
                g.get("present", False), g.get("ready", False),
                g.get("integrity_ok", False),
                "; ".join(r["reasons"]),
            ])

    # write md summary
    from collections import Counter
    status_counts = Counter(r["status"] for r in rows if r.get("parseable"))
    lines = ["# Atom authoritative audit (batch 0, read-only)", "",
             f"total: {len(rows)}", ""]
    lines += [f"- {k}: {v}" for k, v in sorted(status_counts.items())]
    lines += ["",
              "## Anchor risk check (b00-b05 atoms)", ""]
    anchors = ["CVE-2012-1823", "CVE-2018-16509", "CVE-2019-9193",
              "CVE-2014-3120", "CVE-2021-42013", "CVE-2022-22965",
              "CVE-2022-24816", "CVE-2019-17558", "CVE-2021-32568"]
    amap = {r["cve_id"]: r for r in rows}
    for cve in anchors:
        r = amap.get(cve)
        if not r:
            lines.append(f"- {cve}: NOT FOUND")
            continue
        lines.append(
            f"- {cve}: status={r['status']} verified={r['verified']} "
            f"env_ready={r['environment_ready']} service_complete={r['service_contract']['complete']} "
            f"service_empty={r['service_contract']['empty']} "
            f"cap_verified={len(r['capability_contract']['verified'])} "
            f"guide_ready={r['guide'].get('ready')} guide_integrity={r['guide'].get('integrity_ok')}"
        )
    lines += ["", "## Gaps to fix", ""]
    empty_service = [r["cve_id"] for r in rows if r.get("service_contract", {}).get("empty")]
    no_bundle = [r["cve_id"] for r in rows if not r.get("source_bundle", {}).get("present")]
    env_false = [r["cve_id"] for r in rows if r.get("environment_ready") is False]
    unresolvable = [r["cve_id"] for r in rows
                    if r.get("capability_contract", {}).get("unresolvable_evidence_refs")]
    guide_integrity_fail = [r["cve_id"] for r in rows
                            if r.get("guide", {}).get("ready") and r.get("guide", {}).get("integrity_ok") is False]
    lines.append(f"- required_service empty ({len(empty_service)}): {', '.join(empty_service)}")
    lines.append(f"- no source_bundle ({len(no_bundle)}): {', '.join(no_bundle)}")
    lines.append(f"- environment_ready=false ({len(env_false)}): {', '.join(env_false)}")
    lines.append(f"- unresolvable verified evidence_ref ({len(unresolvable)}): {', '.join(unresolvable)}")
    lines.append(f"- ready guide integrity fail ({len(guide_integrity_fail)}): {', '.join(guide_integrity_fail)}")
    (ROOT / "data" / "atom_authoritative_audit.md").write_text("\n".join(lines) + "\n")

    print(f"audited {len(rows)} atoms")
    for k, v in sorted(status_counts.items()):
        print(f"  {k}: {v}")
    print("\nAnchor risk:")
    for cve in anchors:
        r = amap.get(cve)
        if r:
            print(f"  {cve}: {r['status']} | env_ready={r['environment_ready']} "
                  f"service_empty={r['service_contract']['empty']} "
                  f"cap_verified={len(r['capability_contract']['verified'])}")
    print(f"\nwrote: {out_json}")
    print(f"wrote: {out_csv}")
    print(f"wrote: {ROOT / 'data' / 'atom_authoritative_audit.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())