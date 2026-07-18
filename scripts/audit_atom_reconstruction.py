#!/usr/bin/env python3
"""Read-only reconstruction audit and value-ranked Atom wave selector."""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from clab_builder.shared.atom_qualification import qualify_atom
from clab_builder.shared.models.atom import AtomConfig, EvidenceLevel, RuntimeStatus


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--atoms-dir", default="data/atoms")
    parser.add_argument("--output-prefix", default="data/atom_reconstruction_audit")
    parser.add_argument("--wave-output", default="data/atom_reconstruction_wave.json")
    parser.add_argument("--max-wave", type=int, default=25)
    return parser.parse_args()


def _native_success(atom: AtomConfig) -> bool:
    return bool((atom.verification or {}).get("native_verification", {}).get("success"))


def _guide_ready(atom: AtomConfig) -> bool:
    return bool(atom.exploit_guide and atom.exploit_guide.status == "ready")


def _runtime_ready(atom: AtomConfig) -> bool:
    runtime = atom.runtime_spec
    verification = (atom.verification or {}).get("runtime_verification") or {}
    return bool(
        runtime
        and runtime.runtime_status == RuntimeStatus.READY
        and runtime.runtime_image
        and verification.get("status") == RuntimeStatus.READY.value
        and verification.get("service_ready") is True
    )


def _readiness_alignment(atom: AtomConfig) -> dict[str, Any]:
    service = atom.exploit_access.required_service or {}
    target = service.get("port")
    try:
        target = int(target)
    except (TypeError, ValueError):
        target = None
    runtime_ports = list(atom.runtime_spec.ports) if atom.runtime_spec else []
    tcp_targets = [
        str(probe.target)
        for probe in atom.validation_spec.readiness
        if probe.probe_type.value == "tcp"
    ]
    mismatch = bool(
        target is not None
        and len(runtime_ports) > 1
        and str(target) not in tcp_targets
    )
    return {
        "exploit_entry_port": target,
        "runtime_ports": runtime_ports,
        "tcp_probe_targets": tcp_targets,
        "aligned": not mismatch,
    }


def _image_blocked(atom: AtomConfig) -> bool:
    runtime = atom.runtime_spec
    reason = " ".join([
        runtime.runtime_failure_reason if runtime else "",
        str(((atom.verification or {}).get("runtime_verification") or {}).get("failure_reason", "")),
    ]).lower()
    return any(marker in reason for marker in (
        "pull access denied", "manifest unknown", "not found", "image unavailable",
    ))


def _local_image_state(image: str) -> str:
    """Report only local Docker visibility; never pull or substitute an image."""
    if not image:
        return "undeclared"
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    if result.returncode == 0:
        return "present"
    detail = (result.stderr or "").lower()
    if "permission denied" in detail or "cannot connect to the docker daemon" in detail:
        return "unknown"
    return "not_local"


def _classify(atom: AtomConfig, atom_dir: Path) -> tuple[str, list[str], dict[str, Any]]:
    qualification = qualify_atom(atom, atom_dir).to_dict()
    readiness = _readiness_alignment(atom)
    bundle_ok = bool(qualification["checks"]["source_bundle"]["ok"])
    guide = qualification["checks"]["guide"]
    reasons: list[str] = []

    if _image_blocked(atom):
        return "blocked_source_unavailable", ["exact source image unavailable"], readiness
    if atom.version < 3 or not atom.verified or not _native_success(atom) or not _guide_ready(atom):
        if atom.version < 3:
            reasons.append("version<3")
        if not atom.verified or not _native_success(atom):
            reasons.append("native verification unavailable")
        if not _guide_ready(atom):
            reasons.append("ready guide unavailable")
        return "full_reconstruction", reasons, readiness
    if not bundle_ok or not guide["ok"] or not readiness["aligned"] or not _runtime_ready(atom):
        reasons.extend(qualification["checks"]["source_bundle"]["reasons"])
        reasons.extend(guide["reasons"])
        if not readiness["aligned"]:
            reasons.append("multi-port readiness does not probe exploit entry")
        if not _runtime_ready(atom):
            reasons.append("runtime contract not ready")
        return "rebuild_runtime_or_bundle", reasons, readiness
    if not qualification["template_candidate"]:
        return "rebuild_runtime_or_bundle", qualification["reasons"], readiness
    return "range_ready", [], readiness


def _value_score(atom: AtomConfig, role_counts: Counter[str]) -> int:
    grants = {
        grant.type.value
        for grant in atom.capability_grants
        if grant.evidence_level == EvidenceLevel.VERIFIED
    }
    score = 0
    score += 8 if "execute_command" in grants else 0
    score += 3 if "read_file" in grants else 0
    score += 2 if "write_file" in grants else 0
    score += 1 if "read_credential" in grants else 0
    score += max(0, 5 - role_counts[atom.service_role.value])
    if atom.exploit_complexity.value == "simple":
        score += 3
    elif atom.exploit_complexity.value == "medium":
        score += 1
    return score


def audit_atom_dir(atom_dir: Path, role_counts: Counter[str]) -> dict[str, Any]:
    raw = yaml.safe_load((atom_dir / "atom.yaml").read_text()) or {}
    try:
        atom = AtomConfig.model_validate(raw)
    except Exception as exc:
        return {
            "cve_id": atom_dir.name,
            "classification": "full_reconstruction",
            "reasons": [f"atom schema invalid: {exc}"],
            "value_score": 0,
        }
    classification, reasons, readiness = _classify(atom, atom_dir)
    runtime = atom.runtime_spec
    return {
        "cve_id": atom.cve_id,
        "classification": classification,
        "reasons": reasons,
        "value_score": _value_score(atom, role_counts),
        "version": atom.version,
        "service_role": atom.service_role.value,
        "service_family": runtime.service_family if runtime else None,
        "source_image": (runtime.source_image if runtime else None) or atom.docker_image,
        "source_image_local": _local_image_state(
            (runtime.source_image if runtime else None) or atom.docker_image
        ),
        "required_service": atom.exploit_access.required_service,
        "verified_capabilities": sorted({
            grant.type.value for grant in atom.capability_grants
            if grant.evidence_level == EvidenceLevel.VERIFIED
        }),
        "native_success": _native_success(atom),
        "environment_ready": (atom.verification or {}).get("environment_ready"),
        "guide_ready": _guide_ready(atom),
        "runtime_ready": _runtime_ready(atom),
        "readiness_alignment": readiness,
    }


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = [
        "cve_id", "classification", "value_score", "version", "service_role",
        "service_family", "source_image", "native_success", "environment_ready",
        "source_image_local",
        "guide_ready", "runtime_ready", "required_service", "verified_capabilities",
        "reasons",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({
                key: json.dumps(row[key], ensure_ascii=False)
                if isinstance(row.get(key), (dict, list)) else row.get(key, "")
                for key in fields
            })


def main() -> int:
    args = parse_args()
    if args.max_wave < 1:
        raise SystemExit("--max-wave must be positive")
    atoms_dir = ROOT / args.atoms_dir
    atom_dirs = sorted(path.parent for path in atoms_dir.glob("*/atom.yaml"))
    raw_atoms = []
    for atom_dir in atom_dirs:
        try:
            raw_atoms.append(AtomConfig.model_validate(yaml.safe_load((atom_dir / "atom.yaml").read_text()) or {}))
        except Exception:
            continue
    role_counts = Counter(atom.service_role.value for atom in raw_atoms)
    rows = [audit_atom_dir(atom_dir, role_counts) for atom_dir in atom_dirs]
    rows.sort(key=lambda row: row["cve_id"])

    candidates = [
        row for row in rows
        if row["classification"] in {"rebuild_runtime_or_bundle", "full_reconstruction"}
    ]
    wave = sorted(
        candidates,
        key=lambda row: (-row["value_score"], row["classification"], row["cve_id"]),
    )[:args.max_wave]

    prefix = ROOT / args.output_prefix
    prefix.parent.mkdir(parents=True, exist_ok=True)
    (prefix.with_suffix(".json")).write_text(
        json.dumps({"rows": rows, "counts": Counter(row["classification"] for row in rows)}, indent=2, ensure_ascii=False) + "\n"
    )
    _write_csv(prefix.with_suffix(".csv"), rows)
    wave_path = ROOT / args.wave_output
    wave_path.parent.mkdir(parents=True, exist_ok=True)
    wave_path.write_text(json.dumps({
        "source_audit": str(prefix.with_suffix(".json").relative_to(ROOT)),
        "max_wave": args.max_wave,
        "selected": wave,
        "deferred": [row for row in rows if row["classification"] in {
            "blocked_source_unavailable", "range_ready"
        }],
    }, indent=2, ensure_ascii=False) + "\n")
    print(f"audited={len(rows)} counts={dict(Counter(row['classification'] for row in rows))}")
    print(f"wave={len(wave)} path={wave_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
