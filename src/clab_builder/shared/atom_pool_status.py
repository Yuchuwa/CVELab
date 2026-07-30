"""Canonical Atom build-lifecycle snapshot and generated views."""

from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml

from clab_builder.shared.atom_qualification import qualify_atom
from clab_builder.shared.models.atom import AtomConfig, RuntimeStatus


DEFINITIONS = {
    "planned": "accepted into the Atom build queue; atom.yaml does not exist yet",
    "building": (
        "Atom construction or verification has started but strict completion "
        "gates do not all pass"
    ),
    "completed": (
        "strict high-confidence Atom contract passes every recorded "
        "completion gate"
    ),
}

COMPLETION_GATES = (
    "schema_v3",
    "source_bundle_complete",
    "source_bundle_hashed",
    "self_contained_paths",
    "runtime_spec_explicit",
    "runtime_ready",
    "runtime_build_reproducible",
    "flag_contract_explicit",
    "validation_contract_explicit",
    "native_verified",
    "service_contract_complete",
    "verified_capability",
    "guide_ready_valid",
    "orchestrated_environment_verified",
)


def _is_relative_artifact_path(value: Any) -> bool:
    if not value:
        return True
    path = Path(str(value))
    return not path.is_absolute() and ".." not in path.parts


def _self_contained_paths(raw: dict[str, Any]) -> bool:
    paths: list[Any] = []
    bundle = raw.get("source_bundle") or {}
    paths.extend(bundle.get(key) for key in ("compose_file", "readme_file"))
    for key in ("dockerfiles", "init_files", "poc_materials"):
        paths.extend(bundle.get(key) or [])
    paths.extend((bundle.get("hashes") or {}).keys())

    guide = raw.get("exploit_guide") or {}
    paths.append(guide.get("path"))

    runtime_build = (raw.get("runtime_spec") or {}).get("runtime_build") or {}
    paths.extend(
        runtime_build.get(key)
        for key in ("context", "dockerfile", "install_script", "source_dockerfile")
    )
    return all(_is_relative_artifact_path(path) for path in paths)


def _source_bundle_hashed(raw: dict[str, Any]) -> bool:
    bundle = raw.get("source_bundle") or {}
    declared = {
        value
        for value in (bundle.get("compose_file"), bundle.get("readme_file"))
        if value
    }
    for key in ("dockerfiles", "init_files", "poc_materials"):
        declared.update(bundle.get(key) or [])
    hashes = bundle.get("hashes") or {}
    return bool(declared) and declared.issubset(hashes)


def _runtime_build_reproducible(
    raw: dict[str, Any],
    atom_dir: Path,
) -> bool:
    runtime_build = (raw.get("runtime_spec") or {}).get("runtime_build")
    if not isinstance(runtime_build, dict):
        return False
    required_values = (
        "context",
        "dockerfile",
        "install_script",
        "base_image_digest",
        "generated_hash",
    )
    if any(not runtime_build.get(key) for key in required_values):
        return False
    required_paths = ("context", "dockerfile", "install_script")
    if any(not (atom_dir / runtime_build[key]).exists() for key in required_paths):
        return False
    source_dockerfile = runtime_build.get("source_dockerfile")
    return not source_dockerfile or (atom_dir / source_dockerfile).is_file()


def _completion_checks(
    raw: dict[str, Any],
    atom: AtomConfig,
    atom_dir: Path,
) -> dict[str, bool]:
    qualification = qualify_atom(atom, atom_dir)
    checks = qualification.checks
    guide = checks.get("guide", {})
    orchestrated = (raw.get("verification") or {}).get(
        "orchestrated_verification"
    )
    runtime = raw.get("runtime_spec")
    return {
        "schema_v3": atom.version >= 3,
        "source_bundle_complete": bool(
            checks.get("source_bundle", {}).get("ok")
        ),
        "source_bundle_hashed": _source_bundle_hashed(raw),
        "self_contained_paths": _self_contained_paths(raw),
        "runtime_spec_explicit": isinstance(runtime, dict),
        "runtime_ready": (
            isinstance(runtime, dict)
            and atom.runtime_spec is not None
            and atom.runtime_spec.runtime_status == RuntimeStatus.READY
        ),
        "runtime_build_reproducible": _runtime_build_reproducible(
            raw, atom_dir
        ),
        "flag_contract_explicit": isinstance(raw.get("flag_spec"), dict),
        "validation_contract_explicit": isinstance(
            raw.get("validation_spec"), dict
        ),
        "native_verified": bool(
            atom.verified and checks.get("native", {}).get("success")
        ),
        "service_contract_complete": bool(
            checks.get("service", {}).get("ok")
        ),
        "verified_capability": bool(
            checks.get("capability", {}).get("ok")
        ),
        "guide_ready_valid": bool(
            guide.get("present") and guide.get("ready") and guide.get("ok")
        ),
        "orchestrated_environment_verified": bool(
            isinstance(orchestrated, dict)
            and orchestrated.get("success") is True
            and orchestrated.get("evidence")
            and orchestrated.get("timestamp")
        ),
    }


def _building_row(atom_dir: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load((atom_dir / "atom.yaml").read_text()) or {}
        atom = AtomConfig.model_validate(raw)
    except Exception as exc:
        return {
            "cve_id": atom_dir.name,
            "build_status": "building",
            "completion_checks": {name: False for name in COMPLETION_GATES},
            "blockers": ["atom_schema_parse"],
            "parse_error": str(exc),
        }

    checks = _completion_checks(raw, atom, atom_dir)
    blockers = [name for name in COMPLETION_GATES if not checks[name]]
    return {
        "cve_id": atom.cve_id,
        "build_status": "completed" if not blockers else "building",
        "version": atom.version,
        "service_role": atom.service_role.value,
        "vuln_category": atom.vuln_category.value,
        "primary_mitre_phase": atom.primary_mitre_phase.value,
        "completion_checks": checks,
        "blockers": blockers,
    }


def build_snapshot(
    atoms_dir: Path,
    *,
    planned_ids: Iterable[str] = (),
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [
        _building_row(path)
        for path in sorted(atoms_dir.iterdir())
        if path.is_dir() and (path / "atom.yaml").is_file()
    ]
    existing = {row["cve_id"] for row in rows}
    rows.extend(
        {
            "cve_id": cve_id,
            "build_status": "planned",
            "completion_checks": {},
            "blockers": ["atom_not_started"],
        }
        for cve_id in sorted(set(planned_ids) - existing)
    )
    rows.sort(key=lambda row: row["cve_id"])

    summary = {"total": len(rows)}
    summary.update(
        {
            status: sum(row["build_status"] == status for row in rows)
            for status in DEFINITIONS
        }
    )
    digest_payload = {
        "definitions": DEFINITIONS,
        "completion_gates": COMPLETION_GATES,
        "atoms": rows,
    }
    snapshot_hash = hashlib.sha256(
        json.dumps(digest_payload, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()
    return {
        "schema_version": 2,
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(),
        "snapshot_hash": snapshot_hash,
        "definitions": DEFINITIONS,
        "completion_gates": list(COMPLETION_GATES),
        "summary": summary,
        "atoms": rows,
    }


def render_csv(snapshot: dict[str, Any]) -> str:
    fields = [
        "generated_at",
        "snapshot_hash",
        "cve_id",
        "build_status",
        "version",
        "service_role",
        "vuln_category",
        "primary_mitre_phase",
        *snapshot["completion_gates"],
        "blockers",
        "parse_error",
    ]
    stream = io.StringIO()
    writer = csv.DictWriter(
        stream,
        fieldnames=fields,
        extrasaction="ignore",
        lineterminator="\n",
    )
    writer.writeheader()
    for item in snapshot["atoms"]:
        writer.writerow(
            {
                **item,
                **item.get("completion_checks", {}),
                "generated_at": snapshot["generated_at"],
                "snapshot_hash": snapshot["snapshot_hash"],
                "blockers": "; ".join(item.get("blockers", [])),
            }
        )
    return stream.getvalue()


def render_markdown(snapshot: dict[str, Any]) -> str:
    lines = [
        "# Atom Build Status",
        "",
        "Status: generated snapshot",
        "",
        f"Generated at: `{snapshot['generated_at']}`",
        "",
        f"Snapshot hash: `{snapshot['snapshot_hash']}`",
        "",
        "## Lifecycle Definitions",
        "",
    ]
    lines.extend(
        f"- `{name}`: {meaning}" for name, meaning in snapshot["definitions"].items()
    )
    lines.extend(["", "## Strict Completion Gates", ""])
    lines.extend(f"- `{name}`" for name in snapshot["completion_gates"])
    lines.extend(["", "## Summary", ""])
    lines.extend(f"- `{name}`: {value}" for name, value in snapshot["summary"].items())
    lines.extend(["", "## Atoms", ""])
    for item in snapshot["atoms"]:
        blockers = ", ".join(item.get("blockers", [])) or "none"
        lines.append(
            f"- `{item['cve_id']}` — `{item['build_status']}`; "
            f"blockers: {blockers}"
        )
    lines.append("")
    return "\n".join(lines)


def write_snapshot(snapshot: dict[str, Any], output_prefix: Path) -> None:
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    output_prefix.with_suffix(".json").write_text(
        json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n"
    )
    output_prefix.with_suffix(".csv").write_text(render_csv(snapshot))
    output_prefix.with_suffix(".md").write_text(render_markdown(snapshot))
