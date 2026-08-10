"""Canonical Atom build-lifecycle snapshot and generated views."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

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
    "source_bundle_material_metadata_complete",
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

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def load_planned_ids(build_plan: Path) -> list[str]:
    """Load the canonical planned queue from a build-plan JSON file."""
    if not build_plan.is_file():
        return []
    plan = json.loads(build_plan.read_text())
    return [
        item["cve_id"] if isinstance(item, dict) else str(item)
        for item in plan.get("planned", [])
    ]


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
    for key in required_paths:
        value = runtime_build[key]
        if not _is_relative_artifact_path(value):
            return False
        path = atom_dir / value
        if not path.exists() or (key != "context" and not path.is_file()):
            return False
    generated_hash = str(runtime_build["generated_hash"])
    if not _SHA256_RE.fullmatch(generated_hash):
        return False
    source_dockerfile = runtime_build.get("source_dockerfile")
    if source_dockerfile and (
        not _is_relative_artifact_path(source_dockerfile)
        or not (atom_dir / source_dockerfile).is_file()
    ):
        return False

    # New runtime builders persist the exact input hash in this manifest. If
    # the manifest exists, a copied or hand-edited build must not qualify.
    manifest_path = atom_dir / "runtime" / "manifest.yaml"
    if manifest_path.is_file():
        try:
            manifest = yaml.safe_load(manifest_path.read_text()) or {}
        except (OSError, yaml.YAMLError):
            return False
        if manifest.get("generated_hash") != generated_hash:
            return False
    return True


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
        "source_bundle_material_metadata_complete": bool(
            checks.get("source_bundle", {})
            .get("material_metadata", {})
            .get("ok")
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
        # Directory identity is canonical. A YAML ID mismatch is a build
        # blocker instead of silently re-keying or overwriting another row.
        "cve_id": atom_dir.name,
        "build_status": "completed" if not blockers else "building",
        "version": atom.version,
        "service_role": atom.service_role.value,
        "vuln_category": atom.vuln_category.value,
        "primary_mitre_phase": atom.primary_mitre_phase.value,
        "completion_checks": checks,
        "blockers": blockers,
        **(
            {"declared_cve_id": atom.cve_id, "build_status": "building",
             "blockers": [*blockers, "atom_directory_id_mismatch"]}
            if atom.cve_id != atom_dir.name else {}
        ),
    }


def build_lifecycle_index(
    atoms_dir: Path,
    *,
    planned_ids: Iterable[str] = (),
    build_attempts: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Build the canonical live lifecycle index from Atom and plan evidence."""
    rows: dict[str, dict[str, Any]] = {}
    attempts = dict(build_attempts or {})
    if atoms_dir.is_dir():
        for path in sorted(atoms_dir.iterdir()):
            if not path.is_dir():
                continue
            if (path / "atom.yaml").is_file():
                row = _building_row(path)
            elif path.name in attempts:
                row = {
                    "cve_id": path.name,
                    "build_status": "building",
                    "completion_checks": {
                        name: False for name in COMPLETION_GATES
                    },
                    "blockers": ["atom_yaml_missing"],
                    "build_attempt": dict(attempts[path.name]),
                }
            else:
                # Local workspaces are not lifecycle evidence by themselves:
                # they are ignored by Git and therefore invisible in clean CI.
                continue
            rows[row["cve_id"]] = row

    for cve_id, attempt in sorted(attempts.items()):
        if cve_id in rows:
            continue
        rows[cve_id] = {
            "cve_id": cve_id,
            "build_status": "building",
            "completion_checks": {
                name: False for name in COMPLETION_GATES
            },
            "blockers": ["atom_yaml_missing"],
            "build_attempt": dict(attempt),
        }

    for cve_id in sorted(set(planned_ids) - rows.keys()):
        rows[cve_id] = {
            "cve_id": cve_id,
            "build_status": "planned",
            "completion_checks": {},
            "blockers": ["atom_not_started"],
        }
    return dict(sorted(rows.items()))


def snapshot_semantic_identity(snapshot: dict[str, Any]) -> str:
    """Return the schema-v2 identity independent of generation time."""
    payload = {
        "definitions": snapshot.get("definitions"),
        "completion_gates": snapshot.get("completion_gates"),
        "atoms": snapshot.get("atoms"),
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()


def compare_snapshots(
    expected: dict[str, Any],
    actual: dict[str, Any],
) -> list[str]:
    """Compare two snapshots by semantic identity, not ``generated_at``."""
    errors = []
    actual_identity = snapshot_semantic_identity(actual)
    if actual.get("snapshot_hash") != actual_identity:
        errors.append("stored JSON snapshot_hash does not match its content")
    if snapshot_semantic_identity(expected) != actual_identity:
        errors.append("stored Atom lifecycle snapshot is stale")
    return errors


def build_snapshot(
    atoms_dir: Path,
    *,
    planned_ids: Iterable[str] = (),
    build_attempts: Mapping[str, Mapping[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = list(
        build_lifecycle_index(
            atoms_dir,
            planned_ids=planned_ids,
            build_attempts=build_attempts,
        ).values()
    )

    summary = {"total": len(rows)}
    summary.update(
        {
            status: sum(row["build_status"] == status for row in rows)
            for status in DEFINITIONS
        }
    )
    snapshot = {
        "schema_version": 2,
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(),
        "definitions": DEFINITIONS,
        "completion_gates": list(COMPLETION_GATES),
        "summary": summary,
        "atoms": rows,
    }
    snapshot["snapshot_hash"] = snapshot_semantic_identity(snapshot)
    return snapshot


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


def check_snapshot_files(
    live_snapshot: dict[str, Any],
    output_prefix: Path,
) -> list[str]:
    """Validate stored JSON/CSV/Markdown views without writing to disk."""
    paths = {
        "JSON": output_prefix.with_suffix(".json"),
        "CSV": output_prefix.with_suffix(".csv"),
        "Markdown": output_prefix.with_suffix(".md"),
    }
    errors = [f"missing {name} snapshot: {path}" for name, path in paths.items()
              if not path.is_file()]
    if errors:
        return errors

    try:
        stored = json.loads(paths["JSON"].read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return [f"invalid JSON snapshot: {exc}"]

    errors.extend(compare_snapshots(live_snapshot, stored))
    try:
        if paths["CSV"].read_text() != render_csv(stored):
            errors.append("stored CSV snapshot is stale or has a different identity")
        if paths["Markdown"].read_text() != render_markdown(stored):
            errors.append(
                "stored Markdown snapshot is stale or has a different identity"
            )
    except (KeyError, TypeError, OSError) as exc:
        errors.append(f"stored snapshot views are invalid: {exc}")
    return errors
