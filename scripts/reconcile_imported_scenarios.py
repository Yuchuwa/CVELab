#!/usr/bin/env python3
"""Reconcile imported CVELab scenario snapshots with this checkout.

The imported snapshot is treated as topology/case provenance only. Runtime
image identity and Atom host bind paths are resolved from the current Atom
pool and Docker daemon; flag permissions are preserved. The source snapshot
is never modified.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]


def _load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text()) or {}
    if not isinstance(value, dict):
        raise ValueError(f"expected mapping: {path}")
    return value


def _image_id(image: str) -> str:
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", image, "--format", "{{.Id}}"],
            capture_output=True, text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def _safe_image_name(cve_id: str, dockerfile: Path) -> str:
    digest = hashlib.sha256(dockerfile.read_bytes()).hexdigest()[:12]
    safe = re.sub(r"[^a-z0-9_.-]", "-", cve_id.lower())
    return f"cvelab-atom-{safe}-{digest}"


def _atom_selection(cve_id: str, atoms_dir: Path) -> tuple[dict[str, Any], dict[str, str] | None]:
    atom_dir = atoms_dir / cve_id
    raw = _load_yaml(atom_dir / "atom.yaml")
    runtime = raw.get("runtime_spec") or {}
    verification = raw.get("verification") or {}
    runtime_verification = verification.get("runtime_verification") or {}
    runtime_image = str(runtime.get("runtime_image") or "")
    runtime_status = str(runtime.get("runtime_status") or "")
    runtime_build = runtime.get("runtime_build") or {}
    source_image = str(runtime.get("source_image") or raw.get("docker_image") or "")

    if (
        runtime_status == "ready"
        and runtime_image
        and runtime_build
        and runtime_verification.get("status") == "ready"
    ):
        actual = _image_id(runtime_image)
        expected = actual or str(runtime_verification.get("runtime_image_digest") or "")
        return {
            "cve_id": cve_id,
            "source_image": source_image,
            "runtime_image": runtime_image,
            "selected_image": runtime_image,
            "selection": "runtime_image",
            "runtime_status": runtime_status,
            "runtime_verification_status": "ready",
            "base_image_digest": str(runtime_build.get("base_image_digest") or ""),
            "runtime_image_digest": expected,
            "runtime_build_generated_hash": str(runtime_build.get("generated_hash") or ""),
            "fallback_reason": "",
            "local_image_present": bool(actual),
            "digest_source": "local_image" if actual else "atom_verification",
        }, None

    dockerfiles = ((raw.get("source_bundle") or {}).get("dockerfiles") or [])
    if dockerfiles:
        dockerfile_ref = Path(str(dockerfiles[0]))
        dockerfile = atom_dir / dockerfile_ref
        if dockerfile.is_file():
            context = atom_dir / "source_bundle"
            if not context.is_dir() or context not in dockerfile.parents:
                context = dockerfile.parent
            image = _safe_image_name(cve_id, dockerfile)
            build = {
                "cve_id": cve_id,
                "image": image,
                "context": str(context),
                "dockerfile": str(dockerfile),
            }
            return {
                "cve_id": cve_id,
                "source_image": source_image,
                "runtime_image": "",
                "selected_image": image,
                "selection": "legacy_source_bundle_build",
                "runtime_status": runtime_status or "not_requested",
                "runtime_verification_status": str(runtime_verification.get("status") or "missing"),
                "base_image_digest": "",
                "runtime_image_digest": "",
                "runtime_build_generated_hash": "",
                "fallback_reason": "runtime_contract_not_ready",
                "local_image_present": bool(_image_id(image)),
                "digest_source": "not_applicable",
            }, build

    return {
        "cve_id": cve_id,
        "source_image": source_image,
        "runtime_image": "",
        "selected_image": source_image,
        "selection": "source_image",
        "runtime_status": runtime_status or "not_requested",
        "runtime_verification_status": str(runtime_verification.get("status") or "missing"),
        "base_image_digest": "",
        "runtime_image_digest": "",
        "runtime_build_generated_hash": "",
        "fallback_reason": "runtime_contract_not_ready",
        "local_image_present": bool(_image_id(source_image)) if source_image else False,
        "digest_source": "not_applicable",
    }, None


def _rewrite_bind(value: str, atoms_dir: Path) -> str:
    text = str(value)
    marker = "/data/atoms/"
    if marker in text:
        suffix = text.split(marker, 1)[1]
        text = str(atoms_dir / suffix)
    parts = text.split(":")
    return text


def _reconcile_case(source: Path, destination: Path, atoms_dir: Path) -> dict[str, Any]:
    shutil.copytree(source, destination)
    scenario = _load_yaml(destination / "scenario.yaml")
    injections = scenario.get("injections") or []
    cves = [str(item.get("cve_id")) for item in injections if item.get("cve_id")]
    selections: dict[str, dict[str, Any]] = {}
    builds: list[dict[str, str]] = []
    for cve_id in dict.fromkeys(cves):
        selection, build = _atom_selection(cve_id, atoms_dir)
        selections[cve_id] = selection
        if build and not selection["local_image_present"]:
            builds.append(build)

    scenario["runtime_images"] = list(selections.values())
    scenario["runtime_builds"] = builds
    (destination / "scenario.yaml").write_text(
        yaml.safe_dump(scenario, sort_keys=False, allow_unicode=True)
    )

    topology = _load_yaml(destination / "clab.yaml")
    node_to_cve = {
        str(item.get("node_name")): str(item.get("cve_id"))
        for item in injections if item.get("node_name") and item.get("cve_id")
    }
    nodes = ((topology.get("topology") or {}).get("nodes") or {})
    for node_name, cve_id in node_to_cve.items():
        if node_name in nodes and cve_id in selections:
            nodes[node_name]["image"] = selections[cve_id]["selected_image"]
    for node in nodes.values():
        if isinstance(node, dict) and isinstance(node.get("binds"), list):
            node["binds"] = [_rewrite_bind(item, atoms_dir) for item in node["binds"]]
    (destination / "clab.yaml").write_text(
        yaml.safe_dump(topology, sort_keys=False, allow_unicode=True)
    )

    external_result = {}
    result_path = destination / "verify_result.json"
    if result_path.exists():
        try:
            external_result = json.loads(result_path.read_text())
        except json.JSONDecodeError:
            external_result = {"parse_error": True}
        result_path.unlink()
    (destination / "import_provenance.json").write_text(json.dumps({
        "source_dir": str(source),
        "external_verify_result": {
            key: external_result.get(key)
            for key in ("success", "environment_success", "attack_graph_valid", "attack_path_reachable", "failure_stage")
            if key in external_result
        },
        "reconciled_from_current_atoms": True,
        "flag_permissions": "preserved_from_source",
        "flag_mounts": "preserved_from_source",
    }, indent=2, ensure_ascii=False) + "\n")
    return {
        "id": "matrix-" + source.name.removeprefix("enterprise_3tier-"),
        "scenario_dir": str(destination),
        "cves": cves,
        "external_environment_success": bool(external_result.get("environment_success")),
        "missing_local_images": [cve for cve, item in selections.items() if not item["local_image_present"]],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / "data/scenarios/stratified-50-generation-smoke/scenarios")
    parser.add_argument("--manifest", type=Path, default=ROOT / "data/stratified_50_ranges.json")
    parser.add_argument("--atoms-dir", type=Path, default=ROOT / "data/atoms")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    # Scenario files may be launched from a case directory, so all host-side
    # paths written into clab.yaml must be absolute and tied to this checkout.
    args.source = args.source.resolve()
    args.manifest = args.manifest.resolve()
    args.atoms_dir = args.atoms_dir.resolve()
    args.output = args.output.resolve()

    manifest = json.loads(args.manifest.read_text())
    cases = manifest.get("cases") or []
    wanted = {"enterprise_3tier-" + str(case["id"]).removeprefix("matrix-") for case in cases}
    sources = {path.name: path for path in args.source.iterdir() if path.is_dir()}
    missing = sorted(wanted - sources.keys())
    if missing:
        raise SystemExit("missing imported scenarios: " + ", ".join(missing))
    args.output.mkdir(parents=True, exist_ok=False)
    records = []
    for name in sorted(wanted):
        records.append(_reconcile_case(sources[name], args.output / name, args.atoms_dir))
    (args.output / "import_manifest.json").write_text(json.dumps({
        "schema_version": 1,
        "source": str(args.source),
        "manifest": str(args.manifest),
        "selected_cases": len(records),
        "excluded_source_scenarios": sorted(set(sources) - wanted),
        "cases": records,
    }, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({
        "output": str(args.output),
        "selected_cases": len(records),
        "excluded": sorted(set(sources) - wanted),
        "external_environment_success": sum(item["external_environment_success"] for item in records),
        "cases_with_missing_local_images": sum(bool(item["missing_local_images"]) for item in records),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
