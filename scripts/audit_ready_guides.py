#!/usr/bin/env python3
"""Audit ready v2 guides against the Guide integrity contract.

Re-runs Range's _load_atom_guide (which calls validate_exploit_guide with
forbidden_values from the atom's flag) on every verified atom with a ready
guide. Any guide that fails the integrity check (missing material, native
IP, leaked flag, broken structure) is downgraded to review_required.

Guide<->atom capability/principal/port alignment is advisory under the codex
contract and is NOT checked here. Use audit_atom_authoritative.py for the
authoritative atom contract and advisory diagnostics.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from clab_builder.orchestrator.composer.scenario import ScenarioPipeline


def audit_one(sp: ScenarioPipeline, cve_id: str, atoms_dir: Path) -> tuple[str, str]:
    """Return (status, reason). status in {ready, review_required}."""
    atom_path = atoms_dir / cve_id / "atom.yaml"
    try:
        atom = yaml.safe_load(atom_path.read_text()) or {}
    except Exception as exc:
        return "review_required", f"atom.yaml unreadable: {exc}"
    ref = atom.get("exploit_guide") or {}
    if not (isinstance(ref, dict) and ref.get("status") == "ready"):
        return "skip", "not ready"
    # _load_atom_guide runs validate_exploit_guide checking guide integrity
    # (materials exist, no native IP, no leaked flag, v2 structure). It does
    # NOT check capability/principal alignment (advisory). If it returns None
    # the guide failed the integrity contract.
    try:
        guide = sp._load_atom_guide(cve_id)
    except Exception as exc:
        return "review_required", f"_load_atom_guide raised: {exc}"
    if guide is None:
        return "review_required", "guide integrity check failed"
    return "ready", f"v{guide.version} {len(guide.steps)} steps"


def main() -> int:
    atoms_dir = ROOT / "data" / "atoms"
    sp = ScenarioPipeline(templates_dir=str(ROOT / "templates"), atoms_dir=str(atoms_dir))

    targets = []
    for p in sorted(atoms_dir.glob("*/atom.yaml")):
        atom = yaml.safe_load(p.read_text()) or {}
        if not atom.get("verified"):
            continue
        ref = atom.get("exploit_guide") or {}
        if isinstance(ref, dict) and ref.get("status") == "ready":
            targets.append(p.parent.name)

    print(f"=== Auditing {len(targets)} ready guides ===")
    kept = 0
    downgraded: list[tuple[str, str]] = []
    for cve in targets:
        status, reason = audit_one(sp, cve, atoms_dir)
        if status == "ready":
            kept += 1
            print(f"  {cve}: ready ({reason})")
        elif status == "review_required":
            # downgrade the ref in atom.yaml
            atom_path = atoms_dir / cve / "atom.yaml"
            atom = yaml.safe_load(atom_path.read_text()) or {}
            ref = atom.get("exploit_guide") or {}
            ref["status"] = "review_required"
            atom["exploit_guide"] = ref
            atom_path.write_text(
                yaml.safe_dump(atom, sort_keys=False, allow_unicode=True),
                encoding="utf-8",
            )
            downgraded.append((cve, reason))
            print(f"  {cve}: DOWNGRADED ({reason})")

    print(f"\n=== Audit done: {kept} ready, {len(downgraded)} downgraded ===")
    if downgraded:
        print("\nDowngraded atoms + reasons:")
        for cve, reason in downgraded:
            print(f"  {cve}: {reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())