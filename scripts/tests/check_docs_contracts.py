#!/usr/bin/env python3
"""Check maintained documentation links and Phase 5 contract wording."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
MAINTAINED_DOCS = (
    ROOT / "README.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "docs" / "README.md",
    ROOT / "docs" / "INTERFACES.md",
    ROOT / "docs" / "COLLABORATION_PLAYBOOK.md",
    ROOT / "docs" / "OPERATIONS.md",
    ROOT / "docs" / "CURRENT_STATUS.md",
    ROOT / "docs" / "ROADMAP.md",
)


def _require(path: Path, *phrases: str) -> None:
    text = path.read_text(encoding="utf-8")
    folded = text.casefold()
    missing = [phrase for phrase in phrases if phrase.casefold() not in folded]
    if missing:
        raise AssertionError(f"{path.relative_to(ROOT)} is missing: {', '.join(missing)}")


def _check_links(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", text):
        target = target.strip().split("#", 1)[0]
        if not target or target.startswith(("http://", "https://", "mailto:")):
            continue
        resolved = (path.parent / target).resolve()
        if not resolved.exists():
            raise AssertionError(
                f"broken documentation link in {path.relative_to(ROOT)}: {target}"
            )


def _check_workflow() -> None:
    workflow_path = ROOT / ".github" / "workflows" / "test.yml"
    try:
        workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise AssertionError(f"invalid workflow YAML: {exc}") from exc
    if not isinstance(workflow, dict) or not isinstance(workflow.get("jobs"), dict):
        raise AssertionError("workflow must define a jobs mapping")
    contract_job = workflow["jobs"].get("contract-gates")
    if not isinstance(contract_job, dict):
        raise AssertionError("workflow must define the contract-gates job")
    commands = "\n".join(
        str(step.get("run", ""))
        for step in contract_job.get("steps", [])
        if isinstance(step, dict)
    )
    for command in (
        "generate_atom_pool_status.py --check",
        "scripts/tests/check_status_contracts.py",
        "scripts/tests/check_docs_contracts.py",
        "pytest",
    ):
        if command not in commands:
            raise AssertionError(f"contract-gates job is missing {command}")
    if "data/guide_ablation" in commands or "data/sft" in commands:
        raise AssertionError("fast CI must not require private Range/SFT data")


def main() -> int:
    try:
        for path in MAINTAINED_DOCS:
            if not path.is_file():
                raise AssertionError(f"missing maintained document: {path}")
            _check_links(path)

        _require(ROOT / "README.md", "uv run cvelab", "uv run pytest")
        _require(
            ROOT / "CONTRIBUTING.md",
            "release integrator",
            "uv run",
            "affected contracts",
        )
        _require(
            ROOT / "docs" / "README.md",
            "OPERATIONS.md",
            "COLLABORATION_PLAYBOOK.md",
        )
        _require(
            ROOT / "docs" / "COLLABORATION_PLAYBOOK.md",
            "Atom lane",
            "Range lane",
            "Agent lane",
            "SFT lane",
            "release integrator",
            "required reviewer",
        )
        _require(
            ROOT / "docs" / "INTERFACES.md",
            "AgentExposureProfile",
            "cvelab.sft-corpus-manifest.v1",
            "lifecycle freshness",
            "material visibility",
            "Untyped gaps",
        )
        _require(
            ROOT / "docs" / "OPERATIONS.md",
            "uv sync --locked --group dev",
            "uv run cvelab",
            "generate_atom_pool_status.py --check",
            "data/vulhub",
            "CVE-Factory",
            "artifact handoff",
        )
        _require(
            ROOT / "docs" / "CURRENT_STATUS.md",
            "Status: generated snapshot",
            "284",
            "`0` `planned`",
            "`238` `building`",
            "`46` `completed`",
            "506",
        )
        _require(
            ROOT / "docs" / "ROADMAP.md",
            "generated live status",
            "284",
            "238",
            "46",
            "506",
        )
        _check_workflow()
    except (AssertionError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("documentation contracts: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
