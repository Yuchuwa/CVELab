#!/usr/bin/env python3
"""Create a SysArmor-instrumented copy of the solved Stratified-50 case0 scenario."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

import yaml


DEFAULT_SOURCE = (
    "data/experiments/stratified-50/runs/"
    "trial-stratified50-guided-claude-deepseek-smoke1-materials-20260727/"
    "batch/scenarios/e3-979f5649-e3dd846e816093e9"
)
DEFAULT_OUTPUT = "data/experiments/stratified-50/sysarmor-case0/scenario"

TARGETS = ("target-1", "target-2", "target-3")

SYSARMOR_BINDS = [
    "/sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro",
    "/sys/fs/bpf:/sys/fs/bpf",
]


def patch_clab(clab: dict) -> dict:
    nodes = clab.setdefault("topology", {}).setdefault("nodes", {})
    for target in TARGETS:
        node = nodes[target]
        node.pop("privileged", None)
        node.pop("docker-opts", None)
        node["restart-policy"] = "unless-stopped"
        binds = list(node.get("binds", []))
        for bind in SYSARMOR_BINDS:
            if bind not in binds:
                binds.append(bind)
        node["binds"] = binds
    return clab


def copy_scenario(source: Path, output: Path) -> None:
    if not source.is_dir():
        raise SystemExit(f"source scenario does not exist: {source}")
    if output.exists():
        shutil.rmtree(output)
    ignore = shutil.ignore_patterns("agent_workspace", "output.json", "*.log")
    shutil.copytree(source, output, ignore=ignore)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default=DEFAULT_SOURCE)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    source = Path(args.source).resolve()
    output = Path(args.output).resolve()
    copy_scenario(source, output)

    clab_path = output / "clab.yaml"
    clab = yaml.safe_load(clab_path.read_text()) or {}
    clab = patch_clab(clab)
    clab_path.write_text(yaml.safe_dump(clab, sort_keys=False, allow_unicode=True))
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
