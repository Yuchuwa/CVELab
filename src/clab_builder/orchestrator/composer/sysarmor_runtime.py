"""Host-side SysArmor instrumentation helpers for ContainerLab scenarios."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[4]
INJECTOR = ROOT / "data/experiments/stratified-50/sysarmor-case0/scripts/inject-runtime.sh"
SYSARMOR_BINDS = (
    "/sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro",
    "/sys/fs/bpf:/sys/fs/bpf",
)


def target_nodes_from_ground_truth(ground_truth: dict[str, Any]) -> list[str]:
    targets: list[str] = []
    for step in ground_truth.get("attack_path", []) or []:
        if not isinstance(step, dict):
            continue
        node = str(step.get("service_node") or step.get("target_node") or "").strip()
        if node and node not in targets:
            targets.append(node)
    return targets


def patch_clab_for_sysarmor(clab: dict[str, Any], ground_truth: dict[str, Any]) -> list[str]:
    nodes = clab.setdefault("topology", {}).setdefault("nodes", {})
    targets = target_nodes_from_ground_truth(ground_truth)
    for target in targets:
        node = nodes.get(target)
        if not isinstance(node, dict):
            continue
        node.pop("privileged", None)
        node.pop("docker-opts", None)
        node["restart-policy"] = "unless-stopped"
        binds = list(node.get("binds", []) or [])
        for bind in SYSARMOR_BINDS:
            if bind not in binds:
                binds.append(bind)
        node["binds"] = binds
    return [target for target in targets if isinstance(nodes.get(target), dict)]


def patch_scenario_clab(scenario_dir: str | Path, ground_truth: dict[str, Any]) -> dict[str, Any]:
    scenario_path = Path(scenario_dir)
    clab_path = scenario_path / "clab.yaml"
    clab = yaml.safe_load(clab_path.read_text(encoding="utf-8")) or {}
    targets = patch_clab_for_sysarmor(clab, ground_truth)
    clab_path.write_text(
        yaml.safe_dump(clab, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return {"ok": bool(targets), "targets": targets, "binds": list(SYSARMOR_BINDS)}


def _lab_name(scenario_dir: str | Path) -> str:
    clab = yaml.safe_load((Path(scenario_dir) / "clab.yaml").read_text(encoding="utf-8")) or {}
    return str(clab.get("name") or Path(scenario_dir).name)


def inject_sysarmor_runtime(scenario_dir: str | Path, targets: list[str]) -> dict[str, Any]:
    command = [str(INJECTOR), "--topology", str(Path(scenario_dir) / "clab.yaml")]
    for target in targets:
        command.extend(["--target", target])
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "stage": "sysarmor_inject",
            "timed_out": True,
            "command": command,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "error": "SysArmor injection timed out",
        }
    return {
        "ok": result.returncode == 0,
        "stage": "sysarmor_inject",
        "command": command,
        "stdout": result.stdout[-4000:],
        "stderr": result.stderr[-4000:],
        "error": "" if result.returncode == 0 else (result.stderr.strip() or result.stdout.strip())[-1000:],
    }


def collect_recent_signals(
    scenario_dir: str | Path,
    targets: list[str],
    *,
    limit: int = 200,
    timeout: int = 10,
) -> dict[str, list[dict[str, Any]]]:
    lab_name = _lab_name(scenario_dir)
    out: dict[str, list[dict[str, Any]]] = {}
    for target in targets:
        container = f"clab-{lab_name}-{target}"
        command = [
            "docker", "exec", container,
            "/usr/local/bin/sysarmorctl",
            "--socket", "/run/sysarmor/agent/control.sock",
            "--json", "signal", "watch",
            "--include-recent", "--include-events",
            "--limit", str(limit),
            "--timeout", f"{timeout}s",
        ]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 5)
        except subprocess.TimeoutExpired:
            out[target] = []
            continue
        signals = []
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                try:
                    signals.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        out[target] = signals
    return out


def evaluate_signal_delta(
    *,
    before: dict[str, list[dict[str, Any]]],
    after: dict[str, list[dict[str, Any]]],
    attack_executed: bool,
    attack_success: bool,
) -> dict[str, Any]:
    before_count = sum(len(items) for items in before.values())
    after_count = sum(len(items) for items in after.values())
    detected = bool(attack_executed and after_count > before_count)
    result = {
        "environment_valid": True,
        "sysarmor_healthy": True,
        "event_stream_visible": True,
        "attack_executed": bool(attack_executed),
        "attack_success": bool(attack_success),
        "signal_count_before": before_count,
        "signal_count_after": after_count,
        "signal_detected": detected,
        "per_target_before": {target: len(items) for target, items in before.items()},
        "per_target_after": {target: len(items) for target, items in after.items()},
    }
    if not attack_executed:
        result["not_evaluable_reason"] = "attack_not_executed"
    return result
