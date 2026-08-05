"""Host-side SysArmor instrumentation helpers for ContainerLab scenarios."""

from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime, timezone
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
    timeout = _positive_int_env("SYSARMOR_INJECT_TIMEOUT", 900)
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "stage": "sysarmor_inject",
            "timed_out": True,
            "command": command,
            "stdout": _to_text(exc.stdout),
            "stderr": _to_text(exc.stderr),
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


def _positive_int_env(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, ""))
    except ValueError:
        return default
    return value if value > 0 else default


def _to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


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


def _watch_root(scenario_dir: str | Path) -> Path:
    return Path(scenario_dir) / "_sysarmor_watch"


def start_signal_watchers(
    scenario_dir: str | Path,
    targets: list[str],
    *,
    output_dir: str | Path | None = None,
) -> dict[str, dict[str, Any]]:
    lab_name = _lab_name(scenario_dir)
    watch_dir = Path(output_dir) if output_dir is not None else _watch_root(scenario_dir)
    watch_dir.mkdir(parents=True, exist_ok=True)
    out: dict[str, dict[str, Any]] = {}
    for target in targets:
        container = f"clab-{lab_name}-{target}"
        stdout_path = watch_dir / f"{target}.jsonl"
        stderr_path = watch_dir / f"{target}.stderr.log"
        stdout_handle = stdout_path.open("w", encoding="utf-8")
        stderr_handle = stderr_path.open("w", encoding="utf-8")
        command = [
            "docker", "exec", container,
            "/usr/local/bin/sysarmorctl",
            "--socket", "/run/sysarmor/agent/control.sock",
            "--json", "signal", "watch",
            "--include-events",
        ]
        try:
            process = subprocess.Popen(command, stdout=stdout_handle, stderr=stderr_handle, text=True)
        except Exception:
            stdout_handle.close()
            stderr_handle.close()
            raise
        out[target] = {
            "target": target,
            "container": container,
            "command": command,
            "process": process,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "stdout_handle": stdout_handle,
            "stderr_handle": stderr_handle,
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
    return out


def wait_signal_watchers_ready(
    watchers: dict[str, dict[str, Any]],
    *,
    timeout: float = 10.0,
    poll_interval: float = 0.1,
) -> dict[str, Any]:
    deadline = time.monotonic() + max(timeout, 0.0)
    ready_targets = set()
    failed_targets: dict[str, dict[str, Any]] = {}
    while time.monotonic() <= deadline:
        for target, watcher in watchers.items():
            if target in ready_targets or target in failed_targets:
                continue
            process = watcher.get("process")
            returncode = process.poll() if process is not None else None
            if returncode is None:
                ready_targets.add(target)
                continue
            failed_targets[target] = {
                "returncode": returncode,
                "stderr_path": watcher.get("stderr_path", ""),
            }
        if len(ready_targets) + len(failed_targets) == len(watchers):
            break
        time.sleep(max(poll_interval, 0.01))
    pending_targets = sorted(set(watchers) - ready_targets - set(failed_targets))
    return {
        "ok": len(ready_targets) == len(watchers),
        "ready_targets": sorted(ready_targets),
        "failed_targets": failed_targets,
        "pending_targets": pending_targets,
    }


def stop_signal_watchers(
    watchers: dict[str, dict[str, Any]],
    *,
    timeout: float = 5.0,
) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for target, watcher in watchers.items():
        process = watcher.get("process")
        stdout_handle = watcher.get("stdout_handle")
        stderr_handle = watcher.get("stderr_handle")
        returncode = None
        timed_out = False
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                returncode = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                returncode = process.wait(timeout=1)
        elif process is not None:
            returncode = process.poll()
        if stdout_handle is not None:
            stdout_handle.close()
        if stderr_handle is not None:
            stderr_handle.close()
        results[target] = {
            "returncode": returncode,
            "timed_out": timed_out,
            "stdout_path": watcher.get("stdout_path", ""),
            "stderr_path": watcher.get("stderr_path", ""),
        }
    return results


def load_signal_watcher_frames(
    watchers: dict[str, dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for target, watcher in watchers.items():
        path = Path(str(watcher.get("stdout_path", "")))
        frames: list[dict[str, Any]] = []
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict):
                    frames.append(item)
        out[target] = frames
    return out


def _parse_iso8601(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _frame_observed_at(frame: dict[str, Any]) -> datetime | None:
    if not isinstance(frame, dict):
        return None
    direct = _parse_iso8601(str(frame.get("observedAt") or frame.get("observed_at") or ""))
    if direct is not None:
        return direct
    signal_frame = frame.get("signalFrame")
    if isinstance(signal_frame, dict):
        return _parse_iso8601(str(signal_frame.get("observedAt") or signal_frame.get("observed_at") or ""))
    return None


def classify_signal_frames_by_window(
    frames_by_target: dict[str, list[dict[str, Any]]],
    *,
    attack_started_at: str,
    attack_finished_at: str,
    grace_finished_at: str,
) -> dict[str, dict[str, list[dict[str, Any]]]]:
    start = _parse_iso8601(attack_started_at)
    finish = _parse_iso8601(attack_finished_at)
    grace = _parse_iso8601(grace_finished_at)
    buckets = {
        "pre_attack": {},
        "attack_window": {},
        "grace_window": {},
        "post_grace": {},
        "unclassified": {},
    }
    for target, frames in frames_by_target.items():
        for bucket in buckets.values():
            bucket[target] = []
        for frame in frames:
            observed = _frame_observed_at(frame)
            if observed is None or start is None or finish is None or grace is None:
                buckets["unclassified"][target].append(frame)
            elif observed < start:
                buckets["pre_attack"][target].append(frame)
            elif observed < finish:
                buckets["attack_window"][target].append(frame)
            elif observed < grace:
                buckets["grace_window"][target].append(frame)
            else:
                buckets["post_grace"][target].append(frame)
    return buckets


def _count_signals(signals: dict[str, list[dict[str, Any]]]) -> int:
    return sum(len(items) for items in signals.values())


def evaluate_signal_stream(
    *,
    pre_attack: dict[str, list[dict[str, Any]]],
    attack_window: dict[str, list[dict[str, Any]]],
    grace_window: dict[str, list[dict[str, Any]]],
    attack_executed: bool,
    attack_success: bool,
) -> dict[str, Any]:
    before_count = _count_signals(pre_attack)
    attack_count = _count_signals(attack_window)
    grace_count = _count_signals(grace_window)
    detected = bool(attack_executed and attack_count > 0)
    result = {
        "environment_valid": True,
        "sysarmor_healthy": True,
        "event_stream_visible": True,
        "attack_executed": bool(attack_executed),
        "attack_success": bool(attack_success),
        "signal_count_before": before_count,
        "signal_count_after": attack_count,
        "signal_count_grace": grace_count,
        "signal_detected": detected,
        "per_target_before": {target: len(items) for target, items in pre_attack.items()},
        "per_target_after": {target: len(items) for target, items in attack_window.items()},
        "per_target_grace": {target: len(items) for target, items in grace_window.items()},
    }
    if not attack_executed:
        result["not_evaluable_reason"] = "attack_not_executed"
    return result


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
