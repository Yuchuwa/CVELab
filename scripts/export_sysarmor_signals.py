#!/usr/bin/env python3
"""Export SysArmor signal frames from a Stratified-50 batch summary."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _write_jsonl(path: Path, items: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for item in items:
            handle.write(json.dumps(item, ensure_ascii=False, sort_keys=True))
            handle.write("\n")


def _signals_by_target(payload: Any) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(payload, dict):
        return {}
    out: dict[str, list[dict[str, Any]]] = {}
    for target, items in payload.items():
        if isinstance(items, list):
            out[str(target)] = [item for item in items if isinstance(item, dict)]
    return out


def _load_expected_signals(path: str | Path | None) -> dict[str, Any]:
    if not path:
        return {}
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _signal_rule_id(frame: dict[str, Any]) -> str:
    signal_frame = frame.get("signalFrame")
    if not isinstance(signal_frame, dict):
        return ""
    signal = signal_frame.get("signal")
    if not isinstance(signal, dict):
        return ""
    return str(signal.get("ruleId") or "")


def _signal_key(target: str, frame: dict[str, Any]) -> str:
    signal_frame = frame.get("signalFrame")
    if not isinstance(signal_frame, dict):
        return json.dumps(frame, ensure_ascii=False, sort_keys=True)
    signal = signal_frame.get("signal")
    signal_id = ""
    if isinstance(signal, dict):
        signal_id = str(signal.get("id") or "")
    agent_id = str(signal_frame.get("agentId") or "")
    sequence = str(signal_frame.get("sequence") or "")
    if signal_id or sequence:
        return f"{target}\0{agent_id}\0{sequence}\0{signal_id}"
    return f"{target}\0" + json.dumps(frame, ensure_ascii=False, sort_keys=True)


def _new_signals_by_target(
    before: dict[str, list[dict[str, Any]]],
    after: dict[str, list[dict[str, Any]]],
) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for target in sorted(set(before) | set(after)):
        seen = {_signal_key(target, frame) for frame in before.get(target, [])}
        new_frames: list[dict[str, Any]] = []
        for frame in after.get(target, []):
            key = _signal_key(target, frame)
            if key in seen:
                continue
            seen.add(key)
            new_frames.append(frame)
        out[target] = new_frames
    return out


def _rule_ids_by_target(signals: dict[str, list[dict[str, Any]]]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for target, frames in signals.items():
        ids = sorted({
            rule_id
            for rule_id in (_signal_rule_id(frame) for frame in frames)
            if rule_id
        })
        out[target] = ids
    return out


def evaluate_expected_signals(
    case_id: str,
    observed_signals: dict[str, list[dict[str, Any]]],
    expected_signals: dict[str, Any],
) -> dict[str, Any]:
    cases = expected_signals.get("cases") if isinstance(expected_signals, dict) else {}
    spec = cases.get(case_id) if isinstance(cases, dict) else None
    if not isinstance(spec, dict):
        return {
            "evaluated": False,
            "detected": False,
            "expected_rule_ids": [],
            "matched_rule_ids": [],
            "missing_rule_ids": [],
            "observed_rule_ids": sorted({
                rule_id
                for ids in _rule_ids_by_target(observed_signals).values()
                for rule_id in ids
            }),
            "rule_ids_by_target": _rule_ids_by_target(observed_signals),
        }

    expected_rule_ids = [
        str(rule_id)
        for rule_id in spec.get("expected_rule_ids", [])
        if str(rule_id)
    ]
    observed = sorted({
        rule_id
        for ids in _rule_ids_by_target(observed_signals).values()
        for rule_id in ids
    })
    matched = sorted(set(expected_rule_ids) & set(observed))
    missing = sorted(set(expected_rule_ids) - set(observed))
    return {
        "evaluated": True,
        "detected": bool(expected_rule_ids) and not missing,
        "expected_rule_ids": expected_rule_ids,
        "matched_rule_ids": matched,
        "missing_rule_ids": missing,
        "observed_rule_ids": observed,
        "rule_ids_by_target": _rule_ids_by_target(observed_signals),
    }


def _load_full_result(result: dict[str, Any]) -> dict[str, Any]:
    scenario_dir = result.get("scenario_dir")
    if not scenario_dir:
        return result
    verify_path = Path(str(scenario_dir)) / "verify_result.json"
    try:
        payload = json.loads(verify_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return result
    if isinstance(payload, dict):
        merged = dict(result)
        merged.update(payload)
        return merged
    return result


def export_signals(
    batch_dir: str | Path,
    output_dir: str | Path | None = None,
    expected_signals_path: str | Path | None = None,
) -> dict[str, Any]:
    batch_path = Path(batch_dir)
    out_path = Path(output_dir) if output_dir is not None else batch_path / "signals"
    expected_signals = _load_expected_signals(expected_signals_path)
    summary_path = batch_path / "summary.json"
    payload = json.loads(summary_path.read_text(encoding="utf-8"))
    results = payload.get("results", []) if isinstance(payload, dict) else []

    cases: list[dict[str, Any]] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        result = _load_full_result(result)
        case_id = str(result.get("case_id") or "unknown-case")
        sysarmor = result.get("sysarmor") if isinstance(result.get("sysarmor"), dict) else {}
        pre_attack = _signals_by_target(sysarmor.get("signals_pre_attack"))
        attack_window = _signals_by_target(sysarmor.get("signals_attack_window"))
        grace_window = _signals_by_target(sysarmor.get("signals_grace_window"))
        new = _new_signals_by_target(pre_attack, attack_window)
        targets = sorted(set(pre_attack) | set(attack_window) | set(grace_window))
        case_dir = out_path / case_id
        for target in targets:
            _write_jsonl(case_dir / f"{target}-pre-attack.jsonl", pre_attack.get(target, []))
            _write_jsonl(case_dir / f"{target}-attack-window.jsonl", attack_window.get(target, []))
            _write_jsonl(case_dir / f"{target}-grace-window.jsonl", grace_window.get(target, []))
            _write_jsonl(case_dir / f"{target}-new-attack.jsonl", new.get(target, []))

        detection = sysarmor.get("detection") if isinstance(sysarmor.get("detection"), dict) else {}
        pre_attack_count = sum(len(items) for items in pre_attack.values())
        attack_window_count = sum(len(items) for items in attack_window.values())
        grace_window_count = sum(len(items) for items in grace_window.values())
        new_attack_signal_count = sum(len(items) for items in new.values())
        flag_verification = (
            result.get("flag_verification")
            if isinstance(result.get("flag_verification"), dict)
            else {}
        )
        expected_signal_detection = evaluate_expected_signals(case_id, new, expected_signals)
        cases.append({
            "case_id": case_id,
            "agent_success": bool(result.get("agent_success", False)),
            "flags_all_captured": bool(flag_verification.get("all_captured", False)),
            "flags_per_target": flag_verification.get("per_target", {}),
            "signal_detected": bool(detection.get("signal_detected", False)),
            "pre_attack_count": pre_attack_count,
            "attack_window_count": attack_window_count,
            "grace_window_count": grace_window_count,
            "new_attack_signal_count": new_attack_signal_count,
            "expected_signal_hit": bool(expected_signal_detection.get("detected", False)),
            "new_rule_ids": sorted({
                rule_id
                for ids in _rule_ids_by_target(new).values()
                for rule_id in ids
            }),
            "new_rule_ids_by_target": _rule_ids_by_target(new),
            "targets": targets,
            "case_dir": str(case_dir),
            "expected_signal_detection": expected_signal_detection,
        })

    summary = {
        "batch_dir": str(batch_path),
        "output_dir": str(out_path),
        "case_count": len(cases),
        "cases": cases,
    }
    out_path.mkdir(parents=True, exist_ok=True)
    (out_path / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("batch_dir", help="Batch run directory containing summary.json")
    parser.add_argument(
        "--output",
        default="",
        help="Output directory; defaults to BATCH_DIR/signals",
    )
    parser.add_argument(
        "--expected-signals",
        default="",
        help="Optional JSON spec mapping case IDs to expected generic SysArmor rule IDs",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    summary = export_signals(
        args.batch_dir,
        args.output or None,
        args.expected_signals or None,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
