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


def export_signals(batch_dir: str | Path, output_dir: str | Path | None = None) -> dict[str, Any]:
    batch_path = Path(batch_dir)
    out_path = Path(output_dir) if output_dir is not None else batch_path / "signals"
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
        before = _signals_by_target(sysarmor.get("signals_before"))
        after = _signals_by_target(sysarmor.get("signals_after"))
        targets = sorted(set(before) | set(after))
        case_dir = out_path / case_id
        for target in targets:
            _write_jsonl(case_dir / f"{target}-before.jsonl", before.get(target, []))
            _write_jsonl(case_dir / f"{target}-after.jsonl", after.get(target, []))

        detection = sysarmor.get("detection") if isinstance(sysarmor.get("detection"), dict) else {}
        flag_verification = (
            result.get("flag_verification")
            if isinstance(result.get("flag_verification"), dict)
            else {}
        )
        cases.append({
            "case_id": case_id,
            "agent_success": bool(result.get("agent_success", False)),
            "flags_all_captured": bool(flag_verification.get("all_captured", False)),
            "flags_per_target": flag_verification.get("per_target", {}),
            "signal_detected": bool(detection.get("signal_detected", False)),
            "signals_before_total": sum(len(items) for items in before.values()),
            "signals_after_total": sum(len(items) for items in after.values()),
            "targets": targets,
            "case_dir": str(case_dir),
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
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    summary = export_signals(args.batch_dir, args.output or None)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
