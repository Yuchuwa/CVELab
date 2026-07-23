#!/usr/bin/env python3
"""Re-verify Agent results from saved sessions without re-running the Agent.

Reads each scenario's agent_workspace/session.json, extracts the Agent's final
structured JSON with the fixed extract_json, then re-runs _verify_flags and
_verify_objectives against ground_truth. Writes an updated verify_result.json
and a reverify_summary.json.

Used when a verifier bug (e.g. extract_json missing pretty-printed JSON, or
_verify_flags not accepting IP keys) caused false negatives. Does NOT re-run
the Agent or touch the environment.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from clab_builder.orchestrator.composer.scenario_runner import extract_json
from clab_builder.orchestrator.composer.verifier import ScenarioVerifier


def _load_session_text(session_path: Path) -> str:
    """Concatenate all assistant TextBlock text from the session."""
    s = json.loads(session_path.read_text())
    chunks = []
    for m in s:
        if not isinstance(m, dict) or m.get("type") != "assistant":
            continue
        msg = m.get("message", {})
        if isinstance(msg, str):
            try:
                msg = ast.literal_eval(msg)
            except Exception:
                continue
        if not isinstance(msg, dict):
            continue
        content = msg.get("content", [])
        if not isinstance(content, list):
            continue
        for blk in content:
            if isinstance(blk, dict) and blk.get("type") == "text":
                chunks.append(blk.get("text", ""))
    return "\n".join(chunks)


def reverify_one(scenario_dir: Path, verifier: ScenarioVerifier) -> dict:
    vr_path = scenario_dir / "verify_result.json"
    gt_path = scenario_dir / "ground_truth.json"
    session_path = scenario_dir / "agent_workspace" / "session.json"
    if not (vr_path.exists() and gt_path.exists() and session_path.exists()):
        return {"status": "missing_files", "scenario_dir": str(scenario_dir)}

    vr = json.loads(vr_path.read_text())
    gt = json.loads(gt_path.read_text())

    full_text = _load_session_text(session_path)
    extracted = extract_json(full_text)
    if not extracted:
        return {
            "status": "no_structured_output",
            "scenario_dir": str(scenario_dir),
            "old_agent_success": vr.get("agent_success"),
        }

    # Re-run flag verification with the fixed _verify_flags.
    flag_result = verifier._verify_flags(extracted, gt)
    objective_result = ScenarioVerifier._verify_objectives(
        extracted, gt.get("objectives", [])
    )
    agent_success = bool(flag_result["all_captured"])
    objective_achieved = bool(objective_result["all_satisfied"])

    changed = (
        agent_success != bool(vr.get("agent_success"))
        or objective_achieved != bool(vr.get("objective_achieved"))
    )

    # Update the persisted verify_result.json in place.
    vr["agent_result"] = {**vr.get("agent_result", {}), **extracted,
                          "structured_result": True, "verified_flags": extracted.get("verified_flags", {})}
    vr["flag_verification"] = flag_result
    vr["objective_verification"] = objective_result
    vr["agent_success"] = agent_success
    vr["objective_achieved"] = objective_achieved
    vr["reverified"] = True
    vr_path.write_text(json.dumps(vr, indent=2, ensure_ascii=False))

    return {
        "status": "ok",
        "changed": changed,
        "scenario_dir": str(scenario_dir),
        "agent_success": agent_success,
        "objective_achieved": objective_achieved,
        "flags_captured": sum(1 for v in flag_result.get("per_target", {}).values() if v.get("match")),
        "old_agent_success": not changed and vr.get("agent_success"),
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("batch_dir", help="Batch output dir (contains scenarios/)")
    p.add_argument("--dry-run", action="store_true", help="Don't write updated verify_result.json")
    args = p.parse_args()

    batch = Path(args.batch_dir)
    scenarios_root = batch / "scenarios"
    if not scenarios_root.exists():
        sys.exit(f"No scenarios/ in {batch}")

    verifier = ScenarioVerifier(atoms_dir="data/atoms", validation_mode="guided_agent")
    results = []
    for sd in sorted(scenarios_root.iterdir()):
        if not sd.is_dir():
            continue
        if args.dry_run:
            # Don't write; just report
            vr_path = sd / "verify_result.json"
            gt_path = sd / "ground_truth.json"
            sp = sd / "agent_workspace" / "session.json"
            if not (vr_path.exists() and gt_path.exists() and sp.exists()):
                continue
            vr = json.loads(vr_path.read_text())
            gt = json.loads(gt_path.read_text())
            full_text = _load_session_text(sp)
            extracted = extract_json(full_text)
            if not extracted:
                results.append({"scenario": sd.name, "status": "no_structured_output", "old": vr.get("agent_success")})
                continue
            fr = verifier._verify_flags(extracted, gt)
            orr = ScenarioVerifier._verify_objectives(extracted, gt.get("objectives", []))
            results.append({
                "scenario": sd.name,
                "old_agent_success": vr.get("agent_success"),
                "new_agent_success": bool(fr["all_captured"]),
                "new_objective_achieved": bool(orr["all_satisfied"]),
                "flags": sum(1 for v in fr.get("per_target", {}).values() if v.get("match")),
            })
        else:
            results.append(reverify_one(sd, verifier))

    # Summary
    ok = [r for r in results if r.get("status") == "ok"]
    changed = [r for r in ok if r.get("changed")]
    print(f"Scenarios: {len(results)}")
    print(f"  ok: {len(ok)}, changed: {len(changed)}")
    print(f"  new agent_success: {sum(1 for r in ok if r.get('agent_success'))}")
    print(f"  new objective_achieved: {sum(1 for r in ok if r.get('objective_achieved'))}")
    flags = [r.get("flags_captured", 0) for r in ok]
    if flags:
        from collections import Counter
        print(f"  flag dist: {dict(Counter(flags))}")
    out = batch / "reverify_summary.json"
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"Written: {out}")


if __name__ == "__main__":
    main()