#!/usr/bin/env python3
"""Difficulty-stratified selector for enterprise_3tier Range experiments.

Reads historical L2 batch summaries to compute per-CVE per-slot pass rates
(conditional on the upstream slot passing), classifies each CVE into
easy/mid/hard tiers per slot, then samples a balanced 9-cell matrix
(entry tier x mid tier) from the full candidate matrix so the experiment
covers the full difficulty gradient with a bounded number of cases.

This keeps the experiment small (~50 cases) while preserving the ability
to measure Guide gain across difficulty tiers when max_turns is raised:
each cell has a distinct expected flag-count distribution, so "0 flag"
vs "1-2 flags short of full" stay distinguishable.
"""
from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _parse_batch(batch_dir: Path) -> list[dict]:
    """Load agent-evaluated cases with per-target flag capture from a batch."""
    summary = batch_dir / "summary.json"
    if not summary.exists():
        return []
    data = json.loads(summary.read_text())
    out = []
    for x in data.get("results", []):
        if not x.get("agent_evaluated"):
            continue
        vr_path = Path(x["scenario_dir"]) / "verify_result.json"
        if not vr_path.exists():
            continue
        vr = json.loads(vr_path.read_text())
        per = vr.get("flag_verification", {}).get("per_target", {})
        t1 = bool(per.get("target-1", {}).get("match"))
        t2 = bool(per.get("target-2", {}).get("match"))
        t3 = bool(per.get("target-3", {}).get("match"))
        out.append({"cves": x["cves"], "t1": t1, "t2": t2, "t3": t3})
    return out


def _pass_rates(cases: list[dict]) -> tuple[dict, dict, dict]:
    """Return (entry_rate, mid_rate, data_rate): CVE -> [passed, total].

    mid_rate is conditional on entry passing; data_rate conditional on
    entry+mid passing. This matches the slot chain semantics.
    """
    e = defaultdict(lambda: [0, 0])
    m = defaultdict(lambda: [0, 0])
    d = defaultdict(lambda: [0, 0])
    for c in cases:
        e[c["cves"][0]][1] += 1
        e[c["cves"][0]][0] += int(c["t1"])
        if c["t1"]:
            m[c["cves"][1]][1] += 1
            m[c["cves"][1]][0] += int(c["t2"])
            if c["t2"]:
                d[c["cves"][2]][1] += 1
                d[c["cves"][2]][0] += int(c["t3"])
    return e, m, d


def _tier(passed: int, total: int) -> str:
    if total < 2:
        return "unknown"
    r = passed / total
    if r >= 0.70:
        return "easy"
    if r >= 0.40:
        return "mid"
    return "hard"


def _cell_observations(cases, e_rate, m_rate) -> dict:
    """Bucket historical cases by (entry_tier, mid_tier) for rate lookup."""
    buckets = defaultdict(lambda: {"n": 0, "flag3": 0, "sum_flag": 0})
    for c in cases:
        et = _tier(*e_rate[c["cves"][0]])
        mt = _tier(*m_rate[c["cves"][1]])
        if et == "unknown" or mt == "unknown":
            continue
        k = (et, mt)
        buckets[k]["n"] += 1
        buckets[k]["flag3"] += int(c["t1"] and c["t2"] and c["t3"])
        buckets[k]["sum_flag"] += int(c["t1"]) + int(c["t2"]) + int(c["t3"])
    return buckets


DEFAULT_QUOTA = {
    ("easy", "easy"): 8, ("easy", "mid"): 8, ("easy", "hard"): 5,
    ("mid", "easy"): 8, ("mid", "mid"): 6, ("mid", "hard"): 4,
    ("hard", "easy"): 5, ("hard", "mid"): 4, ("hard", "hard"): 2,
}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--matrix", default="data/range_matrices/enterprise_3tier_hetero.json")
    p.add_argument("--history", nargs="+", default=[
        "data/guide_ablation/l2_decoy_full_v2",
        "data/guide_ablation/l2_decoy_merged",
    ], help="Batch dirs used to compute per-CVE per-slot pass rates.")
    p.add_argument("--output", default="data/guide_ablation/manifest_stratified_50.json")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--quota", default=",".join(f"{e}:{m}:{n}" for (e, m), n in DEFAULT_QUOTA.items()),
                   help="Quota as entry:mid:count,... (default 50-case balanced).")
    p.add_argument("--exclude-ids", default="", help="Comma-separated case ids to exclude.")
    args = p.parse_args()

    matrix = json.loads((ROOT / args.matrix).read_text())
    cases = matrix["cases"]

    # Build historical pass rates.
    hist = []
    for b in args.history:
        hist.extend(_parse_batch(ROOT / b))
    if not hist:
        raise SystemExit("No historical agent-evaluated cases found in --history batches.")
    e_rate, m_rate, d_rate = _pass_rates(hist)
    cell_obs = _cell_observations(hist, e_rate, m_rate)

    # Parse quota.
    quota = {}
    for tok in args.quota.split(","):
        if not tok.strip():
            continue
        e, m, n = tok.split(":")
        quota[(e, m)] = int(n)
    total_quota = sum(quota.values())

    # Classify matrix cases by (entry_tier, mid_tier).
    by_cell = defaultdict(list)
    for c in cases:
        et = _tier(*e_rate.get(c["cves"][0], [0, 0]))
        mt = _tier(*m_rate.get(c["cves"][1], [0, 0]))
        if et == "unknown" or mt == "unknown":
            continue
        by_cell[(et, mt)].append(c)

    exclude = {x.strip() for x in args.exclude_ids.split(",") if x.strip()}
    rng = random.Random(args.seed)
    selected = []
    cell_summary = []
    for (et, mt), n_target in sorted(quota.items()):
        pool = [c for c in by_cell.get((et, mt), []) if c["id"] not in exclude]
        # Sort for determinism, then random sample.
        pool_sorted = sorted(pool, key=lambda c: c["id"])
        picked = pool_sorted[:n_target] if len(pool_sorted) <= n_target else rng.sample(pool_sorted, n_target)
        selected.extend(picked)
        obs = cell_obs.get((et, mt), {"n": 0, "flag3": 0, "sum_flag": 0})
        hist_3flag = obs["flag3"] / obs["n"] if obs["n"] else 0.0
        hist_avg = obs["sum_flag"] / obs["n"] if obs["n"] else 0.0
        cell_summary.append({
            "entry_tier": et, "mid_tier": mt,
            "pool_size": len(pool), "selected": len(picked),
            "hist_n": obs["n"], "hist_3flag_rate": round(hist_3flag, 3),
            "hist_avg_flag": round(hist_avg, 3),
        })

    # Compute expected 3flag / avg flag under the selected quota.
    exp_3flag = sum(q["selected"] * q["hist_3flag_rate"] for q in cell_summary)
    exp_flag = sum(q["selected"] * q["hist_avg_flag"] for q in cell_summary)

    manifest = {
        "schema_version": 1,
        "experiment": "difficulty-stratified-range-experiment",
        "generated_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "source_matrix": args.matrix,
        "history_batches": args.history,
        "selection": {
            "strategy": "entry_tier_x_mid_tier_quota",
            "tier_thresholds": {"easy": ">=0.70", "mid": "0.40-0.69", "hard": "<0.40"},
            "total_quota": total_quota,
            "seed": args.seed,
        },
        "expected_under_historical_maxturns": {
            "exp_3flag_count": round(exp_3flag, 2),
            "exp_3flag_rate": round(exp_3flag / total_quota, 3) if total_quota else 0,
            "exp_avg_flag": round(exp_flag / total_quota, 3) if total_quota else 0,
        },
        "cell_summary": cell_summary,
        "pass_rates": {
            "entry": {c: {"passed": v[0], "total": v[1], "rate": round(v[0]/v[1], 3) if v[1] else 0, "tier": _tier(*v)}
                      for c, v in sorted(e_rate.items())},
            "mid_conditional_on_entry": {c: {"passed": v[0], "total": v[1], "rate": round(v[0]/v[1], 3) if v[1] else 0, "tier": _tier(*v)}
                                         for c, v in sorted(m_rate.items())},
            "data_conditional_on_entry_mid": {c: {"passed": v[0], "total": v[1], "rate": round(v[0]/v[1], 3) if v[1] else 0, "tier": _tier(*v)}
                                              for c, v in sorted(d_rate.items())},
        },
        "cases": selected,
    }
    out = ROOT / args.output
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
    print(f"Stratified manifest: {out}")
    print(f"  total selected: {len(selected)} / quota {total_quota}")
    print(f"  pool sizes by cell:")
    for q in cell_summary:
        print(f"    {q['entry_tier']:>5}x{q['mid_tier']:<5}: pool={q['pool_size']:>3} selected={q['selected']:>2} "
              f"hist 3flag={q['hist_3flag_rate']:.2f} (n={q['hist_n']}) avg_flag={q['hist_avg_flag']:.2f}")
    print(f"  expected under historical max_turns: "
          f"3flag={exp_3flag:.1f} ({100*exp_3flag/total_quota:.0f}%) avg_flag={exp_flag/total_quota:.2f}")


if __name__ == "__main__":
    main()