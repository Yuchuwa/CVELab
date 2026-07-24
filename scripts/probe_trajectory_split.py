"""Probe: can we split multi-hop attack trajectories at hop boundaries?

For each successful clean claude-format trajectory:
  session.json  = full conversation (array of {type,message})
  ground_truth.json -> attack_path = [{cve_id, target, flag, ...}, ...]

We locate each hop's flag-capture event in the session by searching
tool_result content for the ground-truth flag value. Then measure:
  - where each hop boundary falls (event index)
  - token estimate per segment (cumulative: seg1=hop0, seg2=hop0+1, seg3=all)
  - how often the flag is actually findable in the session
"""
import json, glob, os, re, sys

ROOT = "data/guide_ablation"
CLEAN_CTX = {"l0", "l1", "l2", "no_hint"}
CHARS_PER_TOKEN = 3.5


def session_chars_and_flags(session, gt_flags):
    """Walk session; record cumulative chars at each event, and find flag positions."""
    cum = 0
    cum_at = []  # cumulative chars after each event
    flag_hits = {f: None for f in gt_flags}  # flag -> first event idx where seen
    for i, ev in enumerate(session):
        m = ev.get("message", {})
        c = m.get("content")
        text = ""
        if isinstance(c, str):
            text = c
        elif isinstance(c, list):
            for blk in c:
                if not isinstance(blk, dict):
                    continue
                text += (blk.get("thinking") or "")
                tc = blk.get("content")
                if isinstance(tc, str):
                    text += tc
                elif isinstance(tc, list):
                    for b2 in tc:
                        text += json.dumps(b2, ensure_ascii=False) if isinstance(b2, dict) else str(b2)
        cum += len(text)
        cum_at.append(cum)
        for f in gt_flags:
            if flag_hits[f] is None and f and f in text:
                flag_hits[f] = i
    return cum_at, flag_hits


def main():
    cands = []
    for vr in sorted(glob.glob(f"{ROOT}/*/scenarios/*/verify_result.json")):
        try:
            d = json.load(open(vr))
        except Exception:
            continue
        ctx = d.get("agent_context", "")
        if ctx not in CLEAN_CTX:
            continue
        fv = d.get("flag_verification") or {}
        if not (bool(d.get("agent_success")) and bool(d.get("objective_achieved")) and bool(fv.get("all_captured"))):
            continue
        scdir = os.path.dirname(vr)
        sj = os.path.join(scdir, "agent_workspace", "session.json")
        gt = os.path.join(scdir, "ground_truth.json")
        if not (os.path.exists(sj) and os.path.exists(gt)):
            continue
        with open(sj) as f:
            if not f.read(5).lstrip().startswith("["):
                continue
        cands.append((scdir, ctx))

    print(f"candidates: {len(cands)}\n")

    n_hops_dist = {}
    seg_tok = {1: [], 2: [], 3: []}  # cumulative segment token estimates
    full_tok = []
    flag_found_rate = {1: [0, 0], 2: [0, 0], 3: [0, 0]}  # hop -> [found, total]
    boundary_examples = []

    for scdir, ctx in cands:
        gt = json.load(open(os.path.join(scdir, "ground_truth.json")))
        sess = json.load(open(os.path.join(scdir, "agent_workspace", "session.json")))
        ap = gt.get("attack_path") or []
        # flags in attack_path order
        flags = []
        for node in ap:
            fl = node.get("flag")
            if fl:
                flags.append(fl)
        nh = len(flags)
        n_hops_dist[nh] = n_hops_dist.get(nh, 0) + 1

        cum_at, flag_hits = session_chars_and_flags(sess, flags)
        total_chars = cum_at[-1] if cum_at else 0
        full_tok.append(total_chars // CHARS_PER_TOKEN)

        # find event idx where each flag first appears
        ev_idx = [flag_hits[f] for f in flags]
        for i, fi in enumerate(ev_idx):
            hop = i + 1
            flag_found_rate[hop][1] += 1
            if fi is not None:
                flag_found_rate[hop][0] += 1

        # segment token estimates (cumulative chars at each boundary / token)
        if nh >= 1 and ev_idx[0] is not None:
            seg1_chars = cum_at[ev_idx[0]]
            seg_tok[1].append(seg1_chars // CHARS_PER_TOKEN)
        if nh >= 2 and ev_idx[0] is not None and ev_idx[1] is not None:
            seg2_chars = cum_at[ev_idx[1]]
            seg_tok[2].append(seg2_chars // CHARS_PER_TOKEN)
        if nh >= 3 and ev_idx[1] is not None and ev_idx[2] is not None:
            seg3_chars = cum_at[ev_idx[2]]
            seg_tok[3].append(seg3_chars // CHARS_PER_TOKEN)

        if len(boundary_examples) < 3 and nh == 3 and all(e is not None for e in ev_idx):
            boundary_examples.append({
                "dir": os.path.basename(scdir),
                "ctx": ctx,
                "n_events": len(sess),
                "flags": flags,
                "flag_at_event": ev_idx,
                "seg1_tok": cum_at[ev_idx[0]] // CHARS_PER_TOKEN,
                "seg2_tok": cum_at[ev_idx[1]] // CHARS_PER_TOKEN,
                "seg3_tok": cum_at[ev_idx[2]] // CHARS_PER_TOKEN,
                "full_tok": total_chars // CHARS_PER_TOKEN,
            })

    print("=== hop count distribution ===")
    for nh in sorted(n_hops_dist):
        print(f"  {nh} hops: {n_hops_dist[nh]} trajectories")

    print("\n=== flag findable in session (hop -> found/total) ===")
    for hop in sorted(flag_found_rate):
        f, t = flag_found_rate[hop]
        print(f"  hop{hop}: {f}/{t}  ({0 if t==0 else 100*f//t}%)")

    def stats(lst):
        if not lst:
            return "n=0"
        lst = sorted(lst)
        n = len(lst)
        return f"n={n} min={lst[0]} med={lst[n//2]} mean={sum(lst)//n} p90={lst[int(n*0.9)]} max={lst[-1]}"

    print("\n=== cumulative segment token estimates ===")
    print(f"  seg1 (to hop1 flag): {stats(seg_tok[1])}")
    print(f"  seg2 (to hop2 flag): {stats(seg_tok[2])}")
    print(f"  seg3 (to hop3 flag): {stats(seg_tok[3])}")
    print(f"  full trajectory:     {stats(full_tok)}")

    print("\n=== boundary examples (3-hop, all flags found) ===")
    for ex in boundary_examples:
        print(f"  {ex['dir']} [{ex['ctx']}]  events={ex['n_events']}")
        print(f"    flags at events: {ex['flag_at_event']}  seg_tok=({ex['seg1_tok']},{ex['seg2_tok']},{ex['seg3_tok']}) full={ex['full_tok']}")


if __name__ == "__main__":
    main()