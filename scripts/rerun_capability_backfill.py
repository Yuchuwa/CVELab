#!/usr/bin/env python3
"""Rerun agent verification for atoms with empty capability_grants.

Why: 87 verified atoms have capability_grants=[] because they were built
before the v4 capability contract existed (or via --skip-agent structure
backfill). Range orchestration needs capability_grants to (a) match slots
that declare required_capabilities, (b) close network_vantage for chain
middle nodes, and (c) bind reusable command channels. Without them these
atoms can only serve as terminal nodes.

This script reruns the full Atomizer agent pipeline (--force) to refresh
capability_grants + native_verification + exploit_guide in one consistent
pass. To protect existing structure-healthy data from a flaky rerun, it
backs up atom.yaml / exploit_guide.yaml / session.json first and restores
the backup when the rerun fails or leaves the atom unverified.

Flow per atom:
  1. Backup atom.yaml, exploit_guide.yaml, session.json to .rerun_backup/
  2. Run `clab_builder.cli atom run <vulhub_path> --force --max-turns N`
  3. Inspect the new atom.yaml:
     - verified=True AND capability_grants non-empty  -> keep (success)
     - otherwise                                        -> restore backup
  4. Record outcome to a JSONL ledger.

Usage:
    python scripts/rerun_capability_backfill.py --batch 1 [--limit N] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait as futures_wait
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def disk_free_gb(path: str = "/var") -> float:
    """Free disk space in GB at the docker root mount."""
    import shutil as _shutil
    try:
        return _shutil.disk_usage(path).free / (1024 ** 3)
    except OSError:
        return float("inf")


def load_atom(atom_dir: Path) -> dict:
    path = atom_dir / "atom.yaml"
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def is_empty_grants(atom: dict) -> bool:
    if not atom.get("verified"):
        return False
    grants = atom.get("capability_grants") or []
    return len(grants) == 0


def backup_atom(atom_dir: Path) -> Path | None:
    """Copy the files we must be able to restore into .rerun_backup/."""
    backup_dir = atom_dir / ".rerun_backup"
    if backup_dir.exists():
        shutil.rmtree(backup_dir)
    backup_dir.mkdir(parents=True)
    saved_any = False
    for name in ("atom.yaml", "exploit_guide.yaml", "session.json"):
        src = atom_dir / name
        if src.exists():
            shutil.copy2(src, backup_dir / name)
            saved_any = True
    return backup_dir if saved_any else None


def restore_atom(atom_dir: Path, backup_dir: Path) -> None:
    for name in ("atom.yaml", "exploit_guide.yaml", "session.json"):
        src = backup_dir / name
        dst = atom_dir / name
        if src.exists():
            shutil.copy2(src, dst)
        elif dst.exists():
            # The rerun may have created/overwritten a file we did not back up;
            # only remove files that were absent in the backup snapshot.
            pass


def find_vulhub_source(cve_id: str, vulhub_root: Path) -> Path | None:
    hits = list(vulhub_root.glob(f"*/{cve_id}"))
    for hit in hits:
        if (hit / "docker-compose.yml").exists():
            return hit
    return None


def rerun_one(
    cve_id: str,
    vulhub_path: Path,
    atoms_dir: Path,
    python_bin: str,
    max_turns: int,
    timeout: int,
    log_dir: Path | None = None,
) -> tuple[bool, str]:
    """Run `atom run <vulhub_path> --force`. Returns (ok, message).

    When ``log_dir`` is set, the full stdout+stderr of the rerun is written to
    ``<log_dir>/<cve>.log`` so failures can be diagnosed precisely instead of
    relying on the truncated "Failed: ... - unknown" tail from the CLI.
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    cmd = [
        python_bin, "-m", "clab_builder.cli", "atom", "run",
        str(vulhub_path),
        "--force",
        "--max-turns", str(max_turns),
        "--output", str(atoms_dir),
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=str(ROOT), env=env,
        )
    except subprocess.TimeoutExpired:
        return False, f"timeout after {timeout}s"

    stdout = result.stdout or ""
    stderr = result.stderr or ""
    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        (log_dir / f"{cve_id}.log").write_text(
            f"=== CMD ===\n{' '.join(cmd)}\n\n=== STDOUT ===\n{stdout}\n\n=== STDERR ===\n{stderr}\n",
            encoding="utf-8", errors="replace",
        )

    if result.returncode != 0:
        # Prefer the CLI's own failure line, but if it is the uninformative
        # "Failed: <cve> - unknown", mine the stderr for a real cause.
        tail = stdout.strip().splitlines()[-1:] or [stderr.strip()[:200]]
        msg = " | ".join(tail)
        if "unknown" in msg:
            cause = _extract_failure_cause(stderr) or _extract_failure_cause(stdout)
            if cause:
                msg = f"{msg} :: {cause}"
        return False, f"exit={result.returncode}: {msg}"
    tail = stdout.strip().splitlines()[-1:] or [""]
    return True, " | ".join(tail)


def _extract_failure_cause(text: str) -> str:
    """Pull a short, actionable failure reason from rerun output/stderr.

    The CLI prints "Failed: <cve> - unknown" when the agent step did not
    capture a flag. The real reason is usually earlier in stderr, e.g. a
    docker compose up error, an image pull timeout, or an agent runner
    exception. We surface the last informative line.
    """
    if not text:
        return ""
    ignore = ("Traceback (most recent call last)", "File \"", "  ", "WARNING", "[SKIP]")
    candidates = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith(ignore):
            continue
        # Common actionable signal lines.
        if any(k in s for k in (
            "docker compose up failed", "failed to solve", "docker pull failed",
            "request canceled", "TimeoutExpired", "Error response from daemon",
            "compose up failed", "exit code:", "agent failed", "RuntimeError",
            "No such file", "Permission denied", "Connection refused",
        )):
            candidates.append(s)
    if candidates:
        return candidates[-1][:200]
    return ""


def _merge_guide_ref_from_backup(atom_dir: Path, backup_dir: Path) -> bool:
    """Restore the exploit_guide ref/file from backup into the fresh atom.yaml.

    A successful rerun refreshes capability_grants but the agent does not
    always emit a structured exploit_guide, so the new atom.yaml carries
    exploit_guide=None even though a ready guide still exists on disk. We
    port the ref and the guide file back from the backup so the atom keeps
    both the new capability contract and its prior ready guide.
    """
    backup_atom_path = backup_dir / "atom.yaml"
    backup_guide_path = backup_dir / "exploit_guide.yaml"
    if not backup_atom_path.exists():
        return False
    backup_atom = yaml.safe_load(backup_atom_path.read_text(encoding="utf-8")) or {}
    guide_ref = backup_atom.get("exploit_guide")
    if not isinstance(guide_ref, dict) or guide_ref.get("status") != "ready":
        return False
    # Ensure the guide file itself is present (rerun did not touch it, but be safe).
    if backup_guide_path.exists():
        shutil.copy2(backup_guide_path, atom_dir / "exploit_guide.yaml")
    current = load_atom(atom_dir)
    current["exploit_guide"] = guide_ref
    (atom_dir / "atom.yaml").write_text(
        yaml.safe_dump(current, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return True


def _regenerate_guide(
    cve_id: str,
    atoms_dir: Path,
    python_bin: str,
    timeout: int = 320,
) -> tuple[bool, str]:
    """Regenerate exploit_guide.yaml from the fresh evidence + grants.

    A successful rerun refreshes capability_grants and native evidence but
    the agent does not always emit a structured exploit_guide. We regenerate
    the guide from the new evidence so guide.capabilities/principal stay
    consistent with the new atom contract (Range's _validate_guided_chain
    checks this consistency).
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    script = ROOT / "scripts" / "generate_exploit_guides.py"
    cmd = [python_bin, str(script), "--cve", cve_id, "--force",
           "--atoms-dir", str(atoms_dir)]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=str(ROOT), env=env,
        )
    except subprocess.TimeoutExpired:
        return False, f"guide generation timeout after {timeout}s"
    tail = (result.stdout or "").strip().splitlines()[-1:] or [(result.stderr or "").strip()[:200]]
    msg = " | ".join(tail)
    if result.returncode != 0:
        return False, f"exit={result.returncode}: {msg}"
    return True, msg


def evaluate_rerun(
    atom_dir: Path,
    backup_dir: Path,
    cve_id: str,
    atoms_dir: Path,
    python_bin: str,
) -> tuple[str, dict]:
    """Decide keep vs restore based on the post-rerun atom.yaml.

    On a successful rerun (verified + non-empty grants) we regenerate the
    guide from the fresh evidence so it matches the new capability contract.
    Only when the rerun itself fails do we restore the backup.
    """
    atom = load_atom(atom_dir)
    grants = atom.get("capability_grants") or []
    verified = bool(atom.get("verified"))
    native = atom.get("verification", {}).get("native_verification", {}) or {}
    outcome = {
        "verified": verified,
        "capability_grants_count": len(grants),
        "capability_types": [g.get("type") for g in grants if isinstance(g, dict)],
        "native_success": bool(native.get("success")),
        "guide_ready": False,
    }
    if not verified or not grants:
        restore_atom(atom_dir, backup_dir)
        return "restored", outcome
    # Rerun produced a verified capability contract. Regenerate the guide so
    # its capabilities/principal match the new grants.
    guide_ok, guide_msg = _regenerate_guide(cve_id, atoms_dir, python_bin)
    if guide_ok:
        outcome["guide_ready"] = True
        outcome["guide_regen"] = "ok"
    else:
        # Guide regen failed (e.g. LLM truncation) — fall back to the prior
        # guide ref/file from backup so the atom stays Range-usable.
        if _merge_guide_ref_from_backup(atom_dir, backup_dir):
            outcome["guide_ready"] = True
            outcome["guide_regen"] = f"failed, restored backup ({guide_msg[:80]})"
        else:
            outcome["guide_regen"] = f"failed, no backup guide ({guide_msg[:80]})"
    return "kept", outcome


def discover_targets(atoms_dir: Path, batch: int, unstable: set[str]) -> list[tuple[str, Path]]:
    """Return [(cve_id, atom_dir)] for the requested batch."""
    targets = []
    for atom_yaml in sorted(atoms_dir.glob("*/atom.yaml")):
        atom = load_atom(atom_yaml.parent)
        if not is_empty_grants(atom):
            continue
        cve = atom_yaml.parent.name
        if cve in unstable:
            continue
        has_evidence = bool(
            (atom.get("verification", {}).get("native_verification", {}) or {}).get("evidence")
        )
        if batch == 1 and not has_evidence:
            continue
        if batch == 2 and has_evidence:
            continue
        targets.append((cve, atom_yaml.parent))
    return targets


def process_one(
    idx: int,
    total: int,
    cve: str,
    atom_dir: Path,
    vulhub_root: Path,
    atoms_dir: Path,
    python_bin: str,
    max_turns: int,
    timeout: int,
    ledger_path: Path,
    lock: threading.Lock,
    log_dir: Path | None = None,
) -> tuple[str, str, dict]:
    """Run one atom's backup → rerun → evaluate → ledger cycle.

    Returns (cve, decision, outcome) so the caller can aggregate counters.
    All ledger writes and stdout progress are serialized through `lock` to
    avoid interleaved output / corrupted JSONL under parallel workers.
    """
    vulhub_path = find_vulhub_source(cve, vulhub_root)
    if vulhub_path is None:
        with lock:
            print(f"[{idx}/{total}] {cve} SKIP no vulhub source")
            _append_ledger(ledger_path, cve, "no_source", {}, 0.0)
        return cve, "no_source", {}

    backup_dir = backup_atom(atom_dir)
    with lock:
        print(f"[{idx}/{total}] {cve} rerun (src={vulhub_path}) ...", flush=True)
    start = time.monotonic()
    run_ok, run_msg = rerun_one(
        cve, vulhub_path, atoms_dir, python_bin, max_turns, timeout, log_dir,
    )
    elapsed = round(time.monotonic() - start, 1)

    if not run_ok:
        if backup_dir:
            restore_atom(atom_dir, backup_dir)
        with lock:
            print(f"  {elapsed}s -> RERUN FAIL: {run_msg}")
            _append_ledger(ledger_path, cve, "rerun_failed", {"error": run_msg}, elapsed)
        return cve, "rerun_failed", {"error": run_msg, "elapsed_seconds": elapsed}

    decision, outcome = evaluate_rerun(
        atom_dir, backup_dir, cve, atoms_dir, python_bin,
    )
    outcome["elapsed_seconds"] = elapsed
    with lock:
        if decision == "kept":
            print(f"  {elapsed}s -> KEPT grants={outcome.get('capability_types')}")
        else:
            print(f"  {elapsed}s -> RESTORED (verified={outcome.get('verified')} "
                  f"grants={outcome.get('capability_grants_count')})")
        _append_ledger(ledger_path, cve, decision, outcome, elapsed)
    return cve, decision, outcome


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--atoms-dir", default="data/atoms")
    parser.add_argument("--vulhub-root", default="vulhub")
    parser.add_argument("--batch", type=int, choices=[1, 2], required=True,
                        help="1 = atoms with prior native evidence; 2 = structure-only (no evidence)")
    parser.add_argument("--limit", type=int, default=0, help="Stop after N atoms (0=all)")
    parser.add_argument("--max-turns", type=int, default=120)
    parser.add_argument("--timeout", type=int, default=1800,
                        help="Per-atom rerun timeout in seconds")
    parser.add_argument("--python-bin", default=sys.executable)
    parser.add_argument("--ledger", default="",
                        help="JSONL ledger path (default: data/rerun_capability_batch< N>.jsonl)")
    parser.add_argument("--log-dir", default="",
                        help="Per-atom rerun log dir (default: logs/rerun_batch< N>)")
    parser.add_argument("--dry-run", action="store_true",
                        help="List targets and exit without rerunning")
    parser.add_argument("--workers", type=int, default=1,
                        help="Parallel rerun workers (default 1 = serial). "
                             "Each worker runs a full agent+orchestrated rerun, "
                             "so 4 workers mean 4 concurrent CVE environments.")
    parser.add_argument("--min-disk-gb", type=float, default=5.0,
                        help="Pause claiming new tasks when /var free space "
                             "drops below this (parallel mode only)")
    parser.add_argument("--include-unstable", action="store_true",
                        help="Do not exclude the known-unstable CVEs from the target set")
    args = parser.parse_args()

    from dotenv import load_dotenv
    load_dotenv()

    atoms_dir = Path(args.atoms_dir)
    vulhub_root = Path(args.vulhub_root)
    unstable = {"CVE-2012-2122", "CVE-2017-12636", "CVE-2015-5254",
                "CVE-2017-7494", "CVE-2017-12794"}
    if args.include_unstable:
        unstable = set()

    targets = discover_targets(atoms_dir, args.batch, unstable)
    if args.limit:
        targets = targets[:args.limit]

    print(f"=== Batch {args.batch}: {len(targets)} targets "
          f"(unstable excluded: {sorted(unstable)}) ===")
    if args.dry_run:
        for cve, _ in targets:
            print(f"  {cve}")
        return 0

    if not targets:
        print("No targets for this batch.")
        return 0

    ledger_path = Path(args.ledger) if args.ledger else (
        ROOT / "data" / f"rerun_capability_batch{args.batch}.jsonl"
    )
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    log_dir = Path(args.log_dir) if args.log_dir else (
        ROOT / "logs" / f"rerun_batch{args.batch}"
    )
    log_dir.mkdir(parents=True, exist_ok=True)
    print(f"per-atom logs: {log_dir}")

    ok = 0
    restored = 0
    failed = 0
    lock = threading.Lock()

    def _aggregate(decision: str) -> None:
        nonlocal ok, restored, failed
        if decision == "kept":
            ok += 1
        elif decision == "restored":
            restored += 1
        else:
            failed += 1

    if args.workers <= 1:
        for i, (cve, atom_dir) in enumerate(targets, 1):
            _cve, decision, _ = process_one(
                i, len(targets), cve, atom_dir, vulhub_root, atoms_dir,
                args.python_bin, args.max_turns, args.timeout, ledger_path, lock, log_dir,
            )
            _aggregate(decision)
    else:
        # Task-pool model (mirrors scaling.py): N tasks, W workers; claim a
        # new task only when an in-flight slot frees AND /var has room. This
        # bounds concurrent CVE environments and avoids docker pool exhaustion.
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            in_flight: set = set()
            todo = iter(list(enumerate(targets, 1)))
            # Pre-fill W tasks
            for _ in range(args.workers):
                try:
                    i, (cve, atom_dir) = next(todo)
                    in_flight.add(pool.submit(
                        process_one, i, len(targets), cve, atom_dir,
                        vulhub_root, atoms_dir, args.python_bin,
                        args.max_turns, args.timeout, ledger_path, lock, log_dir,
                    ))
                except StopIteration:
                    break
            while in_flight:
                done, in_flight = futures_wait(in_flight, return_when=FIRST_COMPLETED)
                for fut in done:
                    _cve, decision, _outcome = fut.result()
                    _aggregate(decision)
                # Refill freed slots, pausing when disk is low
                while len(in_flight) < args.workers:
                    if args.min_disk_gb > 0 and disk_free_gb() < args.min_disk_gb:
                        break
                    try:
                        i, (cve, atom_dir) = next(todo)
                        in_flight.add(pool.submit(
                            process_one, i, len(targets), cve, atom_dir,
                            vulhub_root, atoms_dir, args.python_bin,
                            args.max_turns, args.timeout, ledger_path, lock, log_dir,
                        ))
                    except StopIteration:
                        break

    print(f"\n=== Batch {args.batch} done: {ok} kept, {restored} restored, {failed} failed ===")
    print(f"ledger: {ledger_path}")
    return 0 if failed == 0 else 1


def _append_ledger(path: Path, cve: str, decision: str, outcome: dict, elapsed: float) -> None:
    row = {
        "cve_id": cve,
        "decision": decision,
        "timestamp": utc_now(),
        "elapsed_seconds": elapsed,
        **outcome,
    }
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())