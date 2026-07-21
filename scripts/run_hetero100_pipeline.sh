#!/usr/bin/env bash
# Run the full heterogeneity experiment pipeline:
#   Stage 1: Guided full verification of 100 new balanced-matrix cases
#            (no overlap with the 64 already-validated l2_decoy_full_v2 cases)
#   Stage 2: Build a reusable manifest from the Guided-verified cases
#            (keeps only environment+attack_graph+attack_path+guided_trial+objective all True)
#   Stage 3: Re-run the Guided-verified cases under L2 + decoy (baseline noise)
#
# All stages share max-turns=150 and agent-timeout=2400 so turn/timeout is not a
# confound between Guided and L2+decoy; the only differences are agent_context
# (guided vs l2), noise_level (none vs baseline), and the prompt (Guide vs
# Guide-removed + decoy topology).
#
# Each stage auto-tags its results with a validation_round provenance tag
# (run_id + agent_context + noise_level + validated_at) in every
# verify_result.json and the batch summary.json.
#
# Usage:  sudo -E bash scripts/run_hetero100_pipeline.sh
# Or set env vars and run directly.

set -euo pipefail

# Resolve repo root from script location (works regardless of CWD).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

PY="${PY:-/home/hanlin/miniconda3/envs/playbook/bin/python}"
export PYTHONPATH="$ROOT/src"
export HOME="${HOME:-/home/hanlin}"
# Ensure the conda env bin (ansible-playbook, python, clab, docker) is on PATH
# even under `sudo -E bash`, which may apply sudo's secure_path and drop the
# user's conda env directory. Prepend the python interpreter's bin dir.
PY_BIN_DIR="$(dirname "$PY")"
case ":$PATH:" in
  *":$PY_BIN_DIR:"*) ;;
  *) export PATH="$PY_BIN_DIR:$PATH" ;;
esac

MANIFEST_HETERO100="data/guide_ablation/manifest_hetero_100.json"
GUIDED_OUT="data/guide_ablation/hetero100_guided"
REUSABLE_MANIFEST="data/guide_ablation/hetero100_reusable.json"
L2_DECOY_OUT="data/guide_ablation/hetero100_l2_decoy"

MAX_TURNS=150
AGENT_TIMEOUT=2400
PARALLEL=8

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

run_stage() {
  local stage_name="$1"; shift
  log "============================================================"
  log "STAGE $stage_name: $*"
  log "============================================================"
  "$@"
}

# ---------- Stage 1: Guided full verification ----------
"$PY" scripts/verify_enterprise3_guided_batch.py \
  --case-manifest "$MANIFEST_HETERO100" \
  --max-cases 100 \
  --agent-context guided \
  --noise-level none \
  --parallel "$PARALLEL" \
  --max-turns "$MAX_TURNS" \
  --agent-timeout "$AGENT_TIMEOUT" \
  --live-output \
  --output "$GUIDED_OUT"
log "Stage 1 finished. Summary: $GUIDED_OUT/summary.json"

# ---------- Stage 2: build reusable manifest ----------
# Pick out the cases that passed the full Guided gate
# (environment_success + attack_graph_valid + attack_path_reachable +
#  guided_trial_success + objective_achieved all True). Failed cases are
# recorded in the manifest's `rejected` list with failure_stage + failed gate
# fields, never silently dropped.
run_stage 2 build-reusable-manifest \
  "$PY" scripts/build_reusable_ranges_manifest.py \
    "$GUIDED_OUT" \
    --output "$REUSABLE_MANIFEST"

# Determine how many cases passed the Guided gate.
VERIFIED_COUNT="$("$PY" -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["cases"]))' "$REUSABLE_MANIFEST")"
log "Stage 2 finished. Guided-verified reusable cases: $VERIFIED_COUNT"
log "Reusable manifest: $REUSABLE_MANIFEST"

if [ "$VERIFIED_COUNT" -eq 0 ]; then
  log "ERROR: no cases passed the Guided gate; aborting Stage 3."
  exit 1
fi

# ---------- Stage 3: L2 + decoy on the Guided-verified cases ----------
# --max-cases 100 is a safe upper bound; the runner slices to the actual
# reusable case count when fewer than 100 passed.
run_stage 3 l2-decoy \
  "$PY" scripts/verify_enterprise3_guided_batch.py \
    --case-manifest "$REUSABLE_MANIFEST" \
    --max-cases 100 \
    --agent-context l2 \
    --noise-level baseline \
    --parallel "$PARALLEL" \
    --max-turns "$MAX_TURNS" \
    --agent-timeout "$AGENT_TIMEOUT" \
    --live-output \
    --output "$L2_DECOY_OUT"

log "Stage 3 finished. Summary: $L2_DECOY_OUT/summary.json"
log "============================================================"
log "PIPELINE COMPLETE"
log "  Stage 1 Guided results:  $GUIDED_OUT/summary.json"
log "  Stage 2 reusable manifest: $REUSABLE_MANIFEST"
log "  Stage 3 L2+decoy results:  $L2_DECOY_OUT/summary.json"
log "============================================================"