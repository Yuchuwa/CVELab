#!/usr/bin/env bash
# Decoy ablation experiment: 4 noise levels (none/low/medium/high) x 8 cases,
# deepseek-v4-pro, claude runner, parallel=6 within each level, levels serial.
# Single sudo invocation for the whole loop (one password prompt).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-/home/hanlin/miniconda3/envs/playbook/bin/python}"
MANIFEST="${MANIFEST:-$ROOT/data/guide_ablation/manifest_sol_smoke8.json}"
LEVELS="${LEVELS:-none low medium high}"
OUTPUT_ROOT="${OUTPUT_ROOT:-$ROOT/data/guide_ablation}"
MAX_TURNS="${MAX_TURNS:-300}"
AGENT_TIMEOUT="${AGENT_TIMEOUT:-3600}"
PARALLEL="${PARALLEL:-6}"
AGENT_CONTEXT="${AGENT_CONTEXT:-l2}"
AGENT_RUNNER="${AGENT_RUNNER:-claude}"

# Preserve explicit environment overrides while loading project defaults.
_LLM_API_KEY_OVERRIDE="${LLM_API_KEY-}"
_LLM_BASE_URL_OVERRIDE="${LLM_BASE_URL-}"
_LLM_MODEL_OVERRIDE="${LLM_MODEL-}"
_LLM_TEMPERATURE_OVERRIDE="${LLM_TEMPERATURE-}"

# Load .env so LLM_* reach the privileged subprocess.
set -a
# shellcheck disable=SC1091
source "$ROOT/.env"
set +a
[[ -n "$_LLM_API_KEY_OVERRIDE" ]] && LLM_API_KEY="$_LLM_API_KEY_OVERRIDE"
[[ -n "$_LLM_BASE_URL_OVERRIDE" ]] && LLM_BASE_URL="$_LLM_BASE_URL_OVERRIDE"
[[ -n "$_LLM_MODEL_OVERRIDE" ]] && LLM_MODEL="$_LLM_MODEL_OVERRIDE"
[[ -n "$_LLM_TEMPERATURE_OVERRIDE" ]] && LLM_TEMPERATURE="$_LLM_TEMPERATURE_OVERRIDE"

sudo -E env \
  HOME="$HOME" \
  PATH="$PATH" \
  PYTHONPATH="$ROOT/src" \
  LLM_TEMPERATURE="${LLM_TEMPERATURE:-0}" \
  LLM_API_KEY="$LLM_API_KEY" \
  LLM_BASE_URL="$LLM_BASE_URL" \
  LLM_MODEL="$LLM_MODEL" \
  bash -c '
set -euo pipefail
ROOT="'"$ROOT"'"
PYTHON_BIN="'"$PYTHON_BIN"'"
MANIFEST="'"$MANIFEST"'"
LEVELS="'"$LEVELS"'"
OUTPUT_ROOT="'"$OUTPUT_ROOT"'"
MAX_TURNS="'"$MAX_TURNS"'"
AGENT_TIMEOUT="'"$AGENT_TIMEOUT"'"
PARALLEL="'"$PARALLEL"'"
AGENT_CONTEXT="'"$AGENT_CONTEXT"'"
AGENT_RUNNER="'"$AGENT_RUNNER"'"

for LEVEL in $LEVELS; do
  echo "===== noise-level: '"'"'$LEVEL'"'"' (context=$AGENT_CONTEXT) ====="
  "$PYTHON_BIN" "$ROOT/scripts/verify_enterprise3_guided_batch.py" \
    --case-manifest "$MANIFEST" \
    --max-cases 8 \
    --agent-context "$AGENT_CONTEXT" \
    --agent-runner "$AGENT_RUNNER" \
    --noise-level "$LEVEL" \
    --parallel "$PARALLEL" \
    --max-turns "$MAX_TURNS" \
    --agent-timeout "$AGENT_TIMEOUT" \
    --live-output \
    --output "$OUTPUT_ROOT/decoy_ablation_${AGENT_CONTEXT}_${LEVEL}"
done
'
