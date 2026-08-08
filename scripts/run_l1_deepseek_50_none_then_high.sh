#!/usr/bin/env bash
# Run the current L1 DeepSeek 50-case decoy comparison.
#
# The none arm must finish before the high arm starts.  Both arms use the same
# manifest, seed, model, runner, turn budget, and Agent timeout; only the
# noise level and worker parallelism differ:
#   none:  noise_level=none, parallel=8
#   high:  noise_level=high, parallel=4
#
# `high` is the current target-surface-matched high-density decoy arm.  The
# historical `matched-high` label is intentionally not used here.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-/home/hanlin/miniconda3/envs/playbook/bin/python}"
MANIFEST="${MANIFEST:-$ROOT/data/guide_ablation/manifest_stratified_50.json}"
OUTPUT_ROOT="${OUTPUT_ROOT:-$ROOT/data/guide_ablation/l1_deepseek_50_current}"
MAX_TURNS="${MAX_TURNS:-300}"
AGENT_TIMEOUT="${AGENT_TIMEOUT:-3600}"
CASE_TIMEOUT="${CASE_TIMEOUT:-5400}"
SEED="${SEED:-1}"
AGENT_RUNNER="${AGENT_RUNNER:-openai}"
AGENT_CONTEXT="l1"

# Preserve explicit shell overrides, then load the project defaults.  The
# model is forced to DeepSeek unless the caller explicitly sets LLM_MODEL.
_LLM_API_KEY_OVERRIDE="${LLM_API_KEY-}"
_LLM_BASE_URL_OVERRIDE="${LLM_BASE_URL-}"
_LLM_MODEL_OVERRIDE="${LLM_MODEL-}"
_LLM_TEMPERATURE_OVERRIDE="${LLM_TEMPERATURE-}"

set -a
# shellcheck disable=SC1091
source "$ROOT/.env"
set +a

[[ -n "$_LLM_API_KEY_OVERRIDE" ]] && LLM_API_KEY="$_LLM_API_KEY_OVERRIDE"
[[ -n "$_LLM_BASE_URL_OVERRIDE" ]] && LLM_BASE_URL="$_LLM_BASE_URL_OVERRIDE"
[[ -n "$_LLM_TEMPERATURE_OVERRIDE" ]] && LLM_TEMPERATURE="$_LLM_TEMPERATURE_OVERRIDE"
LLM_MODEL="${_LLM_MODEL_OVERRIDE:-deepseek-v4-pro}"
LLM_TEMPERATURE="${LLM_TEMPERATURE:-0}"

: "${LLM_API_KEY:?LLM_API_KEY is missing; set it in .env or the shell environment}"
: "${LLM_BASE_URL:?LLM_BASE_URL is missing; set it in .env or the shell environment}"
: "${MANIFEST:?MANIFEST is missing}"
[[ -f "$MANIFEST" ]] || { echo "Manifest not found: $MANIFEST" >&2; exit 2; }
[[ -x "$PYTHON_BIN" ]] || { echo "Python executable not found: $PYTHON_BIN" >&2; exit 2; }

NONE_OUTPUT="$OUTPUT_ROOT/none"
HIGH_OUTPUT="$OUTPUT_ROOT/high"

# Set RESUME=1 to continue an interrupted arm in its existing output
# directory.  The default is deliberately fail-closed so an old result is not
# silently mixed into this run.
if [[ "${RESUME:-0}" != "1" \
  && ( -e "$NONE_OUTPUT" || -e "$HIGH_OUTPUT" ) ]]; then
  echo "Output already exists under $OUTPUT_ROOT; use a new OUTPUT_ROOT or RESUME=1." >&2
  exit 2
fi

PRIVILEGE=()
if command -v docker >/dev/null 2>&1 \
  && docker ps >/dev/null 2>&1 \
  && command -v clab >/dev/null 2>&1 \
  && clab version >/dev/null 2>&1; then
  echo "Using current user's Docker/ContainerLab access."
else
  echo "Current user cannot access Docker/ContainerLab; using sudo for the batch." >&2
  PRIVILEGE=(sudo -E)
fi

run_arm() {
  local level="$1"
  local parallel="$2"
  local output="$3"
  local resume_args=()

  if [[ "${RESUME:-0}" == "1" ]]; then
    if [[ -e "$output" && ! -f "$output/batch_state.json" ]]; then
      echo "RESUME=1 requires batch_state.json in $output." >&2
      exit 2
    fi
    if [[ -f "$output/batch_state.json" ]]; then
      resume_args=(--resume)
    fi
  fi

  echo
  echo "===== L1 DeepSeek arm: noise=$level parallel=$parallel ====="
  echo "manifest=$MANIFEST"
  echo "output=$output"
  echo "model=$LLM_MODEL runner=$AGENT_RUNNER seed=$SEED"
  echo "max_turns=$MAX_TURNS agent_timeout=$AGENT_TIMEOUT case_timeout=$CASE_TIMEOUT"

  "${PRIVILEGE[@]}" env \
    HOME="$HOME" \
    PATH="$PATH" \
    PYTHONPATH="$ROOT/src" \
    LLM_API_KEY="$LLM_API_KEY" \
    LLM_BASE_URL="$LLM_BASE_URL" \
    LLM_MODEL="$LLM_MODEL" \
    LLM_TEMPERATURE="$LLM_TEMPERATURE" \
    "$PYTHON_BIN" "$ROOT/scripts/verify_enterprise3_guided_batch.py" \
      --case-manifest "$MANIFEST" \
      --max-cases 50 \
      --agent-context "$AGENT_CONTEXT" \
      --agent-runner "$AGENT_RUNNER" \
      --model "$LLM_MODEL" \
      --base-url "$LLM_BASE_URL" \
      --noise-level "$level" \
      --seed "$SEED" \
      --parallel "$parallel" \
      --max-turns "$MAX_TURNS" \
      --agent-timeout "$AGENT_TIMEOUT" \
      --case-timeout "$CASE_TIMEOUT" \
      --live-output \
      "${resume_args[@]}" \
      --output "$output"
}

run_arm none 8 "$NONE_OUTPUT"
echo "===== none arm completed; starting high arm ====="
run_arm high 4 "$HIGH_OUTPUT"
echo "===== L1 DeepSeek none/high 50-case comparison completed ====="
