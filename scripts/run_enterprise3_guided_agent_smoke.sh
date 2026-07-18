#!/usr/bin/env bash
# Run the first bounded Guided-Agent trial from environment-passed Range shards.
#
# LLM credentials are loaded by the Python runner from the project `.env`;
# exported LLM_API_KEY / LLM_BASE_URL / LLM_MODEL values still take precedence.
# Override AGENT_CASES, AGENT_MAX_TURNS, AGENT_TIMEOUT, or AGENT_OUTPUT when
# repeating the experiment with a new output directory.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-/home/hanlin/miniconda3/envs/playbook/bin/python}"
ENVIRONMENT_ROOT="${ENVIRONMENT_ROOT:-$ROOT/data/scenarios_enterprise3_env}"
QUEUE_MANIFEST="${QUEUE_MANIFEST:-$ROOT/data/range_matrices/enterprise_3tier_agent_queue_env_000_001.json}"
AGENT_OUTPUT="${AGENT_OUTPUT:-data/scenarios_enterprise3_agent/smoke-000}"
AGENT_CASES="${AGENT_CASES:-5}"
AGENT_MAX_TURNS="${AGENT_MAX_TURNS:-100}"
AGENT_TIMEOUT="${AGENT_TIMEOUT:-1800}"

"$PYTHON_BIN" "$ROOT/scripts/collect_enterprise3_agent_queue.py" \
  --environment-root "$ENVIRONMENT_ROOT" \
  --output "$QUEUE_MANIFEST"

env_args=(
  "HOME=$HOME"
  "PATH=$PATH"
  "PYTHONPATH=$ROOT/src"
)
[[ -n "${LLM_API_KEY:-}" ]] && env_args+=("LLM_API_KEY=$LLM_API_KEY")
[[ -n "${LLM_BASE_URL:-}" ]] && env_args+=("LLM_BASE_URL=$LLM_BASE_URL")
[[ -n "${LLM_MODEL:-}" ]] && env_args+=("LLM_MODEL=$LLM_MODEL")

exec sudo -E env "${env_args[@]}" \
  "$PYTHON_BIN" "$ROOT/scripts/verify_enterprise3_guided_batch.py" \
  --case-manifest "$QUEUE_MANIFEST" \
  --max-cases "$AGENT_CASES" \
  --parallel 1 \
  --max-turns "$AGENT_MAX_TURNS" \
  --agent-timeout "$AGENT_TIMEOUT" \
  --output "$AGENT_OUTPUT"
