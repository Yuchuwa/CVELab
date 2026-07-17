#!/bin/bash
set -euo pipefail

COUNT="${1:-5}"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

LOG_DIR="logs/enterprise3_full_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"
RESULTS="$LOG_DIR/results.txt"

echo "=== enterprise_3tier full batch: $COUNT runs ===" | tee "$RESULTS"

for i in $(seq 1 "$COUNT"); do
  NAME="enterprise3-batch-$(printf '%03d' "$i")"
  LOG_FILE="$LOG_DIR/$NAME.log"
  echo "[$i/$COUNT] $NAME" | tee -a "$RESULTS"
  if PYTHONPATH=src python -m clab_builder.cli verify enterprise_3tier --name "$NAME" --output "$PROJECT_DIR/data/scenarios_batch" --mode full --require-agent-success --max-turns 120 >"$LOG_FILE" 2>&1; then
    echo "[$i/$COUNT] $NAME -> PASS" | tee -a "$RESULTS"
  else
    echo "[$i/$COUNT] $NAME -> FAIL" | tee -a "$RESULTS"
  fi
done

echo "=== done ===" | tee -a "$RESULTS"
echo "logs: $LOG_DIR"
