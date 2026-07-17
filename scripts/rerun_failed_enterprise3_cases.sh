#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

LOG_DIR="logs/enterprise3_rerun_failed_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"
RESULTS="$LOG_DIR/results.txt"

CASES=(
  "enterprise3-batch-001:CVE-2018-16509,CVE-2012-1823,CVE-2017-8386"
  "enterprise3-batch-002:CVE-2018-16509,CVE-2017-10271,CVE-2014-6271"
  "enterprise3-batch-004:CVE-2012-1823,CVE-2014-3120,CVE-2022-24706"
  "enterprise3-batch-005:CVE-2014-3120,CVE-2017-10271,CVE-2022-0543"
)

echo "=== rerun failed enterprise_3tier cases (max-turns=120) ===" | tee "$RESULTS"

idx=0
for item in "${CASES[@]}"; do
  idx=$((idx + 1))
  NAME="${item%%:*}-rerun"
  CVES="${item#*:}"
  LOG_FILE="$LOG_DIR/${NAME}.log"
  echo "[$idx/${#CASES[@]}] $NAME -> $CVES" | tee -a "$RESULTS"
  if PYTHONPATH=src python -m clab_builder.cli verify enterprise_3tier --cve "$CVES" --name "$NAME" --output "$PROJECT_DIR/data/scenarios_rerun" --mode full --require-agent-success --max-turns 120 >"$LOG_FILE" 2>&1; then
    echo "[$idx/${#CASES[@]}] $NAME -> PASS" | tee -a "$RESULTS"
  else
    echo "[$idx/${#CASES[@]}] $NAME -> FAIL" | tee -a "$RESULTS"
  fi
done

echo "=== done ===" | tee -a "$RESULTS"
echo "logs: $LOG_DIR"
