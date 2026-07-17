#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

python scripts/prepare_cve_factory_sources.py

LOG_DIR="logs/cve_factory_wave1_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"
RESULTS="$LOG_DIR/results.txt"
ROOT="data/generated/cve_factory_wave1"

echo "=== cve-factory wave1 atomization ===" | tee "$RESULTS"

while IFS= read -r rel || [[ -n "$rel" ]]; do
  [[ -z "$rel" ]] && continue
  CVE="$(basename "$rel" | tr '[:lower:]' '[:upper:]')"
  SRC="$ROOT/$CVE"
  LOG_FILE="$LOG_DIR/${CVE}.log"
  if [[ ! -d "$SRC" ]]; then
    echo "$CVE -> SKIP (prepared source missing)" | tee -a "$RESULTS"
    continue
  fi
  echo "$CVE -> $SRC" | tee -a "$RESULTS"
  if PYTHONPATH=src python -m clab_builder.cli atom run "$SRC" --force --max-turns 80 >"$LOG_FILE" 2>&1; then
    echo "$CVE -> PASS" | tee -a "$RESULTS"
  else
    echo "$CVE -> FAIL" | tee -a "$RESULTS"
  fi
done < data/cve_factory_wave1_tasks.txt

echo "=== done ===" | tee -a "$RESULTS"
echo "logs: $LOG_DIR"
