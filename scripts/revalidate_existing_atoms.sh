#!/bin/bash
set -euo pipefail

LIST_FILE="${1:-data/revalidate_existing_atoms_wave1.txt}"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

LOG_DIR="logs/revalidate_existing_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"
RESULTS="$LOG_DIR/results.txt"

echo "=== existing atom revalidation: $LIST_FILE ===" | tee "$RESULTS"

while IFS= read -r CVE || [[ -n "$CVE" ]]; do
  [[ -z "$CVE" ]] && continue
  LOG_FILE="$LOG_DIR/${CVE}.log"
  SRC=$(python - <<'PY' "$CVE"
import sys, yaml
from pathlib import Path
cve = sys.argv[1]
atom = Path('data/atoms') / cve / 'atom.yaml'
data = yaml.safe_load(atom.read_text()) or {}
print(data.get('source', ''))
PY
)
  if [[ -z "$SRC" || ! -d "$SRC" ]]; then
    echo "$CVE -> SKIP (source missing: $SRC)" | tee -a "$RESULTS"
    continue
  fi
  echo "$CVE -> $SRC" | tee -a "$RESULTS"
  if PYTHONPATH=src python -m clab_builder.cli atom run "$SRC" --force --max-turns 80 >"$LOG_FILE" 2>&1; then
    echo "$CVE -> PASS" | tee -a "$RESULTS"
  else
    echo "$CVE -> FAIL" | tee -a "$RESULTS"
  fi
done < "$LIST_FILE"

echo "=== done ===" | tee -a "$RESULTS"
echo "logs: $LOG_DIR"
