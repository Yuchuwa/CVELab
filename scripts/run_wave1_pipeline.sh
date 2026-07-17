#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

LOG_DIR="logs/wave1_pipeline_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"

echo "=== wave1 pipeline start ===" | tee "$LOG_DIR/summary.txt"

echo "[1/3] enterprise_3tier full batch" | tee -a "$LOG_DIR/summary.txt"
bash scripts/enterprise3_full_batch.sh 5 > "$LOG_DIR/enterprise3_full_batch.stdout.log" 2>&1

echo "[2/3] revalidate existing atoms" | tee -a "$LOG_DIR/summary.txt"
bash scripts/revalidate_existing_atoms.sh data/revalidate_existing_atoms_wave1.txt > "$LOG_DIR/revalidate_existing.stdout.log" 2>&1

echo "[3/3] atomize CVE-Factory wave1" | tee -a "$LOG_DIR/summary.txt"
bash scripts/atomize_cve_factory_wave1.sh > "$LOG_DIR/cve_factory_wave1.stdout.log" 2>&1

echo "=== wave1 pipeline done ===" | tee -a "$LOG_DIR/summary.txt"
echo "$LOG_DIR"
