#!/bin/bash
# 并行重建 atom（v4 构建流程）
# 用法: rebuild_v4_parallel.sh "cve1,cve2,..." [jobs]
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

INPUT="${1:?usage: $0 'vulhub/php/CVE-2012-1823,vulhub/nginx/CVE-2013-4547' [jobs]}"
JOBS="${2:-4}"

LOG_DIR="logs/rebuild_v4_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"
RESULTS="$LOG_DIR/results.txt"

IFS=',' read -ra CVE_LIST <<< "$INPUT"
TOTAL=${#CVE_LIST[@]}

echo "=== v4 rebuild (parallel, jobs=$JOBS): $TOTAL atoms ===" | tee "$RESULTS"
echo "logs: $LOG_DIR" | tee -a "$RESULTS"

run_one() {
    local idx="$1"
    local total="$2"
    local cve="$3"
    local log_dir="$4"
    local results="$5"
    local log_file="$log_dir/$(echo "$cve" | tr '/' '_').log"
    if PYTHONPATH=src python -m clab_builder.cli atom run "$cve" --force --max-turns 120 >"$log_file" 2>&1; then
        echo "[$idx/$total] $cve -> DONE" >> "$results"
    else
        echo "[$idx/$total] $cve -> FAILED" >> "$results"
    fi
}
export -f run_one
export LOG_DIR RESULTS TOTAL

# 用后台 + wait 控制并发数
running=0
for i in "${!CVE_LIST[@]}"; do
    CVE="${CVE_LIST[$i]}"
    NUM=$((i + 1))
    echo "[$NUM/$TOTAL] $CVE starting..." >> "$RESULTS"
    run_one "$NUM" "$TOTAL" "$CVE" "$LOG_DIR" "$RESULTS" &
    running=$((running + 1))
    if [ "$running" -ge "$JOBS" ]; then
        wait -n 2>/dev/null || wait
        running=$((running - 1))
    fi
done
wait

SUCCESS=$(grep -c '-> DONE' "$RESULTS" || true)
FAIL=$(grep -c '-> FAILED' "$RESULTS" || true)
echo "=== Results: $SUCCESS success, $FAIL failed, $TOTAL total ===" | tee -a "$RESULTS"
echo "logs: $LOG_DIR"