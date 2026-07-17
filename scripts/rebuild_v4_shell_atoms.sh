#!/bin/bash
# 重建 9 个 pivot=shell 的 atom，用新的 v4 构建流程
# （agent 会采集 exploit_access / capability_grants / exploit_principal）
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

LOG_DIR="logs/rebuild_v4_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"
RESULTS="$LOG_DIR/results.txt"

CVE_LIST=(
    "vulhub/php/CVE-2012-1823"
    "vulhub/nginx/CVE-2013-4547"
    "vulhub/elasticsearch/CVE-2014-3120"
    "vulhub/weblogic/CVE-2017-10271"
    "vulhub/git/CVE-2017-8386"
    "vulhub/libssh/CVE-2018-10933"
    "vulhub/ghostscript/CVE-2018-16509"
    "vulhub/php/CVE-2019-11043"
    "vulhub/postgres/CVE-2019-9193"
)

TOTAL=${#CVE_LIST[@]}
SUCCESS=0
FAIL=0

echo "=== v4 rebuild: $TOTAL atoms ===" | tee "$RESULTS"

for i in "${!CVE_LIST[@]}"; do
    CVE="${CVE_LIST[$i]}"
    NUM=$((i + 1))
    LOG_FILE="$LOG_DIR/$(echo "$CVE" | tr '/' '_').log"
    echo "[$NUM/$TOTAL] $CVE" | tee -a "$RESULTS"
    echo "---"

    if PYTHONPATH=src python -m clab_builder.cli atom run "$CVE" --force --max-turns 80 >"$LOG_FILE" 2>&1; then
        SUCCESS=$((SUCCESS + 1))
        echo "[$NUM/$TOTAL] $CVE -> DONE" | tee -a "$RESULTS"
    else
        FAIL=$((FAIL + 1))
        echo "[$NUM/$TOTAL] $CVE -> FAILED" | tee -a "$RESULTS"
    fi
    echo ""
done

echo "=== Results: $SUCCESS success, $FAIL failed, $TOTAL total ===" | tee -a "$RESULTS"
echo "logs: $LOG_DIR"