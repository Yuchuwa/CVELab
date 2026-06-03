#!/bin/bash
# 并行批量原子化 CVE — 3 个 worker 从队列领任务
# 用法: bash scripts/parallel_batch.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

source .venv/bin/activate
set -a && source .env && set +a

LOG_DIR="logs/batch_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"

# CVE 列表 (2018+, 有明确 CVE 编号, 覆盖不同类型)
CVE_LIST=(
    "confluence/CVE-2023-22527"
    "drupal/CVE-2018-7600"
    "thinkphp/5-rce"
    "laravel/CVE-2021-3129"
    "weblogic/CVE-2017-10271"
    "fastjson/1.2.24-rce"
    "shiro/CVE-2016-4437"
    "httpd/CVE-2021-41773"
    "nginx/nginx_parsing_vulnerability"
    "goahead/CVE-2021-42342"
    "redis/CVE-2022-0543"
    "mongo-express/CVE-2019-10758"
    "couchdb/CVE-2022-24706"
    "wordpress/pwnscriptum"
    "joomla/CVE-2023-23752"
    "gitlab/CVE-2021-22205"
    "jenkins/CVE-2018-1000861"
    "saltstack/CVE-2020-11651"
    "kibana/CVE-2019-7609"
    "grafana/CVE-2024-9264"
)

TOTAL=${#CVE_LIST[@]}
WORKERS=3
QUEUE_FILE="$LOG_DIR/queue.txt"

# 写入队列
printf '%s\n' "${CVE_LIST[@]}" > "$QUEUE_FILE"

echo "=== Parallel Batch: $TOTAL CVEs, $WORKERS workers ==="
echo "=== Logs: $LOG_DIR ==="
echo ""

RESULT_FILE="$LOG_DIR/results.txt"
> "$RESULT_FILE"

# Worker: 从队列文件领任务，用 flock 保证并发安全
run_worker() {
    local WORKER_ID=$1
    local SUCCESS=0
    local FAIL=0

    while true; do
        # 原子取任务
        local CVE
        CVE=$(flock "$QUEUE_FILE" bash -c 'head -1 "$1" && sed -i "1d" "$1"' _ "$QUEUE_FILE")

        [ -z "$CVE" ] && break

        local LOG_FILE="$LOG_DIR/$(echo "$CVE" | tr '/' '_').log"
        echo "[Worker-$WORKER_ID] $CVE"

        if clab-builder atom run "$CVE" --force --max-turns 50 > "$LOG_FILE" 2>&1; then
            SUCCESS=$((SUCCESS + 1))
            echo "[Worker-$WORKER_ID] $CVE -> DONE" | tee -a "$RESULT_FILE"
        else
            FAIL=$((FAIL + 1))
            echo "[Worker-$WORKER_ID] $CVE -> FAILED" | tee -a "$RESULT_FILE"
        fi
    done

    echo "[Worker-$WORKER_ID] Done: $SUCCESS ok, $FAIL fail"
}

# 启动 workers
for i in $(seq 1 $WORKERS); do
    run_worker $i &
done

wait

echo ""
echo "=== Results ==="
cat "$RESULT_FILE"
echo ""
DONE=$(grep -c "DONE" "$RESULT_FILE" || echo 0)
FAIL=$(grep -c "FAILED" "$RESULT_FILE" || echo 0)
echo "=== Total: $DONE success, $FAIL failed, $TOTAL CVEs ==="
