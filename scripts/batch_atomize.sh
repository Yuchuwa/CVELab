#!/bin/bash
# 批量原子化 CVE — 覆盖完整攻击链
# 用法: bash scripts/batch_atomize.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# 激活 venv + 加载 .env
source .venv/bin/activate
set -a && source .env && set +a

CVE_LIST=(
    # 重跑失败 + 工具不足的
    "samba/CVE-2017-7494"
    "polkit/CVE-2021-4034"
    "tomcat/CVE-2025-24813"
)

TOTAL=${#CVE_LIST[@]}
SUCCESS=0
FAIL=0

echo "=== Batch Atomization: ${TOTAL} CVEs ==="
echo ""

for i in "${!CVE_LIST[@]}"; do
    CVE="${CVE_LIST[$i]}"
    NUM=$((i + 1))
    echo "[$NUM/$TOTAL] $CVE"
    echo "---"

    if clab-builder atom run "$CVE" --force --max-turns 50; then
        SUCCESS=$((SUCCESS + 1))
        echo "[$NUM/$TOTAL] $CVE -> DONE"
    else
        FAIL=$((FAIL + 1))
        echo "[$NUM/$TOTAL] $CVE -> FAILED"
    fi

    echo ""
done

echo "=== Results: $SUCCESS success, $FAIL failed, $TOTAL total ==="
