#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREPARE="$HERE/../scripts/prepare-assets.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/source" "$WORK/cache"
printf 'agent-package\n' >"$WORK/source/agent.tar.gz"
printf 'tetragon-package\n' >"$WORK/source/tetragon.tar.gz"
printf '#!/bin/sh\necho jq\n' >"$WORK/source/jq"

agent_sha="$(sha256sum "$WORK/source/agent.tar.gz" | awk '{print $1}')"
tetragon_sha="$(sha256sum "$WORK/source/tetragon.tar.gz" | awk '{print $1}')"
jq_sha="$(sha256sum "$WORK/source/jq" | awk '{print $1}')"

run_prepare() {
  SYSARMOR_CASE0_CACHE_DIR="$WORK/cache" \
  SYSARMOR_PACKAGE_URL="file://$WORK/source/agent.tar.gz" \
  SYSARMOR_PACKAGE_SHA256="$agent_sha" \
  SYSARMOR_PACKAGE_FILE="agent.tar.gz" \
  TETRAGON_URL="file://$WORK/source/tetragon.tar.gz" \
  TETRAGON_SHA256="$tetragon_sha" \
  TETRAGON_FILE="tetragon.tar.gz" \
  JQ_URL="file://$WORK/source/jq" \
  JQ_SHA256="$jq_sha" \
  JQ_FILE="jq" \
    "$PREPARE"
}

run_prepare
test "$(sha256sum "$WORK/cache/agent.tar.gz" | awk '{print $1}')" = "$agent_sha"
test "$(sha256sum "$WORK/cache/tetragon.tar.gz" | awk '{print $1}')" = "$tetragon_sha"
test "$(sha256sum "$WORK/cache/jq" | awk '{print $1}')" = "$jq_sha"
test -x "$WORK/cache/jq"

printf 'corrupt\n' >"$WORK/cache/agent.tar.gz"
run_prepare
test "$(sha256sum "$WORK/cache/agent.tar.gz" | awk '{print $1}')" = "$agent_sha"

rm -f "$WORK/cache/agent.tar.gz"
if SYSARMOR_CASE0_CACHE_DIR="$WORK/cache" \
  SYSARMOR_PACKAGE_URL="file://$WORK/source/agent.tar.gz" \
  SYSARMOR_PACKAGE_SHA256="$(printf '0%.0s' {1..64})" \
  SYSARMOR_PACKAGE_FILE="agent.tar.gz" \
  TETRAGON_URL="file://$WORK/source/tetragon.tar.gz" \
  TETRAGON_SHA256="$tetragon_sha" TETRAGON_FILE="tetragon.tar.gz" \
  JQ_URL="file://$WORK/source/jq" JQ_SHA256="$jq_sha" JQ_FILE="jq" \
  "$PREPARE" >/dev/null 2>&1; then
  echo "prepare-assets accepted an invalid digest" >&2
  exit 1
fi
test ! -e "$WORK/cache/agent.tar.gz"

echo "[prepare-assets-test] ok"
