#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INJECT="$HERE/../scripts/inject-runtime.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin" "$WORK/cache" "$WORK/logs"

cat >"$WORK/topology.yaml" <<'EOF'
name: exact-lab
topology:
  nodes: {}
EOF

printf 'agent\n' >"$WORK/cache/agent.tar.gz"
printf 'tetragon\n' >"$WORK/cache/tetragon.tar.gz"
printf 'jq\n' >"$WORK/cache/jq"
chmod +x "$WORK/cache/jq"

cat >"$WORK/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"$FAKE_DOCKER_LOG"
printf '\n' >>"$FAKE_DOCKER_LOG"
case "$1 $2" in
  "inspect -f") echo "true original-image 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" ;;
  "image inspect") echo "linux amd64" ;;
  "exec clab-exact-lab-target-1")
    shift 2
    if [[ "$*" == *sysarmorctl* ]]; then
      [[ -f "$FAKE_HEALTHY" ]]
    elif [[ " $* " == *" .sysarmor-release "* && " $* " == *" cat "* ]]; then
      [[ -f "$FAKE_HEALTHY" ]] && echo "$SYSARMOR_RELEASE_TAG"
    elif [[ "$*" == *"sysarmor-agent run"* ]]; then
      touch "$FAKE_HEALTHY"
    fi
    ;;
  "cp "*) ;;
esac
EOF
chmod +x "$WORK/bin/docker"

export PATH="$WORK/bin:$PATH"
export FAKE_DOCKER_LOG="$WORK/docker.log"
export FAKE_HEALTHY="$WORK/healthy"
export SYSARMOR_RELEASE_TAG="test-release"
export SYSARMOR_CASE0_CACHE_DIR="$WORK/cache"
export SYSARMOR_PACKAGE_FILE="agent.tar.gz"
export SYSARMOR_PACKAGE_SHA256="$(sha256sum "$WORK/cache/agent.tar.gz" | awk '{print $1}')"
export TETRAGON_FILE="tetragon.tar.gz"
export TETRAGON_SHA256="$(sha256sum "$WORK/cache/tetragon.tar.gz" | awk '{print $1}')"
export JQ_FILE="jq"
export JQ_SHA256="$(sha256sum "$WORK/cache/jq" | awk '{print $1}')"
export SYSARMOR_CASE0_LOG_DIR="$WORK/logs"
export SYSARMOR_SKIP_HOST_PREFLIGHT=1
export SYSARMOR_HEALTH_TIMEOUT=2

"$INJECT" --topology "$WORK/topology.yaml" --target target-1
grep -Fq 'clab-exact-lab-target-1' "$WORK/docker.log"
grep -Fq 'stop_existing_agent' "$WORK/docker.log"
grep -Fq 'type:\ container' "$WORK/docker.log"
grep -Fq '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' "$WORK/docker.log"
first_starts="$(grep -c 'sysarmor-agent\\ run' "$WORK/docker.log")"
test "$first_starts" -eq 1

"$INJECT" --topology "$WORK/topology.yaml" --target target-1
second_starts="$(grep -c 'sysarmor-agent\\ run' "$WORK/docker.log")"
test "$second_starts" -eq 1

echo "[inject-runtime-test] ok"
