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
if [[ "$1" == "inspect" && "$2" == "-f" ]]; then
  echo "true original-image 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
elif [[ "$1" == "image" && "$2" == "inspect" ]]; then
  echo "linux amd64"
elif [[ "$1" == "exec" && "$2" == "-u" && "$3" == "0" && "$4" == "clab-exact-lab-target-1" ]]; then
    shift 4
    if [[ "$*" == *"agent health"* ]]; then
      [[ -f "$FAKE_HEALTHY" ]]
    elif [[ "$*" == *"content apply"* ]]; then
      [[ "${FAKE_RULE_FAILURE:-0}" != 1 ]] || exit 44
      echo '{"status":"accepted"}'
    elif [[ "$*" == *"policy apply"* ]]; then
      echo '{"status":"accepted"}'
    elif [[ "$*" == *"policy current"* ]]; then
      echo '{"detection":{"rulesets":[{"ref":"ruleset:cep-endpoint","enabled":true},{"ref":"ruleset:cvelab-general-behavior","enabled":true}]}}'
    elif [[ "$*" == *"sysarmor-agent version"* ]]; then
      [[ -f "$FAKE_HEALTHY" ]] && echo "${FAKE_INSTALLED_VERSION:-$SYSARMOR_RELEASE_TAG}"
    elif [[ " $* " == *" .sysarmor-release "* && " $* " == *" cat "* ]]; then
      [[ -f "$FAKE_HEALTHY" ]] && echo "$SYSARMOR_RELEASE_TAG"
    elif [[ "$*" == *"sysarmor-agent run"* || "$*" == *"/opt/sysarmor/agent/bin/sysarmor-agent"* ]]; then
      touch "$FAKE_HEALTHY"
    fi
elif [[ "$1" == "cp" ]]; then
  :
fi
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
grep -Fq 'exec -u 0 clab-exact-lab-target-1' "$WORK/docker.log"
grep -Fq 'stop_existing_agent' "$WORK/docker.log"
grep -Fq 'type:\ container' "$WORK/docker.log"
grep -Fq '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' "$WORK/docker.log"
first_starts="$(grep -c 'sysarmor-agent\\ run' "$WORK/docker.log")"
test "$first_starts" -eq 1
first_content_applies="$(grep -c 'content\\ apply' "$WORK/docker.log")"
test "$first_content_applies" -eq 3
grep -Fq 'context-execution-tools.json' "$WORK/docker.log"
grep -Fq 'context-network-clients.json' "$WORK/docker.log"
grep -Fq 'rulepack-general-behavior.json' "$WORK/docker.log"
grep -Fq 'detection-policy.json' "$WORK/docker.log"

line_no() {
  grep -n "$1" "$WORK/docker.log" | head -1 | cut -d: -f1
}

last_line_no() {
  grep -n "$1" "$WORK/docker.log" | tail -1 | cut -d: -f1
}

context_line="$(line_no 'context-execution-tools.json')"
network_context_line="$(line_no 'context-network-clients.json')"
rulepack_line="$(line_no 'rulepack-general-behavior.json')"
dry_run_line="$(line_no 'policy\\ apply.*--dry-run')"
apply_line="$(last_line_no 'policy\\ apply.*detection-policy.json')"
current_line="$(line_no 'policy.*current')"
test "$context_line" -lt "$rulepack_line"
test "$network_context_line" -lt "$rulepack_line"
test "$rulepack_line" -lt "$dry_run_line"
test "$dry_run_line" -lt "$apply_line"
test "$apply_line" -lt "$current_line"

"$INJECT" --topology "$WORK/topology.yaml" --target target-1
second_starts="$(grep -c 'sysarmor-agent\\ run' "$WORK/docker.log")"
test "$second_starts" -eq 1
grep -Fq 'sysarmor-agent version' "$WORK/docker.log"
second_content_applies="$(grep -c 'content\\ apply' "$WORK/docker.log")"
test "$second_content_applies" -eq 6

export FAKE_RULE_FAILURE=1
if "$INJECT" --topology "$WORK/topology.yaml" --target target-1 >"$WORK/rule-failure.log" 2>&1; then
  echo "[inject-runtime-test][ERROR] accepted failed additive rule loading" >&2
  exit 1
fi
grep -Fq 'rule loading failed' "$WORK/rule-failure.log"
if grep -Fq 'all targets healthy' "$WORK/rule-failure.log"; then
  echo "[inject-runtime-test][ERROR] reported all targets healthy after rule failure" >&2
  exit 1
fi
unset FAKE_RULE_FAILURE

export FAKE_INSTALLED_VERSION="dev"
if "$INJECT" --topology "$WORK/topology.yaml" --target target-1 >"$WORK/mismatch-existing.log" 2>&1; then
  echo "[inject-runtime-test][ERROR] accepted mismatched version on existing installation" >&2
  exit 1
fi
grep -Fq 'installed Agent version mismatch: got=dev want=test-release' "$WORK/mismatch-existing.log"

rm -f "$FAKE_HEALTHY"
if "$INJECT" --topology "$WORK/topology.yaml" --target target-1 >"$WORK/mismatch-fresh.log" 2>&1; then
  echo "[inject-runtime-test][ERROR] accepted mismatched version after fresh installation" >&2
  exit 1
fi
grep -Fq 'installed Agent version mismatch: got=dev want=test-release' "$WORK/mismatch-fresh.log"

echo "[inject-runtime-test] ok"
