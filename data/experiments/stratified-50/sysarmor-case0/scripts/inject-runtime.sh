#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VARIANT_DIR="$(cd "$HERE/.." && pwd)"

while IFS='=' read -r name value; do
  if [[ -z "${!name+x}" ]]; then
    printf -v "$name" '%s' "${value%$'\r'}"
    export "$name"
  fi
done < <(sed -E '/^[A-Z0-9_]+=/!d; s/^([^=]+)="(.*)"$/\1=\2/' "$HERE/runtime-assets.env")

CACHE_DIR="${SYSARMOR_CASE0_CACHE_DIR:-$VARIANT_DIR/_build/runtime-assets/$SYSARMOR_RELEASE_TAG}"
LOG_DIR="${SYSARMOR_CASE0_LOG_DIR:-$VARIANT_DIR/_build/logs}"
RULES_DIR="$VARIANT_DIR/rules"
HEALTH_TIMEOUT="${SYSARMOR_HEALTH_TIMEOUT:-180}"
HEALTH_COMMAND_TIMEOUT="${SYSARMOR_HEALTH_COMMAND_TIMEOUT:-5}"
TOPOLOGY=""
TARGETS=()
RULE_FILES=(
  "context-execution-tools.json"
  "context-network-clients.json"
  "rulepack-general-behavior.json"
  "detection-policy.json"
)

usage() {
  echo "usage: inject-runtime.sh --topology PATH --target NAME [--target NAME ...]"
}

fail() {
  echo "[sysarmor-inject][ERROR] $*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --topology) TOPOLOGY="$2"; shift 2 ;;
    --target) TARGETS+=("$2"); shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ -f "$TOPOLOGY" ]] || fail "topology not found: $TOPOLOGY"
[[ ${#TARGETS[@]} -gt 0 ]] || fail "at least one --target is required"
[[ "$HEALTH_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || fail "SYSARMOR_HEALTH_TIMEOUT must be positive"
[[ "$HEALTH_COMMAND_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || fail "SYSARMOR_HEALTH_COMMAND_TIMEOUT must be positive"

lab_name="$(awk -F: '$1 == "name" {sub(/^[[:space:]]+/, "", $2); sub(/[[:space:]]+$/, "", $2); print $2; exit}' "$TOPOLOGY" | tr -d "\"'")"
[[ "$lab_name" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]] || fail "invalid or missing topology name"

check_asset() {
  local file="$1" expected="$2"
  [[ -f "$file" ]] || fail "missing cached asset: $file; run prepare-assets.sh"
  [[ "$(sha256sum "$file" | awk '{print $1}')" == "$expected" ]] || fail "cached asset SHA-256 mismatch: $file"
}

agent_package="$CACHE_DIR/$SYSARMOR_PACKAGE_FILE"
tetragon_archive="$CACHE_DIR/$TETRAGON_FILE"
jq_binary="$CACHE_DIR/$JQ_FILE"
check_asset "$agent_package" "$SYSARMOR_PACKAGE_SHA256"
check_asset "$tetragon_archive" "$TETRAGON_SHA256"
check_asset "$jq_binary" "$JQ_SHA256"
for rule_file in "${RULE_FILES[@]}"; do
  [[ -f "$RULES_DIR/$rule_file" ]] || fail "missing SysArmor experiment rule asset: $RULES_DIR/$rule_file"
done

if [[ "${SYSARMOR_SKIP_HOST_PREFLIGHT:-0}" != 1 ]]; then
  [[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || fail "host must be Linux amd64"
  [[ -r /sys/kernel/btf/vmlinux ]] || fail "host BTF is unavailable"
  [[ "$(findmnt -n -o FSTYPE /sys/fs/bpf 2>/dev/null || true)" == bpf ]] || fail "bpffs is not mounted"
  [[ -f /sys/fs/cgroup/cgroup.controllers ]] || fail "cgroup v2 is unavailable"
fi

mkdir -p "$LOG_DIR"

docker_exec_root() {
  docker exec -u 0 "$@"
}

docker_exec_root_timeout() {
  local seconds="$1"
  shift
  timeout "${seconds}s" docker exec -u 0 "$@"
}

health_check() {
  docker_exec_root_timeout "$HEALTH_COMMAND_TIMEOUT" "$1" \
    /usr/local/bin/sysarmorctl --socket /run/sysarmor/agent/control.sock --json agent health \
    >/dev/null 2>&1
}

agent_running() {
  docker_exec_root_timeout "$HEALTH_COMMAND_TIMEOUT" "$1" sh -c '
    for comm in /proc/[0-9]*/comm; do
      read -r name <"$comm" || continue
      if [ "$name" = sysarmor-agent ]; then
        exit 0
      fi
    done
    exit 1
  ' >/dev/null 2>&1
}

start_agent() {
  local container="$1" remote="$2"
  docker_exec_root "$container" sh -c \
    "nohup /opt/sysarmor/agent/bin/sysarmor-agent run --config /etc/sysarmor/agent/agent.yaml >'$remote/agent.log' 2>&1 </dev/null &"
}

installed_version() {
  docker_exec_root_timeout "$HEALTH_COMMAND_TIMEOUT" "$1" \
    /opt/sysarmor/agent/bin/sysarmor-agent version 2>/dev/null
}

ack_not_rejected_filter='(.status // "") != "rejected"'
current_policy_filter='
  def current_rulesets:
    (.detection.rulesets? //
     (.rawJson? | fromjson? | .detection.rulesets?) //
     (.raw_json? | fromjson? | .detection.rulesets?) //
     []);
  (current_rulesets | map(select(.enabled != false) | .ref)) as $refs |
  ($refs | index("ruleset:cep-endpoint")) and
  ($refs | index("ruleset:cvelab-general-behavior"))
'

ensure_remote_rules_workspace() {
  local container="$1" remote="$2"
  docker_exec_root "$container" sh -c "rm -rf '$remote/rules' && mkdir -m 0700 -p '$remote/rules' '$remote/bin'"
  docker cp "$jq_binary" "$container:$remote/bin/jq"
  docker_exec_root "$container" chmod 0755 "$remote/bin/jq"
}

apply_experiment_rules() {
  local container="$1" target="$2" remote="$3"
  local log_file="$remote/rules.log"
  local policy_file="$remote/rules/detection-policy.json"

  ensure_remote_rules_workspace "$container" "$remote"
  for rule_file in "${RULE_FILES[@]}"; do
    docker cp "$RULES_DIR/$rule_file" "$container:$remote/rules/$rule_file"
  done

  docker_exec_root "$container" sh -c ": >'$log_file'"
  for rule_file in context-execution-tools.json context-network-clients.json rulepack-general-behavior.json; do
    if ! docker_exec_root "$container" sh -c \
      "/usr/local/bin/sysarmorctl --socket /run/sysarmor/agent/control.sock --json content apply --file '$remote/rules/$rule_file' --allow-unsigned | '$remote/bin/jq' -e '$ack_not_rejected_filter' >>'$log_file'"; then
      docker cp "$container:$log_file" "$LOG_DIR/$target-rules.log" 2>/dev/null || true
      return 1
    fi
  done

  if ! docker_exec_root "$container" sh -c \
    "/usr/local/bin/sysarmorctl --socket /run/sysarmor/agent/control.sock --json policy apply --type detection --file '$policy_file' --dry-run | '$remote/bin/jq' -e '$ack_not_rejected_filter' >>'$log_file'"; then
    docker cp "$container:$log_file" "$LOG_DIR/$target-rules.log" 2>/dev/null || true
    return 1
  fi
  if ! docker_exec_root "$container" sh -c \
    "/usr/local/bin/sysarmorctl --socket /run/sysarmor/agent/control.sock --json policy apply --type detection --file '$policy_file' | '$remote/bin/jq' -e '$ack_not_rejected_filter' >>'$log_file'"; then
    docker cp "$container:$log_file" "$LOG_DIR/$target-rules.log" 2>/dev/null || true
    return 1
  fi
  if ! docker_exec_root "$container" sh -c \
    "/usr/local/bin/sysarmorctl --socket /run/sysarmor/agent/control.sock --json policy current | '$remote/bin/jq' -e '$current_policy_filter' >>'$log_file'"; then
    docker cp "$container:$log_file" "$LOG_DIR/$target-rules.log" 2>/dev/null || true
    return 1
  fi
  docker cp "$container:$log_file" "$LOG_DIR/$target-rules.log" 2>/dev/null || true
}

for target in "${TARGETS[@]}"; do
  [[ "$target" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]] || fail "invalid target name: $target"
  container="clab-$lab_name-$target"
  read -r running image container_id < <(docker inspect -f '{{.State.Running}} {{.Config.Image}} {{.Id}}' "$container") || fail "$target: container not found"
  [[ "$running" == true ]] || fail "$target: container is not running"
  [[ "$container_id" =~ ^[0-9a-f]{64}$ ]] || fail "$target: invalid Docker container ID"
  read -r image_os image_arch < <(docker image inspect -f '{{.Os}} {{.Architecture}}' "$image")
  [[ "$image_os $image_arch" == "linux amd64" ]] || fail "$target: unsupported image platform $image_os/$image_arch"

  remote="/tmp/sysarmor-inject-$SYSARMOR_RELEASE_TAG"
  already_healthy=0
  if docker_exec_root "$container" sh -c \
    "test \"\$(cat /var/lib/sysarmor/agent/.sysarmor-release 2>/dev/null)\" = '$SYSARMOR_RELEASE_TAG'" \
    && [[ "$(installed_version "$container")" == "$SYSARMOR_RELEASE_TAG" ]] \
    && health_check "$container"; then
    echo "[sysarmor-inject] $target: already healthy at $SYSARMOR_RELEASE_TAG"
    already_healthy=1
  fi

  if [[ "$already_healthy" != 1 ]]; then
    docker_exec_root "$container" sh -c \
      'test "$(id -u)" = 0 && for d in /opt /etc /var/lib /run /usr/local/bin; do test -w "$d"; done && for x in sh tar gzip install cp mv mktemp find sha256sum awk sed; do command -v "$x" >/dev/null; done' \
      || fail "$target: container preflight failed"

    docker_exec_root "$container" sh -c '
      stop_existing_agent() {
        for comm in /proc/[0-9]*/comm; do
          read -r name <"$comm" || continue
          if [ "$name" = sysarmor-agent ]; then
            pid="${comm#/proc/}"; pid="${pid%/comm}"
            kill "$pid" 2>/dev/null || true
          fi
        done
      }
      stop_existing_agent
    '

    docker_exec_root "$container" sh -c "rm -rf '$remote' && mkdir -m 0700 -p '$remote/release' '$remote/bin'"
    docker cp "$agent_package" "$container:$remote/agent.tar.gz"
    docker cp "$tetragon_archive" "$container:$remote/tetragon.tar.gz"
    docker cp "$jq_binary" "$container:$remote/bin/jq"

    if ! docker_exec_root "$container" sh -c \
      "chmod 0755 '$remote/bin/jq' && tar -xzf '$remote/agent.tar.gz' -C '$remote/release' && PATH='$remote/bin':\$PATH SYSARMOR_TETRAGON_ARCHIVE='$remote/tetragon.tar.gz' '$remote/release/install.sh' --profile linux-container >'$remote/install.log' 2>&1 && sed -i -e 's/^    type: namespace$/    type: container/' -e 's/^    selector: self$/    selector: $container_id/' /etc/sysarmor/agent/agent.yaml && printf '%s\\n' '$SYSARMOR_RELEASE_TAG' > /var/lib/sysarmor/agent/.sysarmor-release"; then
      docker cp "$container:$remote/install.log" "$LOG_DIR/$target-install.log" 2>/dev/null || true
      docker_exec_root "$container" rm -rf "$remote" >/dev/null 2>&1 || true
      fail "$target: installation failed; see $LOG_DIR/$target-install.log"
    fi

    start_agent "$container" "$remote"

    healthy=0
    for ((attempt=0; attempt<HEALTH_TIMEOUT; attempt++)); do
      if health_check "$container"; then
        healthy=1
        break
      fi
      if ! agent_running "$container"; then
        start_agent "$container" "$remote"
      fi
      sleep 1
    done
    docker cp "$container:$remote/install.log" "$LOG_DIR/$target-install.log" 2>/dev/null || true
    docker cp "$container:$remote/agent.log" "$LOG_DIR/$target-agent.log" 2>/dev/null || true
    [[ "$healthy" == 1 ]] || fail "$target: Agent health timeout; see $LOG_DIR/$target-agent.log"
  fi
  actual_version="$(installed_version "$container" || true)"
  [[ "$actual_version" == "$SYSARMOR_RELEASE_TAG" ]] || \
    fail "$target: installed Agent version mismatch: got=${actual_version:-missing} want=$SYSARMOR_RELEASE_TAG"
  if ! apply_experiment_rules "$container" "$target" "$remote"; then
    docker_exec_root "$container" rm -rf "$remote" >/dev/null 2>&1 || true
    fail "$target: rule loading failed; see $LOG_DIR/$target-rules.log"
  fi
  docker_exec_root "$container" rm -rf "$remote" >/dev/null 2>&1 || true
  echo "[sysarmor-inject] $target: healthy with additive rules"
done

echo "[sysarmor-inject] all targets healthy"
