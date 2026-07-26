#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VARIANT_DIR="$(cd "$HERE/.." && pwd)"
CVELAB_ROOT="$(cd "$VARIANT_DIR/../../../.." && pwd)"
IMAGE="${1:-cvelab-runtime-2018-16509-ab809fb197}"
LAB="sysarmor-case0-smoke"
NAME="clab-$LAB-target-1"
WORK="$(mktemp -d)"

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

cat >"$WORK/clab.yaml" <<EOF
name: $LAB
topology:
  nodes: {}
EOF

"$HERE/prepare-assets.sh"
docker run -d --name "$NAME" \
  --privileged --cgroupns=host \
  -p 127.0.0.1::8080 \
  -v "$CVELAB_ROOT/data/atoms/CVE-2018-16509/init/index.php:/var/www/html/index.php:ro" \
  -v /sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  "$IMAGE" php -t /var/www/html -S 0.0.0.0:8080 >/dev/null

"$HERE/inject-runtime.sh" --topology "$WORK/clab.yaml" --target target-1
"$HERE/inject-runtime.sh" --topology "$WORK/clab.yaml" --target target-1

port="$(docker port "$NAME" 8080/tcp | awk -F: 'NR == 1 {print $NF}')"
curl -fsS "http://127.0.0.1:$port/" >/dev/null
docker exec "$NAME" /usr/local/bin/sysarmorctl --json agent health >/dev/null
agent_count="$(docker exec "$NAME" sh -c 'pgrep -xc sysarmor-agent || true')"
[[ "$agent_count" == 1 ]] || {
  echo "[sysarmor-case0-smoke][ERROR] expected one Agent, found $agent_count" >&2
  exit 1
}

echo "[sysarmor-case0-smoke] original target-1 service and runtime injection passed"
