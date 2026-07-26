#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VARIANT_DIR="$(cd "$HERE/.." && pwd)"
TOPOLOGY="${1:-$VARIANT_DIR/scenario/clab.yaml}"

"$HERE/prepare-assets.sh"
clab deploy -t "$TOPOLOGY"
"$HERE/inject-runtime.sh" \
  --topology "$TOPOLOGY" \
  --target target-1 \
  --target target-2 \
  --target target-3

echo "[sysarmor-case0] deployed with all SysArmor agents healthy"
