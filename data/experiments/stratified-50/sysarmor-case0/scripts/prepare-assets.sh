#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VARIANT_DIR="$(cd "$HERE/.." && pwd)"

# Callers may override manifest values for mirrors and hermetic tests.
while IFS='=' read -r name value; do
  if [[ -z "${!name+x}" ]]; then
    printf -v "$name" '%s' "${value%$'\r'}"
    export "$name"
  fi
done < <(sed -E '/^[A-Z0-9_]+=/!d; s/^([^=]+)="(.*)"$/\1=\2/' "$HERE/runtime-assets.env")

CACHE_DIR="${SYSARMOR_CASE0_CACHE_DIR:-$VARIANT_DIR/_build/runtime-assets/$SYSARMOR_RELEASE_TAG}"
mkdir -p "$CACHE_DIR"

digest() {
  sha256sum "$1" | awk '{print $1}'
}

fetch() {
  local label="$1" url="$2" expected="$3" filename="$4" mode="$5"
  local output="$CACHE_DIR/$filename" temporary
  if [[ -f "$output" && "$(digest "$output")" == "$expected" ]]; then
    [[ "$mode" != executable ]] || chmod 0755 "$output"
    echo "[sysarmor-assets] cached $label: $output"
    return
  fi
  rm -f "$output"
  temporary="$(mktemp "$CACHE_DIR/.${filename}.XXXXXX")"
  if ! curl -fsSL "$url" -o "$temporary"; then
    rm -f "$temporary"
    echo "[sysarmor-assets][ERROR] failed to download $label: $url" >&2
    return 1
  fi
  if [[ "$(digest "$temporary")" != "$expected" ]]; then
    rm -f "$temporary"
    echo "[sysarmor-assets][ERROR] SHA-256 mismatch for $label" >&2
    return 1
  fi
  [[ "$mode" != executable ]] || chmod 0755 "$temporary"
  mv "$temporary" "$output"
  echo "[sysarmor-assets] prepared $label: $output"
}

fetch sysarmor "$SYSARMOR_PACKAGE_URL" "$SYSARMOR_PACKAGE_SHA256" "$SYSARMOR_PACKAGE_FILE" regular
fetch tetragon "$TETRAGON_URL" "$TETRAGON_SHA256" "$TETRAGON_FILE" regular
fetch jq "$JQ_URL" "$JQ_SHA256" "$JQ_FILE" executable

echo "$CACHE_DIR"
