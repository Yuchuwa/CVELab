#!/bin/bash
# Delete Docker images unrelated to CVELab.
#
# CVELab-related images are derived from the repo at runtime:
#   - vulhub docker-compose `image:` refs            (data/vulhub/**/docker-compose.yml)
#   - vulhub Dockerfile `FROM` base images           (data/vulhub/**/Dockerfile)  [build deps]
#   - raw_records image_name:image_tag               (data/raw_records_*.json)
#   - topology templates / scenarios `image:` refs   (templates/**, data/scenarios/**/clab.yaml)
#   - agent / pivot images from docker/Dockerfile    (clab-agent, cvelab-pivot-base, kali, ubuntu)
# Plus repo-prefix rules: cve-*, vulhub/*, frrouting/frr*, clab-agent, cvelab-pivot-base
# Anything in `docker images` NOT matched is considered unrelated.
#
# Bare image names (no :tag) are normalized to :latest (docker default).
#
# Usage:
#   bash scripts/cleanup_images.sh                     # dry-run: print what would be removed
#   bash scripts/cleanup_images.sh --apply             # remove unrelated images + prune dangling
#   bash scripts/cleanup_images.sh --apply --no-prune  # remove but skip dangling prune
#
# Requires Docker access (run with sudo / docker group).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

APPLY=0
PRUNE=1
for arg in "$@"; do
    case "$arg" in
        --apply) APPLY=1 ;;
        --no-prune) PRUNE=0 ;;
        *) echo "Unknown arg: $arg" >&2; exit 2 ;;
    esac
done

if ! docker info >/dev/null 2>&1; then
    echo "Error: cannot reach Docker daemon (need sudo / docker group)." >&2
    exit 1
fi

KEEP_FILE="$(mktemp)"
trap 'rm -f "$KEEP_FILE"' EXIT

# --- Build keep-list from repo data ----------------------------------------
{
    # vulhub compose image: refs
    find data/vulhub -name docker-compose.yml -exec grep -hE '^[[:space:]]*image:' {} \; 2>/dev/null \
        | sed -E 's/.*image:[[:space:]]*//' | sed 's/[[:space:]]*$//' | sed 's/"//g; s/'\''//g'

    # vulhub Dockerfile FROM base images (build dependencies)
    find data/vulhub -name Dockerfile -exec grep -hE '^FROM ' {} \; 2>/dev/null | awk '{print $2}'

    # raw_records images (JJH-prefixed JSON, one list)
    for rf in data/raw_records_*.json; do
        [ -f "$rf" ] || continue
        python3 - "$rf" <<'PY'
import json, sys
raw = open(sys.argv[1], encoding="utf-8").read().strip()
if raw.startswith("JJH"):
    raw = raw[3:].lstrip()
for row in json.loads(raw):
    name = row.get("image_name")
    if name:
        print(f"{name}:{row.get('image_tag') or 'latest'}")
PY
    done

    # topology templates + scenarios image: refs (covers frrouting/frr, pivot-base, agent, vulhub/*)
    find templates data/scenarios -type f \( -name '*.yaml' -o -name '*.yml' \) 2>/dev/null \
        -exec grep -hE 'image:' {} \; \
        | sed -E 's/.*image:[[:space:]]*//' | sed 's/[[:space:]]*,.*//' | sed 's/[[:space:]]*$//' \
        | sed 's/"//g; s/'\''//g; s/[{}]//g'

    # agent + pivot base images
    grep -hE '^FROM ' docker/Dockerfile docker/pivot-base.Dockerfile 2>/dev/null | awk '{print $2}'

    # explicitly-built cvelab images
    echo "clab-agent:latest"
    echo "cvelab-pivot-base:latest"
} | grep -vE '^[[:space:]]*$' \
  | awk '{ if ($0 !~ /:/) print $0":latest"; else print $0 }' \
  | sort -u > "$KEEP_FILE"

KEEP_COUNT=$(wc -l < "$KEEP_FILE")
echo "Keep-list (cvelab-related images): $KEEP_COUNT entries"

# repo-prefix rules (matched against the repository part before the tag)
keep_by_prefix() {
    local repo="$1"  # repository, no tag
    case "$repo" in
        cve-*)           return 0 ;;
        vulhub/*)        return 0 ;;
        frrouting/frr*)  return 0 ;;
        clab-agent)      return 0 ;;
        cvelab-pivot-base) return 0 ;;
    esac
    return 1
}

# --- List docker images and classify ---------------------------------------
MAP_FILE="$(mktemp)"
trap 'rm -f "$KEEP_FILE" "$MAP_FILE"' EXIT
# skip <none>:<none> (handled by prune); format: repository:tag \t id \t size
docker images --format '{{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Size}}' | grep -v ':<none>$' > "$MAP_FILE"

REMOVE_IDS=()
echo ""
echo "=== Unrelated images (candidates for removal) ==="
removed=0
while IFS=$'\t' read -r repo_tag id size; do
    repo="${repo_tag%:*}"
    if grep -qxF "$repo_tag" "$KEEP_FILE"; then continue; fi
    if keep_by_prefix "$repo"; then continue; fi
    echo "  $repo_tag  [$id]  $size"
    REMOVE_IDS+=("$id")
    removed=$((removed + 1))
done < "$MAP_FILE"
echo ""
echo "Unrelated count: $removed"

if [ "$APPLY" -ne 1 ]; then
    echo ""
    echo "DRY RUN — nothing was removed. Re-run with --apply to delete."
    exit 0
fi

# --- Remove ----------------------------------------------------------------
if [ ${#REMOVE_IDS[@]} -gt 0 ]; then
    echo ""
    echo "Removing ${#REMOVE_IDS[@]} unrelated image(s)..."
    printf '%s\n' "${REMOVE_IDS[@]}" | sort -u | while read -r id; do
        docker rmi -f "$id" >/dev/null 2>&1 && echo "  removed $id" || echo "  skip $id (in use?)"
    done
fi

if [ "$PRUNE" -eq 1 ]; then
    echo ""
    echo "Pruning dangling (<none>) images..."
    docker image prune -f 2>/dev/null | tail -2
fi

echo ""
echo "Done."
