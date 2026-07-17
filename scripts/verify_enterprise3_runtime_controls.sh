#!/usr/bin/env bash
# Run the two single-variable enterprise_3tier environment controls.
# Invoke from the repository root with sudo, because ContainerLab requires it:
#   sudo -E bash scripts/verify_enterprise3_runtime_controls.sh
# Run the two Guided-Agent trials sequentially (uses the project .env):
#   sudo -E env RUN_MODE=guided-agent bash scripts/verify_enterprise3_runtime_controls.sh

set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-/home/hanlin/miniconda3/envs/playbook/bin/python}"
OUTPUT_DIR="${OUTPUT_DIR:-data/scenarios_runtime_matrix}"
RUN_MODE="${RUN_MODE:-environment-only}"

cd "$ROOT_DIR"
export PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"
# The verifier invokes ansible-playbook as a subprocess.  sudo commonly resets
# PATH, so retain the executable directory belonging to the selected Python.
export PATH="$(dirname -- "$PYTHON_BIN"):$PATH"

case "$RUN_MODE" in
  environment-only)
    VERIFY_ARGS=(--environment-only)
    ;;
  guided-agent)
    # Empty values inherited through sudo prevent load_dotenv() from loading
    # the project configuration.  Preserve explicit non-empty overrides.
    for variable in LLM_API_KEY LLM_BASE_URL LLM_MODEL; do
      if [[ -z "${!variable:-}" ]]; then
        unset "$variable"
      fi
    done
    VERIFY_ARGS=()
    ;;
  *)
    echo "RUN_MODE must be environment-only or guided-agent" >&2
    exit 2
    ;;
esac

run_case() {
  local name="$1"
  local cves="$2"

  echo "[$RUN_MODE] $name: $cves"
  "$PYTHON_BIN" -c "from clab_builder.cli import main; main()" \
    verify enterprise_3tier \
    --cve "$cves" \
    --name "$name" \
    --output "$OUTPUT_DIR" \
    --validation-mode guided_agent \
    "${VERIFY_ARGS[@]}"
}

run_case "enterprise3-runtime-b01-dmz-42013" \
  "CVE-2021-42013,CVE-2018-16509,CVE-2019-9193"
run_case "enterprise3-runtime-b02-app-17558" \
  "CVE-2022-22965,CVE-2019-17558,CVE-2019-9193"
