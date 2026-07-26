# SysArmor Runtime Injection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the published SysArmor agent inside existing CVELab case targets without rebuilding or replacing their images.

**Architecture:** A host-side asset script downloads and verifies pinned SysArmor, Tetragon, and static jq artifacts. A host-side injector copies those artifacts into already-running ContainerLab targets, calls the official container-profile installer, starts the agent detached, and gates experiment execution on health.

**Tech Stack:** Bash, Docker CLI, ContainerLab YAML, pytest contract tests

## Global Constraints

- First-version targets are Linux amd64 ContainerLab containers running as root.
- Target images, entrypoints, commands, and vulnerable service processes remain unchanged.
- Target containers never access GitHub; every asset is cached and SHA-256 verified on the host.
- One unsupported or unhealthy target fails the defended experiment.
- The workflow remains observe-only and must not claim enforcement.
- Initial SysArmor tag is `v0.1.0-dev.202607261236+07cecada` with package digest `672a4def0a65e8b456193f5dce736bb6a6a713b02dc12625052cedb0ad93708c`.

---

### Task 1: Preserve Original Images During Materialization

**Files:**
- Modify: `data/experiments/stratified-50/sysarmor-case0/scripts/materialize-defended-scenario.py`
- Modify: `tests/orchestrator/test_sysarmor_case0_experiment.py`

**Interfaces:**
- Consumes: source scenario `clab.yaml`
- Produces: `patch_clab(clab: dict) -> dict` that adds runtime privileges without changing `node["image"]`, `cmd`, or entrypoint-related fields

- [ ] **Step 1: Replace Dockerfile assertions with a failing preservation test**

Create an in-memory topology with the three original image names, call
`patch_clab`, and assert the images and commands are unchanged while
`privileged`, BTF, bpffs, cgroup namespace, and restart policy are present.

- [ ] **Step 2: Run the focused test and verify it fails**

Run: `uv run pytest tests/orchestrator/test_sysarmor_case0_experiment.py -q`

Expected: FAIL because `patch_clab` replaces target images with
`sysarmor-case0-target-*`.

- [ ] **Step 3: Remove image replacement from the materializer**

Delete `IMAGE_BY_TARGET`. Iterate the explicit target tuple
`("target-1", "target-2", "target-3")` and retain only runtime requirement
patching.

- [ ] **Step 4: Run the focused test and commit**

Run: `uv run pytest tests/orchestrator/test_sysarmor_case0_experiment.py -q`

Expected: PASS.

Commit: `test: preserve original images for SysArmor injection`

### Task 2: Prepare Verified Offline Assets

**Files:**
- Create: `data/experiments/stratified-50/sysarmor-case0/scripts/prepare-assets.sh`
- Create: `data/experiments/stratified-50/sysarmor-case0/scripts/runtime-assets.env`
- Create: `data/experiments/stratified-50/sysarmor-case0/tests/prepare-assets-test.sh`
- Modify: `tests/orchestrator/test_sysarmor_case0_experiment.py`

**Interfaces:**
- Consumes: optional `SYSARMOR_CASE0_CACHE_DIR` and `SYSARMOR_CASE0_DOWNLOAD_CMD`
- Produces: verified files named by `SYSARMOR_PACKAGE_FILE`, `TETRAGON_FILE`, and `JQ_FILE` in the cache directory
- Produces manifest constants for URL and SHA-256 of all three assets

- [ ] **Step 1: Write a failing shell test**

The test creates local fixture assets, substitutes their `file://` URLs and
digests through environment overrides, verifies successful preparation, then
corrupts one cached file and verifies it is downloaded and revalidated. A
fixture with a wrong expected digest must exit nonzero and must not leave the
final cache filename behind.

- [ ] **Step 2: Run the shell test and verify it fails**

Run:
`bash data/experiments/stratified-50/sysarmor-case0/tests/prepare-assets-test.sh`

Expected: FAIL because `prepare-assets.sh` does not exist.

- [ ] **Step 3: Implement atomic download and digest validation**

`runtime-assets.env` pins the SysArmor values from Global Constraints, Tetragon
`v1.7.0` URL and digest
`67fe2cad1fbf601a3617eb441423f7e3a01a5cefc8ef56045406c60a68d0f772`, and
static jq 1.7.1 amd64 URL and verified digest. `prepare-assets.sh` sources the
manifest, using jq digest
`478c9ca129fd2e3443fe27314b455e211e0d8c60bc8ff7df703873deeee580c2`, checks
an existing cache before reuse, downloads to a temporary file, verifies with
`sha256sum`, and atomically renames it.

- [ ] **Step 4: Run tests and commit**

Run the shell test and
`uv run pytest tests/orchestrator/test_sysarmor_case0_experiment.py -q`.

Expected: both PASS.

Commit: `feat: prepare verified SysArmor runtime assets`

### Task 3: Inject and Health-Gate Running Targets

**Files:**
- Create: `data/experiments/stratified-50/sysarmor-case0/scripts/inject-runtime.sh`
- Create: `data/experiments/stratified-50/sysarmor-case0/tests/inject-runtime-test.sh`
- Modify: `tests/orchestrator/test_sysarmor_case0_experiment.py`

**Interfaces:**
- Command: `inject-runtime.sh --topology PATH --target NAME [--target NAME ...]`
- Consumes: prepared cache from Task 2 and deployed containers named `clab-<topology-name>-<target>`
- Produces: healthy detached agent in every target, per-target logs under `_build/logs`, and exit status 0 only if all targets pass

- [ ] **Step 1: Write fake-Docker contract tests**

Put a fake `docker` first in `PATH` and record argv. Cover exact container
resolution from topology name, host and container preflight, copy/extract/install
commands, detached agent start, bounded health polling, cleanup, checksum
failure, and early success when the requested healthy version is already
installed.

- [ ] **Step 2: Run the shell test and verify it fails**

Run:
`bash data/experiments/stratified-50/sysarmor-case0/tests/inject-runtime-test.sh`

Expected: FAIL because `inject-runtime.sh` does not exist.

- [ ] **Step 3: Implement the injector**

Parse topology `name:` without broad container matching, validate target names,
perform host checks for amd64/BTF/bpffs/cgroup v2, revalidate asset digests,
inspect each exact Docker container, execute the installer with temporary jq and
the local Tetragon archive, launch
`/opt/sysarmor/agent/bin/sysarmor-agent run --config /etc/sysarmor/agent/agent.yaml`
using `docker exec -d`, and poll `/usr/local/bin/sysarmorctl` until healthy or
timeout. Capture install and agent logs without dumping environment variables.

- [ ] **Step 4: Run contract tests and commit**

Run the shell test and focused pytest file.

Expected: both PASS.

Commit: `feat: inject SysArmor into running case targets`

### Task 4: Case0 Workflow, Documentation, and Docker Smoke

**Files:**
- Create: `data/experiments/stratified-50/sysarmor-case0/scripts/deploy-and-inject.sh`
- Replace: `data/experiments/stratified-50/sysarmor-case0/scripts/smoke-target1.sh`
- Modify: `data/experiments/stratified-50/sysarmor-case0/README.md`
- Modify: `tests/orchestrator/test_sysarmor_case0_experiment.py`

**Interfaces:**
- Command: `deploy-and-inject.sh [TOPOLOGY]` deploys the topology and invokes Task 3 for target-1 through target-3
- Command: `smoke-target1.sh` tests injection against the original target-1 image

- [ ] **Step 1: Add failing workflow contract assertions**

Assert the deploy script runs `prepare-assets.sh`, `clab deploy`, and
`inject-runtime.sh` in that order, passes all three explicit targets, and the
README no longer instructs users to build `sysarmor-case0-target-*` images.

- [ ] **Step 2: Run focused pytest and verify it fails**

Run: `uv run pytest tests/orchestrator/test_sysarmor_case0_experiment.py -q`

Expected: FAIL because the workflow script and updated documentation do not
exist.

- [ ] **Step 3: Implement workflow and smoke**

The deploy script prepares assets, deploys `scenario/clab.yaml`, injects all
three explicit targets, and returns only after health succeeds. The smoke starts
the original target-1 image with the required privileges and mounts, injects
twice, asserts one agent process, verifies the PHP endpoint, and always removes
its test container.

- [ ] **Step 4: Run unit and static verification**

Run:

```bash
bash -n data/experiments/stratified-50/sysarmor-case0/scripts/*.sh
bash data/experiments/stratified-50/sysarmor-case0/tests/prepare-assets-test.sh
bash data/experiments/stratified-50/sysarmor-case0/tests/inject-runtime-test.sh
uv run pytest tests/orchestrator/test_sysarmor_case0_experiment.py -q
```

Expected: all PASS.

- [ ] **Step 5: Run environment-dependent Docker smoke**

Run:
`data/experiments/stratified-50/sysarmor-case0/scripts/smoke-target1.sh`

Expected: original PHP service reachable, agent healthy, second injection
idempotent, exactly one agent process.

- [ ] **Step 6: Commit**

Commit: `feat: run case0 with runtime SysArmor injection`
