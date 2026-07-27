# SysArmor Runtime-Injection Variant for Stratified-50 Case 0

This directory runs the first solved Stratified-50 case with SysArmor in
observe-only mode. It preserves the original CVELab target images, entrypoints,
commands, and vulnerable services. SysArmor is installed into each running
target after ContainerLab deployment and before any attack starts.

## Requirements

- Linux amd64 Docker host with BTF, bpffs, and cgroup v2
- `docker`, `clab`, `curl`, `sha256sum`, and `awk` on the host
- root access inside each target
- outbound host access when the pinned assets are not cached

Target containers do not access GitHub. The host downloads and verifies the
pinned SysArmor Release, Tetragon archive, and static jq once under
`_build/runtime-assets/`.

## Materialize

From the CVELab repository root:

```bash
data/experiments/stratified-50/sysarmor-case0/scripts/materialize-defended-scenario.py
```

The materializer keeps the original target images and adds the BTF and bpffs
mounts required by SysArmor/Tetragon. ContainerLab's Docker runtime creates
Linux nodes in privileged mode by default.

## Deploy and Inject

```bash
data/experiments/stratified-50/sysarmor-case0/scripts/deploy-and-inject.sh
```

The command prepares verified offline assets, deploys the scenario, injects
SysArmor into `target-1`, `target-2`, and `target-3`, and exits successfully only
after every Agent reports healthy. Do not start attack or validation traffic
before this command returns.

To prepare assets separately:

```bash
data/experiments/stratified-50/sysarmor-case0/scripts/prepare-assets.sh
```

To inject an already deployed topology:

```bash
data/experiments/stratified-50/sysarmor-case0/scripts/inject-runtime.sh \
  --topology data/experiments/stratified-50/sysarmor-case0/scenario/clab.yaml \
  --target target-1 --target target-2 --target target-3
```

## Smoke

```bash
data/experiments/stratified-50/sysarmor-case0/scripts/smoke-target1.sh
```

The smoke starts the original target-1 image, injects twice to verify
idempotency, checks Agent health and process count, and confirms the PHP service
remains reachable.

## Experiment Contract

This variant is observe-only. It measures SysArmor Event/Signal coverage and
overhead and must not be used to claim enforcement, blocking, or prevention.
