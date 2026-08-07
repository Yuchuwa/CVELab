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

The experiment pins SysArmor `v0.1.0-rc.5`. The injector verifies the installed
Agent binary reports that exact version before accepting the health gate or an
idempotent reinjection.

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
after every Agent reports healthy and the additive detection rules load. Do not
start attack or validation traffic before this command returns.

During injection, the default rc.5 `ruleset:cep-endpoint` remains enabled and
the CVELab-owned `ruleset:cvelab-general-behavior` is added in observe mode. The
local unsigned content is product/CVE independent: it does not match product
names, CVE IDs, fixed ports, fixed IPs, `/flag`, or lab-private paths. The
ruleset contains:

- `workload_executes_shell_or_interpreter`
- `execution_tool_opens_network_connection`
- `network_client_used_in_workload`

The injector loads content in this order: execution-tool context, network-client
context, general-behavior rulepack, detection-policy dry-run, detection-policy
apply, then `policy current` verification. Any content, policy, or verification
failure blocks attack execution for that target and writes `*-rules.log` under
`_build/logs/`.

Current rc.5 rule support does not include CIDR membership or declared normal
upstream baselines. Because SysArmor is injected after vulnerable services start,
these rules also do not require seeing the original service parent process
startup event.

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
