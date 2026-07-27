# SysArmor Runtime Injection for CVELab Cases

## Goal

Instrument CVELab ContainerLab target containers with the published SysArmor
standalone agent without rebuilding or replacing their runtime images. Preserve
each target's original image, entrypoint, command, and vulnerable service
behavior.

The first implementation applies to the Stratified-50 `sysarmor-case0`
experiment. The scripts and contracts must be reusable by later CVELab cases.

## Scope

The runtime injector supports Linux amd64 ContainerLab targets managed through
Docker. It installs SysArmor after ContainerLab deploys the original targets and
before any attack or experiment validation begins.

The first version does not support arbitrary Docker Compose projects, non-amd64
images, non-root target containers, sidecar deployment, or enforcement claims.
The experiment remains observe-only.

## Release Inputs

The asset preparation step downloads immutable, versioned inputs into a host
cache under the experiment build directory:

- SysArmor GitHub Release tarball
- Tetragon release archive required by that SysArmor release
- statically linked amd64 `jq`

Every URL and expected SHA-256 digest is declared by the preparation script or
its version manifest. Downloads use a temporary file, are verified before being
renamed into the cache, and are reused only after their digest is rechecked.
Target containers never access GitHub.

The initial SysArmor input is:

- tag: `v0.1.0-dev.202607261236+07cecada`
- package: `sysarmor-agent-linux-amd64-v0.1.0-dev.202607261236+07cecada.tar.gz`
- SHA-256: `672a4def0a65e8b456193f5dce736bb6a6a713b02dc12625052cedb0ad93708c`

The preparation step derives the Tetragon version, URL, and digest from the
verified SysArmor package's `sensors/tetragon/bundle.env`. The static `jq`
version, URL, and digest are pinned explicitly.

## Scenario Materialization

The defended scenario keeps the original target image references. The
materializer adds only the runtime mounts required by SysArmor/Tetragon:

- `/sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro`
- `/sys/fs/bpf:/sys/fs/bpf`
- restart policy `unless-stopped`

It does not replace image names, entrypoints, or commands.
ContainerLab 0.72 creates Docker-backed Linux nodes in privileged mode by
default; its topology schema does not accept `privileged` or raw `docker-opts`
node fields.

## Injection Flow

The injector receives a ContainerLab topology path and an explicit target list.
For each target, it resolves the deployed container using ContainerLab's lab and
node naming contract. It must not discover targets by broad Docker name
matching.

Before mutating a target, the injector checks:

1. The host is Linux amd64 and exposes BTF, mounted bpffs, and cgroup v2.
2. The container exists and is running.
3. Docker reports the image as Linux amd64.
4. The container runs as UID 0.
5. Required installation directories are writable.
6. The container provides `sh`, `tar`, `gzip`, `install`, `cp`, `mv`, `mktemp`,
   `find`, `sha256sum`, and `awk`.
7. The cached assets still match their expected digests.

The injector then performs these steps per target:

1. Create a private temporary directory in the running container.
2. Copy the verified SysArmor package, Tetragon archive, and static `jq` into it.
3. Extract the SysArmor package.
4. Run the packaged installer with the temporary `jq` first in `PATH`,
   `SYSARMOR_TETRAGON_ARCHIVE` pointing at the copied archive, and profile
   `linux-container`.
5. Rewrite the installed sensor scope from `namespace/self` to `container` with
   the exact Docker container ID. This preserves per-target isolation without
   requiring ContainerLab to expose Docker's `--cgroupns=host` option.
6. Start the installed Agent detached inside the existing target container.
7. Poll `sysarmorctl agent health` with bounded per-call and overall timeouts.
8. Remove copied archives and temporary extraction data after success or
   failure, while retaining diagnostic logs.

The target service continues running throughout injection. The injector does
not replace PID 1 and does not alter the original workload process.

## Health Gate and Idempotency

No attack, agent evaluation, or experiment validation may begin until every
declared target reports a healthy SysArmor Agent. One unsupported or unhealthy
target fails the entire defended experiment.

Before installation, the injector checks the installed Agent health and its
version. A healthy Agent at the requested version is accepted without
reinstallation or another process. A missing, unhealthy, or different version
is stopped if necessary and reinstalled from the pinned assets. At most one
Agent process may remain for each target.

The few seconds between vulnerable service startup and completion of this gate
are accepted. Experiment orchestration must not send attack traffic during that
window.

## Errors and Diagnostics

Failures identify the target and phase: host preflight, container preflight,
asset copy, package extraction, installation, Agent start, or health wait. The
injector exits nonzero on the first failure and prints a summary for all targets
attempted so far.

Per-target install and Agent logs are copied to the host experiment build
directory before temporary container files are removed. Secrets and complete
environment dumps are not logged.

## Repository Changes

The case0 experiment will replace its image-building main path with:

- a versioned asset preparation script;
- a reusable runtime injection script;
- an experiment entry script that deploys, injects, waits for health, and only
  then allows the existing experiment workflow to continue.

The existing derived Dockerfiles may remain temporarily as historical fallback,
but the README and tests will no longer require or advertise them. The existing
`build-images.sh` will not be used by the runtime-injection workflow.

## Testing

Shell tests use a fake Docker executable to cover container resolution,
preflight failures, checksum rejection, command construction, health polling,
idempotent reinjection, cleanup, and nonzero failure propagation without
requiring privileged Docker.

Python contract tests verify that materialization preserves original image
references and adds exactly the required runtime settings. They also verify the
new scripts are executable and that the documented release version and digest
match the preparation manifest.

A Docker integration smoke uses the three case0 targets and succeeds only when:

- all original vulnerable services remain reachable;
- all three Agents report healthy;
- each target has exactly one Agent process; and
- a second injection run succeeds without starting duplicate Agents.

The integration smoke is an explicit environment-dependent test and is not part
of the default unit-test suite.

## Success Criteria

The design is complete when case0 runs with its three original images, no
`sysarmor-case0-target-*` image is required, all targets pass the health gate,
the original services remain reachable, and repeated injection is idempotent.
