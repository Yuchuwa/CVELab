# SysArmor v0.1.0-rc.5 CVELab Validation

Date: 2026-07-30 (Asia/Shanghai)

## Release identity

- Release commit: `454b69d6c01f778add5836e0af1c9ba3299fd5b1`
- Asset: `sysarmor-agent-linux-amd64-v0.1.0-rc.5.tar.gz`
- SHA-256: `e2ea105552b1e37ab8badb2f03da0f622309bdabaa1010a257cf19c2cca7eb26`
- `manifest.json.version`: `v0.1.0-rc.5`
- `sysarmor-agent version`: `v0.1.0-rc.5`
- `sysarmorctl version`: `v0.1.0-rc.5`

The GitHub Release API digest, locally downloaded asset digest, and checked-in
runtime manifest agree.

## Contract and smoke verification

Commands:

```bash
uv run pytest tests/orchestrator/test_sysarmor_case0_experiment.py -q
bash -n data/experiments/stratified-50/sysarmor-case0/scripts/*.sh
bash data/experiments/stratified-50/sysarmor-case0/tests/prepare-assets-test.sh
bash data/experiments/stratified-50/sysarmor-case0/tests/inject-runtime-test.sh
data/experiments/stratified-50/sysarmor-case0/scripts/smoke-target1.sh
```

Results:

- Python contract tests: 6 passed.
- Shell syntax, asset preparation, and fake-Docker injection tests: passed.
- Real target-1 smoke: original PHP service reachable, Agent healthy, exact
  `v0.1.0-rc.5` binary version, and idempotent reinjection with one Agent process.

## Clean Event visibility

A disposable target-1 container used the original CVE runtime image, the same
BTF/bpffs mounts, `--privileged --cgroupns=host`, and the checked-in injector.
The Agent health response used `scope.type=container` with a 64-character Docker
selector. A controlled write/read/remove probe changed `sensor.eventsSeen` from
7485 to 29384. The disposable container was removed after the check.

Reproduction outline from the CVELab repository root:

```bash
work="$(mktemp -d)"
name="clab-sysarmor-rc5-event-target-1"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
printf 'name: sysarmor-rc5-event\ntopology:\n  nodes: {}\n' >"$work/clab.yaml"
docker run -d --name "$name" --privileged --cgroupns=host \
  -v "$PWD/data/atoms/CVE-2018-16509/init/index.php:/var/www/html/index.php:ro" \
  -v /sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  cvelab-runtime-2018-16509-ab809fb197 \
  php -t /var/www/html -S 0.0.0.0:8080 >/dev/null
data/experiments/stratified-50/sysarmor-case0/scripts/inject-runtime.sh \
  --topology "$work/clab.yaml" --target target-1
docker exec "$name" /usr/local/bin/sysarmorctl --json agent health >"$work/before.json"
docker exec "$name" sh -c \
  'printf rc5-event-probe >/tmp/sysarmor-rc5-event-probe; cat /tmp/sysarmor-rc5-event-probe >/dev/null; rm /tmp/sysarmor-rc5-event-probe'
sleep 2
docker exec "$name" /usr/local/bin/sysarmorctl --json agent health >"$work/after.json"
jq '{status,scope,sensor,detection}' "$work/before.json" "$work/after.json"
```

An independent disposable copy of the full three-target ContainerLab topology
was then deployed under lab name `e3-rc5-scope-validation`. After injection and
one controlled file probe per target, health returned:

| Target | Status | Sensor running | Policy loaded | Events seen | Manifest |
| --- | --- | --- | --- | ---: | --- |
| target-1 | ok | true | true | 18 | v0.1.0-rc.5 |
| target-2 | ok | true | true | 19 | v0.1.0-rc.5 |
| target-3 | ok | true | true | 19 | v0.1.0-rc.5 |

Each target reported its own 64-character container selector. The temporary lab
and the one-target probe container were destroyed after validation.

Three-target reproduction outline:

```bash
work="$(mktemp -d)"
lab="e3-rc5-scope-validation"
trap 'clab destroy -t "$work/clab.yaml" -c >/dev/null 2>&1 || true' EXIT
cp -a data/experiments/stratified-50/sysarmor-case0/scenario/. "$work/"
sed -i "1s/^name:.*/name: $lab/" "$work/clab.yaml"
clab deploy -t "$work/clab.yaml"
data/experiments/stratified-50/sysarmor-case0/scripts/inject-runtime.sh \
  --topology "$work/clab.yaml" \
  --target target-1 --target target-2 --target target-3
for target in target-1 target-2 target-3; do
  name="clab-$lab-$target"
  docker exec "$name" sh -c \
    'printf rc5-scope-probe >/tmp/rc5-scope-probe; cat /tmp/rc5-scope-probe >/dev/null; rm /tmp/rc5-scope-probe'
done
sleep 2
for target in target-1 target-2 target-3; do
  name="clab-$lab-$target"
  docker exec "$name" /usr/local/bin/sysarmorctl --json agent health | jq -c \
    --arg target "$target" \
    '{target:$target,status,scope,eventsSeen:.sensor.eventsSeen,sensorRunning:.sensor.running,policyLoaded:.sensor.policyLoaded,manifestVersion:.detection.defaultManifestVersion}'
done
```

This proves that `event_stream_blind:no_events_seen` no longer reproduces on a
clean rc.5 installation. The controlled probe is not a full Case 0 attack and
does not establish attack Signal coverage.

## Legacy upgrade boundary

An in-place upgrade attempt against the pre-existing three-day Case 0 lab stopped
at target-1. The old policy had `detection: {}`, while rc.5 requires an explicit
detection ruleset. The installer preserves an existing policy file, so the rc.5
Agent rejected that legacy policy. The old target-1 was restored to its prior
development binary/configuration and returned `status=ok`, sensor running, and
policy loaded. Target-2 and target-3 were not changed by the failed serial upgrade.

This is a cross-version policy migration issue, separate from the fixed Tetragon
container ID matching behavior.
