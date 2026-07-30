# SysArmor General Behavior Rules for CVELab

## Goal

Add an experiment-owned, general-purpose detection ruleset to the SysArmor
v0.1.0-rc.5 runtime used by the Stratified-50 experiments. The rules should
emit useful Signals for command execution and follow-on network activity
without matching CVE identifiers, product names, fixed lab addresses, flag
paths, or CVELab-specific directories.

The ruleset is additive. Each target keeps the published
`ruleset:cep-endpoint` ruleset and also enables
`ruleset:cvelab-general-behavior`. Experiment reporting treats all emitted
Signals uniformly; it does not calculate separate baseline and incremental
detection metrics.

## Scope and Semantics

The first version contains three endpoint rules:

1. `workload_executes_shell_or_interpreter` emits a medium-severity Signal
   when a monitored target executes a shell or general scripting interpreter
   after the experiment rules have loaded. The context contains binary names
   such as `sh`, `bash`, `dash`, `python`, `python3`, `perl`, `php`, and `ruby`.
2. `execution_tool_opens_network_connection` emits a high-severity Signal when
   a shell, scripting interpreter, or network-capable execution tool is
   followed by a network connection in the same lineage within two minutes.
   The sequence correlates stable process identifiers where the event data
   provides them.
3. `network_client_used_in_workload` emits a medium-severity Signal when a
   general network or database client such as `curl`, `wget`, `nc`, `ncat`,
   `netcat`, `socat`, `psql`, `mysql`, `mongo`, `mongosh`, or `redis-cli`
   establishes a connection from a monitored target.

These are workload-container behavior Signals, not proof that a particular
CVE was exploited. They intentionally favor attack coverage during the bounded
experiment window. Suppression keys limit repeated Signals from the same
lineage and binary while preserving at least one artifact for evaluation.

## Capability Boundaries

SysArmor rc.5 rule conditions support exact values, sets, string prefixes and
suffixes, numeric comparisons, and temporal event correlation. They do not
provide CIDR membership tests or a declared-upstream baseline. Consequently,
the first version does not label a connection as RFC1918 lateral movement or
compare it with an application-specific allowlist.

The installed Agent begins observing after the vulnerable service has already
started. Its event stream therefore may not contain the service parent's
original `process.exec` event. The rules must not require an observed web-server
startup event as a prerequisite. Container scope supplies the workload context:
only the explicitly selected target container is monitored.

The rules do not reference Elasticsearch, Grafana, Apache, PostgreSQL, any CVE
number, `/flag`, `/opt/cvelab`, fixed ports, or fixed IP addresses.

## Experiment Assets

Versioned assets live under the existing SysArmor experiment directory:

```text
data/experiments/stratified-50/sysarmor-case0/rules/
  context-execution-tools.json
  context-network-clients.json
  rulepack-general-behavior.json
  detection-policy.json
```

The context sets hold reusable behavior categories. The rulepack references
only those context sets and canonical event fields supported by rc.5. The
detection policy enables both `ruleset:cep-endpoint` and
`ruleset:cvelab-general-behavior` in observe mode.

All experiment content is unsigned and is admitted with
`--allow-unsigned`. This exception is limited to the local CVELab targets and
is not presented as a production content-distribution practice.

## Loading Flow

The runtime injector performs the existing release installation, scope rewrite,
Agent start, version check, and health gate first. It then copies the experiment
assets into a private temporary directory inside each target and applies them
in dependency order:

1. Apply both context sets with `sysarmorctl content apply --allow-unsigned`.
2. Apply the general behavior rulepack with the same local-test admission.
3. Dry-run the detection policy with `policy explain` or `policy apply
   --type detection --dry-run`.
4. Apply the detection policy with `policy apply --type detection`.
5. Query Agent health and current policy, and verify that detection is loaded
   and both ruleset references are enabled.
6. Remove the copied rule assets with the other temporary injection files.

An already healthy rc.5 installation is not considered fully ready until this
rule-loading gate also succeeds. Reapplying identical content and policy must
be accepted so repeated injection remains idempotent.

## Failure Handling

Content validation, content application, policy dry-run, policy application,
or post-apply verification failure makes the target injection fail. The formal
case must stop before the attack begins and report an environment failure,
rather than recording a false detection miss.

Per-target logs retain the JSON responses for failed content and policy
operations. Successful logs record content references and policy/ruleset IDs,
but do not dump full event streams or process environments.

## Orchestration and Reporting

The existing formal runner continues to use a single `--sysarmor` switch. When
enabled, every selected target receives rc.5 and the additive experiment
ruleset before the attack Agent starts. There is no per-case product mapping or
rule selection.

Signal export continues to write before/after JSONL files for each target and a
case summary. A case satisfies the detection task when at least one new Signal
is present after the attack. The exported Signal retains its rule ID, ruleset
reference, severity, event references, process lineage, and relevant socket or
file entities.

## Testing

Static JSON tests validate that all assets parse, IDs and versions agree, the
policy references both rulesets, and prohibited product-, CVE-, lab-path-,
address-, and port-specific literals are absent.

The fake-Docker injector test verifies dependency-ordered copies and commands,
root execution, dry-run before policy application, post-apply health checks,
idempotent reinjection, and failure propagation.

Rule behavior is tested against synthetic canonical events covering:

- shell/interpreter execution emits the first Signal;
- a matching execution-to-connect sequence emits the second Signal;
- a network client connection emits the third Signal;
- unrelated workload execution does not emit these Signals;
- suppression prevents duplicate bursts from inflating results.

After local tests pass, the first five Stratified-50 cases are rerun at L2.
The run is accepted only if all targets load both rulesets before attack and
Signal artifacts are exported for every case. Detection coverage is reported
from observed results and is not assumed to be five out of five.

## Success Criteria

The implementation is complete when the additive ruleset loads idempotently on
all three targets of each of the first five cases, attacks do not begin after a
rule-loading failure, the three rule behaviors pass focused tests, and the
formal run exports auditable Signal JSONL artifacts without using product-,
CVE-, fixed-network-, flag-, or CVELab-path-specific matching.
