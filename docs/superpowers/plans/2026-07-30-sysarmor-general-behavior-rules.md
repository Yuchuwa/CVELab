# SysArmor General Behavior Rules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Load three product-agnostic behavior rules additively into every SysArmor rc.5 target before the CVELab attack begins.

**Architecture:** CVELab owns unsigned context sets, one rulepack, and one detection policy under the existing `sysarmor-case0` experiment directory. The existing runtime injector copies and applies these assets after Agent health succeeds, verifies both rulesets through the current policy response, and treats any content or policy failure as an injection failure.

**Tech Stack:** JSON SysArmor content envelopes, Bash runtime injection, `sysarmorctl` local control API, pytest contract tests, fake-Docker shell tests.

## Global Constraints

- Pin SysArmor exactly to `v0.1.0-rc.5`.
- Keep `ruleset:cep-endpoint` enabled and add `ruleset:cvelab-general-behavior`.
- Run in observe mode and treat all exported Signals uniformly.
- Do not match product names, CVE identifiers, fixed IP addresses, fixed ports, `/flag`, or `/opt/cvelab`.
- Do not require a pre-injection service-start event.
- Stop the case before attack if content or policy loading fails.
- Use `--allow-unsigned` only for the local CVELab content assets.

---

### Task 1: Add and validate the general behavior content assets

**Files:**
- Create: `data/experiments/stratified-50/sysarmor-case0/rules/context-execution-tools.json`
- Create: `data/experiments/stratified-50/sysarmor-case0/rules/context-network-clients.json`
- Create: `data/experiments/stratified-50/sysarmor-case0/rules/rulepack-general-behavior.json`
- Create: `data/experiments/stratified-50/sysarmor-case0/rules/detection-policy.json`
- Modify: `tests/orchestrator/test_sysarmor_case0_experiment.py`

**Interfaces:**
- Produces: context refs `ctx:cvelab-execution-tools` and `ctx:cvelab-network-clients`.
- Produces: rulepack ref `rulepack:cvelab-general-behavior` containing ruleset `ruleset:cvelab-general-behavior` version `v1`.
- Produces: a standalone detection-policy JSON accepted by `policy apply --type detection`.

- [ ] **Step 1: Write failing asset contract tests**

Add tests that load every JSON file and assert exact IDs, three rule IDs, both policy ruleset refs, observe mode, suppression, and absence of prohibited literals:

```python
def test_general_behavior_rules_are_additive_and_product_agnostic():
    rules = VARIANT / "rules"
    rulepack = json.loads((rules / "rulepack-general-behavior.json").read_text())
    policy = json.loads((rules / "detection-policy.json").read_text())
    assert {r["ref"] for r in policy["rulesets"]} == {
        "ruleset:cep-endpoint", "ruleset:cvelab-general-behavior"
    }
    assert policy["mode"] == "observe"
    assert {r["rule_id"] for r in rulepack["spec"]["rulesets"][0]["rules"]} == {
        "workload_executes_shell_or_interpreter",
        "execution_tool_opens_network_connection",
        "network_client_used_in_workload",
    }
    raw = "\n".join(path.read_text().lower() for path in rules.glob("*.json"))
    for forbidden in ("elasticsearch", "grafana", "apache", "postgresql", "cve-", "/flag", "/opt/cvelab"):
        assert forbidden not in raw
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run: `uv run pytest tests/orchestrator/test_sysarmor_case0_experiment.py -q`

Expected: FAIL because `rules/rulepack-general-behavior.json` does not exist.

- [ ] **Step 3: Add the two context sets**

Use valid unsigned `sysarmor.content/v1` context envelopes. The execution set contains shell and interpreter binary names plus network-capable execution tools; the client set contains generic HTTP, socket, and database clients. No entry contains a product, CVE, lab path, IP, or port.

- [ ] **Step 4: Add the rulepack**

Define:

```json
{
  "id": "ruleset:cvelab-general-behavior",
  "version": "v1",
  "rules": [
    {"rule_id": "workload_executes_shell_or_interpreter", "runtime": {"type": "expr"}},
    {"rule_id": "execution_tool_opens_network_connection", "runtime": {"type": "sequence"}},
    {"rule_id": "network_client_used_in_workload", "runtime": {"type": "expr"}}
  ]
}
```

The first expression matches `process.exec` binary names in the execution context. The sequence groups by `lineage_id`, starts on matching `process.exec`, and accepts `network.connect` from the same process, its direct child, or the same lineage within `2m`. The third expression matches `network.connect` binary names in the client context. Each rule suppresses duplicate lineage/binary bursts for five minutes.

- [ ] **Step 5: Add the additive detection policy**

Use policy ID `cvelab-general-behavior`, version `1`, mode `observe`, and enabled references to both `ruleset:cep-endpoint` version `v1` and `ruleset:cvelab-general-behavior` version `v1`.

- [ ] **Step 6: Run tests and JSON validation**

Run:

```bash
uv run pytest tests/orchestrator/test_sysarmor_case0_experiment.py -q
for file in data/experiments/stratified-50/sysarmor-case0/rules/*.json; do jq -e . "$file" >/dev/null; done
```

Expected: pytest PASS and every `jq` invocation exits 0.

- [ ] **Step 7: Commit the content assets**

```bash
git add data/experiments/stratified-50/sysarmor-case0/rules tests/orchestrator/test_sysarmor_case0_experiment.py
git commit -m "feat(cvelab): add generic sysarmor behavior rules"
```

### Task 2: Gate runtime injection on additive rule loading

**Files:**
- Modify: `data/experiments/stratified-50/sysarmor-case0/scripts/inject-runtime.sh`
- Modify: `data/experiments/stratified-50/sysarmor-case0/tests/inject-runtime-test.sh`
- Modify: `tests/orchestrator/test_sysarmor_case0_experiment.py`

**Interfaces:**
- Consumes: the four files in `sysarmor-case0/rules/` from Task 1.
- Produces: `apply_experiment_rules CONTAINER TARGET REMOTE`, returning nonzero unless all content, dry-run, apply, and verification commands succeed.
- Produces: per-target `*-rules.log` diagnostics.

- [ ] **Step 1: Extend fake Docker with failing rule-load assertions**

Record all `docker cp` and `docker exec -u 0` calls. Assert context assets precede the rulepack, the rulepack precedes policy dry-run, dry-run precedes policy apply, and current-policy verification follows application. Add `FAKE_RULE_FAILURE=1` behavior that rejects content application and assert the injector exits nonzero before printing `all targets healthy`.

- [ ] **Step 2: Run the shell test and verify it fails**

Run: `bash data/experiments/stratified-50/sysarmor-case0/tests/inject-runtime-test.sh`

Expected: FAIL because no rule assets or `content apply` calls appear in the Docker log.

- [ ] **Step 3: Add rule paths and loading helpers**

Set `RULES_DIR="$VARIANT_DIR/rules"`, validate all four local files before target mutation, copy them under the existing private remote directory, and add a helper that executes:

```bash
sysarmorctl --socket /run/sysarmor/agent/control.sock --json content apply --file FILE --allow-unsigned
sysarmorctl --socket /run/sysarmor/agent/control.sock --json policy apply --type detection --file POLICY --dry-run
sysarmorctl --socket /run/sysarmor/agent/control.sock --json policy apply --type detection --file POLICY
sysarmorctl --socket /run/sysarmor/agent/control.sock --json policy current
```

Parse JSON with the packaged `/tmp/.../bin/jq`; accept only successful content statuses, a non-rejected dry-run/apply status, and a current policy containing both enabled ruleset refs.

- [ ] **Step 4: Apply rules to both fresh and already-healthy Agents**

Move the early `continue` so an already healthy rc.5 Agent skips binary installation but still receives and verifies experiment content. Clean the remote directory after rule loading and copy rule logs before cleanup. Print `$target: healthy with additive rules` only after the gate passes.

- [ ] **Step 5: Run focused shell and Python tests**

Run:

```bash
bash -n data/experiments/stratified-50/sysarmor-case0/scripts/inject-runtime.sh
bash data/experiments/stratified-50/sysarmor-case0/tests/inject-runtime-test.sh
uv run pytest tests/orchestrator/test_sysarmor_case0_experiment.py tests/orchestrator/test_sysarmor_runtime.py -q
```

Expected: all commands exit 0.

- [ ] **Step 6: Commit injection gating**

```bash
git add data/experiments/stratified-50/sysarmor-case0/scripts/inject-runtime.sh data/experiments/stratified-50/sysarmor-case0/tests/inject-runtime-test.sh tests/orchestrator/test_sysarmor_case0_experiment.py
git commit -m "feat(cvelab): load sysarmor behavior rules at injection"
```

### Task 3: Document and validate the formal experiment

**Files:**
- Modify: `data/experiments/stratified-50/sysarmor-case0/README.md`
- Modify: `docs/WORK_PROGRESS_REPORT.md`
- Create after execution: `data/experiments/stratified-50/runs/trial-sysarmor-rc5-general-first5-l2-20260730-a/signals/summary.json` and per-target JSONL artifacts.

**Interfaces:**
- Consumes: the existing formal Stratified-50 runner and Signal exporter.
- Produces: one new L2 first-five run whose injection logs prove both rulesets loaded and whose Signal artifacts are exported for every case.

- [ ] **Step 1: Add a failing documentation assertion**

Extend the experiment contract test to require the README to name `ruleset:cvelab-general-behavior`, state that rules are product/CVE independent, and document that rule-loading failure blocks attack execution.

- [ ] **Step 2: Run the contract test and verify it fails**

Run: `uv run pytest tests/orchestrator/test_sysarmor_case0_experiment.py -q`

Expected: FAIL because the README does not yet describe the additive ruleset.

- [ ] **Step 3: Update experiment documentation**

Document the three rule IDs, additive runtime-loading order, unsigned local-test boundary, failure gate, and current rc.5 CIDR/service-parent limitations. Do not claim a detection rate before the formal run.

- [ ] **Step 4: Run the complete focused test suite**

Run:

```bash
uv run pytest tests/orchestrator/test_sysarmor_case0_experiment.py tests/orchestrator/test_sysarmor_runtime.py tests/orchestrator/test_sysarmor_signal_exporter.py tests/orchestrator/test_batch_runner_serial.py -q
bash data/experiments/stratified-50/sysarmor-case0/tests/prepare-assets-test.sh
bash data/experiments/stratified-50/sysarmor-case0/tests/inject-runtime-test.sh
bash -n data/experiments/stratified-50/sysarmor-case0/scripts/*.sh
```

Expected: all tests PASS.

- [ ] **Step 5: Run a real single-target rule smoke**

Run `data/experiments/stratified-50/sysarmor-case0/scripts/smoke-target1.sh`, confirm both rulesets in `policy current`, then execute `/bin/sh -c true` and a bounded `curl` connection inside its target container. Read recent Signals with `sysarmorctl --json signal watch --include-recent --snapshot --limit 20`. Expected rule IDs include at least `workload_executes_shell_or_interpreter` and `network_client_used_in_workload`.

- [ ] **Step 6: Run the first five cases at L2**

Use run ID `trial-sysarmor-rc5-general-first5-l2-20260730-a` and execute:

```bash
uv run python scripts/run_stratified_50_experiment.py \
  --run-id trial-sysarmor-rc5-general-first5-l2-20260730-a \
  --kind agent_trial \
  --max-cases 5 --offset 0 \
  --agent-context l2 --agent-runner openai \
  --parallel 1 --max-turns 80 --agent-timeout 1800 \
  --case-timeout 3600 --noise-level none \
  --sysarmor --sysarmor-detection --sysarmor-signal-window 30 \
  --execute
```

Expected infrastructure result: all 15 targets install rc.5 and load both rulesets before attack. Detection rate is whatever the exported evidence shows.

- [ ] **Step 7: Export Signals and update progress evidence**

Run:

```bash
uv run python scripts/export_sysarmor_signals.py \
  data/experiments/stratified-50/runs/trial-sysarmor-rc5-general-first5-l2-20260730-a/batch \
  --output data/experiments/stratified-50/runs/trial-sysarmor-rc5-general-first5-l2-20260730-a/signals
```

Record flags and Signal presence per case in `docs/WORK_PROGRESS_REPORT.md`, and link the exact run directory. Verify every target has before/after JSONL output, including empty files.

- [ ] **Step 8: Commit documentation and evidence**

```bash
git add data/experiments/stratified-50/sysarmor-case0/README.md docs/WORK_PROGRESS_REPORT.md tests/orchestrator/test_sysarmor_case0_experiment.py data/experiments/stratified-50/runs/trial-sysarmor-rc5-general-first5-l2-20260730-a
git commit -m "test(cvelab): validate generic sysarmor signals on first five"
```
