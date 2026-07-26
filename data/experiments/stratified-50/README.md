# Stratified-50 Formal Experiments

This note defines the formal experiment layout for the Stratified-50 range set.
It keeps old smoke results separate from new report-grade runs.

## Directory Layout

Formal runs live under:

```text
data/experiments/stratified-50/runs/<run-id>/
  run_manifest.json
  case_index.json
  batch/
  artifacts/
  logs/
  cases/
```

`run_manifest.json` is immutable. It records the case manifest hash, selected case
IDs, git commit and dirty marker, agent context, runner, model label, and the exact
batch command. It must not contain API keys or provider secrets.

`case_index.json` is mutable. It starts with every case as `not_started` and can be
refreshed from `batch/.batch/results/*.json` after execution. Qualification outcome
and agent outcome are separate fields, so an infrastructure failure is not counted
as an agent failure.

## Qualification Run

Create a clean L2 qualification run without executing ContainerLab:

```bash
uv run scripts/run_stratified_50_experiment.py \
  --kind qualification \
  --run-id qual-stratified50-l2-openai-20260726 \
  --agent-context l2 \
  --agent-runner openai \
  --base-url-label configured-env \
  --parallel 1
```

Execute the same run by adding `--execute` when the host is ready:

```bash
uv run scripts/run_stratified_50_experiment.py \
  --kind qualification \
  --run-id qual-stratified50-l2-openai-YYYYMMDD \
  --agent-context l2 \
  --agent-runner openai \
  --base-url-label configured-env \
  --parallel 1 \
  --execute
```

Qualification runs call the mature batch runner in `--environment-only` mode and
write results under the run's `batch/` directory.

## Agent Trials

Agent trials should reference a frozen qualification run:

```bash
uv run scripts/run_stratified_50_experiment.py \
  --kind agent_trial \
  --run-id trial-stratified50-l0-openai-YYYYMMDD \
  --parent-qualification-run qual-stratified50-l2-openai-YYYYMMDD \
  --agent-context l0 \
  --agent-runner openai \
  --model <model-id> \
  --base-url-label <provider-label> \
  --parallel 1
```

For the report, K2 domain knowledge maps directly to CVELab `l2`. Do not introduce
a separate K2 package layer unless the report design changes.

## Report-Level Conditions

Use the following working mapping:

| Report condition | CVELab setting |
| --- | --- |
| LLM on range | `agent_context=l0` |
| LLM + SDK harness on range | same range runner with SDK-backed `agent_runner` |
| LLM + SDK harness + domain knowledge | `agent_context=l2` |
| LLM + SDK harness + domain knowledge + SysArmor standalone | same as L2, with SysArmor standalone installed by the range setup once that integration is added |

The current implementation provides the formal run and manifest layer. SysArmor
standalone installation is intentionally left as a later range setup change.
