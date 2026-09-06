# Difficulty Study Runbook

This runbook turns the difficulty protocol into a fail-closed workflow. It
creates study artifacts and validates evidence, but never starts an LLM or a
Range unless an operator explicitly runs the frozen trials.

## 1. Prepare the pilot

```powershell
python scripts/prepare_difficulty_credibility_pilot.py `
  --output data/difficulty_credibility_pilot_manifest_2026-09-03.json
```

The manifest freezes case selection, predictions, baseline features, split
assignment, and dependency hashes.

## 2. Produce KAT evidence

Each case has one evidence file:

```text
evidence/<case-id>.json
```

It contains artifact references under `controls` for `qualification`, `oracle`, `no_op`,
`partial_solution`, `wrong_evidence`, `pre_agent`, and `repeat_verdicts`.
Every control points to a real artifact using a path relative to the evidence
file and its SHA-256:

The case evidence file contains:

```json
{
  "controls": {
    "oracle": {
      "artifact_path": "case-a/oracle.json",
      "artifact_sha256": "<64 lowercase hex characters>"
    }
  }
}
```

The referenced `case-a/oracle.json` is the source of truth:

```json
{
  "case_id": "case-a",
  "control": "oracle",
  "result": {
    "environment_success": true,
    "agent_success": true,
    "objective_achieved": true
  }
}
```

The framework recomputes hashes and reads the result from that artifact. A
declared hash without its artifact, or an artifact whose case/control identity
does not match, cannot qualify a case.

### Restore sealed runtime images

Runtime rebuilds are not accepted as substitutes for frozen images because a
Dockerfile can produce different image IDs across otherwise identical builds.
Restore exact local images from the tracked lock and separately distributed
archives before KAT execution:

```powershell
python scripts/restore_difficulty_runtime_images.py `
  --archive-dir E:\remote_project\CVELab-runtime-images\2026-09-06
```

The restore command verifies the lock seal, archive path confinement, archive
size and SHA-256, and the loaded Docker image ID. It copies verified bytes to a
private temporary file and preflights that the archive contains exactly the
locked tag and OCI image digest before invoking Docker. It validates the archive
even when the exact image is already present and refuses to overwrite a tag that
points at a different image.

If a frozen runtime cannot be recovered before the first qualified KAT, record a
prequalification amendment in the runtime lock, validate and export one exact
replacement image, then refresh only dependency hashes without reselecting cases:

```powershell
python scripts/prepare_difficulty_credibility_pilot.py `
  --amend-existing-manifest data/difficulty_credibility_pilot_manifest_2026-09-03.json `
  --runtime-image-lock data/difficulty_runtime_image_lock_2026-09-06.json `
  --output data/difficulty_credibility_pilot_manifest_2026-09-03.json
```

The amendment must preserve case IDs, splits, predictions, tiers, and Atom
partitions. It verifies the existing manifest seal, permits Atom hash changes
only for CVEs named in the sealed lock, checks their recovery metadata against
the lock, and rejects all template, guide, or unrelated Atom drift. Never use
the normal full-generation mode to amend a frozen study.

### Execute the controls

Generate live KAT evidence without invoking an LLM:

```powershell
python scripts/run_difficulty_kat.py `
  --manifest data/difficulty_credibility_pilot_manifest_2026-09-03.json `
  --evidence-dir data/experiments/difficulty-pilot/evidence `
  --work-dir data/experiments/difficulty-pilot/kat-work `
  --split calibration
```

The runner generates each frozen Range, executes `environment_only` verification,
then exercises the production flag, objective, and execution-witness parsers with
oracle, no-op, partial, and wrong evidence. It records the production verifier's
pre-Agent objective state and repeats the oracle verdict against one hashed
terminal state. Every control is bound to the frozen manifest, case dependencies,
ground truth, and generated scenario. The runner passes an empty API key and never
starts an Agent.

Containerlab must run with the privileges required by the local installation.
When running through a root shell, ensure the installed `clab` binary is present
in root's `PATH`; a missing executable is an infrastructure failure. Missing
pinned runtime images remain a hard failure. An operator may explicitly
add `--rebuild-missing-runtime-images`; rebuild inputs are copied to a per-case
workspace so canonical Atom files are not modified. Rebuilt images still must
match the frozen base and runtime digests. Do not update frozen hashes merely
because a rebuild differs. A scenario is retained when verification cleanup does
not complete, preserving `clab.yaml` and logs for explicit recovery.

## 3. Assess qualification

```powershell
python scripts/manage_difficulty_study.py qualify `
  --manifest data/difficulty_credibility_pilot_manifest_2026-09-03.json `
  --evidence-dir data/experiments/difficulty-pilot/evidence `
  --output data/experiments/difficulty-pilot/qualification.json
```

`status=qualified` requires every case to pass all controls and every frozen
source/dependency hash to remain valid.

## 4. Freeze models and run order

Create a credential-free model registry:

```json
{
  "models": [
    {"id": "provider-model-a", "family": "family-a", "runner": "openai"},
    {"id": "provider-model-b", "family": "family-b", "runner": "openai"},
    {"id": "provider-model-c", "family": "family-c", "runner": "claude"}
  ]
}
```

Then freeze the study:

```powershell
python scripts/manage_difficulty_study.py freeze `
  --manifest data/difficulty_credibility_pilot_manifest_2026-09-03.json `
  --qualification data/experiments/difficulty-pilot/qualification.json `
  --models data/experiments/difficulty-pilot/models.json `
  --attempts-per-model 3 `
  --seed 20260903 `
  --output data/experiments/difficulty-pilot/run-plan.json
```

Freeze fails unless all cases qualify and at least three distinct model
families are present, with one frozen model per family. The plan randomizes trials within each split, assigns
calibration phase 1 and held-out test phase 2, and seals itself with
`plan_sha256`. Credentials must remain in environment variables, never in the
registry or plan.

## 5. Execute frozen trials

Run trials in `sequence` order. Each trial gets an independently reset
environment. Write one result to:

```text
results/<trial.result_file>
```

The minimum result contract is:

```json
{
  "trial_id": "<exact plan trial_id>",
  "case_id": "<exact plan case_id>",
  "model_id": "<exact plan model_id>",
  "model_family": "<exact plan model_family>",
  "attempt": 1,
  "sequence": 1,
  "split": "calibration",
  "plan_sha256": "<exact run-plan seal>",
  "runner": "openai",
  "agent_context": "guided",
  "max_turns": 30,
  "timeout_seconds": 1800,
  "case_dependency_sha256": "<exact trial value>",
  "status": "valid",
  "verifier": {
    "agent_evaluated": true,
    "environment_success": true,
    "agent_success": true,
    "objective_achieved": true
  }
}
```

The operator copies these identity and configuration fields from the exact
trial entry; the shown sequence value is illustrative. Missing fields,
mismatched trial identity/configuration, Harness aborts, cleanup failures, and
environment failures are invalid trials. They do not become Agent failures.

## 6. Collect calibration and fit baselines

```powershell
python scripts/manage_difficulty_study.py collect `
  --plan data/experiments/difficulty-pilot/run-plan.json `
  --results-dir data/experiments/difficulty-pilot/results `
  --split calibration `
  --output data/experiments/difficulty-pilot/calibration-outcomes.json

python scripts/manage_difficulty_study.py fit-baselines `
  --calibration data/experiments/difficulty-pilot/calibration-outcomes.json `
  --output data/experiments/difficulty-pilot/baseline-fit.json
```

Baseline fitting refuses incomplete calibration data. It fits the constant
predictor and available scalar baselines only on calibration outcomes.

## 7. Collect and analyze held-out results

Do not run or inspect test outcomes until calibration choices and baseline
mappings are frozen.

```powershell
python scripts/manage_difficulty_study.py collect `
  --plan data/experiments/difficulty-pilot/run-plan.json `
  --results-dir data/experiments/difficulty-pilot/results `
  --split test `
  --output data/experiments/difficulty-pilot/test-outcomes.json

python scripts/analyze_difficulty_credibility.py `
  data/experiments/difficulty-pilot/test-outcomes.json `
  --baselines data/experiments/difficulty-pilot/baseline-fit.json `
  --output data/experiments/difficulty-pilot/test-analysis.json
```

Formal analysis refuses an incomplete collected split. The report contains
Brier score, log loss, tie-aware Spearman, Kendall tau-b, per-model-family
results, Wilson case intervals, and improvement relative to each calibration-
fit baseline.
