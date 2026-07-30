# Interface and Artifact Registry

Status: active

Last reviewed: 2026-07-30

This document identifies the contracts that connect CVELab modules. It is a
registry, not a duplicate of every Pydantic field.

## Authority

```text
Pydantic model or current implementation
-> contract test
-> this registry and linked contract documents
-> generated status artifact
-> historical prose
```

Changing a stable contract requires updating its producer, consumer, tests and
this registry in the same change.

## Contract Registry

| Contract | Producer | Consumer | Authority | Stability |
|---|---|---|---|---|
| Atom v3 | Atomizer | Atom loader, matcher, assembler | `shared/models/atom.py` | stable |
| Atom build status v2 | Shared status generator | Atom planning and handoff | `shared/atom_pool_status.py` | versioned generated snapshot |
| Exploit Guide | Atomizer | Guided Agent preflight and prompt | `shared/models/exploit_guide.py` | stable, version semantics need cleanup |
| Topology Template | Template authors | Template loader, matcher, assembler | `shared/models/template.py` | stable |
| Scenario manifest v1 | Scenario assembler | Verifier, batch runner, exporters | `shared/models/artifact_contracts.py` | versioned |
| Ground Truth | Scenario assembler | Verifier only | `scenario_assembler.py` | private, untyped |
| Agent input | Verifier | Agent runner | `verifier.py`, `scenario_runner.py` | stable behavior, untyped |
| Agent output | Agent runner | Verifier | runner implementations | stable behavior, untyped |
| Verification result v1 | Verifier | Batch runner, analysis, SFT | `shared/models/artifact_contracts.py` | versioned |
| Range matrix status v1 | Range matrix generator | Planning, docs, batch preparation | `generate_enterprise3_matrix.py` | versioned compact view |
| Range build status v1 | Range progress generator | Range planning and experiment denominators | `shared/range_progress.py` | versioned sanitized snapshot |
| Experiment status v1 | Range progress generator | Research planning and reporting | `shared/range_progress.py` | versioned sanitized snapshot |
| Experiment manifest | Matrix/select scripts | Batch runner | batch script loaders | operational |
| Batch state/summary | Batch runner | Resume and analysis tools | batch runner | operational |

Ground Truth, Agent I/O and batch files still need versioned Pydantic or JSON
Schema models. Until those exist, field removals or renames are breaking
changes.

## Atom v3

Location: `data/atoms/<CVE>/atom.yaml`

Key contract groups:

- Identity and classification.
- `runtime_spec` and runtime provenance.
- `source_bundle` and material metadata.
- `exploit_access.required_service`.
- verified `capability_grants`.
- `flag_spec` and `validation_spec`.
- native, runtime and orchestrated verification records.
- reference to `exploit_guide.yaml`.

Atom lifecycle has exactly three states: `planned`, `building` and `completed`.
The internal qualification checks remain compatibility diagnostics for current
loaders; they are not lifecycle states and must not be reported as Atom types.
Do not use `verified=true` or one successful check as a substitute for strict
`completed`.

## Atom Pool Status

`data/atom_pool_status.json` is the authoritative generated build snapshot.
`atom_pool_status.csv` and `atom_pool_status.md` are views produced by
`scripts/generate_atom_pool_status.py`; they are not edited independently.

The snapshot defines and counts only `planned`, `building` and `completed`.
Every view carries the same `generated_at` and `snapshot_hash`. Completion
checks and blockers explain status without creating additional Atom types.
The strict gates are defined in
[`ATOM_BUILD_GUIDE.md`](ATOM_BUILD_GUIDE.md).

Matrix candidates, accepted bindings and rejection reasons belong to Range
manifests under `data/range_matrices/`; they are template- and rule-specific.
See [`RANGE_BUILD_GUIDE.md`](RANGE_BUILD_GUIDE.md).

`data/range_matrix_status.json` is the tracked Range-side summary. It records
the source Atom snapshot hash, Range candidate IDs, selected IDs and rejection
counts. Full manifests remain local experiment artifacts.

`data/range_build_status.json` records every discovered sanitized Range attempt
with generation, environment, Range build, attack graph, attack path, cleanup,
Agent and objective stages. Its CSV and Markdown views are generated from the
same snapshot. `data/experiment_status.*` groups those attempts by batch and
records the declared model, runner and experiment dimensions.

## Exploit Guide

Location: `data/atoms/<CVE>/exploit_guide.yaml`

The Guide contains ordered steps, execution scope, typed tool requirements,
materials, success signals and post-exploit capabilities. It is advisory. Range
IP addresses, ports, dependencies and capabilities remain authoritative.

The current model defaults still expose historical version values. Treat Guide
version normalization as a tracked schema task; do not silently infer a version
from a filename.

See [`ATOM_RANGE_EXECUTION_CONTRACT.md`](ATOM_RANGE_EXECUTION_CONTRACT.md).

## Template

Location: `templates/<name>/template.yaml`

The template owns:

- zones, routers, transits and isolation;
- injection points and dependencies;
- required service/capability constraints;
- assets and service-family variants;
- public objective text and private assertions;
- optional benign noise services.

The template must express reusable service contracts. A CVE-specific branch in
a template or matcher is not an accepted fix.

## Generated Scenario

Typical scenario directory:

```text
clab.yaml
scenario.yaml
ground_truth.json
flag-target-N.txt
ansible/base.yaml
ansible/cve-setup.yaml
ansible/asset-setup.yaml
ansible/asset-verify.yaml
exploit_guides/*.yaml
agent_workspace/
verify_result.json
```

`scenario.yaml` is the runtime manifest. `ground_truth.json` is verifier-private
and must never be used as Agent input. Generated scenario directories are run
artifacts, not canonical repository assets.

New `scenario.yaml` files carry `schema_version: 1` and are validated by
`ScenarioManifestV1` before persistence. Version 1 requires `name`, `hash`,
`template` and `injections`, and types the major asset/runtime/Guide metadata
groups while preserving extension diagnostics. Historical manifests without a
version are read as legacy version 0; new writers must not emit version 0.

## Agent Input Profiles

Supported contexts are `guided`, `no_guide`, legacy `no_hint`, and explicit
`l0`, `l1`, `l2`. CLI spelling uses underscores; the batch CLI accepts hyphenated
values and normalizes them for persistence.

The exact information boundary is maintained in
[`AGENT_INPUT_LEVEL_INTERFACE.md`](AGENT_INPUT_LEVEL_INTERFACE.md). Regardless
of profile, Agent input must not contain:

- Ground Truth flags;
- private objective `reference_command` or `success_pattern`;
- verifier-only assertions;
- API keys as Agent tool environment variables.

## Verification Result

`verify_result.json` reports independent gates. Important fields include:

| Field | Meaning |
|---|---|
| `environment_verified` | Deterministic verification was evaluated |
| `environment_success` | Deployment, services, network and assets passed |
| `range_build_verified` | Required Range construction gates passed |
| `attack_graph_valid` | Dependencies and capability closure are valid |
| `attack_path_reachable` | Reference edges are reachable under isolation |
| `agent_success` | Agent completed the attack task in this run |
| `objective_achieved` | Private objective assertion passed |
| `failure_stage` | Classified failure boundary |
| `execution_complete` | The lifecycle produced a terminal result |
| `cleanup_failed` | Cleanup failed independently of research outcome |

Never use `success` alone to aggregate research results. Select an explicit
denominator and report deterministic, Agent and objective outcomes separately.

New results carry `schema_version: 1`. `VerificationResultV1` applies defaults
and validates every verifier exit through the shared persistence boundary,
including early infrastructure failures and final cleanup updates. Historical
unversioned results remain readable as legacy version 0. Unknown future schema
versions are rejected instead of being silently interpreted as version 1.

## Batch Interface

Primary command:

```bash
PYTHONPATH=src python scripts/verify_enterprise3_guided_batch.py \
  --case-manifest <manifest.json> \
  --max-cases <N> \
  --agent-context <context> \
  --noise-level <level> \
  --parallel <N> \
  --max-turns <N> \
  --agent-timeout <seconds> \
  --output <new-directory>
```

The runner persists a fingerprint, per-case state and summary. `--resume` is
valid only when the fingerprint matches. Completed research outcomes are
immutable; only interrupted infrastructure work may be retried automatically.

The model runner is explicit:

- `--agent-runner claude` for Claude SDK compatible endpoints.
- `--agent-runner openai` for OpenAI-compatible streaming tool calls.

Record model, runner, context, noise level, seed, turn/time budgets, code state,
manifest and result directory when publishing an experiment.

## Compatibility Policy

- Legacy fields may be read only when a concrete persisted consumer requires
  them.
- Compatibility code must state the consumer and removal condition.
- Historical noise/context names must remain in historical artifacts; do not
  rewrite them to current terminology.
- New code should use current explicit contracts rather than infer behavior
  from directory names or progress prose.
