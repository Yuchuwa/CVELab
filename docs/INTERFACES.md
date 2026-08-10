# Interface and Artifact Registry

Status: active

Last reviewed: 2026-08-10

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
| Ground Truth v1 | Scenario assembler | Verifier only | `GroundTruthV1` in `artifact_contracts.py` | private, versioned |
| Agent input v1 | Verifier | Agent runner | `AgentInputV1` in `artifact_contracts.py` | sanitized, versioned |
| Agent output v1 | Agent runner/Verifier boundary | Verifier and analysis | `AgentOutputV1` in `artifact_contracts.py` | runner-owned envelope, versioned |
| AgentExposureProfile v1 | Scenario/verification normalization and batch runner | Scenario, verifier, Agent runner, experiment analysis | `shared/models/artifact_contracts.py` | versioned |
| Verification result v1 | Verifier | Batch runner, analysis, SFT | `shared/models/artifact_contracts.py` | versioned |
| Range matrix status v1 | Range matrix generator | Planning, docs, batch preparation | `generate_enterprise3_matrix.py` | versioned compact view |
| Range build status v1 | Range progress generator | Range planning and experiment denominators | `shared/range_progress.py` | versioned sanitized snapshot |
| Experiment status v1 | Range progress generator | Research planning and reporting | `shared/range_progress.py` | versioned sanitized snapshot |
| Experiment manifest | Matrix/select scripts | Batch runner | batch script loaders | operational |
| Batch state/summary v1 | Batch runner | Resume and analysis tools | `BatchStateV1`/`BatchSummaryV1` in `artifact_contracts.py` | versioned |
| SFT corpus manifest v1 | `sft/convert_trajectories_to_sft.py` | SFT split/training/evaluation | `sft/lineage.py` (`cvelab.sft-corpus-manifest.v1`) | versioned |
| SFT split/lineage manifests v1 | SFT splitter and lineage helpers | Training/evaluation and release analysis | `sft/lineage.py` | versioned |
| Atom lifecycle freshness | Status generator and release integrator | Range matrix generator and CI | `scripts/generate_atom_pool_status.py --check` | operational gate |
| Material visibility/audit v1 | Atom source-bundle metadata and shared selector | Range assembly, verifier and exporters | `MaterialAuditV1` in `artifact_contracts.py` | typed policy and audit envelope |

The models intentionally allow extension fields while the contract settles.
Field removals or renames remain breaking changes; new fields must be added to
the producer, consumer and contract tests together.

## Typed Phase 5 Contracts

### AgentExposureProfile v1

`AgentExposureProfile` is the immutable description of the information boundary
for one generated scenario or trial. It records `schema_version: 1`, the
normalized context (`guided`, `no_guide`, `no_hint`, `l0`, `l1` or `l2`) and the
derived profile/hint labels. Scenario manifests and verification results carry
the profile; batch summaries copy it for analysis. A requested context/profile
mismatch is a pre-LLM contract failure, not an Agent result.

Authority/tests: `AgentExposureProfile` in
`shared/models/artifact_contracts.py`; round-trip and mismatch coverage is in
`tests/shared/test_artifact_contracts.py` and the batch profile is preserved by
`tests/orchestrator/test_guided_batch_runner.py`.

This profile does not make private fields public. Ground Truth flags, private
objective assertions, API keys and verifier-only success data stay outside
Agent input under every profile. The v1 input/output envelopes are typed;
raw prompt and tool/session transcripts remain separate private artifacts.

### SFT Corpus and Lineage Manifests

The SFT artifact chain uses these stable identifiers from `sft/lineage.py`:

- `cvelab.sft-record.v1` for a content-addressed SFT record;
- `cvelab.sft-corpus-manifest.v1` for converter inputs, source/skip accounting,
  exact JSONL hash and record count;
- `cvelab.sft-split-manifest.v1` for deterministic train/validation/test groups;
- `cvelab.sft-training-run-manifest.v1` and
  `cvelab.sft-evaluation-manifest.v1` for downstream run identity.

The corpus and split validators reject hash/count drift, duplicate identities,
split overlap, secret fields and non-portable lineage. A clean contract test
uses synthetic records only; raw sessions and model artifacts are not CI
inputs.

Authority/tests: the validators and schema identifiers in `sft/lineage.py`;
synthetic corpus, split, training-run and evaluation-manifest coverage belongs
in the SFT contract test set and does not require a private corpus.

### Ground Truth, Agent I/O and Batch Envelopes

The remaining Range envelopes are versioned in
`shared/models/artifact_contracts.py`:

- `GroundTruthV1` is verifier-private and is written with `schema_version: 1`.
- `AgentInputV1` is the sanitized input written before a runner starts; it
  contains no Ground Truth assertions.
- `AgentOutputV1` separates runner-owned audit fields from `AgentReportedV1`.
- `MaterialAuditV1` records selected/excluded materials, visibility policy and
  source hash decisions on the host side.
- `BatchStateV1` and `BatchSummaryV1` type resumable state and analysis views.

These models preserve extension fields for migration, but producers normalize
the envelope at the persistence boundary. The full raw tool/session event
stream remains a separate runner artifact and is not a trusted result field.

### Lifecycle Freshness

`data/atom_pool_status.json` is generated from the live Atom directory. The
non-writing `scripts/generate_atom_pool_status.py --check` command compares the
semantic snapshot identity and verifies that JSON, CSV and Markdown share one
`generated_at` and `snapshot_hash`. `generated_at` is provenance; the semantic
hash is the freshness identity. Matrix generation independently compares its
stored Atom snapshot to a live snapshot before selecting Atoms.

The release integrator runs this check before Range matrix or dashboard
regeneration. A stale view is a contract failure, not a reason to hand-edit a
generated file.

Authority/tests: `shared/atom_pool_status.py` plus the generator's `--check`
path; `tests/shared/test_atom_pool_status.py` covers stale-view rejection and
non-writing behavior.

### Material Visibility

Atom `SourceBundle` entries carry typed role/visibility metadata. The shared
selector is the one policy boundary for materials mounted into an Agent or
exported to another actor:

- v3 Atoms must provide metadata for every declared `poc_materials` entry;
  missing metadata is a lifecycle/preflight failure rather than an implicit
  public material.
- Guide-referenced materials must be visible under the guided profile. A file
  can exist and pass its hash check while still being correctly rejected if its
  visibility policy is private or incomplete.

- `private` materials are never Agent-visible;
- `assisted` materials are limited to the explicitly assisted profiles;
- `always` materials are visible only where the selected exposure profile
  permits materials;
- runtime, verification and solution materials remain verifier/build inputs,
  not prompt hints.

The selector also enforces the current L0/L1/L2 restrictions. Mount/path
decisions are persisted through `MaterialAuditV1`; raw source contents and
runner session events remain outside the public artifact contract.

Authority/tests: `MaterialMetadata`/`MaterialVisibility` in
`shared/models/atom.py`, the selector/audit helpers in `shared/source_bundle.py`
and the source-bundle/assembler/verifier privacy tests.

## Untyped Gaps

The following remain intentionally listed as gaps rather than being treated as
stable schemas:

- raw private `ground_truth.json` contents and verifier-only objective
  assertions;
- the complete raw tool/session event stream and provider diagnostics;
- extension fields in historical experiment manifests that have not yet been
  migrated to the v1 batch envelope.

Until each gap has a producer, consumer, versioned schema and negative/privacy
tests, readers must preserve unknown fields and treat renames as breaking.

## Atom v3

Location: `data/atoms/<CVE>/atom.yaml`

Key contract groups:

- Identity and classification.
- `runtime_spec` and runtime provenance.
- `source_bundle` and material metadata.
- per-material `role` and `visibility` values used by the shared Agent selector.
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
uv run python scripts/verify_enterprise3_guided_batch.py \
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
