# Collaboration Alignment Repair Plan

Status: active

Owner: rotating release integrator

Last reviewed: 2026-08-09

## Goal

Make Atom, Range, Agent evaluation and SFT independently maintainable while
preserving one tested chain of versioned artifacts:

```text
Atom build attempt
-> Atom lifecycle index
-> completed-only Range selection
-> immutable scenario and Agent exposure
-> independent verification result
-> versioned trajectory export
-> reproducible SFT run
```

Public-history and fixture sanitization are explicitly outside this repair plan
by project-owner decision. They do not relax runtime privacy boundaries or the
rule that new raw experiment artifacts remain untracked.

## Non-Negotiable Rules

1. Atom lifecycle has only `planned`, `building` and `completed`.
2. Production Range construction consumes only live `completed` Atoms.
3. Range never mutates Atom-owned runtime or source-bundle artifacts.
4. Agent exposure is immutable for a generated scenario and verifier-private
   values never enter Agent input.
5. Environment, graph, path, Agent and objective outcomes remain independent.
6. SFT consumes a versioned sanitized trajectory export, not arbitrary raw
   session files.
7. Generated status views have one owner and must pass freshness checks.
8. Contract changes update producer, consumer, model, tests and interface docs
   in the same change.

## Baseline

The 2026-08-09 audit established:

- local tests: 737 passed, 7 skipped;
- Atom snapshot: stored `0/193/46`, live `0/197/42`;
- 45 started Atom directories are absent from the stored lifecycle denominator;
- 1,294 of 1,800 stored completed-matrix combinations reference at least one
  live-building Atom;
- tracked Range progress: 136 batches / 3,787 attempts;
- live local Range progress: 156 batches / 3,931 attempts;
- Agent, Ground Truth, batch and SFT records are not all versioned;
- SFT conversion silently excludes OpenAI JSONL sessions.

## Workstream Ownership

| Workstream | Primary ownership | Required reviewer |
|---|---|---|
| Atom | `atomizer/`, Atom models/data, lifecycle index | Range |
| Range | matcher, templates, assembly, deterministic verification | Atom for consumed Atom contracts |
| Agent | exposure profiles, runners, Agent result semantics | Range and SFT |
| SFT | trajectory export, corpora, training and evaluation | Agent |
| Release integrator | generated status, CI, current dashboard, release branch | one affected workstream |

With three maintainers, combine Agent and SFT. Do not combine Atom and Range
ownership. The release-integrator duty rotates and is not a fifth permanent
role.

## Phase 1: Lifecycle and Admission

Owner: Atom; reviewer: Range

Status: completed for the first lifecycle contract slice

Tasks:

- include started Atom directories without `atom.yaml` as `building` evidence;
- add non-writing status freshness validation to the generator;
- make matrix generation reject a stale Atom snapshot;
- add a completed-only Atom loader backed by the live lifecycle index;
- require completed status for automatic and explicit production scenarios;
- make `atom list` report lifecycle status and blockers;
- keep legacy verified-only loading behind an explicitly named compatibility
  method, not the production path;
- regenerate Atom status before regenerating any Range matrix.

Acceptance:

- all lifecycle output uses only the three canonical states;
- interrupted builds remain visible as building;
- changing any completion gate makes status freshness checks fail;
- direct and matrix generation reject a verified-but-building fixture;
- stored JSON/CSV/Markdown share one timestamp and hash;
- focused lifecycle, loader, scenario and matrix tests pass.

## Phase 2: Range Ownership and Immutability

Owner: Range; reviewers: Atom and Agent

Status: in progress

Tasks:

- remove automatic Atom runtime rebuild from production Range verification;
- require the scenario-pinned runtime image and digest;
- move rebuild into an explicit Atom-owned preparation command;
- fail verification when runtime identity differs from the scenario contract;
- implement one material selector for `private`, `assisted` and `always`;
- use that selector in scenario assembly, Agent mounts and exporters;
- preserve exact matrix slot bindings and source snapshot provenance;
- expand batch fingerprints to template, clab, matcher/assembler code, runtime
  manifests, material hashes, seed and provider settings;
- reject output-directory reuse unless explicitly resumed with a matching
  fingerprint.

Acceptance:

- Range verification does not change any file under `data/atoms/`;
- digest drift is a classified preflight failure;
- private materials are never Agent-visible;
- assisted materials appear only in the declared exposure profile;
- changing any effective generation input changes the batch fingerprint;
- resume cannot mix scenario identities or retain stale leases.

## Phase 3: Agent Contracts and Evaluation Integrity

Owner: Agent; reviewers: Range and SFT

Status: in progress

Tasks:

- add a versioned `AgentExposureProfile` to scenario, input, result and batch
  state;
- reject generation/verification profile mismatch;
- version Ground Truth, Agent input, Agent output, batch state and summary;
- separate Agent-returned fields from runner/verifier-owned audit metadata;
- retain a private shuffled-node identity map and remove positional aliases;
- audit system prompt, user prompt, serialized input and mounted materials;
- keep hygiene aborts outside the model-evaluated denominator;
- generate unpredictable per-run objective canaries;
- name runner workloads and prove termination during timeout/cleanup;
- record runner, model, endpoint class, budgets and termination category.

Acceptance:

- profile mismatch fails before an LLM call;
- Agent output cannot overwrite context, hygiene or verifier outcomes;
- L1 evidence resolves only through the private identity map;
- objective success requires a per-run private witness;
- timeout leaves no runner workload or credential-bearing process;
- paired analyses reject arms with incompatible identities.

## Phase 4: SFT Artifact Chain

Owner: SFT; reviewer: Agent

Status: in progress

Tasks:

- define versioned trajectory, SFT record, corpus manifest, split manifest,
  training run, adapter and evaluation result models;
- parse both Claude array sessions and OpenAI JSONL sessions;
- report every skipped source and reason;
- distinguish task-oracle hygiene from publication sanitization;
- generate immutable corpus IDs and content hashes;
- create chain/CVE-grouped train, validation and test splits;
- declare a pinned SFT dependency group or training container;
- pin model and tokenizer revisions and record CUDA/PyTorch/vLLM identity;
- remove machine-specific executable and model paths;
- propagate training, serving and evaluation subprocess failures;
- add one tracked synthetic end-to-end fixture for clean-clone CI.

Acceptance:

- the same source manifest and code revision produce the same corpus hash;
- no supported session format is silently dropped;
- duplicate task identities and split overlap fail validation;
- a clean environment can run conversion and a CPU-only contract smoke;
- every adapter and evaluation result resolves to an immutable run manifest.

## Phase 5: Collaboration, CI and Progress

Owner: release integrator; reviewers: all workstreams

Status: continuous, final gate after Phases 1-4

Tasks:

- align the collaboration playbook with four ownership lanes;
- add CODEOWNERS, issue and pull-request contract checklists;
- document one clean-clone command sequence using `uv run`;
- document external Vulhub/CVE-Factory acquisition and Agent image build;
- add separate core, Agent-contract and SFT dependency/test groups;
- add CI checks for lifecycle freshness, matrix provenance, schemas, docs links
  and generated-view consistency;
- maintain machine-readable Atom, Range, Agent experiment and SFT run status;
- generate `CURRENT_STATUS.md` from reviewed status sources;
- use issues/PRs for active work and the progress report for accepted evidence;
- allow only the release integrator to regenerate shared status views.

Acceptance:

- a new contributor can clone, select a lane and run its contract smoke;
- every active artifact has one producer, consumer, schema and owner;
- no status dashboard differs from its machine-readable source;
- every PR names affected contracts and includes producer/consumer tests;
- one integrated Atom -> Range -> Agent -> trajectory smoke passes from a clean
  clone before the collaboration baseline is tagged.

## Status Regeneration Order

The release integrator uses this order and stops on the first failed freshness
or contract check:

```text
Atom lifecycle
-> Range matrix
-> Range build progress
-> Agent experiment progress
-> SFT dataset/run registry
-> CURRENT_STATUS dashboard
```

Never regenerate a downstream view from a stale upstream snapshot.

## Required Handoff Record

Every completed work package records:

```text
Owner:
Affected contract and version:
Producer:
Consumers:
Migration or compatibility boundary:
Focused tests:
Freshness/status result:
Known limitations:
Next owner:
```

## Release Gate

The collaboration baseline is ready only when:

- all five phase acceptance sections pass;
- the full non-Docker suite passes in a clean environment;
- generated status checks are clean;
- the working tree contains only reviewed release changes;
- the remote default branch points at the reviewed collaboration baseline.
