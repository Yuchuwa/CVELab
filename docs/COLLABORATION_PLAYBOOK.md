# Collaboration Playbook

Status: active

Last reviewed: 2026-08-09

## Purpose

This playbook divides CVELab into four technical lanes while keeping the
release-integrator duty explicit. A lane owns its producer and scientific
meaning; consumers review the handoff rather than silently redefining it.

Read this with:

- [`ARCHITECTURE.md`](ARCHITECTURE.md) for dependency direction;
- [`INTERFACES.md`](INTERFACES.md) for persisted contracts;
- [`OPERATIONS.md`](OPERATIONS.md) for commands and artifact handoffs;
- [`CURRENT_STATUS.md`](CURRENT_STATUS.md) for generated live status;
- [`ROADMAP.md`](ROADMAP.md) for ordered work;
- [`../CONTRIBUTING.md`](../CONTRIBUTING.md) for pull-request rules.

## Four Lanes

| Lane | Owns | Primary paths | Handoff output | Required reviewer |
|---|---|---|---|---|
| Atom lane | Source acquisition, native verification, runtime/source bundle, Exploit Guide and three-state lifecycle | `src/clab_builder/atomizer/`, Atom models, `data/atoms/`, `tests/atomizer/` and relevant `tests/shared/` | Reviewed `data/atoms/<CVE>/` plus lifecycle evidence | Range lane |
| Range lane | Template matching, matrix selection, scenario assembly, deterministic environment/graph/path gates and Range manifests | `src/clab_builder/orchestrator/composer/`, `templates/`, Range scripts, `tests/orchestrator/` | Versioned scenario, matrix and verification artifacts | Atom lane for consumed Atom contracts; Agent lane for exposure/results |
| Agent lane | `AgentExposureProfile`, prompt/input boundaries, runners, structured Agent results and experiment trial semantics | `scenario_runner.py`, `openai_scenario_runner.py`, verifier Agent boundary, batch runner and Agent tests | Exposure-pinned input/result/batch evidence with hygiene outcome | Range lane and SFT lane |
| SFT lane | Sanitized trajectory conversion, corpus/split lineage, training runs and evaluation manifests | `sft/`, `tests/sft/` | Content-addressed corpus, split and run manifests; sanitized exports only | Agent lane |

The release integrator is a rotating duty, not a fifth scientific lane. It owns
generated status views, CI, documentation indexes, release scope and the final
artifact-chain check. It must not change Atom, Range, Agent or SFT semantics to
make a gate pass.

## Ownership Rules

- The lane that produces a persisted field owns its meaning and migration path.
- A change crossing a lane names the producer, every known consumer, the
  contract version, the privacy boundary and the next owner in the handoff.
- `shared/` is not an unowned lane. The issue names the producing lane for every
  shared-model change.
- Atom lifecycle is exactly `planned`, `building` or `completed`; matrix
  membership belongs to Range.
- Range consumes live `completed` Atoms and never mutates Atom-owned files.
- Agent success never overwrites deterministic Range gates or private objective
  verification.
- SFT consumes a versioned sanitized export and never changes historical Agent
  or verification semantics.
- Generated status views have one producer: the release integrator regenerates
  them in the documented order after upstream freshness checks pass.

## Review Rules

Every pull request states:

```text
State: planned | in progress | blocked | in review | done
Primary lane:
Affected contracts and versions:
Producer and consumers:
Focused tests:
Freshness/status result:
Privacy/publication impact:
Known limitations and next owner:
```

Review is required from the lane owner and every required cross-lane reviewer
listed above. Each required reviewer checks the contract boundary, not only the
changed implementation. The release integrator reviews any change that touches generated
status, CI, docs, package policy, publication state or handoff metadata. The
integrator may approve release plumbing only after the affected scientific lane
confirms that semantics are unchanged.

Additional rules:

- A contract change updates producer, consumer, model or schema, positive and
  negative tests, privacy tests where relevant, and `INTERFACES.md` together.
- The producer author does not provide the sole approval for a cross-lane
  contract change.
- Hotspots `atomizer/pipeline.py`, `scenario_assembler.py` and `verifier.py`
  have one active editor at a time; coordinate before editing them.
- Do not add a CVE-specific or generated-Range-specific branch.
- Do not stage the whole worktree. Keep unrelated Atom, Range, Agent and SFT
  evidence out of a documentation or CI change.
- CI must use synthetic fixtures and tracked compact status, never private raw
  Range runs, raw sessions, flags, credentials or model adapters.
- A reviewer checks both the positive path and the intended rejection path.

## Handoff Contract

A handoff is complete only when the receiving lane can reproduce it without
chat history. Record:

1. the input artifact or callable and its authoritative definition;
2. the output artifact, producer and schema/version;
3. assumptions, supported versions and privacy boundary;
4. the exact `uv run` verification command and established result;
5. hashes, snapshot identity or run fingerprint where applicable;
6. known limitations and the next owner.

The normal order is:

```text
Atom lifecycle/status
  -> completed-only Range matrix
  -> scenario and deterministic verification
  -> immutable Agent exposure and trial result
  -> sanitized SFT corpus and split
  -> training/evaluation run manifest
```

The receiving lane may reject an incomplete handoff. Rejection records the
contract or evidence gap; it does not change the source lane's lifecycle state.

## Contract Documentation

Artifact interfaces are first-class boundaries. Each `INTERFACES.md` entry
names the contract/version, producer, consumers, authority, location or
transport, required invariants, privacy class, compatibility policy, failure
behavior and contract-test coverage. Say `untyped` explicitly when a schema is
missing.

The same pull request updates the producer, known consumers, schema or version
boundary, positive and negative tests, privacy tests when visibility is
involved, and migration notes. Examples use synthetic values only; never copy
flags, credentials, private objectives or raw trajectories into docs or
fixtures.

## Lane Checklists

### Atom Lane

- Capture a self-contained source bundle and record material hashes.
- Preserve runtime startup semantics and readiness evidence.
- Separate native exploit evidence from orchestrated environment evidence.
- Produce a reviewed Guide whose material references are source-bundle-relative.
- Regenerate/check Atom status before offering an Atom to Range.

### Range Lane

- Select only live `completed` Atoms and record the Atom snapshot hash.
- Keep template, slot, dependency, capability and asset rejection reasons.
- Persist scenario and verification schema versions.
- Keep environment, graph, path, Agent and objective outcomes independent.
- Hand Agent only the declared public exposure profile; keep Ground Truth private.

### Agent Lane

- Pin `AgentExposureProfile` at generation, input, result and batch boundaries.
- Abort profile mismatches before an LLM call and audit serialized inputs/prompts.
- Keep API credentials out of Agent subprocess environments and artifacts.
- Record runner, model, endpoint class, budgets and termination category.
- Exclude hygiene aborts from the model-evaluated denominator.

### SFT Lane

- Accept only a versioned corpus manifest and exact JSONL content hash.
- Record every discovered source and every skip reason.
- Split by chain/CVE/source identity so related samples cannot cross splits.
- Keep training and evaluation manifests portable and free of machine paths or
  secrets.
- Publish only sanitized exports; raw sessions and adapters remain local.

## Release Integrator Gate

The release integrator runs the fast gate in a fresh clone and stops at the
first failure:

```text
Atom status freshness
  -> tracked status and matrix provenance
  -> documentation/workflow contracts
  -> focused contract tests
  -> lane-specific tests requested by reviewers
```

The integrator records the exact commands and results in the pull request. A
green CI job proves contract and documentation consistency only; it does not
prove Docker deployment, exploit success, Agent success, objective success or
SFT model improvement.

## Progress Records

Use active documents for current guidance and the append-only progress ledger
for established evidence. Every work session that changes or evaluates a
contract records its scope, result class, command, evidence, limitation and
next owner in `docs/WORK_PROGRESS_REPORT.md`. Generated status views are not a
substitute for that evidence, and historical entries are never rewritten.

The release integrator updates `CURRENT_STATUS.md` only from generated sources
and names the population and denominator for every count. A matrix count is a
composition count unless a separate environment or Agent result says otherwise.
