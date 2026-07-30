# Collaboration Playbook

Status: active

Last reviewed: 2026-07-30

## Purpose

This document turns the architecture and contract registry into work that can
be divided safely. It defines three workstreams, handoff rules, interface
documentation requirements, progress reporting and the first collaboration
sprint. It does not assign people; maintainers record the current assignee in
the issue or pull request.

Read this together with:

- [`ARCHITECTURE.md`](ARCHITECTURE.md) for system and dependency boundaries;
- [`INTERFACES.md`](INTERFACES.md) for persisted contracts;
- [`CURRENT_STATUS.md`](CURRENT_STATUS.md) for established current state;
- [`ROADMAP.md`](ROADMAP.md) for ordered project work;
- [`../CONTRIBUTING.md`](../CONTRIBUTING.md) for change and review rules.

## Workstreams and Technical Boundaries

The project has many technical modules but only three people-facing
workstreams. Technical boundaries identify interfaces; they are not separate
staffing roles.

| Workstream | End-to-end responsibility | Primary paths | Main handoff |
|---|---|---|---|
| A. Atom and vulnerability supply | Source ingestion, native verification, runtime/source bundle, Guide review, Atom qualification and Atom status | `src/clab_builder/atomizer/`, Atom-related `shared/`, `data/atoms/`, `tests/atomizer/`, relevant `tests/shared/` | Publishes a reviewed `data/atoms/<CVE>/` artifact |
| B. Range and evaluation | Template matching, scenario assembly, deterministic verification, Agent contexts/runners, batch experiments and result interpretation | `src/clab_builder/orchestrator/composer/`, `templates/`, Range scripts, `tests/orchestrator/` | Consumes Atom artifacts and publishes versioned scenario/verification/batch results |
| C. Engineering and research support | CLI/config/package, CI, documentation, release/data policy, sanitization, SFT conversion/training/evaluation | cross-cutting `shared/`, `src/clab_builder/cli.py`, `.github/`, `docs/`, `sft/`, `tests/sft/` | Keeps A and B reproducible, reviewable and publishable |

Schema ownership follows the producing workstream instead of assigning all
models to a fourth “shared” owner:

- A owns Atom, Exploit Guide, source-bundle and qualification contracts; B
  reviews changes that affect Range consumption.
- B owns Template, Scenario, Ground Truth, Agent I/O, verification and batch
  contracts; C reviews privacy, publication or SFT effects.
- C owns configuration, package, CI and public-export contracts; A or B reviews
  changes that alter their execution environment.

Files under `shared/` therefore require a named producing workstream in the
issue. Directory location alone does not decide ownership.

### Staffing

For three people:

| Person | Primary workstream | Secondary review |
|---|---|---|
| Person 1 | A. Atom and vulnerability supply | Reviews Atom-to-Range handoff |
| Person 2 | B. Range and evaluation | Reviews Range consumption of Atom contracts |
| Person 3 | C. Engineering and research support | Reviews CI, privacy and release impact |

For two people:

| Person | Primary workstream | Additional duty |
|---|---|---|
| Person 1 | A. Atom and vulnerability supply | Atom-facing shared contracts and status |
| Person 2 | B. Range and evaluation | C is handled as a rotating maintenance duty |

With two people, do not run a separate support backlog in parallel. Schedule CI,
documentation, release and SFT tasks as bounded maintenance work between Atom
and Range milestones. Cross-boundary contract changes still require the other
person's review.

Person B owns the experiment workstream: model/runner comparisons, Agent input
levels, Guide and decoy dimensions, batch denominators and result
interpretation. A third support person may maintain execution/SFT tooling but
does not take over scientific ownership.

The broad files `atomizer/pipeline.py`, `scenario_assembler.py` and
`verifier.py` remain temporary ownership hotspots. Coordinate edits to them in
an issue before parallel implementation. Only one person edits a hotspot at a
time. Split it only after its file contracts have regression tests.

## Change and Handoff Flow

```text
Issue: scope + primary workstream + affected contract + acceptance evidence
  -> implementation in the owning workstream
  -> focused tests
  -> producer/consumer and privacy tests for contract changes
  -> status/ledger update
  -> review by the other affected workstream when a contract changed
```

A handoff is complete only when it states:

1. the input artifact or callable and its authoritative definition;
2. the output artifact and its producer;
3. assumptions, supported versions and privacy boundary;
4. the verification command and established result;
5. known limitations and the next owner.

Do not hand off a chat summary as the only record. Put the durable fact in the
appropriate active document, issue, schema or progress entry.

## Interface Documentation Standard

CVELab has two interface types:

- **Python interfaces** used inside a process;
- **artifact interfaces** such as `atom.yaml`, `template.yaml`,
  `scenario.yaml`, Agent input/output, `verify_result.json` and batch summaries.

Artifact interfaces are the more important subsystem boundary. Documenting only
functions is insufficient.

Every interface entry in [`INTERFACES.md`](INTERFACES.md) must identify:

| Field | Required content |
|---|---|
| Name and version | Stable identifier; say `unversioned` when that is the gap |
| Producer | Module or command that writes/returns it |
| Consumer | Modules or commands that read it |
| Authority | Pydantic model, JSON Schema, implementation or test fixture |
| Location/transport | File path pattern, function import or process boundary |
| Required semantics | Invariants, not a duplicate list of every field |
| Privacy | Public, Agent-visible, verifier-private or sensitive |
| Compatibility | Reader/writer expectations and migration policy |
| Failure behavior | How invalid input is rejected and classified |
| Tests | Round-trip, negative and privacy regression coverage |

For a new or changed persisted contract, the same pull request must update:

1. the producer;
2. every known consumer;
3. the versioned model or schema;
4. positive and negative contract tests;
5. privacy tests when Agent or publication visibility is involved;
6. `INTERFACES.md` and migration notes.

Use small examples in fixtures. Do not copy real flags, credentials, private
objectives or raw trajectories into interface documentation.

## Progress Documentation

Progress has three distinct records:

| Record | Purpose | Update rule |
|---|---|---|
| `docs/CURRENT_STATUS.md` | Concise current-state dashboard | Edit when an established current fact changes |
| `docs/ROADMAP.md` | Prioritized future work and acceptance gates | Edit when priorities or gates change |
| `docs/WORK_PROGRESS_REPORT.md` | Append-only evidence and decision ledger | Append every work session; supersede, never rewrite |

Machine-readable status or experiment files are evidence, not substitutes for
those three views. Every count must name its population and denominator.

Use this ledger entry shape:

```markdown
### YYYY-MM-DD — <workstream>: <result>

- Scope: <what was inspected or changed>
- Atom build status: <planned | building | completed | not applicable>
- Result class: <Atom evidence | Range selection | experiment | docs>
- Result: <established facts, including negative results>
- Verification: <commands and exact outcome>
- Evidence: <paths to durable artifacts>
- Limitations: <what this does not prove>
- Next owner: <workstream and concrete next action>
```

An issue or pull request should use this shorter status block:

```text
State: planned | in progress | blocked | in review | done
Owner workstream:
Affected contracts:
Acceptance:
Evidence:
Blocker or next action:
```

“Done” means the acceptance evidence exists. A running batch, generated file,
Agent claim or unreviewed local result is not completion.

## Parallel Work Rules

- Start from a named commit and record it in the issue or experiment.
- Keep one primary workstream per branch or commit.
- Never stage the whole dirty worktree to collect one change.
- Coordinate before editing a listed hotspot or shared schema.
- Generated scenarios and raw runs are immutable evidence, not merge targets.
- Fix a reusable construction or orchestration contract; do not add a
  CVE-specific or Range-specific branch.
- Rebase or merge only after preserving uncommitted experiment evidence.

## First Collaboration Sprint

The simplest safe first step is a short contract-and-baseline sprint. Do not
begin with package refactoring.

| Work package | Workstream | Deliverable | Acceptance |
|---|---|---|---|
| 1. Repository and CI baseline | C | Classify the dirty tree and align CI/test/Python policy | Intended public files are classified and a clean pull request runs active tests |
| 2. Atom status and handoff | A | Normalize Atom populations and confirm the Atom-to-Range artifact contract | One generated snapshot has consistent JSON/CSV/Markdown and explicit qualification meanings |
| 3. Range result contracts | B | Add versioned Scenario and Verification Result models before changing orchestration structure | Round-trip, invalid-input and privacy tests pass |
| 4. First integrated handoff | A + B, coordinated by C | Generate and verify a small representative Range from the normalized Atom snapshot | Atom, environment, graph, Agent and objective outcomes are recorded separately |

Recommended order:

```text
1 repository and CI baseline
  -> 2 Atom status + 3 Range result contracts in parallel
  -> 4 integrated handoff
  -> only then structural module splitting
```

The first sprint is complete when a new contributor can clone the reviewed
baseline, choose a workstream, find its contracts, run its focused tests,
make a scoped change and report evidence without relying on chat history.

## Current Conflict Map

| Conflict | Why it happens | Working rule |
|---|---|---|
| Atom schema versus Range consumption | Atom fields are produced in A but interpreted in B | A owns the producer change; B must review the consumer and migration |
| Range result versus Agent/SFT interpretation | Result fields are assembled across verifier, runner, batch and SFT code | B owns online semantics; C may consume but cannot redefine historical meaning |
| Shared-directory ownership | `shared/` contains contracts used by both pipelines | Name A, B or C by contract producer; never use `shared/` as an unowned fourth area |
| Hotspot merge conflicts | Three broad files contain several responsibilities | One active editor per hotspot; coordinate before work and add contract tests before splitting |
| Canonical versus generated data | The dirty tree mixes reviewed assets, runs and local evidence | C classifies publication state; A/B decide scientific validity |
| Active versus legacy code | Old packages and docs still coexist with the active pipeline | New work follows `atomizer/` and `orchestrator/composer/`; legacy changes require a named consumer |

## Known Baseline Gaps

The initial inventory found these collaboration blockers:

- Scenario, Ground Truth, Agent I/O, verification and batch artifacts are not
  all backed by versioned models or JSON Schemas.
- The active implementation and legacy `atomic/`, `core/`, `models/` and older
  orchestrator paths coexist.
- Docker, ContainerLab, network and slow tests still need a prepared-host gate
  outside the default non-Docker CI job.
- Local research state, reviewed public state and Git history are not yet one
  clean release snapshot.

These are project-level tasks. They must not be “fixed” by changing one Atom,
one generated Range or one historical result.
