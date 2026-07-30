# Collaboration Playbook

Status: active

Last reviewed: 2026-07-30

## Purpose

This document turns the architecture and contract registry into work that can
be divided safely. It defines ownership areas, handoff rules, interface
documentation requirements, progress reporting and the first collaboration
sprint. It does not assign people; maintainers record the current assignee in
the issue or pull request.

Read this together with:

- [`ARCHITECTURE.md`](ARCHITECTURE.md) for system and dependency boundaries;
- [`INTERFACES.md`](INTERFACES.md) for persisted contracts;
- [`CURRENT_STATUS.md`](CURRENT_STATUS.md) for established current state;
- [`ROADMAP.md`](ROADMAP.md) for ordered project work;
- [`../CONTRIBUTING.md`](../CONTRIBUTING.md) for change and review rules.

## Ownership Areas

Each change has one primary area. A change that crosses areas must name the
contract at the boundary and request review from every affected area.

| Area | Owns | Primary paths | Does not own |
|---|---|---|---|
| Shared contracts | Pydantic models, qualification and cross-stage policy | `src/clab_builder/shared/`, `tests/shared/` | Atom or Range execution |
| Atom construction | Source ingestion, native verification and Atom production | `src/clab_builder/atomizer/`, `tests/atomizer/` | Range-specific compatibility fixes |
| Atom assets | Reviewed Atom metadata, bundles, Guides and runtime manifests | `data/atoms/`, Atom status artifacts | Generated scenarios or raw experiments |
| Range planning | Loading, matching, capability closure and selection | `orchestrator/composer/{atom_loader,cve_matcher,capability_closure,scenario}.py` | Native exploit verification |
| Range assembly | Templates, topology, assets and scenario materialization | `scenario_assembler.py`, `templates/`, assembler tests | Agent success criteria |
| Range verification | Deployment, readiness, isolation, graph and objective verification | `verifier.py`, verifier tests | Prompt strategy or model quality |
| Agent execution | Context exposure, prompt construction, tool transport and structured output | `scenario_runner.py`, `openai_scenario_runner.py`, related tests | Private Ground Truth decisions |
| Experiments and data | Manifests, batching, resume, summaries and public export | `scripts/`, `dataset_saver.py`, experiment artifacts | Redefining online contracts |
| SFT and evaluation | Trajectory conversion, training, serving and offline evaluation | `sft/`, `tests/sft/` | Mutating historical experiment meaning |
| Docs and release | Active docs, contribution flow, release notes and publication checks | `README.md`, `docs/`, CI/release files | Declaring unverified research results |

The broad files `atomizer/pipeline.py`, `scenario_assembler.py` and
`verifier.py` remain temporary ownership hotspots. Coordinate edits to them in
an issue before parallel implementation. Split them only after their file
contracts have regression tests.

## Change and Handoff Flow

```text
Issue: scope + primary area + affected contract + acceptance evidence
  -> implementation in the owning area
  -> focused tests
  -> producer/consumer and privacy tests for contract changes
  -> status/ledger update
  -> review by the primary area
  -> additional boundary-owner review when a contract changed
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
### YYYY-MM-DD — <area>: <result>

- Scope: <what was inspected or changed>
- Classification: <structure-healthy | template-candidate | template-anchor |
  Range/experiment/docs>
- Result: <established facts, including negative results>
- Verification: <commands and exact outcome>
- Evidence: <paths to durable artifacts>
- Limitations: <what this does not prove>
- Next owner: <ownership area and concrete next action>
```

An issue or pull request should use this shorter status block:

```text
State: planned | in progress | blocked | in review | done
Owner area:
Affected contracts:
Acceptance:
Evidence:
Blocker or next action:
```

“Done” means the acceptance evidence exists. A running batch, generated file,
Agent claim or unreviewed local result is not completion.

## Parallel Work Rules

- Start from a named commit and record it in the issue or experiment.
- Keep one primary ownership area per branch or commit.
- Never stage the whole dirty worktree to collect one change.
- Coordinate before editing a listed hotspot or shared schema.
- Generated scenarios and raw runs are immutable evidence, not merge targets.
- Fix a reusable construction or orchestration contract; do not add a
  CVE-specific or Range-specific branch.
- Rebase or merge only after preserving uncommitted experiment evidence.

## First Collaboration Sprint

The simplest safe first step is a short contract-and-baseline sprint. Do not
begin with package refactoring.

| Work package | Primary area | Deliverable | Acceptance |
|---|---|---|---|
| A. Repository baseline | Docs and release | Review dirty files into code, canonical data, generated data and private evidence | Every intended public file has an owner and publication class |
| B. Contract inventory | Shared contracts | Add versioned Scenario and Verification Result models first | Round-trip, invalid-input and privacy tests pass |
| C. Status normalization | Atom assets + experiments | Define managed/candidate/anchor/matrix populations and one generated Atom snapshot | JSON/CSV/Markdown agree on timestamp, population and hash |
| D. CI alignment | Docs and release + area owners | Make CI run the test layout and supported Python version actually present in the repository | A clean pull request runs focused unit tests successfully |
| E. Ownership activation | All areas | Assign one maintainer and one backup/reviewer per active area in repository governance | Every new issue and pull request names an owner area |

Recommended order:

```text
A repository baseline
  -> B contract inventory + D CI alignment in parallel
  -> C status normalization
  -> E ownership activation
  -> only then structural module splitting
```

The first sprint is complete when a new contributor can clone the reviewed
baseline, choose an ownership area, find its contracts, run its focused tests,
make a scoped change and report evidence without relying on chat history.

## Known Baseline Gaps

The initial inventory found these collaboration blockers:

- Scenario, Ground Truth, Agent I/O, verification and batch artifacts are not
  all backed by versioned models or JSON Schemas.
- The active implementation and legacy `atomic/`, `core/`, `models/` and older
  orchestrator paths coexist.
- The current CI workflow references historical `tests/unit`,
  `tests/integration` and `tests/atomic` layouts instead of the active
  `tests/shared`, `tests/atomizer`, `tests/orchestrator` and `tests/sft` layout.
- Project metadata says Python `>=3.10` while onboarding and CI select 3.12;
  the supported-version policy needs one authoritative answer.
- Local research state, reviewed public state and Git history are not yet one
  clean release snapshot.

These are project-level tasks. They must not be “fixed” by changing one Atom,
one generated Range or one historical result.
