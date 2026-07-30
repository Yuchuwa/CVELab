# Documentation Index

Status: active

Last reviewed: 2026-07-30

This page is the entry point for current CVELab documentation. Documents not
listed as active below may describe an earlier architecture, a completed task,
or a historical experiment.

## Start Here

| Question | Document |
|---|---|
| What is the project and how do I run it? | [`../README.md`](../README.md) |
| How are modules separated? | [`ARCHITECTURE.md`](ARCHITECTURE.md) |
| What files and interfaces connect modules? | [`INTERFACES.md`](INTERFACES.md) |
| What is complete and what is not? | [`CURRENT_STATUS.md`](CURRENT_STATUS.md) |
| What should be done next? | [`ROADMAP.md`](ROADMAP.md) |
| How should changes be developed and reviewed? | [`../CONTRIBUTING.md`](../CONTRIBUTING.md) |
| What data can be committed or published? | [`DATA_POLICY.md`](DATA_POLICY.md) |

## Active Contracts

- [`RANGEFACTORY_DESIGN.md`](RANGEFACTORY_DESIGN.md): conceptual Atom-to-Range design.
- [`ATOM_RANGE_EXECUTION_CONTRACT.md`](ATOM_RANGE_EXECUTION_CONTRACT.md): Atom consumption and result semantics.
- [`ATOM_RUNTIME_TO_RANGE_HANDOFF.md`](ATOM_RUNTIME_TO_RANGE_HANDOFF.md): runtime and source-bundle handoff.
- [`AGENT_INPUT_LEVEL_INTERFACE.md`](AGENT_INPUT_LEVEL_INTERFACE.md): Guided and L0/L1/L2 information exposure.
- [`INTERFACES.md`](INTERFACES.md): current contract registry and compatibility rules.

The Pydantic models and contract tests remain authoritative over prose.

## Progress Records

- [`CURRENT_STATUS.md`](CURRENT_STATUS.md) is the current-state dashboard.
- [`ROADMAP.md`](ROADMAP.md) contains planned work and acceptance gates.
- [`WORK_PROGRESS_REPORT.md`](WORK_PROGRESS_REPORT.md) is an append-only historical ledger.

Do not infer current status from an old progress entry. Follow its artifact
links and check whether a later entry superseded it.

## Document Lifecycle

Every maintained document should identify one of these states:

| State | Meaning |
|---|---|
| `active` | Current project or interface guidance |
| `proposal` | Planned work, not implemented behavior |
| `generated snapshot` | Reproducible status derived from data |
| `historical` | Preserved decision, incident or experiment record |
| `superseded` | Replaced as active guidance |

The following families are historical unless their header explicitly says
otherwise:

- May 2026 assessments and `PROGRESS_REPORT.md`.
- `CURRENT_PIPELINE.md` and documents centered on `atomic/` or `core/`.
- Dated OpenCode/Codex task briefs and handoff documents.
- Completed decoy, reconstruction and SFT implementation plans.

Historical files are retained for provenance but should not be used as the
implementation entry point.
