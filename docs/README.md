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
| How is work divided and handed off? | [`COLLABORATION_PLAYBOOK.md`](COLLABORATION_PLAYBOOK.md) |
| What files and interfaces connect modules? | [`INTERFACES.md`](INTERFACES.md) |
| What is complete and what is not? | [`CURRENT_STATUS.md`](CURRENT_STATUS.md) |
| How is an Atom built and completed? | [`ATOM_BUILD_GUIDE.md`](ATOM_BUILD_GUIDE.md) |
| How is a Range selected and validated? | [`RANGE_BUILD_GUIDE.md`](RANGE_BUILD_GUIDE.md) |
| What is the current Range progress? | [`RANGE_PROGRESS.md`](RANGE_PROGRESS.md) |
| How are model/Agent experiments maintained? | [`EXPERIMENT_PROGRESS.md`](EXPERIMENT_PROGRESS.md) |
| What should be done next? | [`ROADMAP.md`](ROADMAP.md) |
| How should changes be developed and reviewed? | [`../CONTRIBUTING.md`](../CONTRIBUTING.md) |
| What data can be committed or published? | [`DATA_POLICY.md`](DATA_POLICY.md) |

## Active Contracts

- [`RANGEFACTORY_DESIGN.md`](RANGEFACTORY_DESIGN.md): conceptual Atom-to-Range design.
- [`ATOM_RANGE_EXECUTION_CONTRACT.md`](ATOM_RANGE_EXECUTION_CONTRACT.md): Atom consumption and result semantics.
- [`ATOM_RUNTIME_TO_RANGE_HANDOFF.md`](ATOM_RUNTIME_TO_RANGE_HANDOFF.md): runtime and source-bundle handoff.
- [`AGENT_INPUT_LEVEL_INTERFACE.md`](AGENT_INPUT_LEVEL_INTERFACE.md): Guided and L0/L1/L2 information exposure.
- [`INTERFACES.md`](INTERFACES.md): current contract registry and compatibility rules.
- [`ATOM_BUILD_GUIDE.md`](ATOM_BUILD_GUIDE.md): three-state Atom lifecycle and strict completion gates.
- [`RANGE_BUILD_GUIDE.md`](RANGE_BUILD_GUIDE.md): Range-owned matrix selection and validation gates.
- [`EXPERIMENT_PROGRESS.md`](EXPERIMENT_PROGRESS.md): experiment code, dimensions, ownership and progress.

The Pydantic models and contract tests remain authoritative over prose.

## Progress Records

- [`CURRENT_STATUS.md`](CURRENT_STATUS.md) is the current-state dashboard.
- [`RANGE_PROGRESS.md`](RANGE_PROGRESS.md) is the Range stage dashboard.
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
