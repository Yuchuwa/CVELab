# Collaboration Baseline Roadmap

Status: active

Last reviewed: 2026-07-30

## Goal

Make CVELab safe for parallel contribution without changing research semantics.
The order is contracts first, structural refactoring second.

## Phase 1: Collaboration Baseline

Deliverables:

- authoritative README and documentation index;
- architecture and interface registry;
- current status dashboard and roadmap;
- contribution and data-publication policy;
- explicit active/legacy document and code boundaries;
- reviewed Git commit containing only collaboration-baseline files.

Acceptance:

- A new contributor can identify the active pipeline and run focused tests.
- Every major artifact has a named producer, consumer and authority.
- Current status is not inferred from the historical ledger.
- Raw experiment data cannot be added accidentally through normal Git commands.

## Phase 2: Version File Contracts

Add versioned models or JSON Schemas for:

- generated scenario manifest;
- private Ground Truth;
- Agent input and output;
- verification result;
- experiment manifest, batch state and batch summary.

Acceptance:

- Producer/consumer contract tests cover required fields and privacy boundaries.
- Breaking field changes fail tests before runtime.
- Every persisted artifact records a schema version.

## Phase 3: Normalize Status and Experiments

Deliverables:

- one canonical Atom-pool JSON with generated CSV/Markdown views;
- explicit population definitions for discovered, managed, candidate, anchor and
  matrix-eligible Atoms;
- experiment registry with model, runner, context, template/Atom fingerprints,
  code revision, denominators and supersession;
- a curated public export format.

Acceptance:

- Counts are reproducible from one command.
- Historical runs remain immutable and can be traced to their input snapshot.
- Aggregate reports cannot mix generation, environment and Agent denominators.

## Phase 4: Reduce Coupling

Refactor only behind established contract tests:

- remove upward imports from `shared`;
- centralize Agent exposure and material-visibility policy;
- separate deterministic verification from Agent transport/execution;
- separate network, asset, objective and noise assembly concerns;
- isolate Atom source, native, Guide and runtime stages;
- mark or retire legacy packages with known consumers.

Acceptance:

- Subsystem changes touch fewer ownership hotspots.
- Existing scenario and result fixtures remain contract-compatible.
- No CVE-specific branch is introduced.

## Phase 5: Research Expansion

After the collaboration and contract baseline is stable:

- expand template shapes using measured Atom coverage;
- expand Atom diversity beyond web RCE and initial access;
- run controlled model/context/decoy experiments;
- publish sanitized manifests, summaries and selected trajectories;
- rebuild SFT evidence with clean holdouts and reproducible evaluation.

## Near-Term Backlog

| Priority | Item | Done when |
|---|---|---|
| P0 | Review and merge collaboration baseline | Docs and ignore policy are on GitHub |
| P0 | Establish a clean code/data release boundary | Intended code changes are reviewed in scoped commits |
| P1 | Add Scenario and Verification Result models | Round-trip and privacy tests pass |
| P1 | Regenerate canonical Atom status | JSON/CSV/Markdown share one timestamp and hash |
| P1 | Add experiment registry | Existing benchmark runs can be indexed without rewriting them |
| P2 | Mark legacy modules and documents | New contributors no longer enter old architecture paths |
| P2 | Build sanitized public exporter | Secret/leak scan passes on exported data |

The backlog does not assign people. Ownership can be added after the repository
baseline is merged and the actual contributor availability is known.
