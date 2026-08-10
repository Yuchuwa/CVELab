# Collaboration Baseline Roadmap

Status: active

Last reviewed: 2026-08-10

## Goal

Make CVELab safe for parallel contribution without changing research semantics.
The order is contracts first, structural refactoring second, and research
expansion only after artifact ownership is explicit.

The current dashboard is a generated live status view of the tracked sources. Its baseline
is **284 Atoms total: 0 planned, 238 building and 46 completed**, plus **506
selected enterprise_3tier cases from 1,800 legal compositions**. These are
lifecycle and composition counts, not claims of experiment, deployment, Agent
or SFT success.

## Four Ownership Lanes

The roadmap is executed through four lanes and a rotating release integrator:

- **Atom:** source, native verification, runtime/source bundle, Guide and
  lifecycle admission.
- **Range:** templates, matching, matrix selection, scenario assembly and
  deterministic verification.
- **Agent:** exposure profiles, input/output boundaries, runners and trial
  result semantics.
- **SFT:** sanitized trajectory export, corpus/split lineage, training and
  evaluation manifests.
- **Release integrator:** generated status, CI, docs, release scope and final
  handoff checks; it does not redefine scientific outcomes.

The lane owner reviews its producer. Every cross-lane contract change also gets
the required consumer-lane review, updates `INTERFACES.md` and positive,
negative and privacy tests, and names a release-integrator reviewer when it
touches generated status, CI or publication policy. See
[`COLLABORATION_PLAYBOOK.md`](COLLABORATION_PLAYBOOK.md).

## Phase 1: Collaboration Baseline

Deliverables:

- authoritative README and documentation index;
- architecture and interface registry;
- generated current-status dashboard and roadmap;
- contribution, operations and data-publication policy;
- explicit active/legacy document and code boundaries;
- fast CI contract gates that do not require private raw Range/SFT data.

Acceptance:

- A new contributor can clone the repository, select a lane and run its focused
  `uv run` tests.
- Every major artifact has a named producer, consumer, authority and privacy
  boundary.
- Generated status is checked without writing in CI.
- Current counts name their source population and denominator.

## Phase 2: Version File Contracts

Scenario Manifest v1, Verification Result v1 and AgentExposureProfile v1 are
the implemented baseline. Continue with versioned models or schemas for:

- private Ground Truth;
- complete Agent input and output plus prompt audit envelope;
- experiment manifest, batch state and batch summary;
- material mount and visibility audit records.

Acceptance:

- Producer/consumer tests cover required fields and privacy boundaries.
- Breaking field changes fail tests before runtime.
- Every persisted artifact records a schema version or is explicitly listed as
  an untyped gap.

## Phase 3: Normalize Status and Experiments

Deliverables:

- one canonical Atom build-status JSON with generated CSV/Markdown views;
- exactly three Atom lifecycle states: planned, building and completed;
- Range-owned matrix manifests with selected bindings, provenance and
  structured rejection reasons;
- experiment registry with model, runner, context, template/Atom fingerprints,
  code revision, denominators and supersession;
- a curated public export format.

Acceptance:

- Counts are reproducible from one read-only check or documented generator.
- Historical runs remain immutable and trace to their input snapshot.
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

## Phase 5: Collaboration, CI and Progress

Status: in progress

The Phase 5 baseline is the collaboration and release plumbing, not a research
result. It includes:

- four-lane ownership and required reviewer rules;
- the executable clean-clone runbook in [`OPERATIONS.md`](OPERATIONS.md);
- registry entries for exposure, SFT lineage, lifecycle freshness and material
  visibility, with remaining untyped gaps called out;
- fast CI checks for generated Atom status, matrix provenance, docs/workflow
  links and synthetic contract tests;
- generated current-status wording that reports the live `284/0/238/46` Atom
  lifecycle counts and `506` selected matrix cases without inferring experiment
  success.

Acceptance:

- A clean clone can run the core gate without Docker, raw Range data, raw SFT
  data or an LLM endpoint.
- Every active handoff has one producer, consumer, contract/version and owner.
- No generated status dashboard differs from its machine-readable source.
- Every pull request names affected contracts and includes producer/consumer
  tests where applicable.
- Environment, Agent, objective and SFT outcomes remain independently reported.

## Phase 6: Research Expansion

After the collaboration and contract baseline is stable:

- expand template shapes using measured Atom coverage;
- expand Atom diversity beyond web RCE and initial access;
- run controlled model/context/decoy experiments;
- publish sanitized manifests, summaries and selected trajectories;
- rebuild SFT evidence with clean holdouts and reproducible evaluation.

This phase must not use the `506` composition count as an experiment denominator
or imply success for cases that have not passed their corresponding gates.

## Near-Term Backlog

| Priority | Item | Done when |
|---|---|---|
| P0 | Review and merge Phase 5 collaboration/CI baseline | Docs, workflow and fast gates pass from a clean clone |
| P0 | Preserve a clean code/data release boundary | Scoped changes exclude raw sessions, flags, credentials, ranges and adapters |
| P1 | Complete Ground Truth, Agent I/O and batch models | Round-trip, negative and privacy tests pass |
| P1 | Complete material visibility audit contract | Mount decisions and audit evidence are versioned and tested |
| P1 | Maintain generated status chain | Atom freshness and Range provenance checks pass before downstream regeneration |
| P2 | Mark legacy modules and documents | New contributors no longer enter old architecture paths |
| P2 | Build sanitized public exporter | Secret/leak scan passes on exported data |

The backlog does not assign people. The release integrator rotates; lane owners
and reviewers are assigned in issues or pull requests after availability is
known.
