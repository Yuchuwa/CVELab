# Range Build Guide

Status: active

Last reviewed: 2026-07-30

## Input Boundary

Range consumes only Atom facts. A production research matrix starts from
`completed` Atoms, then applies template-specific constraints. Atom status does
not contain a global `matrix_eligible` flag.

The Range selector owns:

- template and slot requirements;
- service, role and capability matching;
- dependency and network-reachability constraints;
- asset/service-family compatibility;
- Guide and material availability required by the selected experiment;
- accepted combinations and structured rejection reasons.

## Matrix Record

Every generated matrix must record:

| Field | Requirement |
|---|---|
| Matrix identity/version | Stable name plus schema or rule version |
| Template | Exact template name and relevant revision |
| Atom snapshot | Source Atom status hash or equivalent immutable identity |
| Slot bindings | Atom selected for each injection point |
| Selection rules | Service, capability, dependency and coverage constraints |
| Accepted cases | Complete slot bindings and asset variants |
| Rejections | Candidate, slot and reusable reason code |

Matrix records live under `data/range_matrices/`. Their selected Atom lists are
Range artifacts, not Atom classifications.

Full manifests under `data/range_matrices/` are local experiment artifacts.
`data/range_matrix_status.json` is the tracked compact Range-side view: it
records the Atom snapshot hash, Range candidate Atom IDs, actually selected
Atom IDs and rejection counts.

## Build and Validation Flow

```text
completed Atom snapshot
-> template/slot matching
-> matrix accepted and rejected records
-> generate-only
-> environment-only
-> attack-graph and attack-path checks
-> Agent evaluation when requested
-> private objective verification
-> cleanup
-> batch summary and progress update
```

Report these outcomes independently:

- scenario generation;
- environment;
- Range build gates;
- attack graph;
- attack path;
- Agent;
- objective;
- cleanup.

Agent or objective failure must not overwrite an already successful deterministic
environment result.

## Progress Recording

`data/range_build_status.json` is the authoritative sanitized build ledger.
Its CSV and Markdown views list every discovered attempt and all construction
stages. Under each template, a Range is reported as:

- `succeeded`: generation, environment, Range build, attack graph and attack
  path all passed;
- `failed`: at least one deterministic stage explicitly failed;
- `incomplete`: no explicit deterministic failure, but at least one required
  stage was not evaluated.

Repeated model or context trials remain separate attempts of the same Range.
Agent and objective fields are retained for experiment denominators but do not
change the Range build outcome.

## Acceptance

A generated Range is structurally interpretable only when generation,
environment, Range build, attack graph and attack path checks pass. Agent and
objective outcomes are research results, not substitutes for those gates.

No failed combination may receive a CVE-specific matcher, template or verifier
exception. Record the generic violated contract and fix only reusable logic.
