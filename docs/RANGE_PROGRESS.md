# Range Progress

Status: active current-state view

Snapshot date: 2026-08-10

This file summarizes Range-side progress. Per-matrix manifests and per-run
summaries remain the machine-readable evidence.

## Current Pipeline

| Stage | State | Current evidence | Limitation |
|---|---|---|---|
| Template/slot matching | Operational | Live snapshot supplies 46 completed Atoms; Range rejects 238 building inputs and 7 multi-service inputs before composition | Current implementation supports single-service slots |
| Matrix recording | Operational | Current completed-only matrix: 506 selected cases from 1,800 legal compositions, 245 Atom-input rejections and 21,989 composition rejections | Selection means composition only, not deployment |
| Historical build inventory | Generated | 136 summaries, 3,787 attempts, 2,345 unique Range definitions | Spans different code and Atom snapshots |
| Latest build outcome | Generated | 574 succeeded, 35 failed, 1,736 incomplete | “Latest” follows recorded summary timestamps |
| Generate-only | Operational | No-Hint preflight: 71 selected, 70 generated, 1 rejected | One generic slot/service mismatch |
| Environment-only | Operational | No-Hint smoke: 3 of 4 passed environment, Range build, graph and path gates | Small smoke sample |
| Guided full-gate baseline | Historical reusable evidence | 118 deduplicated Ranges passed environment, graph, path, Guided Agent and objective gates | Historical contract; not proof of current completed-Atom reproducibility |
| Agent evaluation | Operational | L2 DeepSeek batch: 50 evaluated; 15 Agent successes | Model/context-specific result |
| Objective verification | Operational | Same L2 batch: 13 objective successes | Must remain separate from Agent success |
| Cleanup | Operational | Same L2 batch: 49 cleanups passed, 1 cleanup failure | Cleanup is an independent lifecycle result |
| Versioned artifacts | Implemented, uncommitted | Scenario/Truth/Agent/Batch/Material envelopes v1 and Verification Result v1 round-trip | Raw tool/session events remain outside the typed envelopes |

## Active Matrix Sources

- `data/range_matrices/enterprise_3tier_hetero.json` owns the heterogeneous
  historical template selection, accepted combinations and rejection records.
- `data/range_matrices/enterprise_3tier_completed.json` owns the current
  completed-only Atom input list, Range input rejections, accepted slot
  bindings and composition rejections. It records the Atom snapshot hash.
- `data/range_matrix_status.json` is the tracked compact view of that local
  manifest and exposes the Range candidate and selected Atom lists to
  collaborators.
- `data/range_build_status.json`, CSV and Markdown form the sanitized
  per-Range/per-attempt build ledger. The Markdown view lists latest success,
  failure and incomplete state under each template; the attempt ledger records
  generation, environment, Range build, graph, path and cleanup separately.
- `data/experiment_status.json`, CSV and Markdown group the same evidence by
  experiment batch.
- `data/guide_ablation/manifest_reconciled.json` owns the selected cases for
  the Guide-ablation experiment.
- Each batch output directory owns its `summary.json` and per-case
  `verify_result.json`.

These lists belong to Range. They must not be copied into Atom status as
`matrix_eligible`.

## Next Work

1. Use the 506-case completed-only selected matrix for bounded environment validation.
2. Version the matrix/experiment manifest contract.
3. Consolidate Ground Truth, Agent input/output and batch state/summary models.
4. Continue layered environment-only and Agent validation while
   preserving failures as evidence.

## Superseding Correction

The 46-Atom and 1,800-accepted-case figures above the 2026-08-09 snapshot are
historical values from an earlier Atom snapshot. The canonical current values
are owned by `data/atom_pool_status.json`, `data/range_matrices/enterprise_3tier_completed.json`
and `data/range_matrix_status.json`.
