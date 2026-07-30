# Current Project Status

Status: generated snapshot

Snapshot date: 2026-07-30

Scope: local working tree, not a clean public release

This dashboard reports established facts and their evidence. Counts describe
the current local snapshot; the public GitHub branch can lag behind until a
reviewed release includes the corresponding code and data.

## Summary

| Area | Current state | Evidence | Main limitation |
|---|---|---|---|
| Shared contracts | Atom, Guide, Template, Scenario v1 and Verification Result v1 models exist | `shared/models/` | Ground Truth, Agent I/O and batch contracts remain untyped |
| Atom build | 239 tracked; 0 planned, 193 building, 46 completed | `data/atom_pool_status.json` | Most historical Atoms do not meet the strict completion contract |
| Atom diversity | 175 RCE; 228 initial-access; 197 web-application | same snapshot | Weak privilege, credential, lateral, persistence and collection coverage |
| Templates | Three templates; enterprise three-tier is the active research template | `templates/` | Complex template diversity is limited |
| Matrix planning | Completed-only enterprise matrix records 1,800 accepted combinations using 28 selected Atoms from 39 Range inputs | `data/range_matrix_status.json` | Accepted does not mean freshly deployed |
| Range environment | Multiple 50-case runs reached 50/50 deterministic environment gates | experiment summaries | Historical evidence is not a fresh guarantee for every current Atom |
| Range build ledger | 2,345 unique Range definitions; latest state 574 succeeded, 35 failed, 1,736 incomplete | `data/range_build_status.json` | Historical attempts span different code and Atom snapshots |
| Agent evaluation | 136 batches and 3,787 sanitized result records are indexed | `data/experiment_status.json` | Historical summaries did not persist model identity |
| Decoys | Noise generation, readiness and interaction diagnostics work | template/tests/experiment summaries | No clean causal decoy estimate yet |
| SFT | Conversion, adapters and evaluation paths exist | `sft/`, `data/sft/` | No reliable measured model improvement yet |
| Public data | Code repository exists | Git remote and tracked files | Raw trajectories and latest research state are not publication-safe |

## Atom Snapshot

The canonical generated build status contains:

- 239 tracked entries.
- 0 `planned`.
- 193 `building`.
- 46 `completed`.

Atom has only these three lifecycle states. `completed` requires every strict
gate in [`ATOM_BUILD_GUIDE.md`](ATOM_BUILD_GUIDE.md); missing evidence remains
`building`. CSV and Markdown are views of the same JSON snapshot and carry the
same timestamp and hash. Matrix membership is owned by Range and is not an Atom
status. Distribution remains heavily skewed:

- 228 `initial_access`, 6 `execution`, 2 `credential_access`, 2 `discovery`
  and 1 `privilege_escalation`.
- 175 RCE, 23 LFI, 16 Auth Bypass, 8 Injection, 7 Info Leak,
  5 Deserialization, 4 SSRF and 1 LPE.
- 197 web applications, 22 middleware, 9 databases, 6 system services,
  4 frameworks and 1 file service.

Older Atom-scale datasets and progress entries use different historical
populations. Always name the population when reporting a count.

## Range Snapshot

The most mature pattern is:

```text
dmz-web -> app-service -> data-store
```

It supports network isolation, dependency/capability closure, private business
objectives and PostgreSQL/Elasticsearch asset variants. Historical three-hop
environment and Agent evidence exists, but environment validity, Agent success
and objective success must be reported separately.

Representative local artifacts include:

- `data/range_matrices/enterprise_3tier_hetero.json`
- `data/guide_ablation/guided_reconciled/summary.json`
- `data/guide_ablation/l2_deepseek_v3/summary.json`
- `data/guide_ablation/glm52_l2_none_50_rerun_20260728/summary.json`

These are local research artifacts and are not automatically approved for
publication.

See [`RANGE_PROGRESS.md`](RANGE_PROGRESS.md) for stage-by-stage counts.

## Current Risks

1. The working tree contains many modified and untracked code/data artifacts.
2. Current documentation and public Git history describe different snapshots.
3. Raw experiments contain flags, internal IPs, credentials and attack commands.
4. Tracked history contains credential-like strings in documentation, scripts,
   tests and research artifacts; candidates must be reviewed and real
   credentials rotated before public sharing.
5. The active pipeline and legacy architecture coexist without package-level
   enforcement.
6. Ground Truth, Agent I/O and batch files still have untyped contracts.
7. Three broad orchestration modules are likely merge-conflict hotspots.

## Status Update Rule

Update this file only when a current fact changes. Record the underlying run or
decision separately in `WORK_PROGRESS_REPORT.md`. Never paste long experiment
logs into this dashboard.
