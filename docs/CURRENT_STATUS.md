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
| Shared contracts | Atom, Guide and Template models exist | `shared/models/` | Scenario/result/batch contracts remain untyped |
| Atom pool | 117 managed rows; 108 marked template-ready | `data/atom_pool_status.json` | Status populations and qualification terms need normalization |
| Atom diversity | 105 RCE; 113 initial-access; 81 web-application | same snapshot | Weak privilege, credential, lateral, persistence and collection coverage |
| Templates | Three templates; enterprise three-tier is the active research template | `templates/` | Complex template diversity is limited |
| Matrix planning | Heterogeneous enterprise matrix records 1,800 accepted combinations | `data/range_matrices/enterprise_3tier_hetero.json` | Accepted does not mean freshly deployed |
| Range environment | Multiple 50-case runs reached 50/50 deterministic environment gates | experiment summaries | Historical evidence is not a fresh guarantee for every current Atom |
| Agent evaluation | Guided and L0/L1/L2 pipelines are operational | batch summaries | Results vary by model, context and historical contract |
| Decoys | Noise generation, readiness and interaction diagnostics work | template/tests/experiment summaries | No clean causal decoy estimate yet |
| SFT | Conversion, adapters and evaluation paths exist | `sft/`, `data/sft/` | No reliable measured model improvement yet |
| Public data | Code repository exists | Git remote and tracked files | Raw trajectories and latest research state are not publication-safe |

## Atom Snapshot

The current managed status contains:

- 117 structure/source-bundle healthy entries.
- 113 with recorded environment success.
- 114 with recorded native exploit success.
- 108 marked `template_ready`.

Distribution is heavily skewed:

- 113 `initial_access`, 3 `execution`, 1 `credential_access`.
- 105 RCE and 7 LFI; other categories have one entry each.
- 81 web applications, 14 frameworks, 13 middleware, 5 system services and 4 databases.

These are different populations from all `data/atoms/*/atom.yaml` files and
from older Atom-scale datasets. Always name the population when reporting a
count.

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

- `data/guide_ablation/guided_reconciled/summary.json`
- `data/guide_ablation/l2_deepseek_v3/summary.json`
- `data/guide_ablation/glm52_l2_none_50_rerun_20260728/summary.json`

These are local research artifacts and are not automatically approved for
publication.

## Current Risks

1. The working tree contains many modified and untracked code/data artifacts.
2. Current documentation and public Git history describe different snapshots.
3. Raw experiments contain flags, internal IPs, credentials and attack commands.
4. The active pipeline and legacy architecture coexist without package-level
   enforcement.
5. Large untyped file contracts make cross-module changes risky.
6. Three broad orchestration modules are likely merge-conflict hotspots.

## Status Update Rule

Update this file only when a current fact changes. Record the underlying run or
decision separately in `WORK_PROGRESS_REPORT.md`. Never paste long experiment
logs into this dashboard.
