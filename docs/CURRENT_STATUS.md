# Current Project Status

Status: generated snapshot

Snapshot date: 2026-08-10

Scope: local working tree and its tracked generated status artifacts, not a
clean public release

This dashboard is a generated current-state view. Counts below come from the
live tracked status sources named in the evidence column. A matrix acceptance
is a composition result; it is not an environment, Agent or objective success
claim.

## Summary

| Area | Current state | Evidence | Main limitation |
|---|---|---|---|
| Shared contracts | Atom, Guide, Template, Scenario/Truth/Agent/Batch/Material envelopes and Verification Result are represented | `src/clab_builder/shared/models/`, `docs/INTERFACES.md` | Raw tool/session streams and historical extension fields remain outside the typed envelopes |
| Atom lifecycle | **284 total: 0 planned, 238 building, 46 completed** | `data/atom_pool_status.json` | `completed` requires every strict Atom gate; building is not a verified release state |
| Range matrix | **506 selected cases from 1,800 legal** enterprise three-tier compositions | `data/range_matrix_status.json` and its referenced manifest | Selection is no-deploy composition compatibility only; it does not claim deployment or Agent success |
| Range experiments | Existing historical and local result ledgers remain separate from the current matrix snapshot | `data/range_build_status.json`, `data/experiment_status.json` | Results span different code, Atom and model snapshots; no new outcome is inferred here |
| Agent evaluation | Agent runners and exposure-profile paths are operational interfaces | `src/clab_builder/orchestrator/composer/`, `scripts/verify_enterprise3_guided_batch.py` | Trial outcomes require an explicit run manifest and denominator |
| SFT | Versioned corpus, split and run-lineage paths are present | `sft/`, `docs/INTERFACES.md` | No reliable model-improvement claim is made by this dashboard |
| Public data | Code, reviewed contracts and selected status views are tracked | `docs/DATA_POLICY.md`, `.gitignore` | Raw sessions, flags, credentials, generated ranges and adapters remain private |

## Atom Snapshot

The live generated Atom status is:

- `284` total entries;
- `0` `planned`;
- `238` `building`;
- `46` `completed`.

Atom has exactly these three lifecycle states. `completed` requires every
strict gate in [`ATOM_BUILD_GUIDE.md`](ATOM_BUILD_GUIDE.md), including source
bundle, runtime, native, Guide and orchestrated-environment evidence. Matrix
membership is owned by Range and is not an Atom lifecycle state.

The release-integrator freshness command is read-only:

```bash
uv run python scripts/generate_atom_pool_status.py --check
```

It recomputes the live lifecycle index and checks the generated JSON, CSV and
Markdown views for one semantic snapshot hash and timestamp.

## Range Snapshot

The current generated matrix source is:

```text
dmz-web -> app-service -> data-store
```

`data/range_matrix_status.json` records `1,800` legal compositions and `506`
coverage-first selected cases for `enterprise_3tier`, with Atom snapshot
provenance. The referenced manifest is a no-deploy matrix and its selected
cases have not thereby been deployed or sent to an Agent. Environment, graph,
path, Agent and objective outcomes remain independent result fields in their
own artifacts.

See [`RANGE_PROGRESS.md`](RANGE_PROGRESS.md) for historical Range-stage
evidence; do not substitute its older populations for this live matrix count.

## Current Risks

1. The working tree contains local Atom, Range, Agent and SFT changes that are
   not automatically a public release.
2. Raw tool/session streams, provider diagnostics and historical batch extension
   fields still need separate migration/retention policy.
3. Raw experiments can contain flags, internal addresses, credentials and
   attack commands and must not enter normal CI.
4. Docker, ContainerLab, external vulnerability checkouts and LLM endpoints
   are prepared-host dependencies, not core CI assumptions.
5. The active pipeline and legacy architecture coexist; new work follows the
   active paths named in [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Status Source Rule

The release integrator regenerates/checks upstream status before downstream
views in this order:

```text
Atom lifecycle -> Range matrix -> Range/Agent status -> SFT lineage -> this dashboard
```

Never hand-edit generated data to make a count or gate pass. Record the source
snapshot, denominator, command and limitation in the append-only progress
ledger when the project process permits a ledger update.
