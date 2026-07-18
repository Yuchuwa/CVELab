# Phase 1: Batch Atom Reconstruction Audit and Supply Preparation

## Objective

Prepare a reproducible, batch-oriented reconstruction queue for the current
Atom pool. The output is not a hand-picked set of Range fixes. It is a manifest
that states which Atoms are currently usable, which need a shared-pipeline
rebuild, and which are blocked by external source availability.

The Phase 1 gate is:

```text
audit current Atom contracts
→ classify by reusable reconstruction class
→ build a value-ranked reconstruction wave
→ rebuild using the shared Atom pipeline
→ independently record native/runtime/Guide evidence
→ hand accepted Atoms to Range matrix generation
```

No business-data proof, credential binding, CRUD witness, or Range-specific
requirement is added in this phase.

## Shared classification

Every Atom is assigned one primary state, with machine-readable reasons:

| State | Meaning | Action |
|---|---|---|
| `range_ready` | Current high-confidence contract is complete and runtime-ready. | Keep in Range pool. |
| `rebuild_runtime_or_bundle` | Native truth exists, but bundle/runtime/readiness contract is stale or incomplete. | Rebuild through shared pipeline. |
| `full_reconstruction` | Missing v3 contract, verified native evidence, or ready Guide. | Run full Agent-driven Atom reconstruction. |
| `blocked_source_unavailable` | Exact declared source image/material cannot be obtained or built. | Record and defer; never substitute a version. |
| `deferred_low_value_or_unstable` | Candidate has low marginal value or repeated automation/environment instability. | Record and skip this wave. |

An individual CVE may illustrate a class, but the classifier and rebuild path
must never contain a CVE-specific branch.

## A. Codex responsibilities

### A1. Build the reconstruction audit

Implement a shared, no-LLM audit command that reads the Atom pool and writes a
versioned manifest. It must inspect:

- Atom schema/version and `verified` state;
- source-bundle manifest/filesystem completeness;
- native and orchestrated verification records;
- Guide presence, schema validity, safe status, and material references;
- `exploit_access.required_service` and readiness-port consistency;
- runtime contract/status/digest/readiness state;
- exact source-image declaration and locally observable availability state.

The command produces:

```text
data/atom_reconstruction_audit.json
data/atom_reconstruction_audit.csv
```

Implemented command:

```bash
PYTHONPATH="$PWD/src" python scripts/audit_atom_reconstruction.py --max-wave 25
```

Run it in the Docker privilege context used for Atom reconstruction when local
image visibility is needed. Without Docker socket access it records
`source_image_local=unknown`, not `not_local`.

Each row includes classification, reasons, capability/role/service metadata,
and enough evidence to reproduce the decision. It must not modify Atom data.

### A2. Build a generic wave selector

Use the audit results plus the existing value dimensions to select a bounded
wave:

- verified or realistically obtainable `execute_command` / `read_file` value;
- expected automation stability;
- service/capability/role diversity contribution;
- source and runtime environment reliability.

The selector writes a queue manifest, not a list of ad-hoc commands. It may
include a CVE only because its classification and value score meet the same
rule as every other candidate.

### A3. Maintain shared reconstruction contracts

Fix only reusable defects found by the audit, with focused regression tests.
Current examples already covered by shared code are bundle recapture before
orchestrated verification and exploit-entry readiness for multi-port services.
Exact image unavailability remains an external blocker unless a general,
provenance-preserving source-build route exists.

### A4. Accept the OpenCode delivery

For each completed wave, verify contract facts independently:

```text
schema/source bundle
native record
orchestrated record
Guide integrity
runtime smoke/readiness
classification/status artifact
```

Then regenerate the no-deploy Range matrix. Do not deploy or tune a Range as
part of Atom acceptance.

### Codex acceptance criteria

- Audit and wave output are deterministic and do not mutate Atom files.
- Classification rules have unit tests, including multi-port and stale-bundle
  classes.
- Every code change is shared and has a regression test.
- Accepted Atom handoff records distinguish Atom evidence from Range evidence.

## B. OpenCode responsibilities

### B1. Consume the selected wave

Use Codex's reconstruction-wave manifest and the common Atom pipeline. Do not
select work from a failed Range, alter Range code, modify templates, or write
per-CVE compatibility branches.

For each candidate:

1. Confirm the exact source image/material is available; if not, record
   `blocked_source_unavailable` and move on.
2. Run the requested reconstruction path:
   - `rebuild_runtime_or_bundle`: rebuild the source bundle/runtime contract
     through the current shared pipeline;
   - `full_reconstruction`: run native Agent reconstruction, then capture
     source bundle, generate Guide, and build/verify runtime.
3. Record native, orchestrated, Guide, runtime smoke, and readiness results
   independently.
4. On failure, use the shared classification and continue the wave. Do not
   repeatedly force a low-value candidate through the pipeline.

### B2. Permitted Atom-side code changes

OpenCode may change Atom-side code only when a failure recurs as a class. The
change must be independent of CVE ID, template name, target number, or Range
output, and must include a focused regression test. Record the shared contract
change before handing the wave back.

### B3. Required deliverables

- Updated wave manifest with per-candidate result and failure class;
- accepted Atom directories with complete contract evidence;
- updated `atom_pool_status.*`, candidate queue/rebuild status, and
  `docs/WORK_PROGRESS_REPORT.md`;
- one concise table: CVE, classification, role/family/access, verified
  capabilities, Guide state, runtime state, and reason if not accepted.

### OpenCode acceptance criteria

- No Range/template/matcher/composer/verifier/generated-scenario changes.
- No version substitution for an unavailable source image.
- No Atom accepted without all first-stage evidence gates.
- Every deferred/rejected candidate is classified and retained in the queue.
- Source bundles remain self-contained and no source-bundle baseline hash is
  silently changed outside a reconstruction result.

## Execution order

```text
Codex A1/A2 (audit + selected manifest)
→ OpenCode B1 (first bounded reconstruction wave)
→ Codex A4 (contract acceptance + no-deploy matrix regeneration)
→ repeat with the next wave
```

Codex's audit implementation and OpenCode's unrelated candidate preparation may
run in parallel. A candidate must not enter Range generation until its completed
Atom contract has passed Codex acceptance.
