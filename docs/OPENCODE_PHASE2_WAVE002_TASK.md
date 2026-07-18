# OpenCode Task: Phase 2 / Reconstruction Wave 002

## 1. Background and boundary

The first bounded reconstruction wave has completed its Atom-side work:

- 25 existing v3 Atoms were processed through the shared runtime rebuild path;
- 21 are runtime-ready;
- 4 are deferred because their base distributions cannot satisfy the shared
  runtime-tool profile;
- Codex independently accepted those runtime-contract facts and regenerated
  the `enterprise_3tier` batch matrix.

The current bottleneck is Atom supply, not a failed Range. The project needs a
larger, diverse high-confidence Atom pool before it can produce 500--1000
interpretable Guided-Agent Range trials. This task starts the **second
bounded Atom reconstruction wave**. It must not be selected or modified to
make one named CVE, generated Range, or Agent run pass.

This is an **Atom-side-only** task. Do not change Range templates, matcher,
composer, verifier, batch scripts, generated scenarios, or Guided-Agent
prompts. Codex will accept the completed Atom contracts and regenerate the
Range matrix afterwards.

## 2. Objective

Produce and process `wave-002`: a deterministic, value-ranked batch of up to
25 Atom candidates that were not already completed in B1. The desired output
is additional high-confidence, runtime-ready Atoms with useful service-role,
service-family, and capability diversity.

The admission chain remains exactly:

```text
complete runtime_spec
→ self-contained source_bundle
→ native verification record
→ orchestrated environment/runtime verification record
→ reviewed ready Exploit Guide
```

Do not add business-data witnesses, CRUD proof, credential binding, or
Range-specific requirements as new Atom gates.

## 3. Required inputs and prerequisites

These inputs already exist; this task does **not** depend on an ongoing Range
environment or Guided-Agent experiment:

- `data/atom_reconstruction_audit.json` and `.csv`;
- `data/atom_reconstruction_wave.json` (the completed first-wave input);
- `data/atom_batch_2026-07-18_status.md` (B1 result ledger);
- current shared Atom pipeline, runtime builder, smoke contract, and tests.

Before selection, rerun the read-only audit in the Docker-capable execution
context so it sees the current Atom files and local image state. Write new,
wave-specific outputs rather than overwriting the historical first-wave audit:

```bash
PYTHONPATH="$PWD/src" python scripts/audit_atom_reconstruction.py \
  --output-prefix data/atom_reconstruction_audit_wave_002 \
  --wave-output data/atom_reconstruction_wave_002_raw.json \
  --max-wave 50
```

`source_image_local=not_local` only means the image is not cached locally.
It is not a reason to substitute an image version or silently reject the
candidate. Attempt the exact declared source image or the provenance-preserving
source build first; record `blocked_source_unavailable` only when that route
actually fails.

## 4. Wave-002 selection rules

Create `data/atom_reconstruction_wave_002.json` from the new audit and B1
ledger. It must be machine-readable and record both selected and excluded
entries.

1. Exclude every B1 entry already recorded as `runtime-ready`; do not rebuild
   it merely because a historical audit still classified it as stale.
2. Exclude the four B1 deferred entries from this wave unless a **single shared
   runtime-tool/profile correction** has been identified and is explicitly
   tested first. Do not retry them by changing package names or profiles for a
   single CVE.
3. Prefer remaining `rebuild_runtime_or_bundle` entries that can improve the
   pool with a bounded runtime rebuild.
4. Fill remaining places, up to 25 total, with highest-value
   `full_reconstruction` entries according to the same four project criteria:
   verified/likely `execute_command` and `read_file`, automation stability,
   marginal role/family/capability diversity, and environment reliability.
5. Avoid a wave dominated by duplicate web initial-access RCEs when equally
   stable alternatives improve role or service-family coverage.
6. Preserve all non-selected candidates with a concise reason: lower marginal
   value, environment/build risk, exploit automation instability,
   validation-model mismatch, or deferred service/template family.

The resulting manifest must state, per selected candidate: CVE ID, source
audit classification/reasons, value score, role, service family if known,
service access, verified capabilities, source image, and planned path
(`rebuild_runtime_or_bundle` or `full_reconstruction`).

If generic selection functionality is missing, it may be added only as a
reusable, tested audit/wave-selector capability. A hand-written list of CVEs
or a selection based on a failed Range is not acceptable.

## 5. Execution procedure

For each selected candidate, use the current common Atom pipeline.

### 5.1 `rebuild_runtime_or_bundle`

1. Preserve exact source image and source-bundle provenance.
2. Rebuild runtime image/materialisation through the shared builder.
3. Run the standard logical-tool smoke and original-compose service-readiness
   checks.
4. Record runtime image, base/runtime digests, generated hash, smoke result,
   readiness result, and failure class independently.

### 5.2 `full_reconstruction`

1. Run the native Agent reconstruction under the common pipeline.
2. Capture a self-contained source bundle, including attack-side materials.
3. Record native verification separately from environment/runtime results.
4. Generate and review the Exploit Guide. It must be safe public guidance:
   no native IP, real flag, host absolute path, failed trial transcript, or
   private Range objective assertion.
5. Build and verify the runtime image using the same shared runtime contract.

### 5.3 Failure handling

Classify each non-accepted candidate and continue the wave. Valid classes are:

- `blocked_source_unavailable`;
- `environment/build risk`;
- `runtime tool/profile compatibility`;
- `exploit automation instability`;
- `validation-model mismatch`; or
- `deferred service/template family`.

Do not repeatedly retry a low-value or unstable candidate. Do not solve a
failure with a CVE-ID branch, special Dockerfile/path exception, template
change, or Range-aware condition. A shared Atom code change is permitted only
when the same construction-contract defect is demonstrated as a class and has
a focused regression test.

## 6. Required deliverables

1. `data/atom_reconstruction_audit_wave_002.json` and `.csv`;
2. `data/atom_reconstruction_wave_002.json`, including selection and
   exclusions;
3. `data/atom_reconstruction_wave_002_results.json`, with one result per
   selected candidate and independent native/Guide/runtime evidence fields;
4. updated Atom directories and `data/atom_pool_status.*` /
   `data/cve_rebuild_status.md` as applicable;
5. an appended factual entry in `docs/WORK_PROGRESS_REPORT.md`;
6. a concise handoff table containing:

| CVE | planned path | role/family/access | verified capabilities | native | Guide | runtime | classification / failure class |
|---|---|---|---|---|---|---|---|

Do not overwrite historical B1 records. Add a dated wave-002 record instead.

## 7. Acceptance criteria

Codex will accept this wave only when all of the following are true:

- wave-002 selection is reproducible from the audit plus the recorded B1
  results, and excludes already-completed B1 Atoms;
- each accepted Atom has a complete schema/runtime contract, self-contained
  source bundle, native record, ready Guide, runtime image, smoke pass, and
  service-readiness pass;
- native, Guide, runtime, and Range evidence remain explicitly separate;
- source image versions are not substituted and source-bundle provenance is
  retained;
- every rejected/deferred candidate is present in the result ledger with a
  failure class;
- any Atom-side code change is generic, tested, and free of CVE/template/Range
  identifiers;
- no Range-side file or generated Range artifact is modified;
- focused relevant tests and `git diff --check` pass.

## 8. Handoff boundary

After delivery, Codex will independently perform the A4 contract audit,
regenerate the coverage-first matrix, and schedule `generate-only →
environment-only → Guided-Agent` validation. A later Range failure does not
authorise an Atom-specific compatibility patch; it must be analysed as a
shared construction or orchestration contract issue.
