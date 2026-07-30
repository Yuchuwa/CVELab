# OpenCode Task: Batch High-Confidence Atom Supply Expansion

## 1. Background and boundary

CVELab has completed the first generic Range composition step: the
`enterprise_3tier` template can choose compatible PostgreSQL or Elasticsearch
asset setup/verification from an Atom's lightweight runtime service family.
Five generated combinations have passed environment-only validation.

The current bottleneck is therefore not a particular failed Range or CVE. It
is the limited and skewed supply of high-confidence Atoms from which the Range
matrix can be composed. The immediate research objective is to enlarge that
supply quickly and systematically, then let the Range side compose and test it
in batches.

This task belongs to the **Atom side only**. Do not modify Range templates,
matcher/composer/verifier code, batch scripts, generated scenarios, or use a
single Range result to justify a special Atom implementation. Codex owns the
shared Range-side composition and validation mechanisms.

## 2. Task objective

Produce one batch of high-confidence Atom candidates that increases useful
coverage across capability, service role, and automated-runtime reliability.
The batch must be selected from the available candidate pool as a whole, not
because one named Range currently needs one named CVE.

The first-stage admission requirements remain:

```text
complete runtime_spec
→ self-contained source_bundle
→ native verification record
→ orchestrated environment/runtime verification record
→ reviewed ready Exploit Guide
```

Do not add CRUD witnesses, business-data proofs, real credential binding, or
Agent asset-use reporting as Atom admission gates.

## 3. Candidate selection procedure

Before building, assess the available pool and select a **wave** of candidates
using all four dimensions below:

1. expected `capability_grants` value, prioritising reusable
   `execute_command` and `read_file`;
2. expected automated exploit stability (simple/reproducible paths before
   probabilistic, protocol-heavy, or fragile multi-stage exploits);
3. diversity contribution (service role, runtime family, capability, and
   MITRE phase where realistically available);
4. environment reliability (build/startup/image availability).

Choose a balanced wave rather than a list of near-duplicate web RCEs. It is
acceptable for most available candidates to remain initial-access RCEs; the
point is to maximise marginal diversity and reliability, not to fabricate
unavailable phases.

For each rejected or deferred candidate, record one concise class:

- low marginal value;
- environment/build risk;
- exploit automation instability;
- validation-model mismatch; or
- deferred for a later service/template family.

## 4. Required implementation and validation

For every selected candidate, use the common Atom construction path. Any code
change must be a reusable Atom-side pipeline, model, source-bundle, runtime,
or Guide-contract correction that demonstrably applies to a class of Atoms.
Do not add CVE-specific branches, path exceptions, Dockerfile exceptions, or
Range-aware logic.

For each completed Atom, verify and record independently:

1. schema and `runtime_spec` completeness;
2. self-contained source bundle and manifest integrity;
3. native exploit/validation result;
4. runtime image build or materialisation result;
5. smoke and service-readiness result;
6. exploit Guide schema, safe public content, material references, and state
   (`ready` only when the evidence supports it).

When a candidate fails, classify it and move on. Do not spend repeated cycles
trying to force a low-value or unstable candidate through the pipeline.

## 5. Deliverables

1. Update the current candidate queue/status artifact with the assessed wave,
   selection rationale, and rejections/deferments.
2. Build and validate the selected Atom wave under the shared pipeline.
3. Update `data/atom_pool_status.*` and any relevant rebuild/runtime status
   artifacts for each accepted or downgraded Atom.
4. Append established facts to `docs/WORK_PROGRESS_REPORT.md`, including
   build status (`planned`, `building`, or `completed`), failed completion
   gates, validation results, limitations, and handoff boundary.
5. Provide a concise final table: CVE, role/family, verified capabilities,
   Guide state, runtime state, build status, and failure class if rejected.

## 6. Acceptance criteria

The task is accepted only if:

- selection is documented as a batch value assessment, not as fixes for named
  Range cases;
- every accepted Atom satisfies the first-stage admission chain above;
- no accepted Atom depends on an external absolute Vulhub/host path at Range
  runtime;
- any Atom-side code changes are generic and have targeted regression tests;
- rejected candidates are classified instead of silently omitted;
- no Range code, template, generated scenario, or per-CVE Range workaround was
  modified;
- all progress/status records distinguish native, runtime, and Range evidence.

## 7. Handoff to Codex

At completion, hand over the accepted Atom list and their effective role,
runtime service family, service access, verified capabilities, Guide state,
and runtime readiness. Codex will regenerate the Range matrix and run generic
composition/environment validation. A later Range failure is evidence for
shared-contract diagnosis, not a request to customise an Atom for that case.
