# Atom Batch 2026-07-18 Status

## Selection Basis

This wave was selected from the current Atom pool as a capability, service-family,
automation-stability, and environment-reliability batch. It was not selected to
repair one named Range case.

## Accepted

| CVE | Service family | Access | Verified capabilities | Guide | Runtime | Classification |
|---|---|---|---|---|---|---|
| CVE-2022-0543 | Redis 5.0.7 | RESP/TCP 6379, unauthenticated | root `execute_command`, `read_file` | v2, `ready` | `cvelab-runtime-2022-0543-e422f13fd5b6`, digest `sha256:fcb14f42a918acbe68a1269b7ff9ea6979594238c52963fa53d4890e91d3bcc0`; smoke/readiness passed | structure-healthy; runtime-ready data-service candidate |

Source bundle aggregate hash: `926550b0b05e55db`. Native and orchestrated
verification records are already successful. The Atom remains review-required
for the missing `exploit_access.required_service` metadata; no per-CVE Range
exception was added.

## Deferred / Rejected

| CVE | Decision | Failure class | Reason |
|---|---|---|---|
| CVE-2019-0193 | Defer | environment/build risk | Exact `vulhub/solr:8.1.1` image unavailable; do not substitute 8.2.0. |
| CVE-2016-3714 | Defer | validation-model mismatch | Compose expects `source_bundle/index.php` as a file, but the current bundle has a directory conflict. |
| CVE-2016-3088 | Defer | environment/build risk | Exploit entry service is HTTP/8161 while current runtime readiness first probes 61616. |
| CVE-2017-10271 | Defer | deferred for a later service/template family | Old WebLogic startup/data-plane binding remains unresolved. |
| CVE-2019-20933 | Defer | validation-model mismatch | v2/unverified, no self-contained source bundle, no ready Guide, no verified capabilities. |
| CVE-2017-12635 | Defer | deferred for a later service/template family | No native success or complete v3 Atom contract. |

## Range Boundary

No Range template, matcher, composer, verifier, generated scenario, or Guided
Agent run was changed or executed for this batch. Codex owns subsequent generic
matrix composition and validation.

## B1 Runtime Rebuild Results (2026-07-18)

The bounded wave contained 25 existing v3 Atoms classified by A1/A2 as
`rebuild_runtime_or_bundle`. B1 rebuilt runtime artifacts through the shared
runtime pipeline. Native evidence, source-bundle provenance, and Guide records
were not rerun or reclassified by this runtime-only wave.

### Runtime Ready

The following 21 entries are `structure-healthy` with runtime image build,
logical-tool smoke, and original-compose service readiness passing:

| CVE | Result |
|---|---|
| CVE-2012-1823 | ready |
| CVE-2014-3120 | ready |
| CVE-2016-3088 | ready |
| CVE-2016-3714 | ready; source bundle regenerated through shared capture |
| CVE-2017-10271 | ready |
| CVE-2017-11610 | ready |
| CVE-2017-12615 | ready |
| CVE-2017-15715 | ready after generic EOL-Debian fallback fix |
| CVE-2017-17562 | ready |
| CVE-2018-12613 | ready after generic EOL-Debian fallback fix |
| CVE-2018-19475 | ready |
| CVE-2019-0193 | ready; exact declared image retained |
| CVE-2019-11043 | ready after generic EOL-Debian fallback fix |
| CVE-2019-17558 | ready after smoke entrypoint fix |
| CVE-2021-42013 | ready |
| CVE-2022-0543 | ready |
| CVE-2022-22965 | ready |
| CVE-2022-24816 | ready |
| CVE-2023-4450 | ready after smoke entrypoint fix |
| CVE-2023-51467 | ready |
| CVE-2024-27348 | ready |

### Runtime Deferred

| CVE | Failure class | Established result |
|---|---|---|
| CVE-2017-17405 | runtime tool package availability | Debian Jessie archive is reachable, but `python3-pyftpdlib` is unavailable. |
| CVE-2018-2894 | runtime tool profile compatibility | Yum build completes, but RHEL/Oracle repositories do not provide the standard `requests` and `psycopg2` Python modules; smoke fails those logical tools. |
| CVE-2020-10199 | runtime tool package availability | DNF build fails because UBI 8 has no matching `postgresql` package for the standard profile. |
| CVE-2021-32568 | runtime smoke contract | Image builds and all other smoke checks pass; `python3_psycopg2` is missing. Existing orchestrated record also lacks the source compose file. |

Shared B1 fixes were limited to generic runtime contracts: smoke commands now
override inherited image entrypoints, EOL Debian source fallback recognizes
legacy source layouts and creates required man directories, and image-only
runtime generation probes the actual base image package manager. Focused tests:
`40 passed`.
