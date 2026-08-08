# Data-Layer Atom Candidate Queue

Updated: 2026-07-20

This is an Atom-side planning queue for real data services. It does not change
Range matching, templates, assets, or objectives. Capability entries marked
"target" require native verification before promotion.

## 2026-07-20 heterogeneity wave additions

- `CVE-2022-0543` (Redis/6379): `exploit_access.required_service` backfilled to
  `redis/6379` via runtime probe (`echo INFO | nc` returned `redis_version:5.0.7`).
  Now a complete data-store candidate; no longer `review_required` for missing
  service-access metadata.
- `CVE-2019-10758` (mongo-express/8081): native + Guide ready, but runtime
  `service_ready` fails because the compose `depends_on: mongo` has no
  healthcheck and 8081 does not come up within the readiness window.
  Classified `environment/build risk` (compose multi-service healthcheck gap),
  not retried this wave.
- `CVE-2017-12635` (CouchDB 2.1/5984): compose `initd` dependency failed before
  agent start; classified `environment/build risk`, not retried.

## Build Now

| Priority | CVE | Service role / protocol / port | Authentication | Capability status | Data operation | MITRE phase | Automation risk | Environment risk | Diversity value | Rationale |
|---|---|---|---|---|---|---|---|---|---|---|
| P0 | CVE-2015-1427 | Elasticsearch search data service, HTTP/9200 | None | Verified root `execute_command`, `read_file` | Create an indexed document and query it through `_search`; exploit uses Groovy script execution | initial_access, execution | Low: direct HTTP request flow | Low: native/orchestrated pass, self-contained source bundle, runtime build/smoke/9200 readiness passed | Elasticsearch RCE contrasts with PostgreSQL control | Runtime-ready; await Codex data-layer contract review. |
| P1 | CVE-2019-0193 | Solr search/index service, HTTP/8983 | None | Verified root `execute_command`, `read_file`, `write_file`, `read_credential` | DataImportHandler targets the Solr core; indexed-record write/query evidence still needs explicit native proof | initial_access, execution, collection | Low-medium: HTTP payload | Low-medium: existing source and ready Guide, no runtime record | Broadest verified capability set outside PostgreSQL | Build after data CRUD evidence review. |
| P1 | CVE-2022-0543 | Redis KV store, RESP/TCP 6379 | None | Verified root `execute_command`, `read_file`; `write_file` remains unclaimed | Redis `SET`/`GET` are not part of native evidence; current Guide proves Lua RCE/file read | initial_access, execution | Medium: raw RESP and version-sensitive Lua path | Low-medium: runtime build, full smoke, and 6379 readiness passed | First native Redis protocol candidate | Runtime-ready Atom; remains `review_required` until the missing service-access metadata is reconciled generically. |

## Future Production Candidates

| Priority | CVE | Service role / protocol / port | Authentication | Capability status | Data operation | MITRE phase | Automation risk | Environment risk | Diversity value | Rationale |
|---|---|---|---|---|---|---|---|---|---|---|
| P0 | CVE-2019-20933 | InfluxDB time-series database, HTTP/8086 | Forged empty-key JWT impersonates `admin` | Target `authenticate`, data read/write; no command-execution claim | InfluxQL user/database enumeration and seeded time-series read/write | valid_accounts, collection | Low: deterministic stdlib JWT construction | Low: prebuilt single container | First time-series database and data-plane auth bypass | New Atom; requires current native verification and Guide. |
| P1 | CVE-2022-41917 | OpenSearch search data service, HTTPS/9200 | Basic `admin:admin` | Target `read_file`; authenticated index/search write/read | Index/search documents; traversal bytes are reflected by analysis API errors | collection, valid_accounts | Medium: TLS and error-byte parsing | Medium-high: JVM readiness and memory | Modern authenticated search service, unlike legacy unauthenticated Elasticsearch | New Atom; build only after source-bundle/preflight review. |
| P2 | CVE-2017-12635 | CouchDB document database, HTTP/5984 | Duplicate-key JSON creates admin | Target `authenticate`, document/database read/write; no RCE claim | CouchDB CRUD after admin creation | privilege_escalation, valid_accounts | Medium: duplicate JSON keys must be preserved | Low-medium: sidecar/init timing | Document-DB authorization bypass | Reserve; keep separate from CVE-2017-12636 RCE. |
| P2 | CVE-2018-16886 | etcd KV store, HTTPS/2379 | mTLS certificate-based RBAC bypass | Target key read/write/delete and auth administration; no command-execution claim | `/v3beta/kv/range`, `put`, `deleterange` | privilege_escalation, collection | Medium: certificate material lifecycle | High: EOL Go build | Distributed KV control-plane service | Research later; attacker-side key delivery must be self-contained. |

## Existing Controls And Non-Primary Atoms

| CVE | Service / access | Capability status | Data operation | Status |
|---|---|---|---|---|
| CVE-2019-9193 | PostgreSQL/TCP 5432, `postgres/postgres` | Verified `execute_command`, `read_file`, `write_file` as `postgres` | `COPY FROM PROGRAM` and SQL `SELECT`; current relational data-store control | Runtime-ready baseline; do not consume new build work. |
| CVE-2019-17558 | Solr/HTTP 8983, no auth | Verified root `execute_command`, `read_file` | Solr response-writer configuration and query endpoint; indexed-document CRUD not yet proven | Runtime-ready service control, not a primary data-operation Atom. |
| CVE-2015-5531 | Elasticsearch/HTTP 9200, no auth | Verified `read_file` only | Snapshot repository metadata write plus arbitrary file read | Runtime-ready collection-style control; terminal-only. |

## Rejections And Holds

| CVE | Service / access | Reason |
|---|---|---|
| CVE-2017-12636 | CouchDB/HTTP 5984 | Current capability grants are empty and recent native automation is unstable; hold pending generic evidence reconciliation. |
| CVE-2012-2122 | MySQL/TCP 3306 | Probabilistic, host-dependent authentication bypass; low retry value. |
| CVE-2018-1058 | PostgreSQL/TCP 5432 | Requires induced superuser `pg_dump` action; not a direct attacker capability. |
| CVE-2015-3337 | Elasticsearch/HTTP 9200 | Legacy plugin environment build failed; weaker than healthier Elasticsearch alternatives. |
| CVE-2019-10758 | mongo-express/HTTP 8081 | Vulnerable service is a web UI, not MongoDB; excluded from data-layer classification. |

## 2026-07-18 Batch Assessment

Selected build wave:

- `CVE-2022-0543`: selected and built because it combines verified root command/file
  capability, a locally available Redis image, a self-contained bundle, and a distinct
  RESP data-service family.

Deferred or rejected from this wave:

- `CVE-2019-0193`: environment/build risk; exact `vulhub/solr:8.1.1` source image is
  unavailable locally, so `8.2.0` is not a valid substitute.
- `CVE-2016-3714`: validation-model/source-bundle risk; the Compose `index.php` file
  conflicts with the existing empty directory/bundle materialization.
- `CVE-2016-3088`: environment/build risk; the exploit service is HTTP/8161 while the
  current runtime readiness contract first probes broker port 61616.
- `CVE-2017-10271`: deferred for a later service/template family; old WebLogic startup
  and data-plane binding are unresolved.
- `CVE-2019-20933`: validation-model mismatch and structure deficiency; v2, no bundle,
  no ready Guide, and no native verified capability.
- `CVE-2017-12635`: deferred for a later service/template family; no native success or
  complete v3 Atom contract.

## Promotion Gate

Promote a queue entry only after its source bundle is self-contained, native
verification proves the stated capability and data operation, the v2 Guide is
reviewed, and runtime build, smoke, and original-service readiness pass. Codex
owns subsequent generic data-layer Range-contract preflight and experiments.

## 2026-07-18 First Range-composition scope correction

For the first generic Range-composition implementation, data-operation evidence
is retained as candidate research information but is **not** an additional Atom
or Range admission gate. A runtime-ready Atom with a reviewed Guide may enter a
template service variant when its derived runtime family and exposed access
match that variant. PostgreSQL and Elasticsearch are the first supported
variants. Credential binding and proof of Agent asset use remain later research
work.
