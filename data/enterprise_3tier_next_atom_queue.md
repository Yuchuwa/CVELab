# Enterprise 3-Tier Next Atom Queue

> 2026-07-17: retained as the historical strict PostgreSQL/5432 B3 gap
> assessment. Active Atom-side data-service planning is now maintained in
> `data/data_layer_atom_candidate_queue.md` under
> `docs/OPENCODE_DATA_LAYER_ATOM_TASK.md`.

## B3 PostgreSQL Gap

There is no non-baseline Atom that can currently be built as a valid B3
data-store replacement. The slot requires a PostgreSQL server on TCP/5432
that an attacker can directly exploit for verified command execution or file
read. `CVE-2019-9193` is the only current Atom that meets that contract.

| CVE | Service / port | Assessment | Decision |
|---|---|---|---|
| CVE-2018-1058 | PostgreSQL / TCP 5432 | Search-path LPE requires a separate superuser `pg_dump` action; no direct verified command or file capability. | Defer; not B3-admissible. |
| CVE-2021-23222 | PostgreSQL/libpq / TCP 5432 | Client-side MITM protocol issue, not a direct server-side database exploit; no command/read capability. | Reject. |
| CVE-2022-24128 | TimescaleDB on PostgreSQL / TCP 5432 | Privileged extension-install precondition, no proven post-exploit capability, and no published service port. | Reject. |

Evidence sources:

- `vulhub/postgres/CVE-2018-1058/`
- `CVE-Factory/cve_tasks/trainset_0313_part1/cve-2021-23222/`
- `CVE-Factory/cve_tasks/trainset_0313_part2/cve-2022-24128/`
- `data/atoms/CVE-2019-9193/atom.yaml`

The next B3 build must first source a candidate proving all of: PostgreSQL is
the vulnerable server, TCP/5432 is attacker-reachable, the exploit is direct
from the preceding foothold, and native evidence verifies `execute_command` or
`read_file`. This is a generic candidate-admission gate, not a CVE exception.

## DMZ-Web Candidates

| Priority | CVE | Role / protocol | Expected capability grants | MITRE phase | Automation risk | Build risk | Differentiation value | Status |
|---|---|---|---|---|---|---|---|---|
| P0 | CVE-2021-32568 | web_application, HTTP/10086 | Verified root `execute_command`, `read_file`, `write_file` | initial_access, execution | Low: documented login, CSRF, ZIP/YAML flow | Medium: Python 3.7 and old PyYAML; current Factory import omitted source bundle/compose | Authenticated management-plane deserialization, unlike anonymous web RCE | Rehabilitate through the shared Factory importer; not runtime-ready. |
| P1 | CVE-2016-3714 | web_application, HTTP/8080 | Verified root `execute_command`, `read_file`, `write_file`, `network_vantage`, `read_credential` | initial_access, execution | Low: multipart upload, no callback | Low: existing Vulhub image and native/orchestrated evidence | Image upload RCE with broad verified capabilities | Verified Atom; promote to runtime-ready. |
| P1 | CVE-2020-24572 | web_application, HTTP/80 | Target `execute_command`, then prove `read_file` and `write_file` | initial_access, execution | Low: authenticated JSON-RPC request/response | Medium: builds Apache/PHP and fetches RaspAP source | Authenticated network-management console RCE | Future Factory production candidate. |

## App-Service Candidates

| Priority | CVE | Role / protocol | Expected capability grants | MITRE phase | Automation risk | Build risk | Differentiation value | Status |
|---|---|---|---|---|---|---|---|---|
| P0 | CVE-2019-0193 | web_application (Solr middleware), HTTP/8983 | Verified root `execute_command`, `read_file`, `write_file`, `read_credential` | initial_access, execution, collection | Low-medium: one HTTP DataImportHandler payload | Low: existing source and environment evidence | Reusable HTTP command channel and collection evidence | Verified Atom; promote to runtime-ready. |
| P1 | CVE-2016-3088 | web_application (ActiveMQ middleware), HTTP/8161 | Verified root `execute_command`, `read_file`, `write_file`, `network_vantage` | initial_access, execution, persistence behavior | Medium: PUT/MOVE plus deterministic cron wait | Low: existing Vulhub image | Durable cron behavior, a pool diversity gap | Verified Atom; runtime build after Guide preflight reconciles non-reusable channel. |
| P1 | CVE-2017-10271 | middleware, HTTP SOAP/7001 | Verified root `execute_command`, `read_file`, `write_file` | initial_access, execution, collection | Low: one SOAP/XMLDecoder request | Medium: old WebLogic startup | Java SOAP/XMLDecoder alternative to REST and uploads | Full-pass reserve; runtime build after Guide preflight. |

## Strict Data-Store Candidates

| Priority | CVE | Role / protocol | Expected capability grants | MITRE phase | Automation risk | Build risk | Differentiation value | Status |
|---|---|---|---|---|---|---|---|---|
| Baseline | CVE-2019-9193 | database, PostgreSQL/TCP 5432 | Verified `execute_command`, `read_file`, `write_file` as `postgres` | execution | Low: mature authenticated `COPY FROM PROGRAM` channel | Low | Current B0 control | Retain; not a variable candidate. |
| P3 | CVE-2018-1058 | database, PostgreSQL/TCP 5432 | Do not claim command execution; target an induced-action LPE proof only | privilege_escalation | High: low-privilege user, callback, and superuser `pg_dump` action | Low image risk, high validation-model risk | Only local PostgreSQL privilege-escalation direction | Defer until a generic induced-action validation contract exists. |

## Missing Phase Or Capability Candidates

| Priority | CVE | Role / protocol | Expected capability grants | MITRE phase | Automation risk | Build risk | Differentiation value | Status |
|---|---|---|---|---|---|---|---|---|
| P1 | CVE-2023-28432 | file_service/object storage, HTTP/9000 and 9001 | Target `read_credential`, `authenticate`; prove `read_file` through seeded object access | credential_access, valid_accounts | Low for credential leak: one HTTP request | Medium: three-node MinIO readiness and bundled data mounts | Genuine credential-access/object-storage stage | Future template candidate, not enterprise_3tier data-store. |
| P2 | CVE-2020-1938 | middleware, AJP/8009 | Target `read_file`, conditionally `read_credential` | collection, credential_access | Medium-high: AJP framing and path behavior | Low: prebuilt Tomcat image | Non-RCE collection stage | Research candidate; require self-contained PoC validation. |
| P1 | CVE-2016-3088 | middleware, HTTP/8161 | Verified command/file/network capabilities; persistence behavior requires explicit contract support | persistence behavior | Medium: cron timing | Low | Adds durable execution semantics absent from the normalized capability model | Shared capability-schema follow-up, not a new per-CVE field. |

## Queue Rules

- Expected capabilities are verification targets unless the row explicitly says `Verified`.
- A PostgreSQL sidecar, PostgreSQL protocol emulation, or a client-only libpq issue is never a B3 data-store candidate.
- Promote a candidate only after source bundle, native evidence, ready Guide, runtime build, smoke, and original-service readiness all pass.
- Preserve runtime and Guide contracts generically. Do not change Range matching or template semantics to admit a candidate.
