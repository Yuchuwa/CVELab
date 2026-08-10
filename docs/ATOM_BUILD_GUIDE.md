# Atom Build Guide

Status: active

Last reviewed: 2026-07-30

## Lifecycle

Atom has exactly three build states:

```text
planned -> building -> completed
```

| State | Entry rule | Exit rule |
|---|---|---|
| `planned` | An accepted CVE is recorded in `data/atom_build_plan.json`; no `atom.yaml` exists | Construction starts and `atom.yaml` is created |
| `building` | Construction or verification has started | Every strict completion gate passes |
| `completed` | Every strict completion gate passes | Reopens as `building` if later evidence invalidates a gate |

Failed, deferred and unstable attempts remain `building`. Record their attempt
outcome and failure class; do not invent another lifecycle state.

## Strict Completion Contract

`completed` means all of the following are true:

1. `atom.yaml` parses as Atom v3 or newer.
2. `source_bundle` contains an on-disk compose file or Dockerfile and every
   declared PoC material/hash is valid.
3. Every declared PoC material has explicit role/visibility metadata, and every
   Guide-referenced material is visible under the guided profile.
4. Every declared bundle build/material file has a recorded valid hash.
5. Bundle, Guide and runtime-build paths are relative and cannot escape the
   Atom directory.
6. `runtime_spec` is explicit rather than supplied by a compatibility default.
7. `runtime_spec.runtime_status` is `ready`.
8. Runtime context, Dockerfile and install script exist, and the build records
   its base-image digest and generated hash.
9. `flag_spec` and `validation_spec` are explicit.
10. `verified=true` and native verification records `success=true`.
11. The network service contract is complete when the attack vector is network.
12. At least one capability grant has verified evidence.
13. The Exploit Guide exists, is marked `ready` and passes shared integrity
    validation.
14. `verification.orchestrated_verification` records `success=true`, non-empty
   evidence and a timestamp.

These are completion gates, not optional quality labels. A missing result is
not treated as success.

`environment_ready` is a legacy convenience mirror of orchestrated success. It
is not an independent completion gate: a missing mirror must not override a
valid structured verification record.

## Build Flow

```text
value assessment
-> add accepted CVE to atom_build_plan.json
-> create atom.yaml (status becomes building)
-> construct runtime and source bundle
-> run native verification
-> review Exploit Guide
-> run orchestrated environment verification
-> regenerate Atom status
-> completed only if every gate passes
```

Run:

```bash
python3 scripts/generate_atom_pool_status.py
```

The authoritative snapshot is `data/atom_pool_status.json`. CSV and Markdown
are generated views and must not be edited independently.

## Ownership Boundary

Atom publishes objective facts: runtime, service, capabilities, materials,
Guide and verification evidence. Atom does not declare whether it is eligible
for a Range matrix or template slot. Range owns those decisions.
