# Atom Runtime → Range Handoff

This document defines how Range consumes the Atom runtime tool layer added in
batch 11. It is the contract between the Atom build side (which produces the
runtime image) and the Range orchestration side (which deploys it).

## 1. Image selection order

Range MUST select the target image for an atom in this order:

```
runtime_spec.runtime_image        (derived image with base tools; preferred)
    ↓ (empty / runtime_status != ready)
runtime_spec.runtime_build         (build description if image must be built)
    ↓ (empty)
atom.docker_image                  (original image; always present)
```

- `runtime_image` is only set when `runtime_status == ready`. A `pending`,
  `failed`, or `unsupported` runtime means Range falls back to `docker_image`.
- `docker_image` is the original vulnerable image and is always present. It is
  the guaranteed fallback; no atom is ever left without a usable image.
- `source_image` is an alias of `docker_image` for clarity; Range treats it as
  equivalent to `docker_image`.

## 2. What the runtime layer is — and is not

**Is**: a derived image that installs base tools (curl, python3, psycopg2,
postgresql-client, netcat, etc.) on top of the original image, preserving the
original command/entrypoint/environment so the vulnerable service still starts
identically.

**Is not**: a change to the vulnerability, the PoC, the Guide, or the exploit
truth. `verification.native_verification` records the native exploit result and
is never rewritten by the runtime layer. `verification.runtime_verification`
records the tool-layer build/smoke/service result separately.

A `runtime_status=ready` does NOT mean the exploit succeeds under the runtime
image. It means the base tools are installed and the original service still
starts. Range still must independently verify environment, attack graph, and
agent success.

## 3. source_bundle vs runtime/

```
data/atoms/<cve>/
├── atom.yaml
├── source_bundle/      # immutable: original compose/Dockerfile/PoC/init
└── runtime/            # derived: Dockerfile + install-tools.sh + manifest
    ├── Dockerfile
    ├── install-tools.sh
    └── manifest.yaml
```

- `source_bundle` is the original environment + PoC materials. It is never
  modified by the runtime layer. Range mounts its `poc_materials` for the
  attacker.
- `runtime/` is the derived build context. It is reproducible from `atom.yaml`
  + `source_bundle` and carries a `generated_hash` for change detection.

## 4. Runtime build fields

```yaml
runtime_spec:
  source_image: vulhub/php:5.4.1-cgi      # alias of docker_image
  runtime_image: cvelab-runtime-<digest>   # empty unless ready
  tool_profile: enterprise-standard-v1,build-pivot   # comma-joined if multiple
  tool_profile_version: "1"
  user: www-data                            # original user restored after install
  runtime_build:
    context: runtime
    dockerfile: runtime/Dockerfile
    install_script: runtime/install-tools.sh
    base_image_digest: sha256:...          # the image the runtime FROMs
    generated_hash: sha256:...             # stable for unchanged inputs
    intermediate_image: cvelab-orig-<cve>   # custom-Dockerfile intermediate (empty for image-only)
    source_dockerfile: source_bundle/Dockerfile  # custom Dockerfile path (empty for image-only)
  runtime_status: ready                     # not_requested|pending|ready|unsupported|failed
  runtime_failure_reason: ""
```

`base_image_digest` is the digest of the image the runtime Dockerfile FROMs
(the intermediate image for custom-Dockerfile atoms, the source image for
image-only atoms). `runtime_image_digest` (in runtime_verification) is the
final runtime image id. They are distinct.

`intermediate_image` + `source_dockerfile` let a future Range rebuild
reproduce the full two-stage build for custom-Dockerfile atoms.

## 5. Tool profiles

| Profile | When | Tools |
|---|---|---|
| enterprise-standard-v1 | always | bash, coreutils, curl, wget, ca-certificates, openssl, procps, iproute2, netcat, python3, python3-requests, python3-psycopg2, postgresql-client |
| build-pivot | tools_needed implies gcc/make | gcc, make |
| remote-protocol | tools_needed implies paramiko/impacket/smb | paramiko, impacket, pysmb, pyftpdlib, smbclient |
| java-exploit | tools_needed implies java/jmet | JRE |

`nmap` is intentionally NOT installed (reconnaissance is not a generic attack
tool). Package names are mapped per detected package manager (apt/apk/dnf/yum);
no CVE branch hardcodes package names.

## 6. Failure handling

- `unsupported`: the base image has no package manager; or a safe second
  layer cannot be produced for a custom-Dockerfile atom; or there is no
  service port/compose to verify the service still starts. The original atom
  stays usable; Range falls back to `docker_image`.
- `failed`: docker build, smoke test (any tool missing), or service
  readiness failed. The original atom stays usable; Range falls back to
  `docker_image`. The failure reason is recorded; native `verified` is never
  rewritten.
- `not_requested`: the atom was built without `--build-runtime`. Range uses
  `docker_image`.

`ready` means: build succeeded, ALL base + per-profile smoke checks passed,
AND the original service started and accepted connections on the original
port via the original compose semantics. A missing port/compose is
`unsupported`, not `ready`.

## 7. Backward compatibility

Old atoms without `runtime_image` / `tool_profile` / `runtime_build` load
unchanged. `runtime_status` defaults to `not_requested`. Range falls back to
`docker_image`. No existing atom is forced to rebuild.

When assembling a Range, `runtime_image` is selected only if both
`runtime_status` and `verification.runtime_verification.status` are `ready`.
Otherwise Range falls back to `source_image` (or `docker_image`) and records
the selected image, both runtime states, digests, and fallback reason in
`scenario.yaml`. A selected runtime image must exist locally before deploy;
Range never silently substitutes another image at verification time.

## 8. Verification separation

```
verification:
  native_verification:        # exploit reproduced in the original env
  orchestrated_verification: # original env rebuilt cleanly
  environment_ready:          # orchestrated success
  runtime_verification:       # tool-layer build + smoke + service (batch 11)
```

`runtime_verification.status` is independent. A `failed` runtime does not
downgrade `verified` or `environment_ready`. A `ready` runtime does not imply
the exploit works under it. Range consumes each field for its own purpose.
