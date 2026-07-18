"""Runtime image builder + smoke test (batch 11d, revised 3).

Closes the codex review gaps:
  - temp compose override uses --project-directory so relative volumes/
    env_file/build context resolve against source_bundle, not the temp dir;
    the override file lives in runtime/, never in source_bundle
  - target service is selected by is_target / main image match; if no match,
    the build is unsupported (no first-service fallback)
  - base USER is discovered via docker inspect of the base/intermediate
    image when the atom's RuntimeSpec.user is empty (covers base images that
    define a non-root USER with no Compose user:)
  - smoke uses the shared logical-tool -> smoke-command map, covering the
    full selected profile set (incl. pysmb/pyftpdlib, bash/openssl/procps,
    CA via openssl not a Debian path)
  - digests come from docker inspect --format, not image IDs
"""
from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from clab_builder.shared.models.atom import AtomConfig, RuntimeStatus
from clab_builder.shared.runtime_tools import (
    smoke_commands,
)
from clab_builder.atomizer.runtime_generator import (
    RuntimeArtifacts, generate_runtime_artifacts, write_runtime_dir,
)


@dataclass
class RuntimeBuildResult:
    status: RuntimeStatus = RuntimeStatus.NOT_REQUESTED
    runtime_image: str = ""
    failure_reason: str = ""
    smoke_checks: dict = field(default_factory=dict)
    service_ready: bool = False
    artifacts: Optional[RuntimeArtifacts] = None
    base_image_digest: str = ""
    runtime_image_digest: str = ""
    resolved_user: str = ""


def _run(cmd, timeout=60, **kw):
    # Use the legacy Docker builder: the buildx default activity dir can be
    # permission-denied for non-root users, which breaks `docker build`. The
    # legacy builder avoids buildx state entirely. Only applied to docker
    # commands so non-docker subprocess calls are unaffected.
    import os
    env = dict(kw.pop("env", os.environ))
    if cmd and cmd[0] == "docker":
        env.setdefault("DOCKER_BUILDKIT", "0")
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env=env, **kw)


def _runtime_image_name(cve_id: str, digest: str) -> str:
    safe = cve_id.lower().replace("cve-", "")
    return f"cvelab-runtime-{safe}-{digest[:12]}"


def _inspect_digest(image: str) -> str:
    """Return the registry/manifest digest if available, else the image ID.

    `docker images -q --no-trunc` returns a local image id, not a registry
    digest. Prefer the manifest digest via inspect; fall back to the image
    id so the field is never empty for locally-built images.
    """
    r = _run(["docker", "image", "inspect", "--format",
              "{{index .RepoDigests 0}}", image], timeout=15)
    if r.returncode == 0 and r.stdout.strip():
        return r.stdout.strip()
    r2 = _run(["docker", "image", "inspect", "--format", "{{.Id}}", image],
              timeout=15)
    return r2.stdout.strip() if r2.returncode == 0 else ""


def _inspect_user(image: str) -> str:
    """Return the USER the base image runs as (from Config.User)."""
    r = _run(["docker", "image", "inspect", "--format", "{{.Config.User}}", image],
             timeout=15)
    if r.returncode == 0:
        return (r.stdout or "").strip()
    return ""


def _detect_image_package_manager(image: str) -> Optional[str]:
    """Detect the package manager from the actual base image when possible."""
    for manager in ("apt-get", "apk", "dnf", "yum"):
        try:
            r = _run(["docker", "run", "--rm", "--entrypoint", "sh", image,
                      "-c", f"command -v {manager}"], timeout=15)
        except subprocess.TimeoutExpired:
            # A cold image pull or slow entrypoint must not abort the whole
            # rebuild. The generator still has provenance-preserving image
            # heuristics and the later build has its full timeout.
            continue
        if r.returncode == 0:
            return {"apt-get": "apt", "apk": "apk", "dnf": "dnf", "yum": "yum"}[manager]
    return None


def _readiness_port(atom: AtomConfig) -> Optional[int]:
    """Prefer the CVE's recorded exploit entry over Compose port ordering."""
    service = atom.exploit_access.required_service or {}
    try:
        port = int(service.get("port"))
        if port > 0:
            return port
    except (TypeError, ValueError):
        pass
    for port in atom.runtime_spec.ports or atom.ports or []:
        try:
            return int(port)
        except (TypeError, ValueError):
            continue
    return None


def build_runtime_image(
    atom: AtomConfig,
    atom_dir: Path,
    *,
    source_image: Optional[str] = None,
    build_timeout: int = 900,
    smoke_timeout: int = 30,
    service_wait_seconds: int = 40,
) -> RuntimeBuildResult:
    """Build + smoke-test + service-check the derived runtime image."""
    src = source_image or atom.docker_image
    if not src:
        return RuntimeBuildResult(
            status=RuntimeStatus.UNSUPPORTED,
            failure_reason="no source image to derive from",
        )

    image_pm = None
    if not (atom.source_bundle and atom.source_bundle.dockerfiles):
        image_pm = _detect_image_package_manager(src)
    arts = generate_runtime_artifacts(atom, src, atom_dir=atom_dir,
                                      package_manager=image_pm)
    if arts.unsupported_reason:
        return RuntimeBuildResult(
            status=RuntimeStatus.UNSUPPORTED,
            failure_reason=arts.unsupported_reason,
            artifacts=arts,
        )

    # Resolve the original user: prefer the atom's RuntimeSpec.user (from
    # Compose); if empty, inspect the base/intermediate image's Config.User.
    resolved_user = atom.runtime_spec.user or ""
    base_ref = src
    if arts.base_image_for_runtime:
        # Build the original image first so the runtime Dockerfile can FROM it.
        df_path = atom_dir / arts.source_dockerfile
        ctx = df_path.parent
        inter = arts.base_image_for_runtime
        ib = _run(["docker", "build", "-t", inter, "-f", str(df_path), str(ctx)],
                  timeout=build_timeout)
        if ib.returncode != 0:
            return RuntimeBuildResult(
                status=RuntimeStatus.FAILED,
                failure_reason=f"intermediate image build failed: {ib.stderr[-300:]}",
                artifacts=arts,
            )
        base_ref = inter

    if not resolved_user:
        try:
            resolved_user = _inspect_user(base_ref)
        except Exception:
            resolved_user = ""
    # Re-generate artifacts with the resolved user so the Dockerfile restores it.
    if resolved_user and resolved_user != atom.runtime_spec.user:
        atom.runtime_spec.user = resolved_user
        arts = generate_runtime_artifacts(atom, src, atom_dir=atom_dir,
                                          package_manager=image_pm)
        if arts.unsupported_reason:
            return RuntimeBuildResult(
                status=RuntimeStatus.UNSUPPORTED,
                failure_reason=arts.unsupported_reason, artifacts=arts)

    write_runtime_dir(atom_dir, arts)
    image = _runtime_image_name(atom.cve_id, arts.manifest["generated_hash"])

    build = _run(["docker", "build", "-t", image, "-f", str(atom_dir / "runtime" / "Dockerfile"),
                  str(atom_dir / "runtime")], timeout=build_timeout)
    if build.returncode != 0:
        return RuntimeBuildResult(
            status=RuntimeStatus.FAILED,
            failure_reason=f"docker build failed: {build.stderr[-300:]}",
            artifacts=arts,
        )

    base_digest = _inspect_digest(base_ref)
    rt_digest = _inspect_digest(image)
    res = RuntimeBuildResult(
        status=RuntimeStatus.PENDING,
        runtime_image=image,
        artifacts=arts,
        base_image_digest=base_digest,
        runtime_image_digest=rt_digest,
        resolved_user=resolved_user,
    )

    # 2. Smoke every logical tool selected for this Atom. A profile label can
    # cover a subset of its optional protocol tools.
    logical = arts.logical_tools
    smoke = {}
    for name, cmd in smoke_commands(logical):
        c = _run(["docker", "run", "--rm", "--entrypoint", "sh", image, "-c",
                  cmd + " >/dev/null 2>&1"], timeout=smoke_timeout)
        smoke[name] = c.returncode == 0
    res.smoke_checks = smoke

    if not all(smoke.values()):
        res.status = RuntimeStatus.FAILED
        res.failure_reason = f"smoke checks failed: {[k for k,v in smoke.items() if not v]}"
        return res

    # 3. service behavior via the ORIGINAL compose with project-directory.
    rs = atom.runtime_spec
    port = _readiness_port(atom)
    bundle = atom.source_bundle
    compose_ref = bundle.compose_file if bundle else None
    if port is None or not compose_ref:
        res.status = RuntimeStatus.UNSUPPORTED
        res.failure_reason = "no service port or compose to verify service start"
        return res

    ok, detail = _smoke_service_via_compose(
        image, atom_dir, atom, port, service_wait_seconds,
    )
    res.service_ready = ok
    if ok:
        res.status = RuntimeStatus.READY
    else:
        # "no target service identified" is a structural gap (we cannot tell
        # which service is the vulnerable one), not a runtime failure. Mark
        # unsupported so Range falls back to docker_image instead of treating
        # the runtime layer as broken.
        if "no target service identified" in detail:
            res.status = RuntimeStatus.UNSUPPORTED
        else:
            res.status = RuntimeStatus.FAILED
        res.failure_reason = f"service not ready: {detail}"
    return res


def _smoke_service_via_compose(
    runtime_image: str,
    atom_dir: Path,
    atom: AtomConfig,
    port: int,
    wait_seconds: int,
) -> tuple[bool, str]:
    """Start the target service with the runtime image, keeping the original
    compose's relative paths via --project-directory pointing at the
    source_bundle root. The override file is written to runtime/, never
    source_bundle."""
    bundle = atom.source_bundle
    compose_ref = bundle.compose_file if bundle else None
    compose_path = atom_dir / compose_ref
    if not compose_path.is_file():
        return False, f"compose missing: {compose_path}"
    # project directory = the compose file's directory, so relative volumes/
    # env_file/build context resolve against source_bundle, not the temp dir.
    project_dir = compose_path.parent

    try:
        data = yaml.safe_load(compose_path.read_text()) or {}
    except Exception as exc:
        return False, f"compose unreadable: {exc}"
    services = data.get("services") or {}
    if not isinstance(services, dict) or not services:
        return False, "no services in compose"

    # Select target by is_target / main image. No first-service fallback:
    # if we cannot identify the vulnerable service, mark unsupported upstream.
    target_name = None
    target_svc_names = {
        s.get("name") for s in (atom.runtime_spec.services or [])
        if isinstance(s, dict) and s.get("is_target")
    }
    for name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        if name in target_svc_names or svc.get("image") == atom.docker_image:
            target_name = name
            break
    if target_name is None:
        return False, "no target service identified (is_target / image match)"

    # Override only the target service image; keep volumes/env/depends_on.
    services[target_name]["image"] = runtime_image
    services[target_name].pop("build", None)
    data["services"] = services

    # Override file in runtime/, NOT source_bundle. Use it as a second -f so
    # it overrides the original while the original stays the path base.
    override_path = atom_dir / "runtime" / "smoke-override.yml"
    override_path.parent.mkdir(parents=True, exist_ok=True)
    override_path.write_text(yaml.safe_dump(data, sort_keys=False))

    project = f"rtsmoke-{atom.cve_id.lower()}"
    container = f"{project}-{target_name}-1"
    try:
        _run(["docker", "compose", "-p", project,
              "--project-directory", str(project_dir),
              "-f", str(compose_path), "-f", str(override_path),
              "up", "-d"], timeout=120)
        ready = False
        for _ in range(max(1, wait_seconds // 2)):
            probe = _run(["docker", "exec", container, "sh", "-c",
                          f"python3 -c \"import socket;socket.create_connection(('127.0.0.1',{port}),2).close()\" "
                          f"2>/dev/null || (echo > /dev/tcp/127.0.0.1/{port}) 2>/dev/null"],
                         timeout=10)
            if probe.returncode == 0:
                ready = True
                break
            time.sleep(2)
        if not ready:
            logs = _run(["docker", "logs", "--tail", "20", container], timeout=10).stdout
            return False, f"port {port} not listening\n{logs[-300:]}"
        return True, "ok"
    finally:
        _run(["docker", "compose", "-p", project,
              "--project-directory", str(project_dir),
              "-f", str(compose_path), "-f", str(override_path),
              "down", "-v"], timeout=60)
        try:
            override_path.unlink()
        except OSError:
            pass


def runtime_verification_record(res: RuntimeBuildResult) -> dict:
    return {
        "status": res.status.value,
        "runtime_image": res.runtime_image,
        "runtime_image_digest": res.runtime_image_digest,
        "base_image_digest": res.base_image_digest,
        "resolved_user": res.resolved_user,
        "smoke_checks": res.smoke_checks,
        "service_ready": res.service_ready,
        "failure_reason": res.failure_reason,
        "tool_profiles": res.artifacts.tool_profiles if res.artifacts else [],
        "packages": res.artifacts.packages if res.artifacts else [],
    }


__all__ = [
    "RuntimeBuildResult",
    "build_runtime_image",
    "runtime_verification_record",
]
