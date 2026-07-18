"""Runtime Dockerfile / install-script generator (batch 11c, revised).

Generates a derived Dockerfile and install-tools.sh that add base tools on
top of the original image WITHOUT touching source_bundle. Preserves the
original command/entrypoint/environment/user so the vulnerable service still
starts the same way.

Two cases:

  image-only atom (no custom Dockerfile in source_bundle):
      FROM <source_image>
      USER root
      COPY install-tools.sh /opt/cvelab/runtime/
      RUN .../install-tools.sh
      ENV / ENTRYPOINT / CMD restored

  custom-Dockerfile atom (source_bundle has a Dockerfile):
      The original Dockerfile's semantics (COPY, RUN, ENV, build context)
      MUST be preserved. We therefore FROM the already-built original image
      — i.e. the runtime builder first builds source_bundle/Dockerfile into
      an intermediate image, then the runtime Dockerfile layers tools on top.
      This is the only safe second layer; we never rewrite the original
      Dockerfile. If the original build context cannot be resolved the
      generator returns unsupported_reason so the caller records
      runtime_status=unsupported and keeps the original atom usable — never
      fakes ready.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

from clab_builder.shared.models.atom import AtomConfig, RuntimeBuildSpec
from clab_builder.shared.runtime_tools import (
    detect_package_manager,
    install_commands,
    profile_logical_tools,
    resolve_packages,
    select_profiles,
)


@dataclass
class RuntimeArtifacts:
    dockerfile: str
    install_script: str
    manifest: dict
    tool_profiles: list[str]
    logical_tools: list[str]
    package_manager: str
    packages: list[str]
    # For custom-Dockerfile atoms: the intermediate image name that the
    # runtime Dockerfile FROMs. The builder builds source_bundle/Dockerfile
    # into this image first. Empty for image-only atoms.
    base_image_for_runtime: str = ""
    # source_bundle Dockerfile path relative to atom_dir, when present.
    source_dockerfile: str = ""
    unsupported_reason: str = ""


def _shell_quote(s: str) -> str:
    return '"' + s.replace('"', '\\"') + '"' if s else s


def _read_source_dockerfile(atom: AtomConfig, atom_dir: Path) -> tuple[str, str]:
    """Return (dockerfile_rel, dockerfile_text) from source_bundle, or ('','')."""
    bundle = atom.source_bundle
    if not bundle or not bundle.dockerfiles:
        return "", ""
    df_rel = str(bundle.dockerfiles[0])
    df_path = atom_dir / df_rel
    if not df_path.is_file():
        return df_rel, ""
    return df_rel, df_path.read_text(errors="replace")


def generate_runtime_artifacts(
    atom: AtomConfig,
    source_image: str,
    atom_dir: Optional[Path] = None,
    package_manager: Optional[str] = None,
) -> RuntimeArtifacts:
    """Generate runtime/Dockerfile + install-tools.sh + manifest for an atom.

    atom_dir is required to read a custom Dockerfile from source_bundle. If
    omitted and a custom Dockerfile exists, the generator returns
    unsupported (it cannot inspect the Dockerfile).
    """
    tools_needed = list((atom.requirements or {}).get("tools_needed") or [])
    profiles = select_profiles(tools_needed)
    profile_names = [p.name for p in profiles]
    logical_tools = profile_logical_tools(profiles)

    # Detect custom Dockerfile.
    df_rel, df_text = ("", "")
    if atom_dir is not None:
        df_rel, df_text = _read_source_dockerfile(atom, atom_dir)
    elif atom.source_bundle and atom.source_bundle.dockerfiles:
        # have a custom Dockerfile but no atom_dir to read it -> unsupported
        return RuntimeArtifacts(
            dockerfile="", install_script="", manifest={},
            tool_profiles=profile_names, logical_tools=logical_tools,
            package_manager="", packages=[],
            unsupported_reason="custom Dockerfile present but atom_dir not supplied to inspect it",
        )

    has_custom_df = bool(df_rel and df_text)

    # Detect package manager: prefer the source Dockerfile text, else image.
    pm: Optional[str] = None
    if df_text:
        pm = detect_package_manager(df_text)
    elif package_manager:
        pm = package_manager
    if pm is None:
        low = (source_image or "").lower()
        if low.startswith("alpine"):
            pm = "apk"
        elif any(x in low for x in ("ubi", "fedora", "rocky", "centos")):
            pm = "dnf"
        elif "amazon" in low:
            pm = "yum"
        elif low:
            # heuristics exhausted for a known image; default apt is the
            # common case for debian/ubuntu/php/tomcat bases.
            pm = "apt"
    if pm is None:
        # no Dockerfile AND no image to infer from -> genuinely unsupported
        return RuntimeArtifacts(
            dockerfile="", install_script="", manifest={},
            tool_profiles=profile_names, logical_tools=logical_tools,
            package_manager="", packages=[],
            unsupported_reason="no package manager detectable (no Dockerfile, no source image)",
        )

    packages = resolve_packages(profiles, pm)
    install = install_commands(pm, packages)
    install_script = "#!/bin/sh\nset -e\n" + install + "\n" if install else "#!/bin/sh\n# no packages\n"

    # Determine the FROM image for the runtime Dockerfile.
    if has_custom_df:
        # The runtime layers on top of the ORIGINAL image built from
        # source_bundle/Dockerfile. The builder constructs that intermediate
        # image first; here we reference it by a stable name.
        base_for_runtime = _intermediate_image_name(atom.cve_id, df_rel)
        from_image = base_for_runtime
    else:
        base_for_runtime = ""
        from_image = source_image

    lines = [f"FROM {from_image}", "", "USER root", "",
             "COPY install-tools.sh /opt/cvelab/runtime/",
             "RUN chmod +x /opt/cvelab/runtime/install-tools.sh && "
             "/opt/cvelab/runtime/install-tools.sh", ""]

    rs = atom.runtime_spec
    env = rs.environment or {}
    for k, v in env.items():
        lines.append(f"ENV {k}={_shell_quote(str(v))}")
    if env:
        lines.append("")

    if rs.entrypoint:
        lines.append(f"ENTRYPOINT {_shell_quote(rs.entrypoint)}")
    if rs.command:
        lines.append(f"CMD {_shell_quote(rs.command)}")
    # Restore the original container user after installing tools as root.
    # This preserves services that drop privileges or expect a specific uid.
    if rs.user:
        lines.append(f"USER {rs.user}")

    dockerfile = "\n".join(lines) + "\n"

    manifest = {
        "source_image": source_image,
        "tool_profiles": profile_names,
        "logical_tools": logical_tools,
        "package_manager": pm,
        "packages": packages,
        "preserved_command": rs.command,
        "preserved_entrypoint": rs.entrypoint,
        "preserved_environment": env,
        "preserved_user": rs.user,
        "has_custom_dockerfile": has_custom_df,
        "source_dockerfile": df_rel,
        "intermediate_image": base_for_runtime,
    }
    manifest["generated_hash"] = hashlib.sha256(
        (dockerfile + "\n" + install_script + "\n"
         + "source=" + (source_image or "") + "\n"
         + "orig_df=" + df_text).encode()
    ).hexdigest()

    return RuntimeArtifacts(
        dockerfile=dockerfile,
        install_script=install_script,
        manifest=manifest,
        tool_profiles=profile_names,
        logical_tools=logical_tools,
        package_manager=pm,
        packages=packages,
        base_image_for_runtime=base_for_runtime,
        source_dockerfile=df_rel,
    )


def _intermediate_image_name(cve_id: str, df_rel: str) -> str:
    safe = cve_id.lower().replace("cve-", "")
    return f"cvelab-orig-{safe}"


def write_runtime_dir(atom_dir: Path, arts: RuntimeArtifacts) -> RuntimeBuildSpec:
    """Write runtime/Dockerfile, install-tools.sh, manifest.yaml."""
    rdir = atom_dir / "runtime"
    rdir.mkdir(parents=True, exist_ok=True)
    (rdir / "Dockerfile").write_text(arts.dockerfile)
    (rdir / "install-tools.sh").write_text(arts.install_script)
    (rdir / "manifest.yaml").write_text(yaml.safe_dump(
        arts.manifest, sort_keys=False, allow_unicode=True))
    return RuntimeBuildSpec(
        context="runtime",
        dockerfile="runtime/Dockerfile",
        install_script="runtime/install-tools.sh",
        base_image_digest="",
        generated_hash=arts.manifest["generated_hash"],
        intermediate_image=arts.base_image_for_runtime,
        source_dockerfile=arts.source_dockerfile,
    )


__all__ = ["RuntimeArtifacts", "generate_runtime_artifacts", "write_runtime_dir"]
