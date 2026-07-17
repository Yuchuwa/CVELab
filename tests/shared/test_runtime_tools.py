"""Tests for runtime tool profiles + generator (batch 11)."""
from pathlib import Path

import yaml

from clab_builder.shared.models.atom import AtomConfig, RuntimeStatus, SourceBundle
from clab_builder.shared.runtime_tools import (
    select_profiles, resolve_packages, detect_package_manager,
    install_commands, resolve_tools_needed,
    ENTERPRISE_STANDARD_V1, BUILD_PIVOT, REMOTE_PROTOCOL, JAVA_EXPLOIT,
)
from clab_builder.atomizer.runtime_generator import generate_runtime_artifacts, write_runtime_dir


def _atom(**overrides) -> AtomConfig:
    data = {
        "version": 3, "cve_id": "CVE-RT-0001", "category": "test",
        "docker_image": "vulhub/php:5.4", "ports": [80],
        "vuln_category": "RCE", "primary_mitre_phase": "initial_access",
        "service_role": "web_application", "exploit_complexity": "simple",
        "attack_method": "single_request",
        "runtime_spec": {"ports": [80], "command": "apache2-foreground",
                         "environment": {"FOO": "bar"}},
        "requirements": {"tools_needed": ["curl", "python3"]},
    }
    data.update(overrides)
    return AtomConfig(**data)


def test_enterprise_always_selected():
    ps = select_profiles([])
    assert ps[0].name == "enterprise-standard-v1"


def test_gcc_adds_build_pivot():
    ps = select_profiles(["gcc"])
    names = [p.name for p in ps]
    assert "build-pivot" in names


def test_paramiko_adds_remote_protocol():
    ps = select_profiles(["python3-paramiko"])
    names = [p.name for p in ps]
    assert "remote-protocol" in names
    remote = next(p for p in ps if p.name == "remote-protocol")
    assert remote.logical_tools == ["python3_paramiko"]
    pkgs = resolve_packages(ps, "apt")
    assert "python3-impacket" not in pkgs
    assert "python3-pysmb" not in pkgs


def test_java_adds_java_exploit():
    ps = select_profiles(["jmet"])
    names = [p.name for p in ps]
    assert "java-exploit" in names


def test_resolve_tools_needed_psycopg2():
    lt = resolve_tools_needed(["psycopg2"])
    assert "python3_psycopg2" in lt
    assert "postgresql_client" in lt


def test_resolve_packages_apt():
    pkgs = resolve_packages([ENTERPRISE_STANDARD_V1], "apt")
    assert "curl" in pkgs
    assert "python3-psycopg2" in pkgs
    assert "postgresql-client" in pkgs
    # nmap is NOT installed
    assert "nmap" not in pkgs


def test_resolve_packages_apk_maps_netcat():
    pkgs = resolve_packages([ENTERPRISE_STANDARD_V1], "apk")
    assert "netcat-openbsd" in pkgs
    assert "py3-psycopg2" in pkgs


def test_detect_package_manager_alpine():
    assert detect_package_manager("FROM alpine:3.14\n") == "apk"


def test_detect_package_manager_debian_default():
    assert detect_package_manager("FROM vulhub/php:5.4\n") == "apt"


def test_install_commands_apt_noninteractive():
    cmd = install_commands("apt", ["curl", "wget"])
    assert "DEBIAN_FRONTEND=noninteractive" in cmd
    assert "curl" in cmd
    assert "rm -rf /var/lib/apt/lists/*" in cmd


def test_install_commands_apt_eol_archive_fallback():
    """EOL Debian fallback handles 404s even when apt-get exits zero."""
    cmd = install_commands("apt", ["curl"])
    assert "archive.debian.org" in cmd
    assert "Failed to fetch https?://(deb\\.debian\\.org|security\\.debian\\.org)/" in cmd
    assert "sources.list.d/*.list" in cmd
    assert "apt_install_flags=--allow-unauthenticated" in cmd
    assert "apt-get install -y --no-install-recommends $apt_install_flags" in cmd


def test_generator_preserves_command_entrypoint_env(tmp_path):
    atom = _atom()
    arts = generate_runtime_artifacts(atom, atom.docker_image)
    df = arts.dockerfile
    assert "FROM vulhub/php:5.4" in df
    assert "USER root" in df
    assert 'CMD "apache2-foreground"' in df
    assert "ENV FOO=" in df
    assert "install-tools.sh" in df


def test_generator_no_command_keeps_base_cmd(tmp_path):
    atom = _atom(runtime_spec={"ports": [80]})
    arts = generate_runtime_artifacts(atom, atom.docker_image)
    # no CMD/ENTRYPOINT line since atom has neither
    lines = [l for l in arts.dockerfile.splitlines() if l.startswith("CMD") or l.startswith("ENTRYPOINT")]
    assert lines == []


def test_write_runtime_dir_writes_artifacts(tmp_path):
    atom = _atom()
    atom_dir = tmp_path / "CVE-RT"
    atom_dir.mkdir()
    arts = generate_runtime_artifacts(atom, atom.docker_image)
    build_spec = write_runtime_dir(atom_dir, arts)
    assert (atom_dir / "runtime" / "Dockerfile").is_file()
    assert (atom_dir / "runtime" / "install-tools.sh").is_file()
    assert (atom_dir / "runtime" / "manifest.yaml").is_file()
    assert build_spec.generated_hash == arts.manifest["generated_hash"]


def test_runtime_spec_backward_compat_no_runtime_fields():
    """Old atom without any runtime_image/tool_profile loads with defaults."""
    atom = AtomConfig(
        version=3, cve_id="CVE-OLD", category="t", docker_image="x:1",
        ports=[80], vuln_category="RCE", primary_mitre_phase="initial_access",
        service_role="web_application", exploit_complexity="simple",
        attack_method="single_request",
    )
    assert atom.runtime_spec.runtime_status == RuntimeStatus.NOT_REQUESTED
    assert atom.runtime_spec.runtime_image is None


def test_source_image_is_alias():
    atom = _atom(runtime_spec={"ports": [80], "source_image": "orig:1",
                               "runtime_image": "rt:1", "tool_profile": "enterprise-standard-v1"})
    assert atom.runtime_spec.source_image == "orig:1"
    assert atom.runtime_spec.runtime_image == "rt:1"


def test_manifest_hash_stable(tmp_path):
    atom = _atom()
    arts1 = generate_runtime_artifacts(atom, atom.docker_image)
    arts2 = generate_runtime_artifacts(atom, atom.docker_image)
    assert arts1.manifest["generated_hash"] == arts2.manifest["generated_hash"]


# ── custom-Dockerfile support (codex review point 1) ────────────────


def test_custom_dockerfile_froms_intermediate_image(tmp_path):
    """A custom-Dockerfile atom FROMs the built original image, not
    atom.docker_image — so the Dockerfile's COPY/RUN semantics survive."""
    atom_dir = tmp_path / "CVE-CUSTOM"
    atom_dir.mkdir()
    bdir = atom_dir / "source_bundle"
    bdir.mkdir()
    (bdir / "Dockerfile").write_text(
        "FROM alpine:3.14\nCOPY elasticsearch.yml /etc/elasticsearch/\nRUN mkdir /data\n"
    )
    atom = _atom(cve_id="CVE-CUSTOM")
    atom.source_bundle = SourceBundle(dockerfiles=["source_bundle/Dockerfile"])
    arts = generate_runtime_artifacts(atom, atom.docker_image, atom_dir=atom_dir)
    # runtime Dockerfile must FROM the intermediate, not docker_image
    assert "FROM cvelab-orig-custom" in arts.dockerfile
    assert arts.base_image_for_runtime == "cvelab-orig-custom"
    assert arts.manifest["has_custom_dockerfile"] is True


def test_custom_dockerfile_without_atom_dir_is_unsupported():
    """Cannot inspect a custom Dockerfile without atom_dir -> unsupported."""
    atom = _atom(cve_id="CVE-NO-DIR")
    atom.source_bundle = SourceBundle(dockerfiles=["source_bundle/Dockerfile"])
    arts = generate_runtime_artifacts(atom, atom.docker_image, atom_dir=None)
    assert arts.unsupported_reason != ""


# ── package-manager detection (codex review point 2) ────────────────


def test_no_image_no_dockerfile_is_unsupported():
    """No Dockerfile and no source image to infer from -> unsupported, not
    a silent apt default."""
    atom = _atom(cve_id="CVE-NOPM")
    atom.source_bundle = None
    atom.docker_image = ""
    arts = generate_runtime_artifacts(atom, "", atom_dir=None)
    assert arts.unsupported_reason != ""
    assert "package manager" in arts.unsupported_reason


# ── smoke gate is hard (codex review point 3) ────────────────────────
# smoke-as-hard-gate is enforced in runtime_builder (docker-dependent);
# here we pin the promise set the builder checks.


def test_enterprise_promises_recorded_in_manifest():
    atom = _atom()
    arts = generate_runtime_artifacts(atom, atom.docker_image)
    # psycopg2 + psql are part of enterprise-standard-v1
    assert "python3-psycopg2" in arts.packages or any(
        "psycopg2" in p for p in arts.packages)
    assert any("postgresql" in p for p in arts.packages)


# ── multi-profile recording (codex review point 5) ──────────────────


def test_multiple_profiles_in_manifest():
    atom = _atom(requirements={"tools_needed": ["gcc", "paramiko", "jmet"]})
    arts = generate_runtime_artifacts(atom, atom.docker_image)
    names = arts.tool_profiles
    assert "enterprise-standard-v1" in names
    assert "build-pivot" in names
    assert "remote-protocol" in names
    assert "java-exploit" in names
    assert arts.manifest["tool_profiles"] == names


# ── original user restore (codex review point 3) ────────────────────


def test_user_restored_in_runtime_dockerfile():
    atom = _atom(runtime_spec={"ports": [80], "user": "www-data"})
    arts = generate_runtime_artifacts(atom, atom.docker_image)
    assert "USER www-data" in arts.dockerfile
    assert arts.manifest["preserved_user"] == "www-data"


def test_no_user_no_user_line():
    atom = _atom(runtime_spec={"ports": [80]})
    arts = generate_runtime_artifacts(atom, atom.docker_image)
    # no USER line beyond the install-time USER root
    user_lines = [l for l in arts.dockerfile.splitlines() if l.startswith("USER")]
    assert user_lines == ["USER root"]


# ── custom-Dockerfile intermediate info in RuntimeBuildSpec (point 6) ─


def test_custom_dockerfile_build_spec_records_intermediate(tmp_path):
    atom_dir = tmp_path / "CVE-C2"
    atom_dir.mkdir()
    bdir = atom_dir / "source_bundle"
    bdir.mkdir()
    (bdir / "Dockerfile").write_text("FROM alpine:3.14\nRUN echo hi\n")
    atom = _atom(cve_id="CVE-C2")
    atom.source_bundle = SourceBundle(dockerfiles=["source_bundle/Dockerfile"])
    from clab_builder.atomizer.runtime_generator import write_runtime_dir
    arts = generate_runtime_artifacts(atom, atom.docker_image, atom_dir=atom_dir)
    spec = write_runtime_dir(atom_dir, arts)
    assert spec.intermediate_image == arts.base_image_for_runtime
    assert spec.source_dockerfile == "source_bundle/Dockerfile"


# ── digest semantics (codex review point 7) ─────────────────────────
# base_image_digest vs runtime_image_digest is enforced in the builder
# (docker-dependent); here we pin the record shape.


def test_runtime_verification_record_has_both_digests():
    from clab_builder.atomizer.runtime_builder import runtime_verification_record, RuntimeBuildResult
    from clab_builder.shared.models.atom import RuntimeStatus
    res = RuntimeBuildResult(
        status=RuntimeStatus.READY, runtime_image="rt:1",
        base_image_digest="sha:base", runtime_image_digest="sha:rt",
    )
    rec = runtime_verification_record(res)
    assert rec["base_image_digest"] == "sha:base"
    assert rec["runtime_image_digest"] == "sha:rt"
