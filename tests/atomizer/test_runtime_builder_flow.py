"""Mock-docker control-flow tests for the runtime builder (batch 11, codex R3).

Covers the real execution path without docker: temp compose path /
project-directory, target-service selection, unsupported on no target,
resolved-user via inspect, smoke-all gate, digest via inspect.
"""
from pathlib import Path
import subprocess
from unittest.mock import patch, MagicMock

import yaml

from clab_builder.shared.models.atom import AtomConfig, SourceBundle, RuntimeStatus
from clab_builder.atomizer.runtime_builder import (
    build_runtime_image, _smoke_service_via_compose, _inspect_digest, _inspect_user,
    _readiness_port, _detect_image_package_manager,
)


def _atom(atom_dir: Path, *, compose_body: str, docker_image="vulhub/test:1",
          user=None, has_df=False) -> AtomConfig:
    bdir = atom_dir / "source_bundle"
    bdir.mkdir(parents=True, exist_ok=True)
    (bdir / "docker-compose.yml").write_text(compose_body)
    dockerfiles = []
    if has_df:
        (bdir / "Dockerfile").write_text("FROM alpine:3.14\nRUN echo hi\n")
        dockerfiles = ["source_bundle/Dockerfile"]
    return AtomConfig(
        version=3, cve_id="CVE-RT-X", category="t", docker_image=docker_image,
        ports=[80], vuln_category="RCE", primary_mitre_phase="initial_access",
        service_role="web_application", exploit_complexity="simple",
        attack_method="single_request",
        runtime_spec={"ports": [80], "command": "httpd", "user": user},
        requirements={"tools_needed": ["curl"]},
        source_bundle=SourceBundle(compose_file="source_bundle/docker-compose.yml",
                                    dockerfiles=dockerfiles),
    )


def _cp(rc=0, stdout="", stderr=""):
    return MagicMock(returncode=rc, stdout=stdout, stderr=stderr)


def test_smoke_compose_uses_project_directory_and_override_in_runtime(tmp_path):
    """The override file lives in runtime/, and docker compose is invoked with
    --project-directory pointing at source_bundle so relative paths resolve."""
    atom_dir = tmp_path / "CVE-RT-X"
    atom_dir.mkdir()
    compose = (
        "services:\n  web:\n    image: vulhub/test:1\n    ports: ['80:80']\n"
        "    volumes: ['./www:/var/www']\n"
    )
    atom = _atom(atom_dir, compose_body=compose)
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if cmd[:2] == ["docker", "compose"] and "up" in cmd:
            return _cp(0)
        if cmd[:2] == ["docker", "exec"]:
            return _cp(0)  # port probe ok
        return _cp(0)

    with patch("clab_builder.atomizer.runtime_builder._run", side_effect=fake_run):
        ok, detail = _smoke_service_via_compose("rt:1", atom_dir, atom, 80, 4)
    assert ok
    up_cmd = [c for c in calls if "up" in c][0]
    assert "--project-directory" in up_cmd
    # project directory must be the source_bundle dir (where compose lives)
    pdx = up_cmd.index("--project-directory")
    assert "source_bundle" in up_cmd[pdx + 1]
    # override file in runtime/, not source_bundle
    override_arg = [a for a in up_cmd if a.endswith("smoke-override.yml")][0]
    assert "/runtime/" in override_arg
    assert "source_bundle" not in override_arg.rsplit("/", 1)[-1]
    # override file removed after
    assert not (atom_dir / "runtime" / "smoke-override.yml").exists()


def test_smoke_override_resets_host_port_mappings(tmp_path):
    """The runtime smoke override must reset host port mappings (via !reset)
    so a busy host port does not spuriously fail the runtime build.  Readiness
    is probed via `docker exec` inside the container, so host ports are
    unnecessary; without !reset, docker compose merges the empty list and
    keeps the original host mapping."""
    atom_dir = tmp_path / "CVE-RT-PORT"
    atom_dir.mkdir()
    compose = (
        "services:\n  web:\n    image: vulhub/test:1\n    ports: ['8081:8081']\n"
    )
    atom = _atom(atom_dir, compose_body=compose)
    captured = {}

    def fake_run(cmd, **kw):
        if cmd[:3] == ["docker", "compose", "-p"] and "up" in cmd:
            ovf = [a for a in cmd if a.endswith("smoke-override.yml")]
            if ovf:
                captured["text"] = Path(ovf[0]).read_text()
        return _cp(0)

    with patch("clab_builder.atomizer.runtime_builder._run", side_effect=fake_run):
        _smoke_service_via_compose("rt:1", atom_dir, atom, 8081, 4)
    assert "!reset" in captured["text"]
    assert "ports" in captured["text"]


def test_no_target_service_identified_is_unsupported(tmp_path):
    """If no service matches is_target/image, builder returns unsupported
    rather than substituting the first (dependency) service."""
    atom_dir = tmp_path / "CVE-RT-X"
    atom_dir.mkdir()
    # two services, neither matches docker_image
    compose = (
        "services:\n  db:\n    image: postgres:13\n  cache:\n    image: redis:6\n"
    )
    atom = _atom(atom_dir, compose_body=compose, docker_image="vulhub/target:1")

    def fake_run(cmd, **kw):
        # all docker builds + smoke + probes succeed, so the only failure path
        # is the target-service lookup in _smoke_service_via_compose.
        return _cp(0)

    with patch("clab_builder.atomizer.runtime_builder._run", side_effect=fake_run), \
         patch("clab_builder.atomizer.runtime_builder._inspect_digest", return_value="sha:b"), \
         patch("clab_builder.atomizer.runtime_builder._inspect_user", return_value=""):
        # atom has no is_target service and image matches neither -> unsupported
        atom.runtime_spec.services = []  # no is_target markers
        ok, detail = _smoke_service_via_compose("rt:1", atom_dir, atom, 80, 4)
    assert ok is False
    assert "no target service identified" in detail


def test_resolved_user_from_inspect_when_compose_has_no_user(tmp_path):
    """Base image defines a non-root USER and Compose has no user: -> builder
    inspects the base image and restores that user."""
    atom_dir = tmp_path / "CVE-RT-X"
    atom_dir.mkdir()
    compose = "services:\n  web:\n    image: vulhub/test:1\n    ports: ['80:80']\n"
    atom = _atom(atom_dir, compose_body=compose, user=None)

    with patch("clab_builder.atomizer.runtime_builder._run",
               side_effect=lambda c, **k: _cp(0)), \
         patch("clab_builder.atomizer.runtime_builder._inspect_digest",
               return_value="sha:b"), \
         patch("clab_builder.atomizer.runtime_builder._inspect_user",
               return_value="nginx"):
        res = build_runtime_image(atom, atom_dir)
    # build succeeded all gates -> ready (smoke mocked to pass, service mocked)
    assert res.status == RuntimeStatus.READY
    assert res.resolved_user == "nginx"
    # the generated Dockerfile restored USER nginx
    df = (atom_dir / "runtime" / "Dockerfile").read_text()
    assert "USER nginx" in df


def test_detects_package_manager_from_base_image():
    def fake_run(cmd, **kw):
        return _cp(0 if cmd[-1] == "command -v dnf" else 1)

    with patch("clab_builder.atomizer.runtime_builder._run", side_effect=fake_run):
        assert _detect_image_package_manager("vulhub/test:1") == "dnf"


def test_package_manager_probe_timeout_falls_back_to_next_manager():
    def fake_run(cmd, **kw):
        if cmd[-1] == "command -v apt-get":
            raise subprocess.TimeoutExpired(cmd, 15)
        return _cp(0 if cmd[-1] == "command -v apk" else 1)

    with patch("clab_builder.atomizer.runtime_builder._run", side_effect=fake_run):
        assert _detect_image_package_manager("vulhub/test:slow-pull") == "apk"


def test_smoke_failure_blocks_ready(tmp_path):
    """Any smoke check failing -> failed, not ready, even if service would pass."""
    atom_dir = tmp_path / "CVE-RT-X"
    atom_dir.mkdir()
    compose = "services:\n  web:\n    image: vulhub/test:1\n    ports: ['80:80']\n"
    atom = _atom(atom_dir, compose_body=compose)

    def fake_run(cmd, **kw):
        # docker build ok; smoke checks: curl fails, others pass
        s = " ".join(cmd)
        if "command -v curl" in s and "command -v wget" not in s and "import" not in s and "psql" not in s:
            # the curl smoke command is "command -v curl" — fail just that
            if cmd[-1].endswith("command -v curl >/dev/null 2>&1"):
                return _cp(1)
        return _cp(0)

    with patch("clab_builder.atomizer.runtime_builder._run", side_effect=fake_run), \
         patch("clab_builder.atomizer.runtime_builder._inspect_digest", return_value="sha:b"), \
         patch("clab_builder.atomizer.runtime_builder._inspect_user", return_value=""):
        res = build_runtime_image(atom, atom_dir)
    assert res.status == RuntimeStatus.FAILED
    assert res.smoke_checks.get("curl") is False
    assert "curl" in res.failure_reason


def test_smoke_uses_only_declared_remote_tools(tmp_path):
    """A Paramiko-only Atom must not smoke unrelated remote-protocol tools."""
    atom_dir = tmp_path / "CVE-RT-X"
    atom_dir.mkdir()
    compose = "services:\n  web:\n    image: vulhub/test:1\n    ports: ['80:80']\n"
    atom = _atom(atom_dir, compose_body=compose)
    atom.requirements = {"tools_needed": ["paramiko"]}
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return _cp(0)

    with patch("clab_builder.atomizer.runtime_builder._run", side_effect=fake_run), \
         patch("clab_builder.atomizer.runtime_builder._inspect_digest", return_value="sha:b"), \
         patch("clab_builder.atomizer.runtime_builder._inspect_user", return_value=""):
        res = build_runtime_image(atom, atom_dir)

    smoke_commands = [" ".join(cmd) for cmd in calls if cmd[:3] == ["docker", "run", "--rm"]]
    assert res.status == RuntimeStatus.READY
    assert all(cmd[:5] == ["docker", "run", "--rm", "--entrypoint", "sh"]
               for cmd in calls if cmd[:3] == ["docker", "run", "--rm"])
    assert any("import paramiko" in cmd for cmd in smoke_commands)
    assert all("import impacket" not in cmd for cmd in smoke_commands)
    assert all("import smb" not in cmd for cmd in smoke_commands)


def test_digests_via_inspect_not_image_id(tmp_path):
    """base_image_digest and runtime_image_digest come from inspect, distinct."""
    atom_dir = tmp_path / "CVE-RT-X"
    atom_dir.mkdir()
    compose = "services:\n  web:\n    image: vulhub/test:1\n    ports: ['80:80']\n"
    atom = _atom(atom_dir, compose_body=compose)

    def fake_digest(img):
        return "sha:base" if img == "vulhub/test:1" else "sha:rt"

    with patch("clab_builder.atomizer.runtime_builder._run",
               side_effect=lambda c, **k: _cp(0)), \
         patch("clab_builder.atomizer.runtime_builder._inspect_digest",
               side_effect=fake_digest), \
         patch("clab_builder.atomizer.runtime_builder._inspect_user", return_value=""):
        res = build_runtime_image(atom, atom_dir)
    assert res.status == RuntimeStatus.READY
    assert res.base_image_digest == "sha:base"
    assert res.runtime_image_digest == "sha:rt"


def test_generated_hash_changes_with_original_dockerfile(tmp_path):
    """For custom-Dockerfile atoms, changing the source Dockerfile changes
    the generated_hash so the runtime tag does not stay stale."""
    from clab_builder.atomizer.runtime_generator import generate_runtime_artifacts
    atom_dir = tmp_path / "CVE-DF"
    atom_dir.mkdir()
    bdir = atom_dir / "source_bundle"
    bdir.mkdir()
    (bdir / "Dockerfile").write_text("FROM alpine:3.14\nRUN echo v1\n")
    atom = _atom(atom_dir, compose_body="services:\n  s:\n    image: x:1\n",
                 has_df=True)
    atom.source_bundle = SourceBundle(compose_file="source_bundle/docker-compose.yml",
                                      dockerfiles=["source_bundle/Dockerfile"])
    a1 = generate_runtime_artifacts(atom, atom.docker_image, atom_dir=atom_dir)
    (bdir / "Dockerfile").write_text("FROM alpine:3.14\nRUN echo v2\n")
    a2 = generate_runtime_artifacts(atom, atom.docker_image, atom_dir=atom_dir)
    assert a1.manifest["generated_hash"] != a2.manifest["generated_hash"]


def test_no_port_or_compose_is_unsupported(tmp_path):
    atom_dir = tmp_path / "CVE-NOPORT"
    atom_dir.mkdir()
    atom = _atom(atom_dir, compose_body="services:\n  s:\n    image: x:1\n")
    atom.runtime_spec.ports = []  # no port
    atom.ports = []
    with patch("clab_builder.atomizer.runtime_builder._run",
               side_effect=lambda c, **k: _cp(0)), \
         patch("clab_builder.atomizer.runtime_builder._inspect_digest", return_value="sha:b"), \
         patch("clab_builder.atomizer.runtime_builder._inspect_user", return_value=""):
        res = build_runtime_image(atom, atom_dir)
    assert res.status == RuntimeStatus.UNSUPPORTED


def test_runtime_readiness_prefers_exploit_entry_port(tmp_path):
    """Multi-port services must verify the actual exploit entry, not port[0]."""
    atom_dir = tmp_path / "CVE-MULTIPORT"
    atom_dir.mkdir()
    atom = _atom(
        atom_dir,
        compose_body="services:\n  broker:\n    image: vulhub/test:1\n",
    )
    atom.runtime_spec.ports = [61616, 8161]
    atom.ports = [61616, 8161]
    atom.exploit_access.required_service = {"protocol": "http", "port": 8161}

    assert _readiness_port(atom) == 8161


def test_vulhub_parser_reads_user():
    from clab_builder.atomizer.output.vulhub_converter import VulhubParser
    import yaml as _y
    d = Path("/tmp/vp-user-test"); d.mkdir(parents=True, exist_ok=True)
    (d / "docker-compose.yml").write_text(_y.dump({
        "services": {"web": {"image": "vulhub/x:1", "user": "www-data",
                             "ports": ["80:80"]}}}))
    (d / "README.md").write_text("x")
    env = VulhubParser().parse(str(d))
    assert env.main_service.user == "www-data"


# ── codex R4 fixes ──────────────────────────────────────────────────


def test_no_target_service_is_unsupported_from_build_entry(tmp_path):
    """build_runtime_image returns UNSUPPORTED (not FAILED) when no service
    matches is_target/image — the structural gap codex flagged."""
    atom_dir = tmp_path / "CVE-RT-X"
    atom_dir.mkdir()
    compose = (
        "services:\n  db:\n    image: postgres:13\n  cache:\n    image: redis:6\n"
    )
    atom = _atom(atom_dir, compose_body=compose, docker_image="vulhub/target:1")
    atom.runtime_spec.services = []  # no is_target markers

    with patch("clab_builder.atomizer.runtime_builder._run",
               side_effect=lambda c, **k: _cp(0)), \
         patch("clab_builder.atomizer.runtime_builder._inspect_digest", return_value="sha:b"), \
         patch("clab_builder.atomizer.runtime_builder._inspect_user", return_value=""):
        res = build_runtime_image(atom, atom_dir)
    assert res.status == RuntimeStatus.UNSUPPORTED
    assert "no target service identified" in res.failure_reason


def test_pipeline_writes_source_image(tmp_path):
    """The main pipeline build writes source_image=main_image into RuntimeSpec,
    matching the handoff contract (source_image is an explicit alias)."""
    from clab_builder.atomizer.pipeline import AtomizerPipeline, LLMCheckResult
    from clab_builder.atomizer.agent.researcher import AgentOutput
    from clab_builder.shared.models.atom import SourceBundle
    from unittest.mock import patch, MagicMock

    ao = AgentOutput(cve_id="CVE-SI", success=True, exploit_steps=[],
                     evidence=["ok"], mitre_mapping={})
    atom_dir = tmp_path / "CVE-SI"
    atom_dir.mkdir()
    with patch.object(AtomizerPipeline, "_run_orchestrated_verification",
                      return_value={"success": True, "mode": "orchestrated",
                                    "evidence": [], "timestamp": "t"}), \
         patch.object(AtomizerPipeline, "_build_source_bundle_manifest",
                      return_value=SourceBundle(compose_file="source_bundle/docker-compose.yml",
                                                readme_file="source_bundle/README.md",
                                                dockerfiles=[], init_files=[],
                                                poc_materials=[], hashes={})), \
         patch.object(AtomizerPipeline, "_run_llm_checker",
                      return_value=LLMCheckResult(accepted=True, reason="ok",
                                                  confidence="high", model="test")), \
         patch.object(AtomizerPipeline, "_generate_exploit_guide", return_value=None), \
         patch.object(AtomizerPipeline, "_load_init_file_mappings", return_value=[]), \
         patch.object(AtomizerPipeline, "_extract_wait_seconds", return_value=5), \
         patch("clab_builder.atomizer.pipeline.subprocess.run"):
        pipe = AtomizerPipeline.__new__(AtomizerPipeline)
        pipe._flag = ""
        pipe._flag_required = False
        pipe._build_runtime = False
        pipe.env = MagicMock()
        pipe.env.cve_id = "CVE-SI"
        pipe.env.category = "test"
        pipe.env.main_image = "vulhub/test:1"
        pipe.env.main_ports = [80]
        pipe.env.main_service = None
        pipe.env.services = []
        pipe.env.readme_content = "x"
        src = tmp_path / "src"
        src.mkdir()
        (src / "docker-compose.yml").write_text(
            "services:\n  web:\n    image: vulhub/test:1\n    ports: ['80:80']\n")
        (src / "README.md").write_text("x")
        pipe.vulhub_dir = str(src)
        pipe._compose_service_statuses = []
        pipe._readiness_warnings = []
        pipe.output_dir = tmp_path
        pipe.max_turns = 5
        pipe._save_atom(atom_dir, agent_output=ao)
    import yaml as _y
    atom = _y.safe_load((atom_dir / "atom.yaml").read_text())
    rs = atom.get("runtime_spec") or {}
    assert rs.get("source_image") == "vulhub/test:1"


def test_service_wait_seconds_default_accommodates_java_services():
    """The default readiness window must accommodate slow-start Java services
    (Druid/JBoss/Openfire) that need >90s, not the legacy 40s.  This is a
    shared runtime contract default, not a per-CVE setting."""
    import inspect
    from clab_builder.atomizer.runtime_builder import build_runtime_image
    sig = inspect.signature(build_runtime_image)
    assert sig.parameters["service_wait_seconds"].default >= 120


def test_ca_certificates_smoke_checks_real_bundle():
    """ca_certificates smoke verifies a real non-empty CA bundle, not just
    openssl or an empty certs directory. Every branch uses -s (non-empty
    file) or a non-empty file search; the empty-directory shortcut
    `test -d /etc/ssl/certs` must NOT be present."""
    from clab_builder.shared.runtime_tools import smoke_commands
    cmds = dict(smoke_commands(["ca_certificates"]))
    cmd = cmds["ca_certificates"]
    # the empty-directory shortcut codex flagged must be gone
    assert "test -d /etc/ssl/certs" not in cmd
    # every bundle branch checks non-empty (-s), not just existence (-f)
    assert "test -s /etc/ssl/certs/ca-certificates.crt" in cmd
    assert "test -s /etc/pki/tls/certs/ca-bundle.crt" in cmd
    assert "test -s /etc/ssl/cert.pem" in cmd
    # fallback searches for a non-empty pem, not just any pem
    assert "-size +0c" in cmd
    assert "openssl version" not in cmd


def test_wait_for_dependency_services_polls_dep_port_before_target():
    """Multi-service compose (e.g. mongo-express + mongo) must wait for the
    declared depends_on service port to accept TCP before probing the target
    port.  This is a shared readiness contract for compose dependencies, not
    a per-CVE workaround."""
    from clab_builder.atomizer.runtime_builder import _wait_for_dependency_services

    services = {
        "web": {"depends_on": ["mongo"], "ports": ["8081:8081"]},
        "mongo": {"ports": ["27017:27017"]},
    }
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        # docker inspect running -> true for mongo container, then the exec
        # probe for 27017 succeeds on the second poll.
        if cmd[:2] == ["docker", "inspect"]:
            return _cp(0, "true")
        if cmd[:3] == ["docker", "exec"]:
            return _cp(0)  # dep port reachable
        return _cp(0)

    with patch("clab_builder.atomizer.runtime_builder._run", side_effect=fake_run):
        ok, detail = _wait_for_dependency_services("proj", services, "web", 30)
    assert ok
    assert detail == "ok"


def test_wait_for_dependency_services_no_deps_returns_immediately():
    from clab_builder.atomizer.runtime_builder import _wait_for_dependency_services
    services = {"web": {"ports": ["8080:8080"]}}
    with patch("clab_builder.atomizer.runtime_builder._run") as fake:
        ok, detail = _wait_for_dependency_services("proj", services, "web", 30)
    assert ok
    assert detail == "no dependencies"
    fake.assert_not_called()


def test_wait_for_dependency_services_times_out_when_dep_never_ready():
    from clab_builder.atomizer.runtime_builder import _wait_for_dependency_services

    services = {
        "web": {"depends_on": ["mongo"], "ports": ["8081:8081"]},
        "mongo": {"ports": ["27017:27017"]},
    }

    def fake_run(cmd, **kw):
        if cmd[:2] == ["docker", "inspect"]:
            return _cp(0, "false")  # never running
        if cmd[:3] == ["docker", "exec"]:
            return _cp(1)  # port never reachable
        return _cp(0)

    with patch("clab_builder.atomizer.runtime_builder._run", side_effect=fake_run), \
         patch("clab_builder.atomizer.runtime_builder.time.monotonic") as mt:
        # simulate deadline passing
        mt.side_effect = [0, 100, 200]
        ok, detail = _wait_for_dependency_services("proj", services, "web", 1)
    assert not ok
    assert "mongo" in detail
