"""Tests for the shared service-contract resolver (batch 3).

Covers the resolution order:
  1. compose ports (container side)
  2. compose expose
  3. Dockerfile EXPOSE
  4. test endpoint (APP_URL / localhost:PORT)
  5. none detectable

And the integration into pipeline._build_capability_contract:
  - agent returned partial required_service -> filled from resolver
  - agent returned nothing, no main_ports -> filled from Dockerfile EXPOSE
  - no detectable service -> still falls back to empty (local-vector safe)
"""
from pathlib import Path

import yaml

from clab_builder.shared.service_resolver import (
    resolve_service_contract,
    protocol_for_port,
    resolve_service_family,
    service_role_for_family,
)
from clab_builder.atomizer.output.vulhub_converter import VulhubService, VulhubEnvironment


def _env(ports=None, expose=None) -> VulhubEnvironment:
    svc = VulhubService(
        name="web", image="test:latest",
        ports=ports or [], expose=expose or [],
        is_main_target=True,
    )
    return VulhubEnvironment(
        cve_id="CVE-T", category="t", services=[svc],
        main_service=svc,
    )


def test_resolve_from_compose_ports(tmp_path):
    env = _env(ports=["8080:80"])
    assert resolve_service_contract(env, tmp_path) == ("http", 80)


def test_resolve_from_compose_expose_when_no_ports(tmp_path):
    env = _env(expose=["10086"])
    assert resolve_service_contract(env, tmp_path) == ("tcp", 10086)


def test_resolve_from_dockerfile_expose(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM alpine\nEXPOSE 5432\n")
    env = _env()  # no ports, no expose
    assert resolve_service_contract(env, tmp_path) == ("postgres", 5432)


def test_resolve_from_test_endpoint(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM alpine\n")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_vuln.py").write_text(
        "BASE_URL = 'http://localhost:9001'\n"
    )
    env = _env()
    assert resolve_service_contract(env, tmp_path) == ("tcp", 9001)


def test_resolve_from_app_url_default(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM alpine\n")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_vuln.py").write_text(
        "BASE_URL = os.environ.get('APP_URL', 'http://localhost:3000')\n"
    )
    env = _env()
    assert resolve_service_contract(env, tmp_path) == ("tcp", 3000)


def test_resolve_none_when_nothing_detectable(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM alpine\n")
    env = _env()
    assert resolve_service_contract(env, tmp_path) is None


def test_compose_ports_beat_dockerfile(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM alpine\nEXPOSE 9999\n")
    env = _env(ports=["80"])
    assert resolve_service_contract(env, tmp_path) == ("http", 80)


def test_protocol_for_port_known_and_unknown():
    assert protocol_for_port(80) == "http"
    assert protocol_for_port(5432) == "postgres"
    assert protocol_for_port(9999) == "tcp"
    assert protocol_for_port("notint") == "tcp"


def test_resolve_service_family_uses_runtime_identity_before_port_fallback():
    assert resolve_service_family("vulhub/elasticsearch:1.4.2", ports=[9200]) == "elasticsearch"
    assert resolve_service_family("postgres:16", ports=[5432]) == "postgresql"
    assert resolve_service_family("custom/service:latest", ports=[9200]) == "elasticsearch"
    assert resolve_service_family("custom/web:latest", ports=[8080]) == "unknown"
    assert service_role_for_family("elasticsearch") == "database"
    assert service_role_for_family("unknown") == ""


def test_pipeline_fills_partial_required_service_from_resolver(tmp_path):
    """Agent returned protocol but no port; resolver fills the port."""
    from clab_builder.atomizer.pipeline import AtomizerPipeline
    (tmp_path / "Dockerfile").write_text("FROM alpine\nEXPOSE 8443\n")
    env = _env()  # no ports
    ea, _ = AtomizerPipeline._build_capability_contract(
        {"exploit_access": {"attack_vector": "network",
                            "required_service": {"protocol": "https"}}},
        verified=True, main_ports=[], env=env, vulhub_dir=str(tmp_path),
    )
    assert ea.required_service == {"protocol": "https", "port": 8443}


def test_pipeline_fills_missing_from_resolver_when_agent_silent(tmp_path):
    """No exploit_access from agent; resolver fills from Dockerfile."""
    from clab_builder.atomizer.pipeline import AtomizerPipeline
    (tmp_path / "Dockerfile").write_text("FROM alpine\nEXPOSE 3306\n")
    env = _env()
    ea, _ = AtomizerPipeline._build_capability_contract(
        {}, verified=True, main_ports=[], env=env, vulhub_dir=str(tmp_path),
    )
    assert ea.required_service == {"protocol": "mysql", "port": 3306}


def test_pipeline_preserves_complete_agent_service(tmp_path):
    """Agent returned a complete service; resolver does not override it."""
    from clab_builder.atomizer.pipeline import AtomizerPipeline
    (tmp_path / "Dockerfile").write_text("FROM alpine\nEXPOSE 9999\n")
    env = _env(ports=["80"])
    ea, _ = AtomizerPipeline._build_capability_contract(
        {"exploit_access": {"attack_vector": "network",
                            "required_service": {"protocol": "http", "port": 80}}},
        verified=True, main_ports=[80], env=env, vulhub_dir=str(tmp_path),
    )
    assert ea.required_service == {"protocol": "http", "port": 80}


def test_vulhub_parser_reads_expose(tmp_path):
    from clab_builder.atomizer.output.vulhub_converter import VulhubParser
    (tmp_path / "docker-compose.yml").write_text(yaml.dump({
        "services": {"web": {"image": "vulhub/test:latest", "expose": ["10086"]}}
    }))
    (tmp_path / "README.md").write_text("x")
    env = VulhubParser().parse(str(tmp_path))
    assert env.main_ports == [10086]
