"""Shared service-contract resolver.

Resolves the authoritative (protocol, port) for a CVE environment so the
atom's ``exploit_access.required_service`` is never empty for a network
vector. Resolution order (first wins):

  1. Compose service ``ports`` (container side) — already parsed by
     VulhubParser.main_ports
  2. Compose service ``expose``
  3. Dockerfile ``EXPOSE``
  4. test endpoint hint (CVE-Factory ``tests/test_vuln.py`` ``localhost:PORT``
     or ``APP_URL`` env default)
  5. native readiness observation (caller-supplied main_ports)

Used by:
  - pipeline._build_capability_contract (fills required_service when the
    agent omitted it or returned a partial dict, instead of falling back
    to an empty dict)
  - prepare_cve_factory_sources (writes resolved ports into the prepared
    compose so VulhubParser can pick them up at atomize time)

This does NOT read the guide. The guide's port is advisory; the atom is the
authoritative source of the service contract.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

import yaml

from clab_builder.atomizer.output.vulhub_converter import (
    VulhubEnvironment,
    container_port_from_spec,
)

# Common port -> protocol mapping. Mirrors pipeline._infer_protocol so the
# resolver and the legacy fallback agree.
_PORT_PROTOCOL = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql",
    5432: "postgres", 5900: "vnc", 6379: "redis", 7001: "http",
    8080: "http", 8443: "https", 8888: "http", 9042: "cassandra",
    9200: "elasticsearch", 9300: "elasticsearch", 11211: "memcached",
    27017: "mongodb", 50070: "hadoop",
}

_FAMILY_KEYWORDS = {
    "postgresql": ("postgres", "postgresql"),
    "mysql": ("mysql",),
    "mariadb": ("mariadb",),
    "mongodb": ("mongo", "mongodb"),
    "couchdb": ("couchdb",),
    "redis": ("redis",),
    "elasticsearch": ("elasticsearch",),
    "opensearch": ("opensearch",),
    "cassandra": ("cassandra",),
    "influxdb": ("influxdb", "influx"),
}

_PORT_FAMILIES = {
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    9042: "cassandra",
    9200: "elasticsearch",
    9300: "elasticsearch",
    27017: "mongodb",
}


def resolve_service_family(
    image: str = "",
    service_name: str = "",
    ports: Optional[list[int]] = None,
) -> str:
    """Return a conservative canonical runtime service family.

    This is compatibility metadata for Range asset setup, not a claim that an
    Atom has proven any business-data operation.  Image/service names are the
    strongest signal; a well-known database port is only a fallback.
    """
    haystack = f"{image} {service_name}".lower()
    for family, keywords in _FAMILY_KEYWORDS.items():
        if any(keyword in haystack for keyword in keywords):
            return family
    for port in ports or []:
        try:
            family = _PORT_FAMILIES.get(int(port))
        except (TypeError, ValueError):
            family = None
        if family:
            return family
    return "unknown"


def service_role_for_family(family: str) -> str:
    """Return the template role implied by a known runtime family."""
    return "database" if family and family != "unknown" else ""


def protocol_for_port(port: int) -> str:
    try:
        return _PORT_PROTOCOL.get(int(port), "tcp")
    except (TypeError, ValueError):
        return "tcp"


def _expose_from_dockerfile(dockerfile: Path) -> list[int]:
    """Parse EXPOSE lines from a Dockerfile. Returns integer ports."""
    ports: list[int] = []
    if not dockerfile.is_file():
        return ports
    for line in dockerfile.read_text(errors="replace").splitlines():
        if line.strip().startswith("EXPOSE"):
            for m in re.findall(r"\b(\d+)(?:/\w+)?\b", line):
                try:
                    ports.append(int(m))
                except ValueError:
                    pass
    return ports


def _port_from_test_endpoint(src_dir: Path) -> Optional[int]:
    """Infer the service port from CVE-Factory test_vuln.py / test_func.py.

    Looks for the first ``localhost:PORT`` or ``APP_URL`` default that names
    a concrete port. This is the weakest signal (the test may talk to a
    helper service), so it is only used when compose and EXPOSE are silent.
    """
    tests_dir = src_dir / "tests"
    candidates = []
    for name in ("test_vuln.py", "test_func.py"):
        p = tests_dir / name
        if p.is_file():
            candidates.append(p)
    # also root-level test files
    for p in src_dir.glob("test_*.py"):
        if p not in candidates:
            candidates.append(p)
    for c in candidates:
        try:
            text = c.read_text(errors="replace")[:4000]
        except OSError:
            continue
        # APP_URL default
        m = re.search(r"APP_URL[^'\"}]*['\"]http://[^:/]+:(\d+)", text)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                pass
        # plain localhost:PORT (skip 80 to avoid false positives from URLs)
        for m in re.finditer(r"localhost:(\d+)", text):
            try:
                return int(m.group(1))
            except ValueError:
                pass
    return None


def resolve_service_contract(
    env: Optional[VulhubEnvironment],
    src_dir: Optional[Path] = None,
) -> Optional[tuple[str, int]]:
    """Return (protocol, port) or None if no network service is detectable.

    Args:
        env:     parsed VulhubEnvironment (may be None for CVE-Factory-only
                 sources that have no compose yet)
        src_dir: the source directory (vulhub dir or prepared CVE-Factory
                 staging). Used to read Dockerfile EXPOSE and test endpoints
                 when compose ports are absent.
    """
    port: Optional[int] = None

    # 1. compose ports (container side)
    if env is not None and env.main_ports:
        port = int(env.main_ports[0])

    # 2. compose expose
    if port is None and env is not None:
        svc = env.main_service
        if svc is not None:
            expose = getattr(svc, "expose", []) or []
            if expose:
                for spec in expose:
                    p = container_port_from_spec(str(spec))
                    if p is not None:
                        port = p
                        break

    # 3. Dockerfile EXPOSE
    if port is None and src_dir is not None:
        df = src_dir / "Dockerfile"
        ports = _expose_from_dockerfile(df)
        if ports:
            port = ports[0]

    # 4. test endpoint
    if port is None and src_dir is not None:
        port = _port_from_test_endpoint(src_dir)

    if port is None:
        return None
    return protocol_for_port(port), port


__all__ = [
    "resolve_service_contract",
    "protocol_for_port",
    "resolve_service_family",
    "service_role_for_family",
]
