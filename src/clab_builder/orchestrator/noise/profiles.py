"""Versioned passive benign-service profiles.

This module is intentionally independent from templates and individual CVE
data.  A profile is selected from the Atom handoff (family, protocol, port
and image) and produces a non-exploitable service surface.  The first step
keeps the existing generated behavior byte-for-byte compatible; later
workload implementations can extend these profiles without putting more
logic into ``scenario_assembler.py``.
"""

from __future__ import annotations

import base64
from collections import defaultdict
from dataclasses import dataclass
import shlex
from typing import Any

from clab_builder.shared.models.template import NoiseService
from clab_builder.shared.service_resolver import protocol_for_port, resolve_service_family


# This is the profile contract version, not a new public noise level.  Existing
# historical scenarios do not acquire this value retroactively.
NOISE_PROFILE_VERSION = "passive-v2"

# Immutable, locally smoke-tested images used by the versioned profile.  A
# benign profile must never reuse an Atom's vulnerable runtime image.
ALPINE_IMAGE = (
    "alpine:latest@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659"
)
NGINX_IMAGE = (
    "nginx:alpine@sha256:54f2a904c251d5a34adf545a72d32515a15e08418dae0266e23be2e18c66fefa"
)
POSTGRES_IMAGE = (
    "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777"
)
REDIS_IMAGE = (
    "redis:7.4-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99"
)
PYTHON_IMAGE = (
    "python:3.12-alpine@sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78ade7dc31"
)


@dataclass(frozen=True)
class NoiseProfile:
    """One reusable Range-side benign service profile.

    A profile is matched from Atom handoff metadata.  ``supported=False`` is
    intentional for the generic TCP fallback: it remains useful for legacy
    passive surface noise, but it must be visible as a fidelity gap in an
    active high-fidelity experiment.
    """

    profile_id: str
    workload_kind: str
    fidelity: str
    families: frozenset[str] = frozenset()
    products: frozenset[str] = frozenset()
    protocols: frozenset[str] = frozenset()
    ports: frozenset[int] = frozenset()
    supported: bool = True
    reason: str = ""

    def matches(
        self,
        *,
        family: str,
        product: str,
        protocol: str,
        port: int,
    ) -> bool:
        return self.match_score(
            family=family, product=product, protocol=protocol, port=port
        ) > 0

    def match_score(
        self,
        *,
        family: str,
        product: str,
        protocol: str,
        port: int,
    ) -> int:
        """Prefer a service/product/port identity over generic HTTP."""
        score = 0
        if family in self.families:
            score += 100
        if product in self.products:
            score += 120
        if port in self.ports:
            score += 60
        if protocol in self.protocols:
            score += 10
        return score


# Specific profiles precede the generic HTTP profile.  Adding a new service
# family should add one entry here and its workload adapter, not a CVE branch
# in scenario_assembler.py.
NOISE_PROFILE_REGISTRY: tuple[NoiseProfile, ...] = (
    NoiseProfile(
        profile_id="elasticsearch-http",
        workload_kind="http",
        fidelity="facade",
        families=frozenset({"elasticsearch"}),
        products=frozenset({"elasticsearch", "opensearch"}),
        protocols=frozenset({"http"}),
        ports=frozenset({9200}),
    ),
    NoiseProfile(
        profile_id="solr-http",
        workload_kind="http",
        fidelity="facade",
        families=frozenset({"solr"}),
        products=frozenset({"solr"}),
        protocols=frozenset({"http"}),
        ports=frozenset({8983}),
    ),
    NoiseProfile(
        profile_id="tcp-redis",
        workload_kind="redis",
        fidelity="real",
        families=frozenset({"redis"}),
        protocols=frozenset({"redis"}),
        ports=frozenset({6379}),
    ),
    NoiseProfile(
        profile_id="tcp-postgres",
        workload_kind="postgres",
        fidelity="real",
        families=frozenset({"postgres", "postgresql"}),
        protocols=frozenset({"postgres", "postgresql"}),
        ports=frozenset({5432}),
    ),
    NoiseProfile(
        profile_id="http-web",
        workload_kind="http",
        fidelity="facade",
        protocols=frozenset({"http", "https"}),
        ports=frozenset({80, 443, 8080, 8443, 8888}),
    ),
)

NOISE_FALLBACK_PROFILE = NoiseProfile(
    profile_id="tcp-generic",
    workload_kind="tcp",
    fidelity="fallback",
    supported=False,
    reason="no registered high-fidelity profile matched the Atom service surface",
)


def _image_product_version(source_image: str) -> tuple[str, str]:
    image_ref = str(source_image or "").split("@", 1)[0]
    image_name = image_ref.rsplit("/", 1)[-1]
    product, _, version = image_name.partition(":")
    return product.lower(), version or "unknown"


def resolve_noise_profile(injection: dict[str, Any]) -> NoiseProfile:
    """Resolve one deterministic profile from shared Atom runtime metadata."""
    source_image = str(injection.get("source_image", "") or "")
    product, _ = _image_product_version(source_image)
    ports = injection.get("ports", []) or []
    port = int(
        injection.get("exploit_port")
        or (ports[0] if ports else 0)
    )
    family = str(injection.get("service_family", "") or "").lower()
    if not family or family == "unknown":
        family = resolve_service_family(source_image, "", ports) or "unknown"
    protocol = str(
        injection.get("service_protocol") or protocol_for_port(port)
    ).lower()
    matches = [
        profile for profile in NOISE_PROFILE_REGISTRY
        if profile.matches(
            family=family, product=product, protocol=protocol, port=port
        )
    ]
    if matches:
        return max(
            matches,
            key=lambda profile: profile.match_score(
                family=family, product=product, protocol=protocol, port=port
            ),
        )
    return NOISE_FALLBACK_PROFILE


def http_surface_command(
    port: int,
    banner: str,
    routes: dict[str, dict[str, str]],
    http_version: str = "1.1",
    include_server_header: bool = True,
) -> str:
    """Render a persistent NGINX facade for the declared HTTP surface.

    A one-shot ``nc -l`` process loses its listener after every request.  The
    facade therefore writes a small NGINX configuration and stays resident for
    the entire Range lifetime.  Route bodies and the modeled status/content
    type/extra headers remain profile-owned data.
    """
    del banner, http_version, include_server_header

    def quote_nginx(value: object) -> str:
        return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

    locations: list[str] = []
    setup = ["mkdir -p /usr/share/nginx/html/__noise_routes /etc/nginx/conf.d"]
    for index, (path, route) in enumerate(routes.items()):
        status = str(route.get("status", "200 OK")).split(maxsplit=1)[0]
        content_type = quote_nginx(route.get("content_type", "text/html"))
        headers: list[str] = []
        for raw_header in str(route.get("extra_headers", "")).splitlines():
            name, separator, value = raw_header.partition(":")
            if separator and name.strip():
                headers.append(
                    f'      add_header {name.strip()} "{quote_nginx(value.strip())}" always;'
                )
        route_file = f"/__noise_routes/{index}"
        encoded_body = base64.b64encode(str(route.get("body", "")).encode()).decode()
        setup.append(
            f"printf '%s' {shlex.quote(encoded_body)} | base64 -d > "
            f"/usr/share/nginx/html{route_file}"
        )
        locations.extend([
            f"    location = {path} {{",
            f"      default_type \"{content_type}\";",
            *headers,
            (
                f"      return {status} {route.get('extra_headers', '').split('Location: ', 1)[1].splitlines()[0]};"
                if status.startswith("3") and "Location: " in str(route.get("extra_headers", ""))
                else f"      try_files {route_file} =404;"
            ),
            "    }",
        ])
    config = "\n".join([
        "events {}",
        "http {",
        "  server_tokens off;",
        "  server {",
        f"    listen {port};",
        "    server_name _;",
        "    root /usr/share/nginx/html;",
        *locations,
        "  }",
        "}",
        "",
    ])
    encoded = base64.b64encode(config.encode()).decode()
    setup.append(
        f"printf '%s' {shlex.quote(encoded)} | base64 -d > /etc/nginx/nginx.conf"
    )
    script = "; ".join(setup) + "; exec nginx -g 'daemon off;'"
    return f"sh -c {shlex.quote(script)}"


def surface_spec(injection: dict[str, Any]) -> dict[str, Any]:
    """Derive a safe protocol facade from runtime metadata, not a CVE ID."""
    source_image = str(injection.get("source_image", "") or "")
    product, version = _image_product_version(source_image)
    port = int(injection.get("exploit_port") or (injection.get("ports") or [0])[0])
    profile = resolve_noise_profile(injection)
    family = str(injection.get("service_family", "") or "").lower()
    if not family or family == "unknown":
        family = resolve_service_family(
            source_image, "", injection.get("ports", [])
        ) or "unknown"
    protocol = str(
        injection.get("service_protocol") or protocol_for_port(port)
    ).lower()

    if profile.profile_id == "elasticsearch-http":
        root = (
            '{"status":200,"name":"decoy-node","version":'
            f'{{"number":"{version}","build_hash":"f1585f096d3f3985e73456debdc1a0745f512bbc",'
            '"build_snapshot":false,"lucene_version":"4.7"},'
            '"tagline":"You Know, for Search"}'
        )
        health = (
            '{"cluster_name":"elasticsearch","status":"green",'
            '"number_of_nodes":1,"active_primary_shards":1}'
        )
        return {
            "profile": profile.profile_id,
            "family": "elasticsearch",
            "protocol": "http",
            "banner": f"Elasticsearch/{version}",
            "workload_kind": profile.workload_kind,
            "fidelity": profile.fidelity,
            "supported": profile.supported,
            "command": http_surface_command(port, f"Elasticsearch/{version}", {
                "/": {"body": root, "content_type": "application/json; charset=UTF-8"},
                "/_cluster/health": {
                    "body": health,
                    "content_type": "application/json; charset=UTF-8",
                },
            }, http_version="1.0", include_server_header=False),
        }

    if profile.profile_id == "solr-http":
        admin = (
            '<html ng-app="solrAdminApp"><head><title>Solr Admin</title></head>'
            '<body>Solr Admin Dashboard</body></html>'
        )
        api = (
            '{"responseHeader":{"status":0,"QTime":1},'
            '"response":{"numFound":0,"start":0,"docs":[]}}'
        )
        return {
            "profile": profile.profile_id,
            "family": "solr",
            "protocol": "http",
            "banner": f"Apache Solr/{version}",
            "workload_kind": profile.workload_kind,
            "fidelity": profile.fidelity,
            "supported": profile.supported,
            "command": http_surface_command(port, f"Apache Solr/{version}", {
                "/": {
                    "status": "302 Found",
                    "content_type": "text/html",
                    "extra_headers": "Location: /solr/",
                    "body": "",
                },
                "/solr/": {"content_type": "text/html", "body": admin},
                "/solr/select": {"body": api},
            }),
        }

    if profile.profile_id == "http-web":
        if product == "php":
            banner = "Apache/2.4.10"
            extra = f"X-Powered-By: PHP/{version}"
        else:
            banner = product or "Apache"
            extra = ""
        body = "<html><title>Service</title><body>OK</body></html>"
        return {
            "profile": profile.profile_id,
            "family": family if family and family != "unknown" else "http-web",
            "protocol": "http",
            "banner": banner,
            "workload_kind": profile.workload_kind,
            "fidelity": profile.fidelity,
            "supported": profile.supported,
            "command": http_surface_command(port, banner, {
                "/": {
                    "content_type": "text/html",
                    "extra_headers": extra,
                    "body": body,
                },
            }),
        }

    return {
        "profile": profile.profile_id,
        "family": family or "unknown",
        "protocol": protocol or "tcp",
        "banner": "",
        "workload_kind": profile.workload_kind,
        "fidelity": profile.fidelity,
        "supported": profile.supported,
        "command": "",
    }


def matched_noise_services(
    noise_services: list[NoiseService],
    injections: list[dict[str, Any]],
    *,
    real_services: bool = False,
) -> list[NoiseService]:
    """Build target-surface-matched, non-exploitable passive services.

    ``real_services`` is enabled only by the versioned activity experiment
    topology.  Legacy high generation keeps its historical image choices.
    """
    vulnerable_images = {
        str(injection.get(key, "")).split("@", 1)[0]
        for injection in injections
        for key in ("source_image", "runtime_image")
        if injection.get(key)
    }
    ports_by_zone: dict[str, list[int]] = defaultdict(list)
    for injection in injections:
        port = injection.get("exploit_port")
        if port is None:
            ports = injection.get("ports", []) or []
            port = ports[0] if ports else None
        if port is not None:
            ports_by_zone[injection["zone"]].append(int(port))

    matched: list[NoiseService] = []
    for index, service in enumerate(noise_services):
        candidates = ports_by_zone.get(service.zone, [])
        if not candidates:
            matched.append(service)
            continue
        port = candidates[index % len(candidates)]
        injection = next(
            item for item in injections
            if item.get("zone") == service.zone
            and int(item.get("exploit_port") or (item.get("ports") or [0])[0]) == port
        )
        surface = surface_spec(injection)
        if real_services and surface["workload_kind"] == "http" and surface["profile"] == "http-web":
            image = NGINX_IMAGE
            command = (
                "sh -c " + shlex.quote(
                    "mkdir -p /usr/share/nginx/html; "
                    "printf '%s' '<html><title>Business Service</title>"
                    "<body>catalog ok</body></html>' "
                    "> /usr/share/nginx/html/index.html; "
                    f"sed -i -E 's/listen[[:space:]]+80[^;]*;/listen {port};/' "
                    "/etc/nginx/conf.d/default.conf; "
                    "exec nginx -g 'daemon off;'"
                )
            )
            environment = {}
        elif real_services and surface["workload_kind"] == "postgres":
            image = POSTGRES_IMAGE
            command = ""
            environment = {
                "POSTGRES_USER": "noise",
                "POSTGRES_PASSWORD": "noise",
                "POSTGRES_DB": "noise",
            }
        elif surface["profile"] in {"http-web", "elasticsearch-http", "solr-http"}:
            image, command = NGINX_IMAGE, surface["command"]
            environment = {}
        elif port == 6379:
            image, command = REDIS_IMAGE, ""
            environment = {}
        elif port in {22, 3306, 5432}:
            image, command = ALPINE_IMAGE, f"nc -lk -p {port} -e /bin/true"
            environment = {}
        else:
            # Unknown/middleware ports must still expose a reliable benign
            # listener.  BusyBox httpd is not present in every pinned BusyBox
            # variant and caused false environment failures for ports such as
            # ActiveMQ's 8161.  Alpine's netcat listener is already used by
            # the stable TCP profiles above.
            image, command = ALPINE_IMAGE, f"nc -lk -p {port} -e /bin/true"
            environment = {}
        if real_services and surface["workload_kind"] == "http" and surface["profile"] == "http-web":
            fidelity = "real"
        elif real_services and surface["workload_kind"] == "postgres":
            fidelity = "real"
        elif surface["workload_kind"] == "redis":
            fidelity = "real"
        elif surface["profile"] in {"http-web", "elasticsearch-http", "solr-http"}:
            fidelity = "facade"
        else:
            fidelity = "fallback"
        if image.split("@", 1)[0] in vulnerable_images:
            raise ValueError(
                f"noise profile must not reuse Atom runtime image {image.split('@', 1)[0]}"
            )
        matched.append(service.model_copy(update={
            "image": image,
            "ports": [port],
            "command": command,
            "surface_profile": surface["profile"],
            "surface_banner": surface["banner"],
            "entrypoint": surface.get("real_entrypoint", ""),
            "environment": environment,
            "service_family": "redis" if port == 6379 else surface["family"],
            "fidelity": fidelity,
        }))
    return matched


def profile_coverage(
    injections: list[dict[str, Any]], *, real_services: bool = False
) -> list[dict[str, Any]]:
    """Return deterministic profile matching evidence for a scenario.

    ``supported`` means a registered profile exists.  A ``fallback`` row is
    retained for legacy passive experiments but is not admitted to the active
    high-fidelity arm.
    """
    rows: list[dict[str, Any]] = []
    for injection in injections:
        declared = str(injection.get("service_family", "") or "").lower()
        surface = surface_spec(injection)
        profile = resolve_noise_profile(injection)
        resolved = str(surface.get("profile", "generic"))
        if real_services and surface["workload_kind"] == "http" and resolved == "http-web":
            fidelity = "real"
        elif real_services and surface["workload_kind"] == "postgres":
            fidelity = "real"
        elif surface["workload_kind"] == "redis":
            fidelity = "real"
        elif resolved in {"http-web", "elasticsearch-http", "solr-http"}:
            fidelity = "facade"
        else:
            fidelity = "fallback"
        rows.append({
            "cve_id": str(injection.get("cve_id", "")),
            "zone": str(injection.get("zone", "")),
            "declared_family": declared or "unknown",
            "profile": resolved,
            "profile_id": profile.profile_id,
            "match_basis": "declared" if declared and declared != "unknown" else "inferred",
            "fidelity": fidelity,
            "supported": profile.supported,
            "status": "supported" if profile.supported else "fallback",
            "workload_kind": profile.workload_kind,
            "reason": profile.reason,
        })
    return rows


def profile_admission(
    injections: list[dict[str, Any]], *, activity: str | None = None
) -> dict[str, Any]:
    """Report whether a scenario is eligible for a noise experiment arm.

    Legacy/passive generation may keep fallback surfaces for comparability.
    Explicit ``normal`` activity requires every selected Atom surface to have
    a registered profile; the scenario is still generated so the rejection is
    preserved as evidence rather than silently changing the denominator.
    """
    rows = profile_coverage(injections, real_services=activity is not None)
    blocking = [
        row for row in rows
        if activity == "normal" and not bool(row.get("supported"))
    ]
    return {
        "mode": activity or "legacy",
        "eligible": None if activity is None else not blocking,
        "blocking_profiles": blocking,
        "rows": rows,
    }
