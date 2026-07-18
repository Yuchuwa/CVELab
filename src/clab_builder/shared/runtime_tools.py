"""Runtime tool profiles for atom target containers (batch 11).

Profiles define the logical tools a runtime image should provide. Logical
tools are mapped to concrete package names per detected package manager, so
no CVE branch hardcodes apt/apk/dnf package names.

Profiles:
  enterprise-standard-v1  — base tools every buildable atom gets by default
  build-pivot             — gcc/make, only when compilation is required
  remote-protocol         — paramiko/impacket/smbclient, only for remote-proto
                            exploitation
  java-exploit            — JRE + PoC jars, only when java is required

Selection is generic: requirements.tools_needed + guide-declared tools are
resolved to logical tools, then to the union of applicable profiles. nmap is
intentionally NOT installed (recon tool, not a generic attack tool).
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Logical tool -> package per package manager. A logical tool may need
# multiple packages (e.g. python3 + python3-requests). Unknown managers
# fall back to apt names.
_LOGICAL_TOOLS: dict[str, dict[str, list[str]]] = {
    "bash": {"apt": ["bash"], "apk": ["bash"], "dnf": ["bash"], "yum": ["bash"]},
    "coreutils": {"apt": ["coreutils"], "apk": ["coreutils"], "dnf": ["coreutils"], "yum": ["coreutils"]},
    "curl": {"apt": ["curl"], "apk": ["curl"], "dnf": ["curl"], "yum": ["curl"]},
    "wget": {"apt": ["wget"], "apk": ["wget"], "dnf": ["wget"], "yum": ["wget"]},
    "ca_certificates": {"apt": ["ca-certificates"], "apk": ["ca-certificates"],
                       "dnf": ["ca-certificates"], "yum": ["ca-certificates"]},
    "openssl": {"apt": ["openssl"], "apk": ["openssl"], "dnf": ["openssl"], "yum": ["openssl"]},
    "procps": {"apt": ["procps"], "apk": ["procps"], "dnf": ["procps-ng"], "yum": ["procps-ng"]},
    "iproute2": {"apt": ["iproute2"], "apk": ["iproute2"], "dnf": ["iproute"], "yum": ["iproute"]},
    "netcat": {"apt": ["netcat-openbsd"], "apk": ["netcat-openbsd"],
               "dnf": ["nmap-ncat"], "yum": ["nmap-ncat"]},
    "python3": {"apt": ["python3"], "apk": ["python3"], "dnf": ["python3"], "yum": ["python3"]},
    "python3_requests": {"apt": ["python3-requests"], "apk": ["py3-requests"],
                         "dnf": ["python3-requests"], "yum": ["python3-requests"]},
    "python3_psycopg2": {"apt": ["python3-psycopg2"], "apk": ["py3-psycopg2"],
                         "dnf": ["python3-psycopg2"], "yum": ["python3-psycopg2"]},
    "postgresql_client": {"apt": ["postgresql-client"], "apk": ["postgresql-client"],
                          "dnf": ["postgresql"], "yum": ["postgresql"]},
    "gcc": {"apt": ["gcc"], "apk": ["gcc"], "dnf": ["gcc"], "yum": ["gcc"]},
    "make": {"apt": ["make"], "apk": ["make"], "dnf": ["make"], "yum": ["make"]},
    "python3_paramiko": {"apt": ["python3-paramiko"], "apk": ["py3-paramiko"],
                        "dnf": ["python3-paramiko"], "yum": ["python3-paramiko"]},
    "python3_impacket": {"apt": ["python3-impacket"], "apk": ["py3-impacket"],
                         "dnf": ["python3-impacket"], "yum": ["python3-impacket"]},
    "python3_pysmb": {"apt": ["python3-pysmb"], "apk": ["py3-smbprotocol"],
                      "dnf": ["python3-smbprotocol"], "yum": ["python3-smbprotocol"]},
    "python3_pyftpdlib": {"apt": ["python3-pyftpdlib"], "apk": ["py3-pyftpdlib"],
                          "dnf": ["python3-pyftpdlib"], "yum": ["python3-pyftpdlib"]},
    "smbclient": {"apt": ["smbclient"], "apk": ["samba-client"],
                  "dnf": ["samba-client"], "yum": ["samba-client"]},
    "java": {"apt": ["default-jre"], "apk": ["openjdk17-jre"],
             "dnf": ["java-17-openjdk"], "yum": ["java-17-openjdk"]},
}

# requirement/tools_needed free-text -> logical tool(s). Case-insensitive
# substring match. psycopg2 maps to both the python module and the postgres
# client so psql is available too.
_TOOL_NEED_TO_LOGICAL: list[tuple[str, list[str]]] = [
    ("curl", ["curl"]),
    ("wget", ["wget"]),
    ("python3", ["python3", "python3_requests"]),
    ("python", ["python3", "python3_requests"]),
    ("psycopg2", ["python3_psycopg2", "postgresql_client"]),
    ("postgres", ["postgresql_client"]),
    ("psql", ["postgresql_client"]),
    ("nc", ["netcat"]),
    ("netcat", ["netcat"]),
    ("gcc", ["gcc", "make"]),
    ("make", ["make"]),
    ("paramiko", ["python3_paramiko"]),
    ("impacket", ["python3_impacket"]),
    ("smb", ["smbclient", "python3_pysmb"]),
    ("pyftpdlib", ["python3_pyftpdlib"]),
    ("java", ["java"]),
    ("jmet", ["java"]),
    ("ysoserial", ["java"]),
]


@dataclass
class ToolProfile:
    name: str
    version: str
    logical_tools: list[str] = field(default_factory=list)


ENTERPRISE_STANDARD_V1 = ToolProfile(
    name="enterprise-standard-v1",
    version="1",
    logical_tools=[
        "bash", "coreutils", "curl", "wget", "ca_certificates", "openssl",
        "procps", "iproute2", "netcat", "python3", "python3_requests",
        "python3_psycopg2", "postgresql_client",
    ],
)

BUILD_PIVOT = ToolProfile(
    name="build-pivot", version="1",
    logical_tools=["gcc", "make"],
)

REMOTE_PROTOCOL = ToolProfile(
    name="remote-protocol", version="1",
    logical_tools=[
        "python3_paramiko", "python3_impacket", "python3_pysmb",
        "python3_pyftpdlib", "smbclient",
    ],
)

JAVA_EXPLOIT = ToolProfile(
    name="java-exploit", version="1",
    logical_tools=["java"],
)

_PROFILES = {
    "enterprise-standard-v1": ENTERPRISE_STANDARD_V1,
    "build-pivot": BUILD_PIVOT,
    "remote-protocol": REMOTE_PROTOCOL,
    "java-exploit": JAVA_EXPLOIT,
}


def resolve_tools_needed(tools_needed: list[str]) -> set[str]:
    """Map free-text requirements.tools_needed to logical tools."""
    logical: set[str] = set()
    for raw in tools_needed or []:
        low = str(raw).lower().strip()
        for needle, tools in _TOOL_NEED_TO_LOGICAL:
            if needle in low:
                logical.update(tools)
    return logical


def select_profiles(tools_needed: list[str]) -> list[ToolProfile]:
    """Select the base profile plus optional profiles from tools_needed.

    enterprise-standard-v1 is always included. build-pivot/remote-protocol/
    java-exploit are added only when tools_needed implies them.
    """
    selected = [ENTERPRISE_STANDARD_V1]
    logical = resolve_tools_needed(tools_needed)
    if logical & {"gcc", "make"}:
        selected.append(BUILD_PIVOT)
    remote_tools = [
        tool for tool in REMOTE_PROTOCOL.logical_tools if tool in logical
    ]
    if remote_tools:
        selected.append(ToolProfile(
            name=REMOTE_PROTOCOL.name,
            version=REMOTE_PROTOCOL.version,
            logical_tools=remote_tools,
        ))
    if logical & {"java"}:
        selected.append(JAVA_EXPLOIT)
    return selected


def resolve_packages(profiles: list[ToolProfile], package_manager: str) -> list[str]:
    """Map the union of profile logical tools to concrete packages.

    Deduplicates and preserves a stable order. Unknown manager falls back
    to apt names.
    """
    pm = package_manager if package_manager in ("apt", "apk", "dnf", "yum") else "apt"
    pkgs: list[str] = []
    seen: set[str] = set()
    for prof in profiles:
        for lt in prof.logical_tools:
            mapping = _LOGICAL_TOOLS.get(lt)
            if not mapping:
                continue
            for p in mapping.get(pm, mapping["apt"]):
                if p not in seen:
                    seen.add(p)
                    pkgs.append(p)
    return pkgs


def detect_package_manager(dockerfile_text: str) -> str | None:
    """Detect the base image's package manager from a Dockerfile.

    Inspects FROM and any existing RUN apt/apk/dnf/yum hints. Returns None
    if it cannot be determined (caller should mark unsupported).
    """
    low = dockerfile_text.lower()
    # explicit RUN hints take priority
    if "apk add" in low:
        return "apk"
    if "apt-get" in low or "apt install" in low:
        return "apt"
    if "dnf install" in low:
        return "dnf"
    if "yum install" in low:
        return "yum"
    # infer from FROM image
    for line in dockerfile_text.splitlines():
        s = line.strip().lower()
        if s.startswith("from "):
            img = s.split()[1]
            if img.startswith("alpine"):
                return "apk"
            if "ubi" in img or "fedora" in img or "rocky" in img or "centos" in img:
                return "dnf"
            if "amazon" in img:
                return "yum"
            # default for debian/ubuntu/python/php/tomcat/etc
            return "apt"
    return None


def install_commands(package_manager: str, packages: list[str]) -> str:
    """Build the non-interactive install command block for a manager.

    Uses proxy env inheritance (HTTP_PROXY/HTTPS_PROXY/NO_PROXY) from the
    build environment without hardcoding any address. Cleans caches.

    For apt: EOL Debian releases (jessie/stretch/buster) have their package
    sources removed from deb.debian.org; this block falls back to
    archive.debian.org when the primary apt-get update fails. This is a
    generic release-aging fix, not a per-CVE branch.
    """
    if not packages:
        return ""
    if package_manager == "apt":
        # EOL Debian releases (jessie/stretch/buster) lose their deb.debian.org
        # sources; archive.debian.org serves them but with expired signing
        # keys, so [trusted=yes] + --allow-unauthenticated are required. This
         # fallback extracts the codename from any Debian source entry (so it
         # also handles httpredir.debian.org), rewrites to a single archive
         # line, and drops security/updates (archive does not mirror them).
         # Only that archive path permits expired signatures.
        # Generic release-aging handling, not a per-CVE branch.
        return (
            "export DEBIAN_FRONTEND=noninteractive\n"
            "apt_install_flags=\n"
            "apt_log=/tmp/cvelab-apt-update.log\n"
             "if ! apt-get update -qq >\"$apt_log\" 2>&1 || "
             "grep -Eq 'Failed to fetch https?://(deb\\.debian\\.org|security\\.debian\\.org|httpredir\\.debian\\.org|security\\.debian\\.org/debian)/' \"$apt_log\"; then\n"
             "  . /etc/os-release 2>/dev/null || true\n"
             "  codename=$(awk '$1 == \"deb\" {print $3; exit}' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null)\n"
             "  codename=${codename:-${VERSION_CODENAME:-}}\n"
             "  case \"${ID:-}\":\"$codename\" in\n"
             "    debian:jessie|debian:stretch|debian:buster|debian:bullseye)\n"
             "      echo \"deb [trusted=yes] http://archive.debian.org/debian $codename main\" > /etc/apt/sources.list\n"
             "      rm -f /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources 2>/dev/null || true\n"
             "      apt-get update -qq\n"
             "      apt_install_flags=--allow-unauthenticated\n"
             "      ;;\n"
             "    *) cat \"$apt_log\" >&2; exit 1 ;;\n"
             "  esac\n"
             "fi &&\n"
             "rm -f \"$apt_log\" &&\n"
             "mkdir -p /usr/share/man/man1 /usr/share/man/man7 &&\n"
             "apt-get install -y --no-install-recommends $apt_install_flags "
            + " ".join(packages) + " && "
            "rm -rf /var/lib/apt/lists/*"
        )
    if package_manager == "apk":
        return "apk add --no-cache " + " ".join(packages)
    if package_manager == "dnf":
        return "dnf install -y " + " ".join(packages) + " && dnf clean all"
    if package_manager == "yum":
        return "yum install -y " + " ".join(packages) + " && yum clean all"
    return ""


# logical tool -> a shell smoke command that succeeds iff the tool is usable.
# Commands are manager-agnostic (no hardcoded CA path). python module checks
# use a bare import; binary checks use command -v; CA is verified via openssl
# trusting the system store.
_TOOL_SMOKE: dict[str, str] = {
    "bash": "command -v bash",
    "coreutils": "command -v cat && command -v echo && command -v grep",
    "curl": "command -v curl",
    "wget": "command -v wget",
    "ca_certificates": ("test -s /etc/ssl/certs/ca-certificates.crt "
                       "|| test -s /etc/pki/tls/certs/ca-bundle.crt "
                       "|| test -s /etc/ssl/cert.pem "
                       "|| find /etc/ssl/certs -type f -size +0c -name '*.pem' "
                       "| grep -q ."),
    "openssl": "command -v openssl",
    "procps": "command -v ps",
    "iproute2": "command -v ip",
    "netcat": "command -v nc || command -v netcat || command -v ncat",
    "python3": "command -v python3",
    "python3_requests": "python3 -c 'import requests'",
    "python3_psycopg2": "python3 -c 'import psycopg2'",
    "postgresql_client": "psql --version || command -v psql",
    "gcc": "gcc --version",
    "make": "make --version",
    "python3_paramiko": "python3 -c 'import paramiko'",
    "python3_impacket": "python3 -c 'import impacket'",
    "python3_pysmb": "python3 -c 'import smb'",
    "python3_pyftpdlib": "python3 -c 'import pyftpdlib'",
    "smbclient": "command -v smbclient",
    "java": "java -version",
}


def smoke_commands(logical_tools: list[str]) -> list[tuple[str, str]]:
    """Return (logical_tool, smoke_command) for each requested tool.

    Used by the builder to verify installed tools per the selected profiles,
    not a hand-picked subset. Unknown tools are skipped.
    """
    out = []
    for lt in logical_tools:
        cmd = _TOOL_SMOKE.get(lt)
        if cmd:
            out.append((lt, cmd))
    return out


def profile_logical_tools(profiles: list[ToolProfile]) -> list[str]:
    """Union of logical tools across the selected profiles, deduped."""
    seen: list[str] = []
    s: set[str] = set()
    for p in profiles:
        for lt in p.logical_tools:
            if lt not in s:
                s.add(lt)
                seen.append(lt)
    return seen


__all__ = [
    "ToolProfile",
    "ENTERPRISE_STANDARD_V1", "BUILD_PIVOT", "REMOTE_PROTOCOL", "JAVA_EXPLOIT",
    "resolve_tools_needed", "select_profiles", "resolve_packages",
    "detect_package_manager", "install_commands",
    "smoke_commands", "profile_logical_tools",
]
