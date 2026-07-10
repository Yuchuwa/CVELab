"""Shared chain-contract inference for atom composition."""

from __future__ import annotations

from typing import Any, Iterable

from clab_builder.shared.models.atom import ChainContract, ChainGrants, ChainRequires


COMMAND_EXECUTION_MARKERS = (
    "runtime.getruntime",
    ".exec(",
    "cmd=",
    "command=",
    "cat /flag",
    "cat%20/flag",
    "/bin/sh",
    "/bin/bash",
    "bash -c",
    "/dev/tcp",
    "nc -",
    "netcat",
    "wget ",
    "curl ",
    "python3 -c",
    "copy from program",
)

FILE_READ_MARKERS = (
    "/etc/passwd",
    "/flag",
    "/tmp/flag",
    "load_file",
    "path traversal",
    "file read",
    "arbitrary file",
    "connect-node \"@",
)


def infer_chain_contract(
    *,
    ports: Iterable[Any] = (),
    requirements: dict[str, Any] | None = None,
    network_requirements: Any = None,
    vuln_category: Any = "",
    attack_method: Any = "",
    vulnerability_type: str = "",
    flag_verify_command: str = "",
    evidence: Iterable[Any] = (),
    exploit_steps: Iterable[dict[str, Any]] = (),
    verified: bool = False,
    flag_matched: bool = False,
    flag_value: str = "",
) -> ChainContract:
    """Infer a compact composition contract from atom evidence."""
    normalized_ports = _normalize_ports(ports)
    auth = infer_chain_auth(requirements or {})
    callback = _network_bool(network_requirements, "needs_callback")
    internet = _network_bool(network_requirements, "needs_tool_download")
    text = _chain_evidence_text(
        vulnerability_type=vulnerability_type,
        flag_verify_command=flag_verify_command,
        evidence=evidence,
        exploit_steps=exploit_steps,
    )

    vuln_value = _enum_value(vuln_category)
    attack_value = _enum_value(attack_method)
    command_execution = infer_chain_command_execution(
        vuln_category=vuln_value,
        attack_method=attack_value,
        text=text,
    )
    file_read = infer_chain_file_read(
        vuln_category=vuln_value,
        text=text,
        command_execution=command_execution,
    )
    flag_capture = bool(flag_value and verified and flag_matched)
    outbound_network = command_execution
    relay_compatible = bool(command_execution and outbound_network and not callback and not internet)

    roles = []
    if normalized_ports and auth in {"none", "default", "unknown"} and not internet:
        roles.append("entry")
    if relay_compatible:
        roles.append("relay")
    if flag_capture:
        roles.append("terminal")

    return ChainContract(
        requires=ChainRequires(
            ports=normalized_ports,
            auth=auth,
            callback=callback,
            internet=internet,
        ),
        grants=ChainGrants(
            command_execution=command_execution,
            file_read=file_read,
            outbound_network=outbound_network,
            flag_capture=flag_capture,
        ),
        relay_compatible=relay_compatible,
        roles=roles,
    )


def infer_chain_contract_from_atom_data(data: dict[str, Any]) -> ChainContract:
    """Backfill chain_contract for atoms produced before this schema existed."""
    return infer_chain_contract(
        ports=data.get("ports", []),
        requirements=data.get("requirements") or {},
        network_requirements=data.get("network_requirements") or {},
        vuln_category=data.get("vuln_category") or "",
        attack_method=data.get("attack_method") or "",
        vulnerability_type=str(data.get("vulnerability_type") or ""),
        flag_verify_command=str(data.get("flag_verify_command") or ""),
        evidence=data.get("evidence") or (),
        verified=bool(data.get("verified")),
        flag_matched=bool(data.get("verified") and data.get("flag_value")),
        flag_value=str(data.get("flag_value") or ""),
    )


def infer_chain_auth(requirements: dict[str, Any]) -> str:
    auth = str((requirements or {}).get("authentication", "") or "").strip().lower()
    if not auth:
        return "none"
    if auth in {"none", "no", "n/a", "unauthenticated"} or "none" in auth:
        return "none"
    if "default" in auth or "weak" in auth:
        return "default"
    if "unknown" in auth:
        return "unknown"
    return "required"


def infer_chain_command_execution(*, vuln_category: str, attack_method: str, text: str) -> bool:
    if vuln_category in {"RCE", "Deserialization"}:
        return True
    if any(marker in text for marker in COMMAND_EXECUTION_MARKERS):
        return True
    return attack_method in {"deserialization", "file_upload"} and "flag" in text


def infer_chain_file_read(*, vuln_category: str, text: str, command_execution: bool) -> bool:
    if command_execution and "flag" in text:
        return True
    if vuln_category in {"LFI", "Info_Leak"}:
        return True
    return any(marker in text for marker in FILE_READ_MARKERS)


def _normalize_ports(ports: Iterable[Any]) -> list[int]:
    normalized = []
    for port in ports or ():
        port_text = str(port).split("/")[0]
        if ":" in port_text:
            port_text = port_text.rsplit(":", 1)[-1]
        if port_text.isdigit():
            normalized.append(int(port_text))
    return normalized


def _network_bool(network_requirements: Any, field: str) -> bool:
    if isinstance(network_requirements, dict):
        return bool(network_requirements.get(field))
    return bool(getattr(network_requirements, field, False))


def _enum_value(value: Any) -> str:
    return str(getattr(value, "value", value) or "")


def _chain_evidence_text(
    *,
    vulnerability_type: str,
    flag_verify_command: str,
    evidence: Iterable[Any],
    exploit_steps: Iterable[dict[str, Any]],
) -> str:
    parts = [vulnerability_type or "", flag_verify_command or ""]
    parts.extend(str(item) for item in evidence or ())
    parts.extend(str(step.get("command", "")) for step in exploit_steps or ())
    return "\n".join(parts).lower()
