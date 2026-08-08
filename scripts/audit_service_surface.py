#!/usr/bin/env python3
"""Audit target/decoy service surfaces without invoking an Agent."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

import yaml

from clab_builder.orchestrator.composer.scenario_assembler import _surface_spec


PROBE_CODE = r'''
import json, socket, sys
host, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
result = {"host": host, "port": port, "path": path}
try:
    sock = socket.create_connection((host, port), 4)
    sock.settimeout(4)
    request = (
        "GET " + path + " HTTP/1.0\r\nHost: " + host
        + "\r\nConnection: close\r\n\r\n"
    )
    sock.sendall(request.encode())
    chunks = []
    while sum(len(item) for item in chunks) < 8192:
        try:
            item = sock.recv(2048)
        except socket.timeout:
            break
        if not item:
            break
        chunks.append(item)
    raw = b"".join(chunks)
    result.update({
        "reachable": True,
        "bytes": len(raw),
        "response": raw[:4096].decode("utf-8", "replace"),
    })
    sock.close()
except Exception as exc:
    result.update({"reachable": False, "error": str(exc), "response": ""})
print(json.dumps(result, ensure_ascii=True))
'''


def _run(command: list[str], cwd: Path | None = None, timeout: int = 300):
    return subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _lab_name(scenario_dir: Path) -> str:
    data = yaml.safe_load((scenario_dir / "clab.yaml").read_text()) or {}
    return str(data.get("name", scenario_dir.name))


def _source_by_zone(ground_truth: dict) -> dict[str, str]:
    result: dict[str, str] = {}
    source = "attacker"
    for step in ground_truth.get("attack_path", []) or []:
        zone = str(step.get("zone", ""))
        if zone and zone not in result:
            result[zone] = source
        source = str(step.get("target_node", source))
    return result


def _tokens(value: str) -> set[str]:
    return set(re.findall(r"[a-z0-9][a-z0-9._/-]{2,}", value.lower()))


def _similarity(left: str, right: str) -> float:
    a, b = _tokens(left), _tokens(right)
    if not a or not b:
        return 0.0
    return round(len(a & b) / len(a | b), 3)


def _probe(lab_name: str, source: str, ip: str, port: int, path: str) -> dict:
    container = f"clab-{lab_name}-{source}"
    result = _run([
        "docker", "exec", container, "python3", "-c", PROBE_CODE,
        ip, str(port), path,
    ], timeout=20)
    if result.returncode != 0:
        return {
            "reachable": False,
            "error": result.stderr.strip() or result.stdout.strip(),
            "response": "",
        }
    try:
        return json.loads(result.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {
            "reachable": False,
            "error": "probe returned invalid JSON: " + result.stdout[-500:],
            "response": "",
        }


def _profile_paths(profile: str) -> list[str]:
    if profile == "elasticsearch-http":
        return ["/", "/_cluster/health"]
    if profile == "solr-http":
        return ["/", "/solr/"]
    return ["/"]


def _surface_summary(target: dict, decoy: dict) -> dict:
    target_response = target.get("response", "")
    decoy_response = decoy.get("response", "")
    target_status = target_response.splitlines()[0] if target_response else ""
    decoy_status = decoy_response.splitlines()[0] if decoy_response else ""
    return {
        "target_reachable": bool(target.get("reachable")),
        "decoy_reachable": bool(decoy.get("reachable")),
        "same_status_line": target_status == decoy_status and bool(target_status),
        "response_token_similarity": _similarity(target_response, decoy_response),
    }


def _deploy(scenario_dir: Path, network: str, subnet: str) -> None:
    clab = scenario_dir / "clab.yaml"
    result = _run([
        "clab", "deploy", "-t", str(clab), "--network", network,
        "--ipv4-subnet", subnet,
    ], cwd=scenario_dir, timeout=900)
    if result.returncode != 0:
        raise RuntimeError(result.stderr[-4000:] or result.stdout[-4000:])

    lab = _lab_name(scenario_dir)
    inventory = scenario_dir / f"clab-{lab}" / "inventory" / "hosts.yaml"
    for playbook in ("base.yaml", "cve-setup.yaml"):
        command = ["ansible-playbook", str((scenario_dir / "ansible" / playbook).resolve())]
        if inventory.exists():
            command.extend(["-i", str(inventory.resolve())])
        result = _run(command, cwd=scenario_dir, timeout=600)
        if result.returncode != 0:
            raise RuntimeError(f"{playbook}: {result.stderr[-4000:]}")


def _cleanup(scenario_dir: Path) -> dict:
    result = _run([
        "clab", "destroy", "-t", str((scenario_dir / "clab.yaml").resolve()),
        "--cleanup", "--keep-mgmt-net",
    ], cwd=scenario_dir, timeout=300)
    return {"ok": result.returncode == 0, "stderr": result.stderr[-2000:]}


def audit(scenario_dir: Path, output: Path, deploy: bool, network: str, subnet: str) -> dict:
    ground_truth = json.loads((scenario_dir / "ground_truth.json").read_text())
    scenario = yaml.safe_load((scenario_dir / "scenario.yaml").read_text()) or {}
    injections = {
        item["node_name"]: item for item in scenario.get("injections", [])
    }
    lab_name = _lab_name(scenario_dir)
    source_by_zone = _source_by_zone(ground_truth)
    results = []
    deployed = False
    try:
        if deploy:
            _deploy(scenario_dir, network, subnet)
            deployed = True
        targets = {
            item["zone"]: item for item in ground_truth.get("attack_path", [])
        }
        decoys_by_zone: dict[str, list[dict]] = {}
        for item in ground_truth.get("noise_nodes", []) or []:
            decoys_by_zone.setdefault(item["zone"], []).append(item)
        for zone, target in targets.items():
            injection = injections.get(target["target_node"], {})
            spec = _surface_spec(injection)
            source = source_by_zone.get(zone, "attacker")
            port = int(target.get("exploit_port") or target["ports"][0])
            for path in _profile_paths(spec["profile"]):
                target_probe = _probe(lab_name, source, target["target_ip"], port, path)
                for decoy in decoys_by_zone.get(zone, []):
                    decoy_probe = _probe(lab_name, source, decoy["ip"], int(decoy["ports"][0]), path)
                    results.append({
                        "zone": zone,
                        "source": source,
                        "profile": spec["profile"],
                        "path": path,
                        "target": {
                            "node": target["target_node"],
                            "ip": target["target_ip"],
                            "probe": target_probe,
                        },
                        "decoy": {
                            "node": decoy["name"],
                            "ip": decoy["ip"],
                            "probe": decoy_probe,
                        },
                        "comparison": _surface_summary(target_probe, decoy_probe),
                    })
        report = {
            "scenario_dir": str(scenario_dir),
            "lab_name": lab_name,
            "deployed": deployed,
            "probe_count": len(results),
            "results": results,
        }
    finally:
        if deployed:
            report["cleanup"] = _cleanup(scenario_dir)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario-dir", required=True)
    parser.add_argument("--output", default="")
    parser.add_argument("--no-deploy", action="store_true")
    parser.add_argument("--network", default="cvelab-range-mgmt-v2")
    parser.add_argument("--ipv4-subnet", default="172.30.240.0/23")
    args = parser.parse_args()
    scenario_dir = Path(args.scenario_dir).resolve()
    output = Path(args.output).resolve() if args.output else scenario_dir / "surface_audit.json"
    report = audit(scenario_dir, output, not args.no_deploy, args.network, args.ipv4_subnet)
    print(json.dumps({"output": str(output), "probe_count": report["probe_count"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
