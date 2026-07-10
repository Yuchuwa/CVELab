"""Runtime prechecks for deployed benchmark scenarios."""

import json
import subprocess
from pathlib import Path
from typing import Any

import yaml


class RuntimeValidator:
    """Validate that a deployed scenario is healthy before agent evaluation."""

    def __init__(self, scenario_dir: str, atoms_dir: str = "data/atoms"):
        self.scenario_path = Path(scenario_dir)
        self.atoms_dir = Path(atoms_dir)
        self.clab = yaml.safe_load((self.scenario_path / "clab.yaml").read_text())
        self.ground_truth = json.loads((self.scenario_path / "ground_truth.json").read_text())
        self.scenario_meta = self._load_yaml(self.scenario_path / "scenario.yaml")
        self.lab_name = self.clab.get("name", self.scenario_path.name)

    def validate(self) -> dict[str, Any]:
        checks = []
        checks.extend(self._check_containers())
        checks.extend(self._check_targets())
        checks.extend(self._check_attack_chain_connectivity())
        ok = all(check["success"] for check in checks if check.get("required", True))
        return {
            "success": ok,
            "scenario": self.ground_truth.get("scenario", self.lab_name),
            "checks": checks,
        }

    def _check_containers(self) -> list[dict[str, Any]]:
        checks = []
        for node in self.clab.get("topology", {}).get("nodes", {}):
            container = self._container_name(node)
            result = self._run(["docker", "inspect", container], timeout=10)
            checks.append({
                "name": f"container:{node}",
                "required": True,
                "success": result.returncode == 0,
                "details": self._details(result),
            })
        return checks

    def _check_targets(self) -> list[dict[str, Any]]:
        checks = []
        for step in self.ground_truth.get("attack_path", []):
            node = step["target_node"]
            container = self._container_name(node)
            checks.append(self._exec_check(
                node,
                "toolbox",
                "test -d /opt/toolbox && test -x /opt/toolbox/busybox",
                required=True,
            ))
            flag_path = "/flag.txt"
            if str(step.get("flag_hint", "")).startswith("file:"):
                flag_path = str(step["flag_hint"]).split(":", 1)[1]
            checks.append(self._exec_check(
                node,
                "flag",
                f"test -r {flag_path}",
                required=True,
            ))
            for port in self._target_ports(node):
                checks.append(self._exec_check(
                    node,
                    f"listen:{port}",
                    (
                        "if command -v ss >/dev/null 2>&1; then "
                        f"ss -ltn | grep -q ':{port} '; "
                        "else exit 0; fi"
                    ),
                    required=False,
                ))
        return checks

    def _check_attack_chain_connectivity(self) -> list[dict[str, Any]]:
        checks = []
        path = self.ground_truth.get("attack_path", [])
        for index, step in enumerate(path):
            source = "attacker" if index == 0 else path[index - 1]["target_node"]
            target_ip = step.get("target_ip", "")
            if not target_ip:
                continue
            source_container = self._container_name(source)
            command = f"ping -c 1 -W 2 {target_ip} >/dev/null 2>&1"
            result = self._run([
                "docker", "exec", source_container, "sh", "-lc", command
            ], timeout=10)
            checks.append({
                "name": f"chain-reachability:{source}->{step['target_node']}",
                "required": True,
                "success": result.returncode == 0,
                "details": self._details(result),
            })
            for port in self._target_ports(step["target_node"], step.get("cve_id", "")):
                tcp_command = self._tcp_probe_command(target_ip, port)
                tcp_result = self._run([
                    "docker", "exec", source_container, "sh", "-lc", tcp_command
                ], timeout=10)
                checks.append({
                    "name": f"chain-service:{source}->{step['target_node']}:{port}",
                    "required": True,
                    "success": tcp_result.returncode == 0,
                    "details": self._details(tcp_result),
                })
        return checks

    def _exec_check(
        self,
        node: str,
        check_name: str,
        command: str,
        required: bool,
    ) -> dict[str, Any]:
        result = self._run([
            "docker", "exec", self._container_name(node), "sh", "-lc", command
        ], timeout=10)
        return {
            "name": f"{check_name}:{node}",
            "required": required,
            "success": result.returncode == 0,
            "details": self._details(result),
        }

    def _target_ports(self, node: str, cve_id: str = "") -> list[int]:
        ports = self.clab.get("topology", {}).get("nodes", {}).get(node, {}).get("ports", [])
        if not ports and cve_id:
            atom_yaml = self.atoms_dir / cve_id / "atom.yaml"
            if atom_yaml.exists():
                atom = yaml.safe_load(atom_yaml.read_text()) or {}
                ports = atom.get("ports", [])
        return [int(port) for port in ports if isinstance(port, int | str) and str(port).isdigit()]

    def _tcp_probe_command(self, ip: str, port: int) -> str:
        return (
            "if [ -x /opt/toolbox/busybox ]; then "
            f"/opt/toolbox/busybox nc -z -w 2 {ip} {port}; "
            "elif command -v nc >/dev/null 2>&1; then "
            f"nc -z -w 2 {ip} {port}; "
            "elif command -v bash >/dev/null 2>&1; then "
            f"timeout 3 bash -lc 'cat < /dev/null > /dev/tcp/{ip}/{port}'; "
            "else exit 1; fi"
        )

    def _container_name(self, node: str) -> str:
        return f"clab-{self.lab_name}-{node}"

    def _load_yaml(self, path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}
        return yaml.safe_load(path.read_text()) or {}

    def _run(self, cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as e:
            return subprocess.CompletedProcess(
                cmd,
                124,
                stdout=e.stdout or "",
                stderr=e.stderr or "timeout",
            )

    def _details(self, result: subprocess.CompletedProcess) -> dict[str, Any]:
        return {
            "returncode": result.returncode,
            "stdout": (result.stdout or "")[-1000:],
            "stderr": (result.stderr or "")[-1000:],
        }
