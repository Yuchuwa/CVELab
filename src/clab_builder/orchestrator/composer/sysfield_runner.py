"""Small host-side wrapper for executing a generated SysField playbook."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

import yaml


class SysFieldRunner:
    """Execute a playbook against an already deployed ContainerLab topology."""

    def __init__(self, binary: str | None = None):
        self.binary = binary or os.environ.get(
            "SYSFIELD_BIN", "/home/hanlin/sysfield/dist/sysfield"
        )

    def run(
        self,
        scenario_dir: str,
        playbook_path: str | None = None,
        output_dir: str | None = None,
        timeout: int = 900,
    ) -> dict[str, Any]:
        scenario_path = Path(scenario_dir).resolve()
        clab_path = scenario_path / "clab.yaml"
        playbook = Path(playbook_path or scenario_path / "sysfield" / "playbook.yaml").resolve()
        if not clab_path.exists():
            return self._failure("clab.yaml not found")
        if not playbook.exists():
            return self._failure("Range SysField playbook not found")
        try:
            playbook_data = yaml.safe_load(playbook.read_text()) or {}
        except yaml.YAMLError as exc:
            return self._failure(f"Invalid Range SysField playbook: {exc}")
        if not isinstance(playbook_data.get("steps"), list) or not playbook_data["steps"]:
            return self._failure("Range SysField playbook has no executable steps")
        objective = playbook_data.get("reference_objective", {})
        if not isinstance(objective, dict) or not objective.get("step"):
            return self._failure("Range SysField playbook has no reference objective")
        if objective["step"] not in {step.get("id") for step in playbook_data["steps"] if isinstance(step, dict)}:
            return self._failure("Range SysField reference objective step is missing")
        topology_name = yaml.safe_load(clab_path.read_text()).get("name", "")
        if not topology_name:
            return self._failure("ContainerLab topology name is missing")
        result_dir = Path(output_dir or scenario_path / "sysfield" / "result").resolve()
        result_dir.mkdir(parents=True, exist_ok=True)

        command = [
            self.binary,
            "run",
            "-p", str(playbook),
            "--topology-name", str(topology_name),
            "--no-monitor",
            "--keep-topology",
            "-o", str(result_dir),
        ]
        try:
            result = subprocess.run(
                command,
                cwd=str(scenario_path),
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            return self._failure(f"SysField binary not found: {self.binary}", command=command)
        except subprocess.TimeoutExpired as exc:
            return self._failure(
                f"SysField execution timed out after {timeout}s",
                command=command,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
            )

        expected_step_ids = {
            step.get("id") for step in playbook_data["steps"]
            if isinstance(step, dict) and step.get("id")
        }
        step_results: dict[str, dict[str, Any]] = {}
        for line in result.stdout.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            step_id = event.get("step_id")
            status = event.get("status")
            if step_id and status in {"PASS", "FAIL"}:
                step_results[str(step_id)] = {
                    "status": status,
                    "exit_code": event.get("exit_code"),
                }

        ok = result.returncode == 0
        step_match = re.search(r"Steps:\s+(\d+)/(\d+)\s+succeeded", result.stdout)
        if not step_match:
            ok = False
        elif step_match.group(1) != step_match.group(2):
            ok = False
        if expected_step_ids and set(step_results) != expected_step_ids:
            ok = False
        if any(item["status"] != "PASS" for item in step_results.values()):
            ok = False
        objective_id = objective["step"]
        if step_results.get(objective_id, {}).get("status") != "PASS":
            ok = False
        return {
            "ok": ok,
            "returncode": result.returncode,
            "command": command,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "output_dir": str(result_dir),
            "steps_succeeded": int(step_match.group(1)) if step_match else None,
            "steps_total": int(step_match.group(2)) if step_match else None,
            "step_results": step_results,
        }

    @staticmethod
    def _failure(
        reason: str,
        *,
        command: list[str] | None = None,
        stdout: str = "",
        stderr: str = "",
    ) -> dict[str, Any]:
        return {
            "ok": False,
            "returncode": None,
            "command": command or [],
            "stdout": stdout,
            "stderr": stderr,
            "error": reason,
        }
