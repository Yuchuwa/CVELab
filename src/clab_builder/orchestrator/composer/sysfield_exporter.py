"""Export CVELab scenarios to SysField playbooks."""

import json
import re
from pathlib import Path
from typing import Any, Optional

import yaml

from clab_builder.orchestrator.composer.atom_loader import AtomLoader
from clab_builder.shared.models.atom import AtomConfig


_TEMPLATE_RE = re.compile(r"{{\s*([^{}\s]+)\s*}}")


def _slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]+", "-", value).strip("-").lower() or "step"


class SysFieldExporter:
    """Build a SysField-compatible playbook from a generated CVELab scenario."""

    def __init__(self, atoms_dir: str = "data/atoms"):
        self.atom_loader = AtomLoader(atoms_dir=atoms_dir)
        self.atoms_dir = Path(atoms_dir)

    def export(
        self,
        scenario_dir: str,
        output_file: Optional[str] = None,
        actor_node: str = "attacker",
    ) -> str:
        """Write a SysField playbook for an existing CVELab scenario directory."""
        scenario_path = Path(scenario_dir)
        ground_truth_path = scenario_path / "ground_truth.json"
        if not ground_truth_path.exists():
            raise FileNotFoundError(f"ground_truth.json not found in {scenario_dir}")

        ground_truth = json.loads(ground_truth_path.read_text())
        scenario_meta = self._load_scenario_meta(scenario_path)
        scenario_name = ground_truth.get("scenario") or scenario_path.name
        steps = []
        actors = {
            "attacker": {
                "node": actor_node,
                "description": "CVELab attacker node",
                "capabilities": ["network", "exploit"],
            }
        }

        previous_step_id = ""
        attack_path = ground_truth.get("attack_path", [])
        for index, target in enumerate(attack_path, start=1):
            cve_id = target["cve_id"]
            atom = self.atom_loader.load(cve_id)
            actor_id, step_actor_node = self._step_actor(index, attack_path, actor_node)
            actors.setdefault(actor_id, {
                "node": step_actor_node,
                "description": f"CVELab execution node {step_actor_node}",
                "capabilities": ["network", "exploit", "pivot"],
            })
            atom_steps = self._select_steps(atom, target, scenario_meta, step_actor_node)
            for sub_index, atom_step in enumerate(atom_steps, start=1):
                step_id = (
                    f"{index:02d}-{sub_index:02d}-{_slug(cve_id)}-"
                    f"{_slug(target['target_node'])}-{_slug(atom_step['id'])}"
                )
                output_path = f"/tmp/cvelab-sysfield/{step_id}.out"

                step = {
                    "id": step_id,
                    "stage": atom_step.get("stage") or atom.primary_mitre_phase.value,
                    "actor": actor_id,
                    "description": atom_step.get("description")
                    or (
                        f"Exploit {cve_id} against {target['target_node']} "
                        f"({target.get('target_ip', 'unknown')})"
                    ),
                    "mitre": atom_step.get("mitre") or self._mitre(atom),
                    "executor": {
                        "type": "direct",
                        "command": self._wrap_command(atom_step["command"], output_path),
                    },
                    "expected_output": {"exit_code": 0},
                    "postconditions": {
                        "files": [{"path": output_path, "op": "write"}],
                    },
                    "timeout": max(atom.service_startup.wait_seconds, 30),
                }
                if previous_step_id:
                    step["dependencies"] = [previous_step_id]
                steps.append(step)
                previous_step_id = step_id

        playbook = {
            "playbook": {
                "id": _slug(scenario_name),
                "name": f"CVELab {scenario_name}",
                "description": "Generated from CVELab scenario ground truth.",
                "scenario_type": "pentest",
                "author": "CVELab",
                "version": "1.0",
            },
            "monitor": {"preset": "standard"},
            "actors": actors,
            "steps": steps,
            "validation": {
                "success_criteria": [
                    {"step": step["id"], "condition": "exit_code", "value": 0}
                    for step in steps
                ],
                "failure_handling": {
                    "on_step_failure": "continue",
                    "max_retries": 0,
                    "retry_delay": 1,
                },
            },
        }

        out = Path(output_file) if output_file else scenario_path / "sysfield" / "playbook.yaml"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(yaml.dump(playbook, default_flow_style=False, sort_keys=False))
        return str(out)

    def _select_steps(
        self,
        atom: AtomConfig,
        target: dict[str, Any],
        scenario_meta: dict[str, Any],
        actor_node: str,
    ) -> list[dict[str, Any]]:
        atom_steps = self._extract_atom_sysfield_steps(atom.cve_id)
        rendered_steps = []
        for step in atom_steps:
            rendered = self._render_command(
                step["command"], atom, target, scenario_meta, actor_node
            )
            if self._has_unresolved_template(rendered):
                continue
            rendered_steps.append({**step, "command": rendered})
        if rendered_steps:
            return rendered_steps

        if atom.flag_verify_command:
            rendered = self._render_command(
                atom.flag_verify_command, atom, target, scenario_meta, actor_node
            )
            if not self._is_local_flag_probe(rendered):
                return [{
                    "id": "verify-flag-command",
                    "stage": atom.primary_mitre_phase.value,
                    "description": (
                        f"Run flag verification command for {atom.cve_id} "
                        f"against {target['target_node']}"
                    ),
                    "mitre": self._mitre(atom),
                    "command": rendered,
                }]

        target_ip = target.get("target_ip", "")
        port = self._target_port(atom)
        if target_ip and port:
            command = f"curl -fsS http://{target_ip}:{port}/ >/dev/null"
        elif target_ip:
            command = f"ping -c 1 {target_ip}"
        else:
            command = "true"
        return [{
            "id": "connectivity-check",
            "stage": atom.primary_mitre_phase.value,
            "description": (
                f"Check connectivity to {target['target_node']} "
                f"({target.get('target_ip', 'unknown')})"
            ),
            "mitre": self._mitre(atom),
            "command": command,
        }]

    def _extract_atom_sysfield_steps(self, cve_id: str) -> list[dict[str, Any]]:
        playbook_path = self.atoms_dir / cve_id / "playbook" / "sysfield.yaml"
        if not playbook_path.exists():
            return []
        data = yaml.safe_load(playbook_path.read_text()) or []
        steps = []
        for step in data.get("steps", []):
            executor = step.get("executor", {})
            command = executor.get("command")
            if isinstance(command, str):
                steps.append({
                    "id": step.get("id") or f"atom-step-{len(steps) + 1}",
                    "stage": step.get("stage"),
                    "description": step.get("description"),
                    "mitre": step.get("mitre"),
                    "command": self._unwrap_command(command),
                })
        return steps

    def _render_command(
        self,
        command: str,
        atom: AtomConfig,
        target: dict[str, Any],
        scenario_meta: dict[str, Any],
        actor_node: str,
    ) -> str:
        actor_ip = self._node_ip(scenario_meta, actor_node)
        values = {
            "target_ip": target.get("target_ip", ""),
            "target_port": str(self._target_port(atom)),
            "attacker_ip": actor_ip,
            "actor_ip": actor_ip,
            "listener_port": "1389",
            "lib_path": "/usr/lib/x86_64-linux-gnu/liblua5.1.so.0",
            "payload": "cat /flag.txt",
            "command": "cat /flag.txt",
            "command_to_execute": "cat /flag.txt",
        }

        def replace(match: re.Match) -> str:
            return values.get(match.group(1), match.group(0))

        return _TEMPLATE_RE.sub(replace, command)

    def _step_actor(
        self,
        index: int,
        attack_path: list[dict[str, Any]],
        actor_node: str,
    ) -> tuple[str, str]:
        if index == 1:
            return "attacker", actor_node
        previous_target = attack_path[index - 2]["target_node"]
        return _slug(previous_target), previous_target

    def _load_scenario_meta(self, scenario_path: Path) -> dict[str, Any]:
        scenario_meta = scenario_path / "scenario.yaml"
        if not scenario_meta.exists():
            return {}
        return yaml.safe_load(scenario_meta.read_text()) or {}

    def _node_ip(self, scenario_meta: dict[str, Any], node: str) -> str:
        node_alloc = scenario_meta.get("ip_allocations", {}).get(node, {})
        for key, value in node_alloc.items():
            if key.startswith("eth") and isinstance(value, str):
                return value.split("/", 1)[0]
        return ""

    def _unwrap_command(self, command: str) -> str:
        match = re.search(
            r"(?:^|\n)\((?P<body>.*)\)\s*>\s*/tmp/cvelab-sysfield/",
            command,
            flags=re.DOTALL,
        )
        if match:
            return match.group("body").strip()
        return command

    def _is_local_flag_probe(self, command: str) -> bool:
        return bool(re.search(r"(^|[;&|]\s*)echo\s+\$FLAG(\s|$)", command))

    def _target_port(self, atom: AtomConfig) -> int:
        return atom.ports[0] if atom.ports else 80

    def _has_unresolved_template(self, command: str) -> bool:
        return bool(_TEMPLATE_RE.search(command))

    def _wrap_command(self, command: str, output_path: str) -> str:
        return (
            "mkdir -p /tmp/cvelab-sysfield\n"
            f"({command}) > {output_path} 2>&1\n"
            "status=$?\n"
            f"cat {output_path}\n"
            "exit $status"
        )

    def _mitre(self, atom: AtomConfig) -> dict[str, str]:
        tactic = atom.primary_mitre_phase.value
        techniques = atom.mitre_mapping.get(tactic, [])
        technique = techniques[0] if techniques else ""
        return {
            "tactic": tactic,
            "technique": technique,
            "technique_name": technique or tactic,
        }
