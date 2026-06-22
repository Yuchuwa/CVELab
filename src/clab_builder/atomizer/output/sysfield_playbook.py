"""Generate SysField-native playbooks from CVELab atom data."""

import json
import re
from pathlib import Path
from typing import Any, Optional

import yaml


_TEMPLATE_RE = re.compile(r"{{\s*([^{}\s]+)\s*}}")


def _slug(value: str, max_len: int = 0) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", value).strip("-").lower() or "step"
    if max_len and len(slug) > max_len:
        cut = slug.rfind("-", 0, max_len)
        slug = slug[:cut if cut > 0 else max_len].rstrip("-")
    return slug


def _literal(text: str) -> str:
    return text.strip() if text else "true"


class SysFieldPlaybookGenerator:
    """Generate SysField playbooks for single-CVE atoms."""

    def generate(
        self,
        cve_id: str,
        exploit_steps: list[dict[str, Any]],
        mitre_mapping: dict[str, list[str]],
        target_ip: str = "{{ target_ip }}",
        target_port: int = 80,
        vulnerability_type: str = "",
        requirements: Optional[dict[str, Any]] = None,
        session_path: Optional[str] = None,
    ) -> str:
        steps = exploit_steps or []
        if not steps and session_path:
            steps = self.steps_from_session(session_path)

        sysfield_steps = []
        previous_id = ""
        for index, step in enumerate(steps, start=1):
            command = self._render_command(
                step.get("command", "true"),
                target_ip=target_ip,
                target_port=target_port,
            )
            step_id = f"{index:02d}-{_slug(step.get('name', 'step'), max_len=40)}"
            mitre = self._mitre_for_step(step, mitre_mapping)
            sysfield_step = {
                "id": step_id,
                "stage": self._stage_for_step(mitre_mapping),
                "actor": "attacker",
                "description": step.get("description") or step.get("name") or f"Run {cve_id} step",
                "mitre": mitre,
                "executor": {
                    "type": "direct",
                    "command": command,
                },
                "expected_output": {"exit_code": 0},
                "timeout": 120,
            }
            if previous_id:
                sysfield_step["dependencies"] = [previous_id]
            sysfield_steps.append(sysfield_step)
            previous_id = step_id

        playbook = {
            "playbook": {
                "id": _slug(cve_id),
                "name": f"{cve_id} SysField Playbook",
                "description": f"Generated from CVELab atom ({vulnerability_type or 'unknown'}).",
                "scenario_type": "pentest",
                "author": "CVELab",
                "version": "1.0",
                "mitre_attack": mitre_mapping or {},
            },
            "variables": {
                "target_ip": target_ip,
                "target_port": target_port,
                "requirements": requirements or {},
            },
            "monitor": {"preset": "standard"},
            "actors": {
                "attacker": {
                    "node": "attacker",
                    "description": "CVELab attacker node",
                    "capabilities": ["network", "exploit"],
                }
            },
            "steps": sysfield_steps,
            "validation": {
                "success_criteria": [
                    {"step": step["id"], "condition": "exit_code", "value": 0}
                    for step in sysfield_steps
                ],
                "failure_handling": {
                    "on_step_failure": "continue",
                    "max_retries": 0,
                    "retry_delay": 1,
                },
            },
        }
        return yaml.dump(playbook, default_flow_style=False, sort_keys=False, allow_unicode=True)

    def from_atom_dir(self, atom_dir: str) -> str:
        atom_path = Path(atom_dir)
        atom_data = yaml.safe_load((atom_path / "atom.yaml").read_text())
        exploit_steps = self._steps_from_ansible(atom_path / "playbook" / "exploit.yaml")
        session_path = atom_path / "session.json"
        return self.generate(
            cve_id=atom_data["cve_id"],
            exploit_steps=exploit_steps,
            mitre_mapping=atom_data.get("mitre_mapping", {}),
            target_ip="{{ target_ip }}",
            target_port=(atom_data.get("ports") or [80])[0],
            vulnerability_type=atom_data.get("vulnerability_type", ""),
            requirements=atom_data.get("requirements", {}),
            session_path=str(session_path) if session_path.exists() else None,
        )

    def write_atom_playbook(self, atom_dir: str, output_name: str = "sysfield.yaml") -> str:
        atom_path = Path(atom_dir)
        out = atom_path / "playbook" / output_name
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(self.from_atom_dir(str(atom_path)))
        return str(out)

    def steps_from_session(self, session_path: str) -> list[dict[str, Any]]:
        data = json.loads(Path(session_path).read_text())
        steps = []
        for entry in data:
            message = entry.get("message", entry) if isinstance(entry, dict) else {}
            for block in message.get("content", []) or []:
                if not isinstance(block, dict):
                    continue
                if block.get("type") != "tool_use" or block.get("name") != "Bash":
                    continue
                tool_input = block.get("input", {})
                command = tool_input.get("command")
                if not command:
                    continue
                steps.append({
                    "name": tool_input.get("description") or f"Session command {len(steps) + 1}",
                    "description": tool_input.get("description", ""),
                    "command": self._generalize_observed_command(command),
                })
        return steps

    def _steps_from_ansible(self, playbook_path: Path) -> list[dict[str, Any]]:
        if not playbook_path.exists():
            return []
        data = yaml.safe_load(playbook_path.read_text()) or []
        steps = []
        for play in data if isinstance(data, list) else [data]:
            for task in play.get("tasks", []):
                command = task.get("ansible.builtin.shell") or task.get("shell")
                if not isinstance(command, str):
                    continue
                steps.append({
                    "name": task.get("name", f"Step {len(steps) + 1}"),
                    "description": self._description_from_tags(task.get("tags", [])),
                    "command": command,
                    "mitre_technique_id": self._technique_from_tags(task.get("tags", [])),
                })
        return steps

    def _render_command(self, command: str, target_ip: str, target_port: int) -> str:
        values = {
            "target_ip": str(target_ip),
            "target_port": str(target_port),
            "command": "cat /flag.txt",
            "command_to_execute": "cat /flag.txt",
        }

        def replace(match: re.Match) -> str:
            return values.get(match.group(1), match.group(0))

        return _literal(_TEMPLATE_RE.sub(replace, command))

    def _generalize_observed_command(self, command: str) -> str:
        return re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "{{ target_ip }}", command)

    def _stage_for_step(self, mitre_mapping: dict[str, list[str]]) -> str:
        return next(iter(mitre_mapping.keys()), "execution")

    def _mitre_for_step(self, step: dict[str, Any], mitre_mapping: dict[str, list[str]]) -> dict[str, str]:
        technique = step.get("mitre_technique_id") or ""
        tactic = self._stage_for_step(mitre_mapping)
        if not technique:
            techniques = mitre_mapping.get(tactic, [])
            technique = techniques[0] if techniques else ""
        return {
            "tactic": tactic,
            "technique": technique,
            "technique_name": technique or tactic,
        }

    def _technique_from_tags(self, tags: list[Any]) -> str:
        for tag in tags:
            if isinstance(tag, str) and re.fullmatch(r"T\d{4}(?:\.\d{3})?", tag):
                return tag
        return ""

    def _description_from_tags(self, tags: list[Any]) -> str:
        for tag in tags:
            if isinstance(tag, str) and tag.startswith("desc: "):
                return tag.removeprefix("desc: ")
        return ""
