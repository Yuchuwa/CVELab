"""Deterministically compose Range attack playbooks for SysField."""

import json
import base64
import re
import shlex
from pathlib import Path
from typing import Any, Optional

import yaml

from clab_builder.atomizer.output.sysfield_playbook import SysFieldPlaybookGenerator
from clab_builder.orchestrator.composer.atom_loader import AtomLoader
from clab_builder.shared.source_bundle import select_agent_materials
from clab_builder.shared.source_bundle import verify_material_hash
from clab_builder.shared.models.artifact_contracts import normalize_agent_context

_TEMPLATE_RE = re.compile(r"{{\s*([^{}\s]+)\s*}}")


def _slug(value: str, max_len: int = 0) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", value).strip("-").lower() or "step"
    if max_len and len(slug) > max_len:
        cut = slug.rfind("-", 0, max_len)
        slug = slug[:cut if cut > 0 else max_len].rstrip("-")
    return slug


class _Dumper(yaml.SafeDumper):
    pass


def _represent(dumper, value):
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|" if "\n" in value else None)


_Dumper.add_representer(str, _represent)


class SysFieldExporter:
    """Build a complete executable playbook; never fall back to connectivity probes."""

    def __init__(self, atoms_dir: str = "data/atoms"):
        self.atoms_dir = Path(atoms_dir)
        self.atom_loader = AtomLoader(atoms_dir=atoms_dir)

    def export(self, scenario_dir: str, output_file: Optional[str] = None, actor_node: str = "attacker") -> str:
        root = Path(scenario_dir)
        gt_path = root / "ground_truth.json"
        if not gt_path.exists():
            raise FileNotFoundError(f"ground_truth.json not found in {scenario_dir}")
        ground_truth = json.loads(gt_path.read_text())
        meta = self._load_meta(root)
        clab_path = root / "clab.yaml"
        clab_data = yaml.safe_load(clab_path.read_text()) or {} if clab_path.exists() else {}
        topology_nodes = clab_data.get("topology", {}).get("nodes", {})
        attack_path = ground_truth.get("attack_path", [])
        if not attack_path:
            raise ValueError("Range attack path is empty")

        actors = {"attacker": {
            "node": actor_node,
            "description": "CVELab attacker node",
            "capabilities": ["network", "exploit"],
        }}
        steps: list[dict[str, Any]] = []
        previous = ""
        last_actor = ""
        last_atom = None
        last_target = None

        for index, target in enumerate(attack_path, 1):
            cve_id = target["cve_id"]
            atom = self.atom_loader.load(cve_id)
            actor_id, actor_node_for_step = self._step_actor(
                index, target, attack_path, actor_node
            )
            actors.setdefault(actor_id, {
                "node": actor_node_for_step,
                "description": f"CVELab execution node {actor_node_for_step}",
                "capabilities": ["network", "exploit", "pivot"],
            })
            agent_context = self._agent_context(meta)
            self._validate_actor_materials(
                atom,
                target,
                actor_node_for_step,
                topology_nodes,
                agent_context,
            )
            for sub_index, atom_step in enumerate(self._select_steps(atom, target, meta, actor_node_for_step), 1):
                command = self._adapt_command(atom_step["command"], target)
                step_id = f"{index:02d}-{sub_index:02d}-{_slug(cve_id)}-{_slug(target['target_node'])}-{_slug(atom_step['id'], 30)}"
                step = {
                    "id": step_id,
                    "stage": atom_step.get("stage") or atom.primary_mitre_phase.value,
                    "actor": actor_id,
                    "description": atom_step.get("description") or f"Exploit {cve_id}",
                    "mitre": atom_step.get("mitre") or self._mitre(atom),
                    "executor": {"type": "direct", "command": command},
                    "expected_output": atom_step.get("expected_output", {"exit_code": 0}),
                    "timeout": atom_step.get("timeout") or max(atom.service_startup.wait_seconds, 30),
                    "source_atom": cve_id,
                    "injection_point": target.get("injection_point", ""),
                    "capability_grants": [
                        getattr(grant, "model_dump", lambda **_: {})(mode="json")
                        for grant in getattr(atom, "capability_grants", [])
                    ],
                    "exploit_access": getattr(
                        getattr(atom, "exploit_access", None),
                        "model_dump", lambda **_: {}
                    )(mode="json"),
                    "requirements": dict(getattr(atom, "requirements", {}) or {}),
                    "execution_host": target.get("execution_host", actor_node_for_step),
                    "logical_actor": actor_node_for_step,
                    "execution_adapter": target.get("execution_adapter"),
                }
                match_entry = next(
                    (item for item in (meta.get("match_report") or [])
                     if item.get("injection_point") == target.get("injection_point")
                     and item.get("cve_id") == cve_id),
                    None,
                )
                if match_entry:
                    step["match_report"] = match_entry
                if previous:
                    step["dependencies"] = [previous]
                steps.append(step)
                previous = step_id
            last_actor, last_atom, last_target = actor_id, atom, target

        objective = self._objective_step(last_atom, last_target, last_actor, previous, meta)
        steps.append(objective)
        scenario_name = ground_truth.get("scenario") or root.name
        playbook = {
            "playbook": {
                "id": _slug(scenario_name),
                "name": f"CVELab {scenario_name}",
                "description": "Generated deterministically from CVELab attack path.",
                "scenario_type": "pentest", "author": "CVELab", "version": "1.0",
            },
            "monitor": {"preset": "standard"},
            "actors": actors,
            "steps": steps,
            "reference_objective": {
                "step": objective["id"],
                "validation": objective.get("objective_validation", "reference_path"),
                "success_pattern": objective.get("success_pattern", ""),
            },
            "validation": {
                "success_criteria": [{"step": step["id"], "condition": "exit_code", "value": 0} for step in steps],
                "failure_handling": {"on_step_failure": "continue", "max_retries": 0, "retry_delay": 1},
            },
        }
        out = Path(output_file) if output_file else root / "sysfield" / "playbook.yaml"
        out.parent.mkdir(parents=True, exist_ok=True)
        rendered = yaml.dump(playbook, Dumper=_Dumper, default_flow_style=False, sort_keys=False, allow_unicode=True)
        SysFieldPlaybookGenerator.validate(rendered)
        out.write_text(rendered)
        return str(out)

    def _select_steps(self, atom, target, meta, actor_node):
        if not target.get("target_ip"):
            raise ValueError(f"Target IP is missing for {atom.cve_id}")
        if actor_node != "attacker" and not self._node_ip(meta, actor_node):
            raise ValueError(f"Actor node {actor_node} has no runtime IP allocation")
        steps = self._extract(atom.cve_id)
        if not steps:
            raise ValueError(f"Atom {atom.cve_id} has no executable SysField steps")
        rendered = []
        for step in steps:
            command = self._render(step["command"], atom, target, meta, actor_node)
            if _TEMPLATE_RE.search(command):
                raise ValueError(f"Unresolved template in {atom.cve_id} step {step['id']}: {command}")
            if self._non_executable(command):
                raise ValueError(f"Non-executable atom step {atom.cve_id}/{step['id']}")
            rendered.append({**step, "command": command})
        return rendered

    def _extract(self, cve_id):
        path = self.atoms_dir / cve_id / "playbook" / "sysfield.yaml"
        if not path.exists():
            raise ValueError(f"Atom {cve_id} is missing playbook/sysfield.yaml")
        data = SysFieldPlaybookGenerator.validate(path.read_text())
        result = []
        for step in data["steps"]:
            command = (step.get("executor") or {}).get("command")
            if isinstance(command, str):
                result.append({"id": step["id"], "stage": step.get("stage"), "description": step.get("description"), "mitre": step.get("mitre"), "command": self._unwrap(command), "expected_output": step.get("expected_output", {"exit_code": 0}), "timeout": step.get("timeout")})
        return result

    def _render(self, command, atom, target, meta, actor_node):
        values = {
            "target_ip": target.get("target_ip", ""),
            "target_port": str(target.get("target_port") or (atom.ports[0] if atom.ports else 80)),
            "attacker_ip": self._node_ip(meta, "attacker"),
            "actor_ip": self._node_ip(meta, actor_node),
            "listener_port": "1389", "lib_path": "/usr/lib/x86_64-linux-gnu/liblua5.1.so.0",
            "payload": "cat /flag.txt", "command": "cat /flag.txt", "command_to_execute": "cat /flag.txt",
        }
        agent_context = self._agent_context(meta)
        materials = select_agent_materials(atom, agent_context)
        declared_materials = list(
            getattr(getattr(atom, "source_bundle", None), "poc_materials", []) or []
        )
        selected_materials = set(materials)
        for material in declared_materials:
            if material in selected_materials:
                continue
            name = Path(material).name
            if f"/vulhub/{name}" in command or f"/vulhub/{atom.cve_id}__{name}" in command:
                raise ValueError(
                    f"Atom {atom.cve_id} command references material excluded by "
                    f"agent exposure profile: {material}"
                )
        for material in materials:
            if Path(material).is_absolute() or ".." in Path(material).parts:
                raise ValueError(f"Atom {atom.cve_id} has an unsafe PoC material path: {material}")
            src = self.atoms_dir / atom.cve_id / material
            if not src.is_file():
                raise ValueError(f"Atom {atom.cve_id} declares missing PoC material: {material}")
            material_name = Path(material).name
            material_is_referenced = (
                f"/vulhub/{material_name}" in command
                or f"/vulhub/{atom.cve_id}__{material_name}" in command
                or "{{poc_path}}" in command
                and Path(material_name).suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".py", ".sh"}
            )
            bundle_hashes = getattr(getattr(atom, "source_bundle", None), "hashes", {}) or {}
            if material_is_referenced and bundle_hashes and not verify_material_hash(
                atom, self.atoms_dir / atom.cve_id, material
            ):
                raise ValueError(f"Atom {atom.cve_id} material hash mismatch: {material}")
            name = material_name
            mounted = f"/vulhub/{atom.cve_id}__{name}"
            if "id_rsa" in name or "id_dsa" in name or "id_ed25519" in name:
                values.update({"key_path": "/tmp/" + name, "ssh_key": "/tmp/" + name})
            if Path(name).suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".py", ".sh"}:
                # poc_path 映射到第一个 PoC 材料（图片或可执行脚本）。
                # setdefault 确保多个材料时只用第一个（poc_materials 已排序，
                # 真正的攻击 payload 排在依赖文件前面）。
                values.setdefault("poc_path", mounted)
            command = re.sub(rf"(?<![A-Za-z0-9_/-])/vulhub/{re.escape(name)}(?![A-Za-z0-9_.-])", mounted, command)
        return _TEMPLATE_RE.sub(lambda m: values.get(m.group(1), m.group(0)), command)

    def _objective_step(self, atom, target, actor, previous, meta):
        objectives = meta.get("objectives") or []
        objective = objectives[-1] if objectives else {
            "validation": "atom_flag",
            "reference_command": getattr(atom, "flag_verify_command", ""),
            "success_pattern": "",
        }
        command = objective.get("reference_command")
        if not command:
            raise ValueError(
                "Range objective must declare an executable reference_command; "
                "falling back to the last Atom flag command is not allowed"
            )
        command = self._render(command, atom, target, meta, actor)
        if _TEMPLATE_RE.search(command) or self._non_executable(command) or re.search(r"(^|[;&|]\s*)echo\s+\$FLAG(\s|$)", command):
            raise ValueError("Final objective is not executable from the reference actor")
        pattern = objective.get("success_pattern") or ""
        if objectives and not pattern:
            raise ValueError(
                "Range objective must declare a non-empty success_pattern"
            )
        if pattern:
            command = "tmp=/tmp/cvelab-objective.$$; (" + command + ") > \"$tmp\" 2>&1; status=$?; if [ $status -ne 0 ]; then cat \"$tmp\"; rm -f \"$tmp\"; exit $status; fi; cat \"$tmp\"; grep -F -- " + shlex.quote(str(pattern)) + " \"$tmp\"; status=$?; rm -f \"$tmp\"; exit $status"
        step = {"id": "99-objective-" + _slug(objective.get("validation", "reference-path")), "stage": "objective", "actor": actor, "description": objective.get("validation", "Verify final objective"), "mitre": self._mitre(atom), "executor": {"type": "direct", "command": command}, "expected_output": {"exit_code": 0}, "timeout": max(atom.service_startup.wait_seconds, 30), "objective_validation": objective.get("validation", "reference_path"), "success_pattern": pattern, "source_atom": atom.cve_id}
        if previous:
            step["dependencies"] = [previous]
        return step

    def _step_actor(self, index, target, attack_path, actor_node):
        if index == 1:
            return "attacker", actor_node
        execution_host = target.get("execution_host")
        if not execution_host or execution_host == "attacker":
            return "attacker", actor_node

        # A dependent step must declare how its command is executed from the
        # upstream foothold.  Without this contract, mapping the step directly
        # to a pre-created target/pivot container would be a false foothold.
        adapter = target.get("execution_adapter")
        if not adapter:
            raise ValueError(
                f"Attack step {target.get('step', index)} requires execution_adapter "
                f"for upstream host {execution_host}"
            )
        self._validate_execution_adapter(adapter, target)

        slot_to_node = {
            item.get("injection_point"): item.get("target_node")
            for item in attack_path
        }
        node = slot_to_node.get(execution_host, execution_host)
        return _slug(node), node

    @staticmethod
    def _validate_execution_adapter(adapter: Any, target: dict[str, Any]) -> dict[str, Any]:
        """Validate the small stateless adapter contract used by Range export."""
        if not isinstance(adapter, dict):
            raise ValueError(
                f"Attack step {target.get('step', '?')} has an invalid execution_adapter"
            )
        if adapter.get("mode") != "stateless":
            raise ValueError(
                f"Attack step {target.get('step', '?')} requires a stateless "
                "execution_adapter; session adapters are not yet executable"
            )
        if adapter.get("verified") is not True:
            raise ValueError(
                f"Attack step {target.get('step', '?')} execution_adapter is not verified"
            )
        template = adapter.get("command_template")
        if not isinstance(template, str) or not template.strip():
            raise ValueError(
                f"Attack step {target.get('step', '?')} execution_adapter has no command_template"
            )
        if "{{command}}" not in template and "{{command_b64}}" not in template:
            raise ValueError(
                f"Attack step {target.get('step', '?')} execution_adapter must expose "
                "{{command}} or {{command_b64}}"
            )
        return adapter

    def _adapt_command(self, command: str, target: dict[str, Any]) -> str:
        """Run a dependent atom step through the upstream foothold contract."""
        execution_host = target.get("execution_host")
        if not execution_host or execution_host == "attacker":
            return command
        adapter = self._validate_execution_adapter(target.get("execution_adapter"), target)
        template = adapter["command_template"]
        if "{{command_b64}}" in template:
            encoded = base64.b64encode(command.encode()).decode()
            rendered = template.replace("{{command_b64}}", encoded)
        else:
            rendered = template.replace("{{command}}", shlex.quote(command))
        if _TEMPLATE_RE.search(rendered):
            raise ValueError(
                f"Attack step {target.get('step', '?')} execution_adapter leaves unresolved variables"
            )
        if self._non_executable(rendered):
            raise ValueError(
                f"Attack step {target.get('step', '?')} execution_adapter produced a non-executable command"
            )
        return rendered

    def _validate_actor_materials(
        self, atom, target, actor_node, topology_nodes, agent_context="guided"
    ):
        """Fail before SysField when a local actor cannot see executed PoC files."""
        materials = select_agent_materials(atom, agent_context)
        if not materials:
            return
        if target.get("material_staging"):
            return
        required = self._required_actor_material_mounts(atom, materials)
        if not required:
            return
        node = topology_nodes.get(actor_node, {}) or {}
        binds = [str(item) for item in node.get("binds", [])]
        missing = []
        for mounted in required:
            if not any(mounted in bind for bind in binds):
                missing.append(mounted)
        if missing:
            raise ValueError(
                f"Atom {atom.cve_id} materials are not available on actor {actor_node}: "
                + ", ".join(missing)
            )

    @staticmethod
    def _agent_context(meta: dict[str, Any]) -> str:
        profile = meta.get("agent_exposure_profile") or {}
        profile_context = profile.get("context") if isinstance(profile, dict) else None
        raw_context = meta.get("agent_context")
        if profile_context and raw_context:
            if normalize_agent_context(raw_context) != normalize_agent_context(profile_context):
                raise ValueError("scenario agent_context disagrees with pinned exposure profile")
        return normalize_agent_context(profile_context or raw_context or "guided")

    def _required_actor_material_mounts(self, atom, materials: list[str]) -> list[str]:
        """Return source_bundle materials actually referenced by SysField commands."""
        commands = [
            str(step.get("command", ""))
            for step in self._extract(atom.cve_id)
        ]
        required: list[str] = []
        for material in materials:
            name = Path(material).name
            mounted = f"/vulhub/{atom.cve_id}__{name}"
            if any(
                mounted in command
                or f"/vulhub/{name}" in command
                or material in command
                or f"source_bundle/{name}" in command
                for command in commands
            ):
                required.append(mounted)

        if any("{{poc_path}}" in command for command in commands):
            for material in materials:
                name = Path(material).name
                if Path(name).suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".py", ".sh"}:
                    mounted = f"/vulhub/{atom.cve_id}__{name}"
                    if mounted not in required:
                        required.append(mounted)
                    break
        return required

    def _load_meta(self, root):
        path = root / "scenario.yaml"
        return yaml.safe_load(path.read_text()) or {} if path.exists() else {}

    def _node_ip(self, meta, node):
        for key, value in (meta.get("ip_allocations", {}).get(node, {}) or {}).items():
            if key.startswith("eth") and isinstance(value, str):
                return value.split("/", 1)[0]
        return ""

    @staticmethod
    def _unwrap(command):
        match = re.search(r"(?:^|\n)\((?P<body>.*)\)\s*>\s*/tmp/cvelab-sysfield/", command, flags=re.DOTALL)
        return match.group("body").strip() if match else command

    @staticmethod
    def _non_executable(command):
        text = command.strip().lower()
        if text.startswith(("use pexpect", "once inside", "then type ", "type '!")):
            return True
        if text.startswith(("ping ", "true", ": ", "nmap ")):
            return True
        if re.search(r"\bnc\s+(-z|-zv)\b", text):
            return True
        return "in the less pager" in text

    @staticmethod
    def _mitre(atom):
        tactic = atom.primary_mitre_phase.value
        technique = (atom.mitre_mapping.get(tactic) or [""])[0]
        return {"tactic": tactic, "technique": technique, "technique_name": technique or tactic}
