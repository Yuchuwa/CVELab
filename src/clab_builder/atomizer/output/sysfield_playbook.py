"""Generate SysField-native playbooks from CVELab atom data."""

import json
import re
from pathlib import Path
from typing import Any, Optional

import yaml


_TEMPLATE_RE = re.compile(r"{{\s*([^{}\s]+)\s*}}")
ALLOWED_TEMPLATE_VARIABLES = {
    "target_ip", "target_port", "attacker_ip", "actor_ip", "listener_port",
    "lib_path", "payload", "command", "command_to_execute", "key_path",
    "ssh_key", "poc_path",
}


def _slug(value: str, max_len: int = 0) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", value).strip("-").lower() or "step"
    if max_len and len(slug) > max_len:
        cut = slug.rfind("-", 0, max_len)
        slug = slug[:cut if cut > 0 else max_len].rstrip("-")
    return slug


def _literal(text: str) -> str:
    return text.strip() if text else "true"


# 命令质量校验：拦截不可执行的步骤
_CODE_FRAGMENT_RE = [
    re.compile(p) for p in [
        r"\.add_byte\(", r"transport\._send", r"\.exec_command\(",
        r"client\s*=\s*transport", r"message\s*=\s*paramiko",
        r"^import\s+(paramiko|socket)", r"sock\s*=\s*socket\.socket",
    ]
]
# 探索性命令（在 transcript 提取时过滤掉）——按行匹配，避免注释行绕过
_EXPLORE_LINE_RE = re.compile(
    r"^\s*(ls|cat|head|strings|xxd|which|find|grep|wc|file|docker|pwd|env|echo|stat|du|df|ps|id|whoami|uname)\s",
    re.MULTILINE,
)
_EXPLORE_VULHUB_RE = re.compile(r"\b(cat|ls|head|strings|xxd|grep|wc|file|find)\s+/vulhub\b")
# 工具/环境探索（按前缀，这些不会出现在多行命令首行以外）
_TOOL_EXPLORE_PREFIXES = (
    "apt ", "apt-get ", "pip install", "pip3 install", "gem install",
    "dpkg ", "locate ", "msfconsole ",
)
# 编译/构建命令（不是攻击步骤）
_BUILD_PREFIXES = (
    "gcc ", "g++ ", "make ", "cmake ", "go build", "cargo build",
)
# heredoc 多行命令不是单行可执行步骤
_HEREDOC_RE = re.compile(r"<<\s*['\"]?\w+['\"]?")


# 纯探测命令（不作为正式攻击步骤）——按行匹配，不只是开头
_RECON_LINE_RE = re.compile(
    r"^\s*nmap\s"  # 任何 nmap 行都是侦察/扫描，不作为 exploit step
    r"|^\s*(nc|netcat)\s+(-\S+\s+)*-z"  # nc -z / nc -zv 端口探测
    r"|^\s*(masscan|rustscan|nikto)\s",
    re.MULTILINE,
)


def _is_executable_command(command: str) -> bool:
    """判断命令是否是可直接执行的 shell 命令（非 Python 代码片段）。"""
    if not command or not command.strip():
        return False
    if command.lower().startswith(("use pexpect", "once inside", "then type ")):
        return False
    for pat in _CODE_FRAGMENT_RE:
        if pat.search(command):
            return False
    return True


def _is_recon_command(command: str) -> bool:
    """判断命令是否含纯侦察/端口探测行（不应作为正式攻击步骤）。

    按行匹配，避免命令前面带注释或多行 shell 时绕过开头检测。
    """
    return bool(_RECON_LINE_RE.search(command))


def _is_explore_command(command: str) -> bool:
    """判断 transcript 命令是否是探索性命令（提取时过滤掉）。

    按行匹配，避免命令前面带注释时绕过开头检测。
    """
    if "curl -s -o /dev/null" in command:
        return True
    if _EXPLORE_LINE_RE.search(command) or _EXPLORE_VULHUB_RE.search(command):
        return True
    stripped = command.strip()
    return stripped.startswith(_TOOL_EXPLORE_PREFIXES)


def _has_non_allowed_vars(command: str, declared: set[str]) -> set[str]:
    """返回命令里不在白名单也不在 declared 里的模板变量。"""
    found = {m.group(1) for m in _TEMPLATE_RE.finditer(command)}
    # target_ip/target_port 在 YAML 里写法可能带空格 {{ target_ip }}
    allowed = ALLOWED_TEMPLATE_VARIABLES | declared
    return {v for v in found if v not in allowed and not v.startswith("target")}


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
        transcript_path: Optional[str] = None,
    ) -> str:
        # 收集 dynamic_values 声明，用于质量校验
        declared_dyn: set[str] = set()
        for step in (exploit_steps or []):
            for key in (step.get("dynamic_values") or {}):
                declared_dyn.add(str(key).strip("{}").strip())

        # ── 数据源优先级：自报 → transcript → session ──
        # 1. 优先用 agent 自报的 exploit_steps，但要过质量校验
        steps = self._filter_quality_steps(exploit_steps or [], cve_id, declared_dyn)
        source = "agent-reported"
        # 2. 自报为空或全部不达标 → 回退 transcript 实际命令
        if not steps and transcript_path and Path(transcript_path).exists():
            raw = self.steps_from_transcript(transcript_path)
            steps = self._filter_quality_steps(raw, cve_id, declared_dyn)
            source = "transcript"
        # 3. transcript 也没有 → 回退 session.json
        if not steps and session_path and Path(session_path).exists():
            raw = self.steps_from_session(session_path)
            steps = self._filter_quality_steps(raw, cve_id, declared_dyn)
            source = "session"
        if not steps:
            raise ValueError(
                f"Atom {cve_id} has no usable exploit steps "
                f"(tried agent-reported, transcript, session)"
            )

        sysfield_steps = []
        dynamic_variables = {}
        previous_id = ""
        for index, step in enumerate(steps, start=1):
            command_text = str(step.get("command", "")).strip()
            command = self._render_command(
                command_text,
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
            for key, value in (step.get("dynamic_values") or {}).items():
                dynamic_variables[str(key).strip("{}").strip()] = value

        playbook = {
            "playbook": {
                "id": _slug(cve_id),
                "name": f"{cve_id} SysField Playbook",
                "description": f"Generated from CVELab atom ({vulnerability_type or 'unknown'}, source={source}).",
                "scenario_type": "pentest",
                "author": "CVELab",
                "version": "1.0",
                "mitre_attack": mitre_mapping or {},
            },
            "variables": {
                "target_ip": target_ip,
                "target_port": target_port,
                "requirements": requirements or {},
                "dynamic_values": dynamic_variables,
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

    @staticmethod
    def validate(text: str, *, require_steps: bool = True) -> dict[str, Any]:
        """Validate the persisted atom-level SysField contract."""
        try:
            data = yaml.safe_load(text) or {}
        except yaml.YAMLError as exc:
            raise ValueError(f"invalid SysField YAML: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("playbook"), dict):
            raise ValueError("SysField playbook.playbook is required")
        steps = data.get("steps")
        if not isinstance(steps, list) or (require_steps and not steps):
            raise ValueError("SysField atom playbook must contain at least one step")
        declared = set(ALLOWED_TEMPLATE_VARIABLES)
        dynamic = (data.get("variables") or {}).get("dynamic_values", {})
        if isinstance(dynamic, dict):
            declared.update(str(key) for key in dynamic)
        for index, step in enumerate(steps, start=1):
            if not isinstance(step, dict) or not step.get("id"):
                raise ValueError(f"SysField step {index} is missing id")
            executor = step.get("executor")
            if not isinstance(executor, dict) or not isinstance(executor.get("command"), str):
                raise ValueError(f"SysField step {step.get('id', index)} needs executor.command")
            unknown = sorted({
                match.group(1) for match in _TEMPLATE_RE.finditer(executor["command"])
                if match.group(1) not in declared
            })
            if unknown:
                raise ValueError(
                    f"SysField step {step['id']} contains unsupported template variable(s): "
                    + ", ".join(unknown)
                )
        return data

    def from_atom_dir(self, atom_dir: str) -> str:
        atom_path = Path(atom_dir)
        atom_data = yaml.safe_load((atom_path / "atom.yaml").read_text())
        exploit_steps = self._steps_from_ansible(atom_path / "playbook" / "exploit.yaml")
        session_path = atom_path / "session.json"
        transcript_path = atom_path / "agent_transcript.log"
        generated = self.generate(
            cve_id=atom_data["cve_id"],
            exploit_steps=exploit_steps,
            mitre_mapping=atom_data.get("mitre_mapping", {}),
            target_ip="{{ target_ip }}",
            target_port=(atom_data.get("ports") or [80])[0],
            vulnerability_type=atom_data.get("vulnerability_type", ""),
            requirements=atom_data.get("requirements", {}),
            session_path=str(session_path) if session_path.exists() else None,
            transcript_path=str(transcript_path) if transcript_path.exists() else None,
        )
        self.validate(generated)
        bundle = atom_data.get("source_bundle") or {}
        declared_materials = {
            Path(str(item)).name for item in bundle.get("poc_materials", [])
        }
        for reference in re.findall(r"/vulhub/([A-Za-z0-9_.-]+)", generated):
            if declared_materials and reference not in declared_materials:
                raise ValueError(
                    f"Atom {atom_data['cve_id']} references PoC material not present in source_bundle: {reference}"
                )
        return generated

    def write_atom_playbook(self, atom_dir: str, output_name: str = "sysfield.yaml") -> str:
        atom_path = Path(atom_dir)
        out = atom_path / "playbook" / output_name
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(self.from_atom_dir(str(atom_path)))
        return str(out)

    def _filter_quality_steps(
        self, steps: list[dict[str, Any]], cve_id: str, declared_dyn: set[str]
    ) -> list[dict[str, Any]]:
        """过滤出质量达标的步骤：命令非空、可执行、非 recon、无非白名单变量。

        保留 quality 达标的步骤；丢弃 recon（nmap/nc -z）和代码片段。
        对非白名单变量：丢弃该步骤（因为它无法被 Range exporter 解析）。
        """
        out: list[dict[str, Any]] = []
        for step in steps:
            command = str(step.get("command", "")).strip()
            if not command:
                continue
            if not _is_executable_command(command):
                continue
            if _is_recon_command(command):
                continue
            # 非白名单变量（且不在 dynamic_values 声明里）→ 丢弃
            if _has_non_allowed_vars(command, declared_dyn):
                continue
            out.append(step)
        return out

    def steps_from_session(self, session_path: str) -> list[dict[str, Any]]:
        raw = Path(session_path).read_text(encoding="utf-8", errors="replace")
        # session.json 可能是单个 JSON 数组，也可能是 JSONL（每行一个事件）。
        # 先尝试单文档；失败则按 JSONL 逐行解析。
        entries: list = []
        try:
            parsed = json.loads(raw)
            entries = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        steps = []
        for entry in entries:
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

    def steps_from_transcript(self, transcript_path: str) -> list[dict[str, Any]]:
        """从 agent_transcript.log 的 [Tool] Bash 行提取实际执行的命令。

        过滤探索性命令，IP 模板化为 {{ target_ip }}，只保留可执行攻击命令。
        """
        text = Path(transcript_path).read_text(encoding="utf-8", errors="replace")
        # [Tool] Bash: {"command": "...", "description": "..."}
        raw_cmds = re.findall(
            r'\[Tool\] Bash: \{[^}]*"command": "((?:[^"\\]|\\.)*)"[^}]*\}',
            text,
        )
        steps: list[dict[str, Any]] = []
        for raw in raw_cmds:
            # transcript 里命令的转义还原
            try:
                cmd = raw.encode("utf-8").decode("unicode_escape")
            except (UnicodeDecodeError, UnicodeEncodeError):
                cmd = raw
            # 去掉首尾的 shell 引号
            cmd = cmd.strip()
            if not cmd:
                continue
            # 过滤探索性命令
            if _is_explore_command(cmd) or _is_recon_command(cmd):
                continue
            # 过滤编译/构建命令
            if cmd.startswith(_BUILD_PREFIXES):
                continue
            # heredoc 多行命令：curl heredoc 是有效的 HTTP 攻击请求（如
            # multipart 上传构造完整 body），应保留；其他 heredoc（python/ruby
            # 多行脚本）不适合作为单步 playbook，过滤掉。
            if _HEREDOC_RE.search(cmd) and not cmd.startswith(("curl ", "curl\t")):
                continue
            # 过滤代码片段
            if not _is_executable_command(cmd):
                continue
            # 取第一行作为 name 线索
            first_line = cmd.split("\n", 1)[0][:60]
            steps.append({
                "name": _slug(first_line, max_len=40) or f"step-{len(steps)+1}",
                "description": first_line,
                "command": self._generalize_observed_command(cmd),
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
