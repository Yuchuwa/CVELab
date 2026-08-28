"""Security Researcher Agent - 容器生命周期管理

职责：启动/停止 Agent 容器，传递输入，执行 agent_runner.py，收集输出。
Agent 使用 Claude Agent SDK，自带 Bash/Read/Write 工具。
"""

import subprocess
import json
import os
import shutil
import time
import uuid
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass

# agent_runner.py 在本包内的路径
AGENT_RUNNER_SRC = Path(__file__).parent / "agent_runner.py"
OPENAI_AGENT_RUNNER_SRC = Path(__file__).parent / "openai_agent_runner.py"


def _uses_openai_protocol(model: str) -> bool:
    """Decide which agent harness + protocol a model needs.

    Models exposed only via the OpenAI-compatible /v1 endpoint (and not the
    Anthropic/Claude protocol) must use the openai_agent_runner. GLM-5.x is
    the current case; DeepSeek and Anthropic models keep the claude_agent_sdk
    harness. The check is by name prefix so it covers glm-5.2 / z-ai/glm-5.2
    / glm-5.1 etc.
    """
    m = (model or "").lower()
    return m.startswith("glm-") or "glm-5" in m or m.startswith("z-ai/glm")


@dataclass
class CVEInput:
    """Agent 输入"""
    cve_id: str
    description: str
    target_ip: str
    target_ports: List[int]
    writeup: str = ""
    exploit_files: Dict[str, str] = None  # filename → content
    flag_hint: str = ""  # where the flag lives on the target (location only, NOT the value)
    environment_context: Dict[str, Any] = None
    exploit_guidance: str = ""
    role: str = "exploiter"
    foothold_context: Dict[str, Any] = None

    def __post_init__(self):
        if self.exploit_files is None:
            self.exploit_files = {}
        if self.environment_context is None:
            self.environment_context = {}
        if self.foothold_context is None:
            self.foothold_context = {}


@dataclass
class AgentOutput:
    """Agent 输出"""
    cve_id: str
    success: bool
    exploit_steps: List[Dict[str, Any]]
    evidence: List[str]
    mitre_mapping: Dict[str, List[str]]
    exploit_guide: Dict[str, Any] | None = None
    vulnerability_type: str = ""
    captured_flag: str = ""  # flag value the agent retrieved from the target
    requirements: Dict[str, Any] = None
    # v2 额外字段（agent 明确输出时优先，缺失时 pipeline 走推断）
    extra_fields: Dict[str, Any] = None
    probe_evidence: List[Dict[str, Any]] = None

    def __post_init__(self):
        if self.requirements is None:
            self.requirements = {}
        if self.extra_fields is None:
            self.extra_fields = {}
        if self.probe_evidence is None:
            self.probe_evidence = []


class SecurityResearcherAgent:
    """Agent 容器生命周期管理器"""

    def __init__(
        self,
        agent_image: str = "clab-agent:latest",
        max_turns: int = 80,
        agent_timeout: int = 900,
    ):
        self.agent_image = agent_image
        self.max_turns = max_turns
        self.agent_timeout = agent_timeout
        self.container_id: str | None = None
        self.container_name = f"agent-{uuid.uuid4().hex[:8]}"
        self.model: str = ""  # set by start(); read by run() to pick the harness

    def start(self, network_name: str, workspace_dir: str,
              api_key: str, base_url: str = "", model: str = "") -> str:
        """
        启动 Agent 容器

        Args:
            network_name: Docker 网络名（与 CVE 目标同一网络）
            workspace_dir: 宿主机工作目录（挂载到 /workspace）
            api_key: LLM API key (ANTHROPIC_API_KEY)
            base_url: LLM API base URL
            model: LLM model name

        Returns:
            container_id
        """
        self.model = model
        # Remove any container left by a previous timed-out create/start call.
        self._remove_container_by_name(timeout=10)

        workspace_dir = str(Path(workspace_dir).resolve())
        agent_runner_src = str(AGENT_RUNNER_SRC.resolve())
        openai_runner_src = str(OPENAI_AGENT_RUNNER_SRC.resolve())
        # 挂载一个宿主目录到容器内 ~/.claude，让 Claude Agent SDK 原生 session
        # （.jsonl，含 tool-result/sidechain 等全部事件）落盘到宿主，供回捞保存
        claude_cache_dir = str((Path(workspace_dir) / ".claude_cache").resolve())
        Path(claude_cache_dir).mkdir(parents=True, exist_ok=True)
        # 容器内 agent 用户 (uid 1000) 与宿主用户 uid 不同，挂载目录必须
        # world-writable 才能让 SDK 在 /home/agent/.claude 下创建 session-env
        # 等运行时目录，否则 EACCES 中断每次工具调用。
        os.chmod(claude_cache_dir, 0o777)

        use_openai = _uses_openai_protocol(model)
        runner_src = openai_runner_src if use_openai else agent_runner_src

        cmd = [
            "docker", "run", "-d",
            f"--name={self.container_name}",
            f"--network={network_name}",
            "--cap-add", "NET_RAW",
            "--cap-add", "NET_ADMIN",
            # 挂载 workspace（input.json/output.json）
            "-v", f"{workspace_dir}:/workspace",
            # 挂载 agent_runner.py（按协议选择）
            "-v", f"{runner_src}:/opt/agent_runner.py:ro",
            # openai_agent_runner 导入 agent_runner 的纯函数 helper，两个都挂上
            "-v", f"{agent_runner_src}:/opt/agent_runner_lib.py:ro",
            # 挂载 ~/.claude 缓存：SDK 原生 session .jsonl 落盘到这里
            "-v", f"{claude_cache_dir}:/home/agent/.claude",
            "-e", "CLAUDE_CONFIG_DIR=/home/agent/.claude",
            "-e", "HOME=/home/agent",
            # API key: both protocols read it; set the env var each harness expects.
            "-e", f"ANTHROPIC_API_KEY={api_key}",
            "-e", f"OPENAI_API_KEY={api_key}",
            "-e", f"LLM_API_KEY={api_key}",
        ]
        if base_url:
            # Anthropic harness reads ANTHROPIC_BASE_URL; openai harness reads
            # OPENAI_BASE_URL (and falls back to LLM_BASE_URL). Set both so the
            # selected runner finds its endpoint without branching here.
            cmd.extend(["-e", f"ANTHROPIC_BASE_URL={base_url}"])
            cmd.extend(["-e", f"OPENAI_BASE_URL={base_url}"])
            cmd.extend(["-e", f"LLM_BASE_URL={base_url}"])
        if model:
            cmd.extend(["-e", f"MODEL={model}"])

        cmd.append(self.agent_image)

        print(f"Starting agent container: {self.agent_image}")
        last_error = ""
        result = None
        for attempt in range(1, 4):
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=60,
                )
            except subprocess.TimeoutExpired:
                last_error = "docker run timed out after 60 seconds"
                adopted = self._adopt_started_container()
                if adopted:
                    return adopted
            else:
                if result.returncode == 0:
                    break
                last_error = (result.stderr or result.stdout or "").strip()
                if "already in use" in last_error.lower():
                    adopted = self._adopt_started_container()
                    if adopted:
                        return adopted
                else:
                    break

            self._remove_container_by_name(timeout=15)
            time.sleep(attempt)
        else:
            result = None

        if result is None or result.returncode != 0:
            raise RuntimeError(f"Failed to start agent container: {last_error}")

        self.container_id = result.stdout.strip()
        print(f"Agent container started: {self.container_id[:12]}")
        return self.container_id

    def _adopt_started_container(self) -> str | None:
        """Recover a container created by a docker run whose client call timed out."""
        for attempt in range(3):
            try:
                inspected = subprocess.run(
                    [
                        "docker", "inspect", self.container_name,
                        "--format", "{{.Id}}\t{{.State.Status}}",
                    ],
                    capture_output=True, text=True, timeout=10,
                )
            except subprocess.TimeoutExpired:
                inspected = None

            if inspected is not None and inspected.returncode == 0:
                container_id, _, status = inspected.stdout.strip().partition("\t")
                if status == "created":
                    try:
                        started = subprocess.run(
                            ["docker", "start", self.container_name],
                            capture_output=True, text=True, timeout=30,
                        )
                    except subprocess.TimeoutExpired:
                        started = None
                    if started is not None and started.returncode == 0:
                        status = "running"
                if status == "running" and container_id:
                    self.container_id = container_id
                    print(f"Agent container recovered: {container_id[:12]}")
                    return container_id

            if attempt < 2:
                time.sleep(attempt + 1)
        return None

    def _remove_container_by_name(self, timeout: int = 30) -> bool:
        """Remove the named Agent even when start never returned a container id."""
        for attempt in range(3):
            try:
                result = subprocess.run(
                    ["docker", "rm", "-f", self.container_name],
                    capture_output=True, text=True, timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                result = None

            if result is not None:
                message = ((result.stderr or "") + (result.stdout or "")).lower()
                if result.returncode == 0 or "no such container" in message:
                    self.container_id = None
                    return True
            if attempt < 2:
                time.sleep(attempt + 1)
        return False

    def run(self, cve_input: CVEInput, workspace_dir: str) -> AgentOutput:
        """
        执行 Agent 任务

        1. 写 input.json 到 workspace
        2. docker exec 运行 agent_runner.py
        3. 读 output.json
        """
        workspace = Path(workspace_dir).resolve()

        # 写入输入
        input_data = {
            "cve_id": cve_input.cve_id,
            "description": cve_input.description,
            "target_ip": cve_input.target_ip,
            "target_ports": cve_input.target_ports,
            "writeup": cve_input.writeup,
            "exploit_files": cve_input.exploit_files,
            "flag_hint": cve_input.flag_hint,
            "environment_context": cve_input.environment_context,
            "exploit_guidance": cve_input.exploit_guidance,
            "role": cve_input.role,
            "foothold_context": cve_input.foothold_context,
        }
        input_path = workspace / "input.json"
        input_path.write_text(json.dumps(input_data, ensure_ascii=False, indent=2))

        output_path = workspace / "output.json"

        # Never let a failed retry (or a second role such as Explorer) read a
        # previous role's result.  The runner writes this file only after it
        # has completed; removing it makes an absent/partial result explicit.
        # A fresh Exploiter workspace is already cleaned by AtomizerPipeline.
        # Explorer runs in that same workspace, so only Explorer must remove
        # the prior role's result before launching its runner.  Keeping the
        # legacy Exploiter behavior also makes the lightweight runner mock
        # used by downstream integrations backwards compatible.
        if cve_input.role != "exploiter":
            output_path.unlink(missing_ok=True)
            (workspace / "session.json").unlink(missing_ok=True)

        # 执行 agent_runner.py（挂载在 /opt/agent_runner.py）
        # 实时流式输出 Agent 的 stderr（进度信息）
        print(f"Running agent for {cve_input.cve_id} (max_turns={self.max_turns})...")
        stderr_chunks = []
        # The OpenAI-protocol runner needs the openai SDK, which the clab-agent
        # image does not ship. Install it once before launching the runner.
        # This is a no-op for the claude_agent_sdk runner path.
        if _uses_openai_protocol(self.model):
            install = subprocess.run(
                ["docker", "exec", self.container_name,
                 "pip3", "install", "--quiet", "--disable-pip-version-check", "openai"],
                capture_output=True, text=True, timeout=120,
            )
            if install.returncode != 0:
                print(f"  [setup] pip install openai failed: {(install.stderr or '')[:200]}")
        try:
            proc = subprocess.Popen(
                [
                    "docker", "exec",
                    self.container_name,
                    "python3", "/opt/agent_runner.py",
                    "--input", "/workspace/input.json",
                    "--output", "/workspace/output.json",
                    "--max-turns", str(self.max_turns),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            # 实时读取 stderr 并打印
            import threading

            def read_stderr():
                for line in proc.stderr:
                    stderr_chunks.append(line)
                    print(line, end="", flush=True)

            reader = threading.Thread(target=read_stderr, daemon=True)
            reader.start()

            # 墙钟上限：max_turns=80 正常约 12 分钟（170 次 API 调用 × ~4s）。
            # 15 分钟足够跑满 80 turns 的慢任务，超时后 self.stop() 强制终止容器。
            wall_timeout = self.agent_timeout
            proc.wait(timeout=wall_timeout)
            reader.join(timeout=5)

        except subprocess.TimeoutExpired:
            # proc.kill() 只杀宿主侧的 docker exec 进程，容器内的 claude/agent_runner
            # 子进程仍会继续烧 token。必须 docker rm -f 容器才能真正终止 agent。
            proc.kill()
            stderr_chunks.append(f"Agent timed out after {wall_timeout}s")
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            self._recover_native_session(workspace)
            if not self.stop(timeout=30):
                stderr_chunks.append(
                    f"\nWarning: timed out removing agent container {self.container_name}; "
                    "it may require manual docker cleanup."
                )

        self._recover_native_session(workspace)
        returncode = proc.returncode if proc.returncode is not None else -1
        stderr_text = "".join(stderr_chunks)

        if returncode != 0:
            print(f"Agent exited with code {returncode}")
            if not output_path.exists():
                # agent 被强杀（SIGKILL/超时）时 output.json 可能没写成功，
                # 但 SDK 原生 session .jsonl 里通常已有最终 JSON。尝试恢复，
                # 否则像 CVE-2017-8386 这样 agent 实际成功却因 -9 被判失败。
                from clab_builder.atomizer.agent.agent_runner import (
                    _extract_json_from_native_session,
                )
                recovered = _extract_json_from_native_session(workspace / "session.json")
                if recovered is not None:
                    output_path.write_text(
                        json.dumps(recovered, ensure_ascii=False, indent=2)
                    )
                    print(f"Recovered agent output from native session: {output_path}")
                else:
                    return AgentOutput(
                        cve_id=cve_input.cve_id,
                        success=False,
                        exploit_steps=[],
                        exploit_guide=None,
                        evidence=[f"Agent failed (code={returncode}): {stderr_text[:500]}"],
                        mitre_mapping={},
                    )

        # 读取输出
        try:
            output_data = json.loads(output_path.read_text())
        except (json.JSONDecodeError, FileNotFoundError) as e:
            return AgentOutput(
                cve_id=cve_input.cve_id,
                success=False,
                exploit_steps=[],
                exploit_guide=None,
                evidence=[f"Failed to read agent output: {e}"],
                mitre_mapping={},
            )

        print(f"Agent finished: success={output_data.get('success')}")

        return AgentOutput(
            cve_id=cve_input.cve_id,
            success=output_data.get("success", False),
            exploit_steps=output_data.get("exploit_steps", []),
            exploit_guide=output_data.get("exploit_guide"),
            evidence=output_data.get("evidence", []),
            mitre_mapping=output_data.get("mitre_mapping", {}),
            vulnerability_type=output_data.get("vulnerability_type", ""),
            captured_flag=output_data.get("captured_flag", ""),
            requirements=output_data.get("requirements", {}),
            probe_evidence=output_data.get("probe_evidence", []),
            extra_fields={
                k: output_data[k]
                for k in [
                    "vuln_category", "primary_mitre_phase", "service_role",
                    "exploit_complexity", "attack_method",
                    "needs_callback", "callback_type", "needs_ssh", "needs_tool_download",
                    "default_username", "default_password",
                    "flag_verify_command", "health_check", "init_tasks",
                    "captured_flag",
                    "exploit_principal", "exploit_access", "capability_grants",
                    "exploit_guide",
                    "probe_evidence",
                ]
                if k in output_data
            },
        )

    @staticmethod
    def _recover_native_session(workspace: Path) -> Path | None:
        """Recover the SDK JSONL when agent_runner exits before copying it."""
        session_path = workspace / "session.json"
        if session_path.exists():
            return session_path

        projects_dir = workspace / ".claude_cache" / "projects"
        if not projects_dir.is_dir():
            return None

        candidates = list(projects_dir.rglob("*.jsonl"))
        if not candidates:
            return None

        source = max(candidates, key=lambda path: path.stat().st_mtime_ns)
        shutil.copy2(source, session_path)
        print(f"Recovered native Agent session: {session_path}")
        return session_path

    def stop(self, timeout: int = 30) -> bool:
        """停止并移除容器。

        Docker can occasionally block while removing a container that has an
        active exec session. Cleanup must be best-effort so it does not mask the
        real agent failure reason.
        """
        had_container = bool(self.container_id)
        if self._remove_container_by_name(timeout=timeout):
            if had_container:
                print("Agent container stopped")
            return True

        print(
            f"Warning: failed to remove agent container "
            f"{self.container_name} after retries"
        )
        return False
