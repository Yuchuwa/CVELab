"""Security Researcher Agent - 容器生命周期管理

职责：启动/停止 Agent 容器，传递输入，执行 agent_runner.py，收集输出。
Agent 使用 Claude Agent SDK，自带 Bash/Read/Write 工具。
"""

import subprocess
import json
import os
import uuid
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass

# agent_runner.py 在本包内的路径
AGENT_RUNNER_SRC = Path(__file__).parent / "agent_runner.py"


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

    def __post_init__(self):
        if self.exploit_files is None:
            self.exploit_files = {}
        if self.environment_context is None:
            self.environment_context = {}


@dataclass
class AgentOutput:
    """Agent 输出"""
    cve_id: str
    success: bool
    exploit_steps: List[Dict[str, Any]]
    evidence: List[str]
    mitre_mapping: Dict[str, List[str]]
    vulnerability_type: str = ""
    captured_flag: str = ""  # flag value the agent retrieved from the target
    requirements: Dict[str, Any] = None
    # v2 额外字段（agent 明确输出时优先，缺失时 pipeline 走推断）
    extra_fields: Dict[str, Any] = None

    def __post_init__(self):
        if self.requirements is None:
            self.requirements = {}
        if self.extra_fields is None:
            self.extra_fields = {}


class SecurityResearcherAgent:
    """Agent 容器生命周期管理器"""

    def __init__(self, agent_image: str = "clab-agent:latest", max_turns: int = 80):
        self.agent_image = agent_image
        self.max_turns = max_turns
        self.container_id: str | None = None
        self.container_name = f"agent-{uuid.uuid4().hex[:8]}"

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
        # 移除旧容器
        subprocess.run(
            ["docker", "rm", "-f", self.container_name],
            capture_output=True, timeout=10,
        )

        workspace_dir = str(Path(workspace_dir).resolve())
        agent_runner_src = str(AGENT_RUNNER_SRC.resolve())
        # 挂载一个宿主目录到容器内 ~/.claude，让 Claude Agent SDK 原生 session
        # （.jsonl，含 tool-result/sidechain 等全部事件）落盘到宿主，供回捞保存
        claude_cache_dir = str((Path(workspace_dir) / ".claude_cache").resolve())
        Path(claude_cache_dir).mkdir(parents=True, exist_ok=True)

        cmd = [
            "docker", "run", "-d",
            f"--name={self.container_name}",
            f"--network={network_name}",
            "--cap-add", "NET_RAW",
            "--cap-add", "NET_ADMIN",
            # 挂载 workspace（input.json/output.json）
            "-v", f"{workspace_dir}:/workspace",
            # 挂载 agent_runner.py（从 src 包内）
            "-v", f"{agent_runner_src}:/opt/agent_runner.py:ro",
            # 挂载 ~/.claude 缓存：SDK 原生 session .jsonl 落盘到这里
            "-v", f"{claude_cache_dir}:/home/agent/.claude",
            "-e", "CLAUDE_CONFIG_DIR=/home/agent/.claude",
            "-e", "HOME=/home/agent",
            # Claude Agent SDK 使用 ANTHROPIC_API_KEY
            "-e", f"ANTHROPIC_API_KEY={api_key}",
        ]
        if base_url:
            cmd.extend(["-e", f"ANTHROPIC_BASE_URL={base_url}"])
        if model:
            cmd.extend(["-e", f"MODEL={model}"])

        cmd.append(self.agent_image)

        print(f"Starting agent container: {self.agent_image}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode != 0:
            raise RuntimeError(f"Failed to start agent container: {result.stderr}")

        self.container_id = result.stdout.strip()
        print(f"Agent container started: {self.container_id[:12]}")
        return self.container_id

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
        }
        input_path = workspace / "input.json"
        input_path.write_text(json.dumps(input_data, ensure_ascii=False, indent=2))

        output_path = workspace / "output.json"

        # 执行 agent_runner.py（挂载在 /opt/agent_runner.py）
        # 实时流式输出 Agent 的 stderr（进度信息）
        print(f"Running agent for {cve_input.cve_id} (max_turns={self.max_turns})...")
        stderr_chunks = []
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
            wall_timeout = 900
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
            if not self.stop(timeout=30):
                stderr_chunks.append(
                    f"\nWarning: timed out removing agent container {self.container_name}; "
                    "it may require manual docker cleanup."
                )

        returncode = proc.returncode if proc.returncode is not None else -1
        stderr_text = "".join(stderr_chunks)

        if returncode != 0:
            print(f"Agent exited with code {returncode}")
            if not output_path.exists():
                return AgentOutput(
                    cve_id=cve_input.cve_id,
                    success=False,
                    exploit_steps=[],
                    evidence=[f"Agent failed: {stderr_text[:500]}"],
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
                evidence=[f"Failed to read agent output: {e}"],
                mitre_mapping={},
            )

        print(f"Agent finished: success={output_data.get('success')}")

        return AgentOutput(
            cve_id=cve_input.cve_id,
            success=output_data.get("success", False),
            exploit_steps=output_data.get("exploit_steps", []),
            evidence=output_data.get("evidence", []),
            mitre_mapping=output_data.get("mitre_mapping", {}),
            vulnerability_type=output_data.get("vulnerability_type", ""),
            captured_flag=output_data.get("captured_flag", ""),
            requirements=output_data.get("requirements", {}),
            extra_fields={
                k: output_data[k]
                for k in [
                    "vuln_category", "primary_mitre_phase", "service_role",
                    "exploit_complexity", "attack_method",
                    "needs_callback", "callback_type", "needs_ssh", "needs_tool_download",
                    "default_username", "default_password",
                    "flag_verify_command", "health_check", "init_tasks",
                    "captured_flag",
                ]
                if k in output_data
            },
        )

    def stop(self, timeout: int = 30) -> bool:
        """停止并移除容器。

        Docker can occasionally block while removing a container that has an
        active exec session. Cleanup must be best-effort so it does not mask the
        real agent failure reason.
        """
        if self.container_id:
            try:
                result = subprocess.run(
                    ["docker", "rm", "-f", self.container_name],
                    capture_output=True, text=True, timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                print(
                    f"Warning: timed out removing agent container "
                    f"{self.container_name} after {timeout}s"
                )
                return False

            if result.returncode != 0:
                stderr = (result.stderr or "").strip()
                print(
                    f"Warning: failed to remove agent container "
                    f"{self.container_name}: {stderr}"
                )
                return False

            self.container_id = None
            print("Agent container stopped")
        return True
