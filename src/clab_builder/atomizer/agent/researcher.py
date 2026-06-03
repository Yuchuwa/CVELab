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

    def __post_init__(self):
        if self.exploit_files is None:
            self.exploit_files = {}


@dataclass
class AgentOutput:
    """Agent 输出"""
    cve_id: str
    success: bool
    exploit_steps: List[Dict[str, Any]]
    evidence: List[str]
    mitre_mapping: Dict[str, List[str]]
    vulnerability_type: str = ""
    requirements: Dict[str, Any] = None

    def __post_init__(self):
        if self.requirements is None:
            self.requirements = {}


class SecurityResearcherAgent:
    """Agent 容器生命周期管理器"""

    def __init__(self, agent_image: str = "clab-agent:latest", max_turns: int = 50):
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

        cmd = [
            "docker", "run", "-d",
            f"--name={self.container_name}",
            f"--network={network_name}",
            # 挂载 workspace（input.json/output.json）
            "-v", f"{workspace_dir}:/workspace",
            # 挂载 agent_runner.py（从 src 包内）
            "-v", f"{agent_runner_src}:/opt/agent_runner.py:ro",
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

            proc.wait(timeout=960)
            reader.join(timeout=5)

        except subprocess.TimeoutExpired:
            proc.kill()
            stderr_chunks.append("Agent timed out after 16 minutes")

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
            requirements=output_data.get("requirements", {}),
        )

    def stop(self):
        """停止并移除容器"""
        if self.container_id:
            subprocess.run(
                ["docker", "rm", "-f", self.container_name],
                capture_output=True, timeout=10,
            )
            self.container_id = None
            print("Agent container stopped")
