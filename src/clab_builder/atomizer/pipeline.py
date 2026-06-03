"""Atomizer Pipeline - 项目一主流程

从 vulhub CVE 目录到验证后的 atom 输出：
1. 解析 vulhub docker-compose → 生成 ansible/deploy.yaml
2. 启动 CVE 环境（docker-compose）
3. 启动 Agent 容器，传入 writeup
4. Agent 自主执行 exploit 并验证
5. 生成 playbook/exploit.yaml
6. 保存到 data/atoms/CVE-XXXX/
"""

import subprocess
import json
import yaml
import time
import os
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass, field

from .output.vulhub_converter import VulhubParser, AnsiblePlaybookGenerator
from .output.exploit_playbook import ExploitPlaybookGenerator
from .agent.researcher import SecurityResearcherAgent, CVEInput
from .environment.container import CVEEnvironmentManager, ContainerInfo


@dataclass
class AtomMeta:
    """Atom 元数据"""
    cve_id: str
    category: str
    docker_image: str
    ports: List[int]
    verified: bool = False
    services: List[str] = field(default_factory=list)
    mitre_mapping: Dict[str, List[str]] = field(default_factory=dict)
    timestamp: str = ""


class AtomizerPipeline:
    """项目一完整流程"""

    def __init__(self, vulhub_dir: str, output_dir: str = "data/atoms",
                 network_name: str = "cve-network", max_turns: int = 50):
        self.vulhub_dir = vulhub_dir
        self.output_dir = Path(output_dir)
        self.network_name = network_name
        self.max_turns = max_turns

        # 解析 vulhub 环境
        self.parser = VulhubParser()
        self.env = self.parser.parse(vulhub_dir)

        # Agent 镜像
        self.agent_image = os.environ.get("AGENT_IMAGE", "clab-agent:latest")

    def run(self, api_key: str = "", base_url: str = "", model: str = "",
            skip_agent: bool = False) -> Dict[str, Any]:
        """
        执行完整流程

        Args:
            api_key: LLM API key (也可从环境变量读取)
            base_url: LLM API base URL
            model: LLM model name
            skip_agent: 跳过 Agent 步骤（仅生成 ansible 配置）

        Returns:
            结果字典
        """
        cve_id = self.env.cve_id
        atom_dir = self.output_dir / cve_id
        workspace = atom_dir / ".workspace"

        print(f"=== Atomizer: {cve_id} ===")
        print(f"  Vulhub: {self.vulhub_dir}")
        print(f"  Output: {atom_dir}")

        try:
            # Step 1: 生成 ansible/deploy.yaml
            print(f"\n[1/5] Generating ansible/deploy.yaml")
            ansible_yaml = self._generate_ansible(atom_dir)

            # Step 2: 启动 CVE 环境
            print(f"\n[2/5] Starting CVE environment")
            cve_info, cve_network = self._start_cve_environment()

            if skip_agent:
                print("\n[SKIP] Agent step skipped (--skip-agent)")
                self._save_atom(atom_dir)
                return {"success": True, "cve_id": cve_id, "output": str(atom_dir), "agent_skipped": True}

            # Step 3: 准备 Agent 输入并执行（使用 CVE 的网络）
            print(f"\n[3/5] Running Agent")
            agent_output = self._run_agent(
                cve_info, workspace,
                api_key=api_key, base_url=base_url, model=model,
                network_name=cve_network,
            )

            # Step 4: 生成 playbook/exploit.yaml
            print(f"\n[4/5] Generating playbook/exploit.yaml")
            self._generate_exploit_playbook(atom_dir, agent_output, cve_info)

            # Step 5: 保存 atom 元数据
            print(f"\n[5/5] Saving atom")
            self._save_atom(atom_dir, agent_output=agent_output)

            print(f"\n=== Done: {cve_id} (success={agent_output.success}) ===")
            return {
                "success": agent_output.success,
                "cve_id": cve_id,
                "output": str(atom_dir),
                "evidence": agent_output.evidence[:3],
            }

        except Exception as e:
            print(f"\n[ERROR] {e}")
            import traceback
            traceback.print_exc()
            return {"success": False, "cve_id": cve_id, "error": str(e)}

        finally:
            # 清理环境
            self._cleanup()

    def _generate_ansible(self, atom_dir: Path) -> str:
        """从 vulhub docker-compose 生成 Ansible deploy playbook"""
        ansible_dir = atom_dir / "ansible"
        ansible_dir.mkdir(parents=True, exist_ok=True)

        gen = AnsiblePlaybookGenerator()
        playbook = gen.generate(self.env, network_name=self.network_name)

        deploy_path = ansible_dir / "deploy.yaml"
        deploy_path.write_text(playbook)
        print(f"  Written: {deploy_path}")
        return playbook

    def _compose_project_name(self) -> str:
        """生成合法的 docker compose 项目名"""
        import re
        return re.sub(r'[^a-z0-9_-]', '-', Path(self.vulhub_dir).resolve().name.lower())

    def _start_cve_environment(self) -> tuple:
        """用 docker-compose 启动 CVE 环境（不映射端口到宿主机）

        Returns:
            (ContainerInfo, cve_network_name)
        """
        import shutil
        vulhub_path = Path(self.vulhub_dir).resolve()

        # 生成无端口映射的 compose 文件，避免暴露到宿主机
        compose_src = vulhub_path / "docker-compose.yml"
        compose_data = yaml.safe_load(compose_src.read_text())

        # 记录内部端口（容器侧端口）
        internal_ports = []
        for name, svc in compose_data.get("services", {}).items():
            ports = svc.get("ports", [])
            for p in ports:
                # "8080:80" → 80, "8080" → 8080
                internal = int(str(p).split(":")[-1]) if ":" in str(p) else int(p)
                if svc.get("image", "") == self.env.main_image or name == (self.env.main_service.name if self.env.main_service else ""):
                    internal_ports.append(internal)
            # 去掉端口映射 — Agent 在同一 Docker 网络内直接访问容器端口
            svc.pop("ports", None)
            # 转换相对路径 volume 为绝对路径
            abs_volumes = []
            for v in svc.get("volumes", []):
                if isinstance(v, str) and v.startswith("./"):
                    abs_volumes.append(str(vulhub_path / v[2:]))
                else:
                    abs_volumes.append(v)
            if abs_volumes:
                svc["volumes"] = abs_volumes

        # 写到临时 compose 文件
        compose_tmp = vulhub_path / ".compose-no-ports.yml"
        compose_tmp.write_text(yaml.dump(compose_data, default_flow_style=False))

        # 预拉 build 所需的基础镜像（带重试）
        for name, svc in compose_data.get("services", {}).items():
            if svc.get("build") and not svc.get("image"):
                # 从 Dockerfile 提取 FROM 镜像
                build_ctx = svc["build"] if isinstance(svc["build"], str) else svc["build"].get("context", ".")
                dockerfile_path = vulhub_path / build_ctx / "Dockerfile"
                if dockerfile_path.exists():
                    for line in dockerfile_path.read_text().splitlines():
                        if line.strip().startswith("FROM "):
                            base_image = line.strip().split()[1]
                            break
                    else:
                        base_image = None
                    if base_image:
                        print(f"  Pre-pulling base image: {base_image}")
                        for attempt in range(3):
                            r = subprocess.run(
                                ["docker", "pull", base_image],
                                capture_output=True, text=True, timeout=120,
                            )
                            if r.returncode == 0:
                                break
                            print(f"  Pull attempt {attempt+1} failed, retrying...")

        # 启动 compose（有些 CVE 需要本地 build 镜像，给足够时间）
        # 项目名: 目录名，替换非法字符（只允许 [a-z0-9_-]）
        import re
        project_name = self._compose_project_name()
        result = subprocess.run(
            ["docker", "compose", "-p", project_name, "-f", ".compose-no-ports.yml", "up", "-d", "--build"],
            cwd=str(vulhub_path),
            capture_output=True, text=True, timeout=600,
        )
        if result.returncode != 0:
            raise RuntimeError(f"docker compose up failed: {result.stderr}")

        print(f"  CVE containers started (no host port mapping)")

        # 等待服务就绪
        time.sleep(5)

        # 获取主服务容器 — 用 compose 项目名过滤（目录名即项目名）
        project_name = self._compose_project_name()
        inspect = subprocess.run(
            ["docker", "ps", "--filter", f"label=com.docker.compose.project={project_name}",
             "--format", "{{.ID}} {{.Names}} {{.Networks}}"],
            capture_output=True, text=True, timeout=10,
        )
        lines = inspect.stdout.strip().split("\n")
        if not lines or not lines[0]:
            raise RuntimeError(f"No container found for compose project {project_name}")

        container_id = lines[0].split()[0]
        container_name = lines[0].split()[1]
        cve_network = lines[0].split()[2] if len(lines[0].split()) > 2 else self.network_name

        # 获取 IP
        ip_result = subprocess.run(
            ["docker", "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
             container_id],
            capture_output=True, text=True, timeout=10,
        )
        container_ip = ip_result.stdout.strip()
        if not container_ip:
            raise RuntimeError(f"Cannot get IP for container {container_id}")

        print(f"  Main container: {container_name} ({container_ip}) on {cve_network}")
        print(f"  Internal ports: {internal_ports}")

        info = ContainerInfo(
            container_id=container_id,
            container_name=container_name,
            container_ip=container_ip,
            image_name=self.env.main_image,
            ports=internal_ports or self.env.main_ports,
            status="running",
            created_time=time.strftime("%Y-%m-%d %H:%M:%S"),
        )
        return info, cve_network

    def _run_agent(self, cve_info: ContainerInfo, workspace: Path,
                   api_key: str, base_url: str, model: str,
                   network_name: str = ""):
        """启动 Agent 容器并执行"""
        workspace.mkdir(parents=True, exist_ok=True)

        # 准备 exploit files（从 vulhub 目录读取 poc 文件）
        exploit_files = {}
        vulhub_path = Path(self.vulhub_dir)
        for ext in ["*.py", "*.xml", "*.sh", "*.rb"]:
            for f in vulhub_path.glob(ext):
                exploit_files[f.name] = f.read_text(encoding="utf-8", errors="replace")

        cve_input = CVEInput(
            cve_id=self.env.cve_id,
            description=f"{self.env.main_image} - {self.env.category}",
            target_ip=cve_info.container_ip,
            target_ports=cve_info.ports,
            writeup=self.env.readme_content,
            exploit_files=exploit_files,
        )

        # 从参数或环境变量获取 API 配置
        key = api_key or os.environ.get("LLM_API_KEY", "")
        url = base_url or os.environ.get("LLM_BASE_URL", "")
        mdl = model or os.environ.get("LLM_MODEL", "claude-sonnet-4-6")

        if not key:
            raise ValueError("LLM_API_KEY required for Agent. Set in .env or pass --api-key.")

        agent = SecurityResearcherAgent(agent_image=self.agent_image,
                                         max_turns=self.max_turns)
        agent.start(
            network_name=network_name or self.network_name,
            workspace_dir=str(workspace),
            api_key=key,
            base_url=url,
            model=mdl,
        )
        self._agent = agent  # 保存引用用于 cleanup

        return agent.run(cve_input, str(workspace))

    def _generate_exploit_playbook(self, atom_dir: Path, agent_output, cve_info):
        """从 Agent 结果生成 exploit playbook"""
        playbook_dir = atom_dir / "playbook"
        playbook_dir.mkdir(parents=True, exist_ok=True)

        gen = ExploitPlaybookGenerator()
        playbook = gen.generate(
            cve_id=self.env.cve_id,
            exploit_steps=agent_output.exploit_steps,
            mitre_mapping=agent_output.mitre_mapping,
            target_ip=cve_info.container_ip,
            target_port=cve_info.ports[0] if cve_info.ports else 80,
            evidence=agent_output.evidence,
            vulnerability_type=agent_output.vulnerability_type,
            requirements=agent_output.requirements,
        )

        playbook_path = playbook_dir / "exploit.yaml"
        playbook_path.write_text(playbook)
        print(f"  Written: {playbook_path}")

    def _save_atom(self, atom_dir: Path, agent_output=None):
        """保存 atom.yaml 元数据"""
        from datetime import datetime

        verified = agent_output.success if agent_output else False
        mitre_mapping = agent_output.mitre_mapping if agent_output else {}
        vuln_type = agent_output.vulnerability_type if agent_output else ""
        requirements = agent_output.requirements if agent_output else {}
        evidence = agent_output.evidence if agent_output else []

        # 从 README 提取简短描述
        readme = self.env.readme_content
        short_desc = ""
        for line in readme.split("\n"):
            line = line.strip().strip("#")
            if line and len(line) > 10:
                short_desc = line[:200]
                break

        meta = {
            "cve_id": self.env.cve_id,
            "category": self.env.category,
            "description": short_desc,
            "vulnerability_type": vuln_type,
            "docker_image": self.env.main_image,
            "ports": self.env.main_ports,
            "services": [
                {"name": s.name, "image": s.image, "is_target": s.is_main_target}
                for s in self.env.services
            ],
            "verified": verified,
            "mitre_mapping": mitre_mapping,
            "requirements": requirements,
            "evidence": evidence[:5],
            "timestamp": datetime.now().isoformat(),
            "source": str(self.vulhub_dir),
        }

        atom_path = atom_dir / "atom.yaml"
        atom_path.write_text(yaml.dump(meta, default_flow_style=False,
                                       sort_keys=False, allow_unicode=True))
        print(f"  Written: {atom_path}")

        # 清理 workspace（session.json 已在 agent_runner 中直接保存到 workspace）
        workspace = atom_dir / ".workspace"
        if workspace.exists():
            # 移动 session.json 到 atom 根目录
            session_src = workspace / "session.json"
            if session_src.exists():
                import shutil
                shutil.copy2(str(session_src), str(atom_dir / "session.json"))
                print(f"  Session saved: {atom_dir / 'session.json'}")
            import shutil
            shutil.rmtree(workspace, ignore_errors=True)

    def _cleanup(self):
        """清理 CVE 容器和 Agent 容器"""
        # 停止 docker-compose（用同一个无端口映射的 compose 文件）
        import re
        vulhub_path = Path(self.vulhub_dir).resolve()
        compose_tmp = vulhub_path / ".compose-no-ports.yml"
        compose_file = str(compose_tmp) if compose_tmp.exists() else "docker-compose.yml"
        project_name = self._compose_project_name()
        subprocess.run(
            ["docker", "compose", "-p", project_name, "-f", compose_file, "down", "-v"],
            cwd=str(vulhub_path),
            capture_output=True, timeout=30,
        )

        # 停止 Agent 容器
        agent = getattr(self, "_agent", None)
        if agent:
            agent.stop()
