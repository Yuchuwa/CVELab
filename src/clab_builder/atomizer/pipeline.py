"""Atomizer Pipeline - 项目一主流程

从 vulhub CVE 目录到验证后的 atom 输出：
1. 解析 vulhub docker-compose → 生成 ansible/deploy.yaml
2. 启动 CVE 环境（docker-compose）
3. 启动 Agent 容器，传入 writeup
4. Agent 自主执行 exploit 并验证
5. 生成 exploit_guide.yaml（SysField 仅保留兼容产物）
6. 保存到 data/atoms/CVE-XXXX/
"""

import subprocess
import copy
import json
import yaml
import time
import os
import hashlib
import shutil
import re
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

from .output.vulhub_converter import (
    VulhubParser,
    AnsiblePlaybookGenerator,
    container_port_from_spec,
)
from .output.sysfield_playbook import SysFieldPlaybookGenerator
from .output.exploit_guide import ExploitGuideGenerator
from .agent.researcher import SecurityResearcherAgent, CVEInput
from .environment.container import CVEEnvironmentManager, ContainerInfo
from clab_builder.shared.models.atom import RuntimeSpec
from clab_builder.shared.service_resolver import resolve_service_family, service_role_for_family


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


@dataclass
class SuccessEvaluation:
    """Single source of truth for atom verification."""
    verified: bool
    flag_matched: bool
    captured_flag: str = ""
    reason: str = ""


@dataclass
class LLMCheckResult:
    """LLM checker decision for non-flag objective evidence."""
    accepted: bool
    reason: str = ""
    issues: List[str] = field(default_factory=list)
    confidence: str = "unknown"
    skipped: bool = False
    model: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "reason": self.reason,
            "issues": self.issues,
            "confidence": self.confidence,
            "skipped": self.skipped,
            "model": self.model,
        }


class AtomizerPipeline:
    """项目一完整流程"""

    def __init__(self, vulhub_dir: str, output_dir: str = "data/atoms",
                 network_name: str = "cve-network", max_turns: int = 80):
        self.vulhub_dir = vulhub_dir
        self.output_dir = Path(output_dir)
        self.network_name = network_name
        self.max_turns = max_turns
        self._build_runtime = False

        # 解析 vulhub 环境
        self.parser = VulhubParser()
        self.env = self.parser.parse(vulhub_dir)

        # Agent 镜像
        self.agent_image = os.environ.get("AGENT_IMAGE", "clab-agent:latest")
        self._compose_service_statuses: list[dict[str, Any]] = []
        self._readiness_warnings: list[str] = []

    def run(self, api_key: str = "", base_url: str = "", model: str = "",
            skip_agent: bool = False, llm_checker: bool = True,
            force: bool = False) -> Dict[str, Any]:
        """
        执行完整流程

        Args:
            api_key: LLM API key (也可从环境变量读取)
            base_url: LLM API base URL
            model: LLM model name
            skip_agent: 跳过 Agent 步骤（仅生成 ansible 配置）
            llm_checker: 对无 flag 成功样本启用 LLM 二级仲裁
            force: 覆盖已有 atom；失败时回滚旧版本

        Returns:
            结果字典
        """
        cve_id = self.env.cve_id
        atom_dir = self.output_dir / cve_id
        workspace = atom_dir / ".workspace"
        self._flag_required = self._should_inject_flag_for_env()
        self._flag = self._generate_flag(cve_id) if self._flag_required else ""

        print(f"=== Atomizer: {cve_id} ===")
        print(f"  Vulhub: {self.vulhub_dir}")
        print(f"  Output: {atom_dir}")

        # Transactional protection: when force-overwriting an existing atom,
        # snapshot it first so a failed run restores the previous good
        # version instead of leaving a half-written atom that loses verified
        # truth and a working source_bundle.
        backup_dir: Optional[Path] = None
        if force and atom_dir.exists():
            backup_dir = atom_dir.parent / f".{atom_dir.name}.bak"
            if backup_dir.exists():
                self._force_rmtree(backup_dir)
            atom_dir.rename(backup_dir)
            atom_dir.mkdir(parents=True)

        succeeded = False
        try:
            # Step 1: 生成 ansible/deploy.yaml
            print(f"\n[1/5] Generating ansible/deploy.yaml")
            ansible_yaml = self._generate_ansible(atom_dir)

            # Step 2: 启动 CVE 环境
            print(f"\n[2/5] Starting CVE environment")
            cve_info, cve_network = self._start_cve_environment()

            if skip_agent:
                print("\n[SKIP] Agent step skipped (--skip-agent)")
                # Structure-only backfill must NOT inherit verified=True. A
                # verified atom means the exploit was reproduced by the native
                # agent; --skip-agent never runs the agent, so the result is
                # structurally complete but unverified. Force this explicitly
                # so the contract does not depend on the implicit
                # _evaluate_agent_success(None) path and cannot regress.
                self._flag_required = False
                self._flag = ""
                self._save_atom(atom_dir)
                succeeded = True
                return {"success": True, "cve_id": cve_id, "output": str(atom_dir), "agent_skipped": True}

            # Step 3: 准备 Agent 输入并执行（使用 CVE 的网络）
            print(f"\n[3/5] Running Agent")
            agent_output = self._run_agent(
                cve_info, workspace,
                api_key=api_key, base_url=base_url, model=model,
                network_name=cve_network,
            )

            # Step 4: guide 在 _save_atom 中依据结构化 Agent 输出生成。
            # SysField 仅作为旧消费者的兼容产物，失败不影响 Atom 保存。
            print(f"\n[4/5] Generating exploit guide")
            try:
                self._generate_exploit_playbook(atom_dir, agent_output, cve_info)
            except (OSError, ValueError, TypeError) as exc:
                print(f"  Legacy SysField skipped: {exc}")

            # Step 5: 保存 atom 元数据
            print(f"\n[5/5] Saving atom")
            verified, flag_matched = self._save_atom(
                atom_dir,
                agent_output=agent_output,
                llm_checker=llm_checker,
                api_key=api_key,
                base_url=base_url,
                model=model,
            )

            # success 与 atom.yaml.verified 同源，避免重复计算导致 manifest / atom 不一致
            success = verified
            print(f"\n=== Done: {cve_id} (success={success}, flag_matched={flag_matched}) ===")
            succeeded = True
            return {
                "success": success,
                "cve_id": cve_id,
                "output": str(atom_dir),
                "evidence": agent_output.evidence[:3],
                "captured_flag": agent_output.captured_flag,
                "flag_matched": flag_matched,
            }

        except Exception as e:
            print(f"\n[ERROR] {e}")
            import traceback
            traceback.print_exc()
            return {"success": False, "cve_id": cve_id, "error": str(e)}

        finally:
            # 清理环境
            self._cleanup()
            # Transactional backup resolution.
            if backup_dir is not None and backup_dir.exists():
                if succeeded:
                    # New atom written successfully; discard the old backup.
                    self._force_rmtree(backup_dir)
                else:
                    # Run failed: restore the previous good atom.
                    if atom_dir.exists():
                        self._force_rmtree(atom_dir)
                    backup_dir.rename(atom_dir)

    def _generate_ansible(self, atom_dir: Path) -> str:
        """从 vulhub docker-compose 生成 Ansible deploy playbook

        同时拷贝 vulhub 初始化文件到 atom/init/ 并在 deploy.yaml 中注入 FLAG。
        """
        ansible_dir = atom_dir / "ansible"
        ansible_dir.mkdir(parents=True, exist_ok=True)

        # 1. 拷贝 vulhub 初始化文件（compose volumes 引用的文件）到 atom/init/
        init_files = self._save_init_files(atom_dir)

        # 2. 生成 deploy playbook（含 FLAG 环境变量注入）
        gen = AnsiblePlaybookGenerator()
        playbook = gen.generate(self.env, network_name=self.network_name)

        # 3. 对 RCE/文件读等 direct-impact 漏洞注入 FLAG；Auth_Bypass/Info_Leak 等
        # 只要求证明漏洞本身，避免 agent 偏到不属于该 CVE 的 RCE 路径。
        if getattr(self, "_flag_required", self._should_inject_flag_for_env()):
            playbook = self._inject_flag_to_playbook(playbook, init_files)

        deploy_path = ansible_dir / "deploy.yaml"
        deploy_path.write_text(playbook)
        print(f"  Written: {deploy_path}")
        return playbook

    def _save_init_files(self, atom_dir: Path) -> dict[str, str]:
        """拷贝 vulhub compose volumes 引用的源文件到 atom/init/

        Returns:
            {container_path: relative_init_path} 映射
            e.g. {"/var/www/html/victim.cgi": "victim.cgi"}
        """
        init_dir = atom_dir / "init"
        init_dir.mkdir(parents=True, exist_ok=True)

        vulhub_path = Path(self.vulhub_dir).resolve()
        init_files = {}

        for svc in self.env.services:
            for vol in svc.volumes:
                # 格式: "./local_file:/container/path" 或 "local_file:/container/path"
                if not isinstance(vol, str) or ":" not in vol:
                    continue
                parts = vol.split(":", 1)
                local_ref = parts[0]
                container_path = parts[1]

                # 解析本地文件路径（相对于 vulhub 目录）
                if local_ref.startswith("./"):
                    local_path = vulhub_path / local_ref[2:]
                else:
                    local_path = vulhub_path / local_ref

                if local_path.is_file():
                    # 拷贝到 init/ 目录
                    dest = init_dir / local_path.name
                    shutil.copy2(str(local_path), str(dest))
                    init_files[container_path] = local_path.name
                    print(f"  Init file: {local_path.name} -> {container_path}")
                elif local_path.is_dir():
                    # 目录类型 volume（如 ./www）— 整个目录拷贝
                    dest_dir = init_dir / local_path.name
                    if dest_dir.exists():
                        shutil.rmtree(str(dest_dir))
                    shutil.copytree(str(local_path), str(dest_dir))
                    init_files[container_path] = local_path.name
                    print(f"  Init dir: {local_path.name}/ -> {container_path}")

        return init_files

    def _inject_flag_to_playbook(self, playbook_text: str, init_files: dict) -> str:
        """在 deploy.yaml 的主服务容器中注入 FLAG 环境变量

        同时更新 volumes 为 atom init/ 路径（供独立部署时使用）。
        """
        playbook = yaml.safe_load(playbook_text)

        # 确定 FLAG 注入方式
        flag_injection = self._determine_flag_injection()

        for play in (playbook if isinstance(playbook, list) else [playbook]):
            for task in play.get("tasks", []):
                docker_cfg = task.get("community.docker.docker_container", {})
                if not docker_cfg:
                    continue

                # 检查是否是主服务（image 包含 vulhub/ 或与 main_image 匹配）
                img = docker_cfg.get("image", "")
                if self.env.main_image not in img:
                    continue

                # 注入 FLAG 环境变量
                env = docker_cfg.get("env", {})
                if isinstance(env, dict):
                    env[flag_injection["env_var"]] = "flag{placeholder_change_me}"
                    docker_cfg["env"] = env
                else:
                    docker_cfg["env"] = {flag_injection["env_var"]: "flag{placeholder_change_me}"}

                # 如果 FLAG 是文件方式，添加 volume 挂载（在 cve-setup 时通过 docker cp 注入）
                # deploy.yaml 保留原始 volumes + init files 路径标记
                if init_files:
                    volumes = docker_cfg.get("volumes", [])
                    # volumes 保持原样（记录了容器内路径），orchestrator 会在 cve-setup 时用 docker cp
                    docker_cfg["volumes"] = volumes

        return yaml.dump(playbook, default_flow_style=False, sort_keys=False, allow_unicode=True)

    def _determine_flag_injection(self) -> dict:
        """根据漏洞能力确定 FLAG 注入方式

        Web RCE -> env_var (可通过 RCE 执行 echo $FLAG)
        SSH -> file in /root/flag.txt
        LFI -> file in web-readable path
        Database -> database record
        Redis -> redis key
        """
        # 基于攻击方式推断
        vuln_cat = self._infer_vuln_category(
            self.env.main_image.split(":")[0] if self.env.main_image else ""
        )

        # 简化：大部分 CVE 是 Web RCE，用 env_var 即可
        # 更精确的推断在 _save_atom() 中根据 agent 输出完成
        return {"env_var": "FLAG", "method": "env_var"}

    def _should_inject_flag_for_env(self) -> bool:
        """Only plant a flag when the CVE objective can directly retrieve it.

        Auth bypass, pure privilege/role changes, SSRF, and info leaks should be
        judged by their native objective evidence. Planting a flag for those bugs
        pushes the agent toward unrelated RCE/file-read chains.
        """
        category = (self.env.category or "").lower()
        image = (self.env.main_image or "").lower()
        source = str(self.vulhub_dir).lower()
        text = "\n".join([
            self.env.readme_content or "",
            category,
            image,
            source,
        ]).lower()

        non_flag_keywords = [
            "auth bypass", "authentication bypass", "authorization bypass",
            "privilege escalation", "permission bypass", "csrf", "xss",
            "cross-site scripting", "cross site scripting", "ssrf",
            "information disclosure", "info leak", "cache leak",
        ]
        direct_flag_keywords = [
            "remote command execution", "command execution", "arbitrary command",
            "code execution", "execute arbitrary", "arbitrary code",
            "arbitrary file read", "file read", "directory traversal",
            "path traversal", "local file inclusion", "lfi", "file inclusion",
            "deserialization", "template injection", "expression injection",
            "file upload", "upload", "xxe",
        ]

        # Explicit RCE category/path names are strong signals, but avoid treating
        # arbitrary "rce" text in reference URLs as enough.
        if category == "rce" or source.endswith("-rce") or "/rce" in source:
            return True

        if any(keyword in text for keyword in direct_flag_keywords):
            return True
        if any(keyword in text for keyword in non_flag_keywords):
            return False

        inferred = self._infer_vuln_category(text)
        return inferred in {"RCE", "LFI", "RFI", "Deserialization"}

    def _compose_project_name(self) -> str:
        """生成合法的 docker compose 项目名"""
        import re
        return re.sub(r'[^a-z0-9_-]', '-', Path(self.vulhub_dir).resolve().name.lower())

    @staticmethod
    def _generate_flag(cve_id: str) -> str:
        """Deterministic, unique per-CVE flag: flag{<cve_lower>-<sha256[:8]>}."""
        digest = hashlib.sha256(cve_id.upper().encode()).hexdigest()[:8]
        return f"flag{{{cve_id.lower()}-{digest}}}"

    @staticmethod
    def _flag_injection_command(flag: str) -> str:
        """Build the target-side command that writes CTF-style flag files."""
        flag_esc = flag.replace("'", "'\''")
        return (
            f"printf '%s' '{flag_esc}' > /flag && chmod 644 /flag && "
            "cp /flag /tmp/flag.txt && chmod 644 /tmp/flag.txt && "
            "mkdir -p /root && cp /flag /root/flag.txt && chmod 600 /root/flag.txt"
        )

    def _pull_image_with_retry(self, image: str, attempts: int = 3) -> None:
        """Ensure an image exists locally, pulling with retries when needed."""
        if not image:
            return
        inspect = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True, text=True, timeout=10,
        )
        if inspect.returncode == 0:
            return

        last_error = ""
        pull_timeout = int(os.environ.get("ATOMIZER_DOCKER_PULL_TIMEOUT", "900"))
        for attempt in range(1, attempts + 1):
            print(f"  Pulling image ({attempt}/{attempts}): {image}", flush=True)
            try:
                result = subprocess.run(
                    ["docker", "pull", image],
                    capture_output=True, text=True, timeout=pull_timeout,
                )
            except subprocess.TimeoutExpired as exc:
                last_error = (
                    f"docker pull timed out after {pull_timeout}s"
                    + (f": {exc.stderr}" if exc.stderr else "")
                )
                time.sleep(min(5 * attempt, 15))
                continue
            if result.returncode == 0:
                return
            last_error = (result.stderr or result.stdout or "").strip()
            time.sleep(min(5 * attempt, 15))
        raise RuntimeError(f"docker pull failed for {image}: {last_error}")

    def _start_cve_environment(self) -> tuple:
        """用 docker-compose 启动 CVE 环境（不映射端口到宿主机）

        Returns:
            (ContainerInfo, cve_network_name)
        """
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
                internal = container_port_from_spec(p)
                if internal is None:
                    continue
                if svc.get("image", "") == self.env.main_image or name == (self.env.main_service.name if self.env.main_service else ""):
                    internal_ports.append(internal)
            # 去掉端口映射 — Agent 在同一 Docker 网络内直接访问容器端口
            svc.pop("ports", None)
            # 主服务注入 FLAG 环境变量（供 RCE 类漏洞通过 echo $FLAG 读取）
            is_main = (svc.get("image", "") == self.env.main_image
                       or name == (self.env.main_service.name if self.env.main_service else ""))
            if is_main and getattr(self, "_flag", ""):
                env = svc.get("environment", {})
                if isinstance(env, dict):
                    env["FLAG"] = self._flag
                elif isinstance(env, list):
                    env.append(f"FLAG={self._flag}")
                else:
                    env = {"FLAG": self._flag}
                svc["environment"] = env
            # 转换相对路径 volume 为绝对路径
            abs_volumes = []
            for v in svc.get("volumes", []):
                if isinstance(v, str) and v.startswith("./"):
                    abs_volumes.append(str(vulhub_path / v[2:]))
                else:
                    abs_volumes.append(v)
            if abs_volumes:
                svc["volumes"] = abs_volumes
            self._materialize_missing_env_files(name, svc, vulhub_path)

        # 写到临时 compose 文件
        compose_tmp = vulhub_path / ".compose-no-ports.yml"
        compose_tmp.write_text(yaml.dump(compose_data, default_flow_style=False))

        # 预拉 compose 镜像 / build 所需的基础镜像（带重试），尽早暴露网络/镜像问题。
        for name, svc in compose_data.get("services", {}).items():
            image = svc.get("image")
            has_build = bool(svc.get("build"))
            if image and not has_build:
                # Pure image reference (Vulhub style) — pull from registry.
                self._pull_image_with_retry(image)
            if has_build:
                # Compose with a build section (CVE-Factory style): the
                # image field, if present, is the local tag the build will
                # produce — it must NOT be pulled. Pre-pull the base image
                # declared in the Dockerfile's FROM so the build does not
                # fail on a missing base layer.
                build_ctx = svc["build"] if isinstance(svc["build"], str) else svc["build"].get("context", ".")
                dockerfile_path = vulhub_path / build_ctx / "Dockerfile"
                if dockerfile_path.exists():
                    base_image = None
                    for line in dockerfile_path.read_text().splitlines():
                        if line.strip().startswith("FROM "):
                            base_image = line.strip().split()[1]
                            break
                    if base_image:
                        print(f"  Pre-pulling base image: {base_image}")
                        self._pull_image_with_retry(base_image)

        # 启动 compose（有些 CVE 需要本地 build 镜像，给足够时间）
        # 项目名: 目录名，替换非法字符（只允许 [a-z0-9_-]）
        import re
        project_name = self._compose_project_name()
        self._cleanup_compose_project(vulhub_path, ".compose-no-ports.yml", project_name,
                                      context="pre-start")
        # 若主镜像已存在则跳过 --build（加速 resume / 复用已构建镜像）
        up_cmd = ["docker", "compose", "-p", project_name, "-f", ".compose-no-ports.yml", "up", "-d"]
        if self.env.main_image:
            inspect = subprocess.run(
                ["docker", "image", "inspect", self.env.main_image],
                capture_output=True, text=True, timeout=10,
            )
            if inspect.returncode != 0:
                up_cmd.append("--build")
        else:
            up_cmd.append("--build")
        try:
            result = subprocess.run(
                up_cmd,
                cwd=str(vulhub_path),
                capture_output=True, text=True, timeout=600,
            )
        except Exception:
            self._cleanup_compose_project(
                vulhub_path,
                ".compose-no-ports.yml",
                project_name,
                context="compose-up-error",
            )
            raise
        if result.returncode != 0:
            self._cleanup_compose_project(
                vulhub_path,
                ".compose-no-ports.yml",
                project_name,
                context="compose-up-failed",
            )
            raise RuntimeError(f"docker compose up failed: {result.stderr}")

        print(f"  CVE containers started (no host port mapping)")

        # 等待服务就绪
        time.sleep(5)
        self._compose_service_statuses = self._validate_compose_services(project_name)

        # 获取主服务容器 — 优先按 compose service label 精确过滤，避免多服务环境拿到依赖容器。
        project_name = self._compose_project_name()
        main_service_name = self.env.main_service.name if self.env.main_service else ""
        inspect = subprocess.run(
            ["docker", "ps", "--filter", f"label=com.docker.compose.project={project_name}",
             "--filter", f"label=com.docker.compose.service={main_service_name}",
             "--format", "{{.ID}} {{.Names}} {{.Networks}}"],
            capture_output=True, text=True, timeout=10,
        )
        lines = inspect.stdout.strip().split("\n")
        if not lines or not lines[0]:
            inspect = subprocess.run(
                ["docker", "ps", "--filter", f"label=com.docker.compose.project={project_name}",
                 "--format", "{{.ID}} {{.Names}} {{.Networks}}"],
                capture_output=True, text=True, timeout=10,
            )
            lines = inspect.stdout.strip().split("\n")
        if not lines or not lines[0]:
            raise RuntimeError(
                f"No container found for compose project {project_name} service {main_service_name}"
            )

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

        # 把 FLAG 写入容器内多个位置，覆盖不同漏洞类型：
        # /flag          — CTF-style common flag path, world-readable for web/RCE/LFI
        # /tmp/flag.txt  — fallback for payloads constrained to /tmp
        # /root/flag.txt — root-only copy for LPE/SSH style exploits
        if getattr(self, "_flag", ""):
            flag_result = subprocess.run(
                ["docker", "exec", "-u", "0", container_id, "sh", "-c",
                 self._flag_injection_command(self._flag)],
                capture_output=True, text=True, timeout=15,
            )
            if flag_result.returncode != 0:
                raise RuntimeError(
                    f"flag injection failed for {container_name}: {flag_result.stderr}"
                )

        # Probe service readiness — detect install wizard, port not listening, etc.
        probe_ports = internal_ports or self.env.main_ports
        readiness = self._probe_service_ready(container_id, probe_ports)
        self._readiness_warnings = readiness["warnings"]
        for w in readiness["warnings"]:
            print(f"  WARNING: {w}")

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

    def _readme_env_defaults(self) -> str:
        """Extract KEY=value examples from the README for missing compose env_file entries."""
        env_lines: list[str] = []
        for line in self.env.readme_content.splitlines():
            stripped = line.strip()
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=.*$", stripped):
                env_lines.append(stripped)
        if env_lines:
            return "\n".join(env_lines) + "\n"
        return "# Generated by atomizer because the compose env_file was missing.\n"

    def _materialize_missing_env_files(self, service_name: str, svc: dict[str, Any],
                                       vulhub_path: Path) -> None:
        """Create local env files referenced by compose when Vulhub omits them.

        Some Vulhub examples intentionally ask users to create `.env` manually.
        Docker Compose fails before the environment can start if that file is
        absent, so atomizer writes a generated env file from README examples and
        rewrites the compose reference to an absolute path.
        """
        env_file = svc.get("env_file")
        if not env_file:
            return

        if isinstance(env_file, (str, Path)):
            entries = [str(env_file)]
            scalar = True
        else:
            entries = [str(item) for item in env_file]
            scalar = False

        generated_dir = vulhub_path / ".atomizer-env"
        rewritten: list[str] = []
        for idx, entry in enumerate(entries):
            if os.path.isabs(entry):
                env_path = Path(entry)
            else:
                env_path = vulhub_path / entry
            if env_path.exists():
                rewritten.append(str(env_path))
                continue

            generated_dir.mkdir(exist_ok=True)
            safe_entry = re.sub(r"[^A-Za-z0-9_.-]", "_", Path(entry).name or f"env{idx}")
            generated = generated_dir / f"{service_name}-{safe_entry}"
            generated.write_text(self._readme_env_defaults(), encoding="utf-8")
            rewritten.append(str(generated))
            print(f"  Generated missing env_file for {service_name}: {generated}")

        svc["env_file"] = rewritten[0] if scalar else rewritten

    def _compose_network_ids(self, project_name: str) -> list[str]:
        """List docker network ids owned by one compose project."""
        result = subprocess.run(
            [
                "docker", "network", "ls", "-q",
                "--filter", f"label=com.docker.compose.project={project_name}",
            ],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(f"docker network ls failed for {project_name}: {result.stderr}")
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    def _remove_compose_networks(self, project_name: str) -> None:
        """Remove only networks created for this compose project."""
        for network_id in self._compose_network_ids(project_name):
            result = subprocess.run(
                ["docker", "network", "rm", network_id],
                capture_output=True, text=True, timeout=20,
            )
            if result.returncode != 0:
                msg = (result.stderr or result.stdout or "").strip()
                # A network can still be in use if compose down is racing with daemon cleanup.
                print(f"  [cleanup] network rm skipped for {network_id}: {msg}")

    def _cleanup_compose_project(self, vulhub_path: Path, compose_file: str,
                                 project_name: str, context: str = "cleanup") -> None:
        """Targeted cleanup for one CVE compose project, including orphan networks."""
        try:
            subprocess.run(
                [
                    "docker", "compose", "-p", project_name, "-f", compose_file,
                    "down", "-v", "--remove-orphans",
                ],
                cwd=str(vulhub_path),
                capture_output=True, timeout=45,
            )
        except Exception as exc:
            print(f"  [{context}] compose down failed: {exc}")

        # Compose can time out while stopping a large project. Force-remove any
        # containers still owned by this project before removing its networks.
        try:
            ps = subprocess.run(
                [
                    "docker", "ps", "-aq",
                    "--filter", f"label=com.docker.compose.project={project_name}",
                ],
                capture_output=True, text=True, timeout=15,
            )
            container_ids = [line.strip() for line in ps.stdout.splitlines() if line.strip()]
            if container_ids:
                subprocess.run(
                    ["docker", "rm", "-f", *container_ids],
                    capture_output=True, text=True, timeout=60,
                )
        except Exception as exc:
            print(f"  [{context}] forced container cleanup failed: {exc}")

        try:
            self._remove_compose_networks(project_name)
        except Exception as exc:
            print(f"  [{context}] compose network cleanup failed: {exc}")

    def _inspect_compose_services(self, project_name: str) -> list[dict[str, Any]]:
        """Return docker inspect summaries for every service in a compose project."""
        ps = subprocess.run(
            [
                "docker", "ps", "-a",
                "--filter", f"label=com.docker.compose.project={project_name}",
                "--format", "{{.ID}}",
            ],
            capture_output=True, text=True, timeout=10,
        )
        if ps.returncode != 0:
            raise RuntimeError(f"docker ps failed for compose project {project_name}: {ps.stderr}")
        container_ids = [line.strip() for line in ps.stdout.splitlines() if line.strip()]
        if not container_ids:
            raise RuntimeError(f"No containers found for compose project {project_name}")

        inspected = None
        last_error = ""
        for attempt in range(1, 4):
            try:
                inspected = subprocess.run(
                    ["docker", "inspect", *container_ids],
                    capture_output=True, text=True, timeout=20,
                )
            except subprocess.TimeoutExpired:
                last_error = "docker inspect timed out after 20 seconds"
            else:
                if inspected.returncode == 0:
                    break
                last_error = (inspected.stderr or inspected.stdout or "").strip()
            time.sleep(attempt)

        if inspected is None:
            raise RuntimeError(
                f"docker inspect failed for compose project {project_name}: {last_error}"
            )
        if inspected.returncode != 0:
            raise RuntimeError(
                f"docker inspect failed for compose project {project_name}: {last_error}"
            )

        raw_items = json.loads(inspected.stdout)
        services: list[dict[str, Any]] = []
        main_service_name = self.env.main_service.name if self.env.main_service else ""
        for item in raw_items:
            labels = item.get("Config", {}).get("Labels", {}) or {}
            state = item.get("State", {}) or {}
            health = state.get("Health", {}) or {}
            networks = item.get("NetworkSettings", {}).get("Networks", {}) or {}
            ports = item.get("NetworkSettings", {}).get("Ports", {}) or {}
            service_name = labels.get("com.docker.compose.service", "")
            image = item.get("Config", {}).get("Image") or item.get("Image", "")
            network_ips = {
                name: data.get("IPAddress", "")
                for name, data in networks.items()
                if data.get("IPAddress")
            }
            services.append({
                "id": item.get("Id", "")[:12],
                "container_name": (item.get("Name") or "").lstrip("/"),
                "service": service_name,
                "image": image,
                "is_target": service_name == main_service_name or image == self.env.main_image,
                "running": bool(state.get("Running")),
                "status": state.get("Status", ""),
                "exit_code": state.get("ExitCode"),
                "health": health.get("Status", "none"),
                "started_at": state.get("StartedAt", ""),
                "finished_at": state.get("FinishedAt", ""),
                "networks": network_ips,
                "ports": sorted(ports.keys()),
            })
        return sorted(services, key=lambda svc: (not svc["is_target"], svc["service"], svc["container_name"]))

    def _environment_hint(self, service: dict[str, Any], logs: str = "") -> str:
        """Known local Docker prerequisites that are otherwise hard for the agent to infer."""
        text = " ".join([
            service.get("service", ""),
            service.get("image", ""),
            service.get("container_name", ""),
            logs,
        ]).lower()
        if "elasticsearch" in text or "vm.max_map_count" in text:
            return "Host prerequisite: set vm.max_map_count to at least 262144 before starting Elasticsearch."
        if "permission denied" in text and "docker-entrypoint" in text:
            return "Check bind-mounted init files and container user permissions."
        return ""

    def _validate_compose_services(self, project_name: str) -> list[dict[str, Any]]:
        """Fail fast when any compose dependency exited or became unhealthy."""
        services = self._inspect_compose_services(project_name)
        bad_services = [
            svc for svc in services
            if (
                (not svc.get("running") and not self._is_completed_init_service(svc))
                or svc.get("health") == "unhealthy"
            )
        ]
        if not bad_services:
            print(f"  Compose services healthy/running: {len(services)}")
            return services

        details = []
        for svc in bad_services:
            logs = subprocess.run(
                ["docker", "logs", "--tail", "80", svc["id"]],
                capture_output=True, text=True, timeout=15,
            )
            log_text = (logs.stderr or "") + (logs.stdout or "")
            hint = self._environment_hint(svc, log_text)
            svc["recent_logs"] = log_text[-4000:]
            if hint:
                svc["hint"] = hint
            detail = (
                f"{svc['service']} ({svc['container_name']}, image={svc['image']}): "
                f"status={svc['status']} exit_code={svc['exit_code']} health={svc['health']}"
            )
            if hint:
                detail += f"; {hint}"
            if log_text.strip():
                detail += f"\n--- recent logs ---\n{log_text.strip()[-2000:]}"
            details.append(detail)

        raise RuntimeError(
            "compose service dependency failed before agent start:\n" + "\n\n".join(details)
        )

    @staticmethod
    def _is_completed_init_service(service: dict[str, Any]) -> bool:
        """Accept explicitly named non-target one-shot setup services that exit 0."""
        if service.get("is_target") or service.get("exit_code") != 0:
            return False
        name = " ".join([
            str(service.get("service", "")),
            str(service.get("container_name", "")),
        ]).lower()
        return bool(re.search(r"(^|[-_])(init|setup|bootstrap|migrate|migration|install)([-_]|$)", name))

    def _build_agent_environment_context(self, cve_info: ContainerInfo,
                                         network_name: str) -> dict[str, Any]:
        """Compact runtime context passed to the agent so it understands the lab shape."""
        return {
            "cve_id": self.env.cve_id,
            "compose_project": self._compose_project_name(),
            "docker_network": network_name or self.network_name,
            "target": {
                "container_name": cve_info.container_name,
                "ip": cve_info.container_ip,
                "image": cve_info.image_name,
                "ports": cve_info.ports,
            },
            "services": self._compose_service_statuses,
            "readiness_warnings": self._readiness_warnings,
            "flag_objective_required": bool(getattr(self, "_flag", "")),
            "flag_locations": ["/flag", "/tmp/flag.txt", "/root/flag.txt"]
            if getattr(self, "_flag", "") else [],
        }

    def _build_agent_exploit_guidance(self) -> str:
        guidance = [
            "Start from the README steps and any provided local PoC files. Translate raw HTTP requests exactly, including headers, path, query string, body, encoding, and cookies.",
            "Before exploitation, use the Running Environment Context to identify the target service and any dependency service names/IPs. For multi-service bugs, dependency containers are reachable on the same Docker network by service/container IP.",
            "If readiness_warnings mention an install/setup wizard or missing initialization, complete that setup first using the README, then run the exploit.",
            "For RCE/file-read style bugs, prove impact by reading the planted flag through the vulnerability. For Auth_Bypass/Info_Leak/SSRF or role-change bugs, prove the exact objective described by the README and do not pivot to unrelated RCE/file-read chains.",
            "Record only the final successful exploit path in exploit_steps; keep failed probes in evidence only when they explain an environmental limitation.",
        ]
        return "\n".join(f"- {item}" for item in guidance)


    def _probe_service_ready(self, container_id: str, ports: list,
                             max_wait: int = 90) -> dict:
        """Probe whether the CVE service is actually ready (not just container running).

        Detects common environment issues that the ansible/docker-compose setup
        cannot catch with a fixed sleep:
        - Service process not listening on exposed ports yet
        - App install/setup wizard pending (e.g., Drupal, WordPress, Grafana)

        Returns dict with 'ready' (bool) and 'warnings' (list[str]).
        """
        warnings: list[str] = []
        ready = False
        interval = 5
        attempts = max(1, max_wait // interval)

        for attempt in range(attempts):
            all_open = True
            for port in ports:
                r = subprocess.run(
                    ["docker", "exec", container_id, "sh", "-c",
                     f"timeout 2 sh -c 'echo > /dev/tcp/127.0.0.1/{port}' 2>/dev/null"],
                    capture_output=True, text=True, timeout=10,
                )
                if r.returncode != 0:
                    all_open = False
                    break

            if not all_open:
                time.sleep(interval)
                continue

            # Ports are open — for common HTTP ports, check for install wizard
            http_ports = {80, 8080, 8443, 443, 3000, 8888, 9000, 4848, 7001, 8069}
            for port in ports:
                if port not in http_ports:
                    continue
                r = subprocess.run(
                    ["docker", "exec", container_id, "sh", "-c",
                     "curl -s -o /dev/null -w '"
                     + str(port)
                     + ":%{http_code}:%{redirect_url}' http://127.0.0.1:"
                     + str(port)
                     + "/ 2>/dev/null || true"],
                    capture_output=True, text=True, timeout=10,
                )
                out = r.stdout.strip()
                # Format: <port>:<code>:<redirect_url>
                parts = out.split(":", 2)
                if len(parts) < 2:
                    continue
                code = parts[1]
                redirect = parts[2] if len(parts) > 2 else ""
                if code in ("301", "302", "307") and redirect:
                    lower = redirect.lower()
                    if any(k in lower for k in
                           ("install", "setup", "wizard", "configure", "init")):
                        warnings.append(
                            f"Port {port}: HTTP {code} -> {redirect} — app "
                            f"installation wizard pending. The agent MUST complete "
                            f"setup before exploitation (follow the bug report)."
                        )
                    else:
                        warnings.append(
                            f"Port {port}: HTTP {code} redirect -> {redirect}"
                        )

            ready = True
            break

        if not ready:
            warnings.append(
                f"Service did not become ready on ports {ports} within {max_wait}s "
                f"— container is running but the service may not be listening."
            )

        return {"ready": ready, "warnings": warnings}

    def _run_agent(self, cve_info: ContainerInfo, workspace: Path,
                   api_key: str, base_url: str, model: str,
                   network_name: str = ""):
        """启动 Agent 容器并执行"""
        # Interrupted runs can leave output/session/cache files that must not be
        # treated as the result of this run. Agent container (uid 1000) writes
        # .claude_cache subdirs that the host user cannot rmtree, so fall back
        # to a root container to wipe them.
        if workspace.exists():
            self._force_rmtree(workspace)
        workspace.mkdir(parents=True, exist_ok=True)
        # 容器内 agent 用户 (uid 1000) 与宿主用户 uid 不同，挂载的 /workspace
        # 必须 world-writable 才能让 agent_runner 写 output.json。
        os.chmod(workspace, 0o777)

        # 准备 exploit files（从 vulhub 目录读取 poc 文件）
        exploit_files = {}
        vulhub_path = Path(self.vulhub_dir)
        for ext in ["*.py", "*.xml", "*.sh", "*.rb"]:
            for f in vulhub_path.glob(ext):
                exploit_files[f.name] = f.read_text(encoding="utf-8", errors="replace")

        flag_hint = ""
        if getattr(self, "_flag", ""):
            flag_hint = (
                "the target contains the same flag in /flag and /tmp/flag.txt "
                "(world-readable for web/RCE/LFI style exploits). A root-only copy "
                "also exists at /root/flag.txt for privilege-escalation style exploits."
            )

        cve_input = CVEInput(
            cve_id=self.env.cve_id,
            description=f"{self.env.main_image} - {self.env.category}",
            target_ip=cve_info.container_ip,
            target_ports=cve_info.ports,
            writeup=self.env.readme_content,
            exploit_files=exploit_files,
            flag_hint=flag_hint,
            environment_context=self._build_agent_environment_context(cve_info, network_name),
            exploit_guidance=self._build_agent_exploit_guidance(),
        )

        # 从参数或环境变量获取 API 配置
        key = api_key or os.environ.get("LLM_API_KEY", "")
        url = base_url or os.environ.get("LLM_BASE_URL", "")
        mdl = model or os.environ.get("LLM_MODEL", "claude-sonnet-4-6")

        if not key:
            raise ValueError("LLM_API_KEY required for Agent. Set in .env or pass --api-key.")

        agent = SecurityResearcherAgent(agent_image=self.agent_image,
                                         max_turns=self.max_turns)
        self._agent = agent  # cleanup must see containers created by a timed-out start
        agent.start(
            network_name=network_name or self.network_name,
            workspace_dir=str(workspace),
            api_key=key,
            base_url=url,
            model=mdl,
        )
        return agent.run(cve_input, str(workspace))

    def _generate_exploit_playbook(self, atom_dir: Path, agent_output, cve_info):
        """从 Agent 结果生成 SysField playbook。

        数据源优先级：agent 自报 exploit_steps → transcript 实际命令 → session。
        agent 自报为空或质量差时自动回退 transcript，不再硬性要求 agent 必须输出 steps。
        """
        playbook_dir = atom_dir / "playbook"
        playbook_dir.mkdir(parents=True, exist_ok=True)

        transcript_path = atom_dir / "agent_transcript.log"
        session_path = atom_dir / "session.json"
        exploit_steps = agent_output.exploit_steps if agent_output else []

        sysfield_playbook = SysFieldPlaybookGenerator().generate(
            cve_id=self.env.cve_id,
            exploit_steps=exploit_steps,
            mitre_mapping=agent_output.mitre_mapping if agent_output else {},
            target_ip="{{ target_ip }}",
            target_port=cve_info.ports[0] if cve_info.ports else 80,
            vulnerability_type=agent_output.vulnerability_type if agent_output else "",
            requirements=agent_output.requirements if agent_output else {},
            session_path=str(session_path) if session_path.exists() else None,
            transcript_path=str(transcript_path) if transcript_path.exists() else None,
        )
        SysFieldPlaybookGenerator.validate(sysfield_playbook, require_steps=True)
        sysfield_path = playbook_dir / "sysfield.yaml"
        sysfield_path.write_text(sysfield_playbook)
        print(f"  Written: {sysfield_path}")

    def _generate_exploit_guide(
        self,
        atom_dir: Path,
        agent_output,
        *,
        service_role: str,
        exploit_access: dict,
        capabilities: list[str],
        requirements: dict,
        source_bundle,
        evidence: list[str],
        forbidden_values: list[str] | None = None,
    ):
        """Write a descriptive guide when the Agent supplied one.

        Missing/invalid guides are recorded as a Range usability warning; they
        do not rewrite native/orchestrated Atom verification truth. When the
        Agent's guide is structurally valid but inconsistent with the verified
        capability contract (e.g. a LFI bug declaring a reusable command
        channel), we attempt an automatic downgrade before rejecting, so a
        usable guide is preserved instead of being silently dropped.

        ``forbidden_values`` carries the native ground-truth flag so the guide
        validator can reject a guide that leaks it. Both the primary generate
        and the reusable-channel downgrade retry pass it through.
        """
        if not agent_output:
            return None
        raw_guide = getattr(agent_output, "exploit_guide", None)
        if not raw_guide:
            print("  Guide skipped: Agent did not return exploit_guide")
            return None
        materials = getattr(source_bundle, "poc_materials", []) if source_bundle else []
        evidence_refs = [f"native_verification.evidence[{i}]" for i in range(min(len(evidence), 5))]
        forbidden = list(forbidden_values or [])
        try:
            guide = ExploitGuideGenerator().generate(
                cve_id=self.env.cve_id,
                agent_output=agent_output,
                service_role=service_role,
                exploit_access=exploit_access,
                capabilities=capabilities,
                requirements=requirements,
                source_bundle_materials=materials,
                evidence_refs=evidence_refs,
                forbidden_values=forbidden,
            )
            ref = ExploitGuideGenerator().write(atom_dir, guide)
            print(f"  Written: {atom_dir / ref.path}")
            return ref
        except (OSError, ValueError, TypeError) as exc:
            # Common inconsistency: the Agent declared a reusable command
            # channel for a bug that does not grant execute_command (LFI,
            # SSRF, auth-bypass). Downgrade the channel to non-reusable and
            # retry once, instead of dropping the whole guide.
            if "reusable command channel requires execute_command" in str(exc):
                patched = self._downgrade_reusable_channel(raw_guide)
                if patched is not None:
                    try:
                        guide = ExploitGuideGenerator().generate(
                            cve_id=self.env.cve_id,
                            agent_output=patched,
                            service_role=service_role,
                            exploit_access=exploit_access,
                            capabilities=capabilities,
                            requirements=requirements,
                            source_bundle_materials=materials,
                            evidence_refs=evidence_refs,
                            forbidden_values=forbidden,
                        )
                        ref = ExploitGuideGenerator().write(atom_dir, guide)
                        print(f"  Written (after reusable downgrade): {atom_dir / ref.path}")
                        return ref
                    except (OSError, ValueError, TypeError) as exc2:
                        exc = exc2
            print(f"  Guide skipped: {exc}")
            if agent_output and hasattr(agent_output, "evidence"):
                agent_output.evidence.append(f"exploit_guide rejected: {exc}")
            return None

    @staticmethod
    def _downgrade_reusable_channel(raw_guide) -> Any:
        """Return a copy of raw_guide with command_channel.reusable=false.

        Used when the Agent declared a reusable channel without
        execute_command. The copy preserves every other field so the guide
        stays usable as a non-pivoting exploit description.
        """
        if isinstance(raw_guide, dict):
            guide = copy.deepcopy(raw_guide)
            post = guide.get("post_exploit") or {}
            channel = post.get("command_channel") or {}
            channel["reusable"] = False
            if not channel.get("type"):
                channel["type"] = "none"
            # established_by must be empty when not reusable (model validator).
            channel["established_by"] = []
            post["command_channel"] = channel
            guide["post_exploit"] = post
            return guide
        # ExploitGuide model instance
        if hasattr(raw_guide, "model_copy"):
            guide = raw_guide.model_copy(deep=True)
            guide.post_exploit.command_channel.reusable = False
            guide.post_exploit.command_channel.established_by = []
            if not guide.post_exploit.command_channel.type:
                guide.post_exploit.command_channel.type = "none"
            return guide
        return None

    def _save_atom(
        self,
        atom_dir: Path,
        agent_output=None,
        llm_checker: bool = False,
        api_key: str = "",
        base_url: str = "",
        model: str = "",
    ) -> tuple[bool, bool]:
        """保存 atom.yaml v2 元数据，返回 (verified, flag_matched) 供调用方复用判断。"""
        from datetime import datetime
        from clab_builder.shared.models.atom import (
            AtomConfig, VulnCategory, MitrePhase, ServiceRole,
            ExploitComplexity, AttackMethod, FlagMethod, FlagInjection,
            ServiceInfo, NetworkRequirements, DefaultCredentials, ServiceStartup,
            CapabilityType, ProbeType, ReadinessProbe, ValidationSpec,
            EvidenceLevel,
        )

        # Agent v2 输出的额外字段（向后兼容：缺失时走推断）
        agent_extra = {}
        if agent_output and hasattr(agent_output, "extra_fields"):
            agent_extra = agent_output.extra_fields or {}

        vuln_type = agent_output.vulnerability_type if agent_output else ""
        inferred_vuln_category = self._normalize_vuln_category(
            agent_extra.get("vuln_category") or self._infer_vuln_category(vuln_type)
        )

        # 客观验证：是否需要 flag 只由本次是否实际注入 flag 决定。
        ground_truth = getattr(self, "_flag", "")
        evaluation = self._evaluate_agent_success(agent_output, ground_truth)
        verified = evaluation.verified
        flag_matched = evaluation.flag_matched
        if agent_output and agent_output.success and not verified:
            agent_output.evidence.append(
                f"Verification failed: {evaluation.reason} — downgrading to unverified"
            )
        llm_check = LLMCheckResult(
            accepted=True,
            reason="skipped: flag-based or checker disabled",
            skipped=True,
            model=model or os.environ.get("LLM_MODEL", ""),
        )
        if agent_output and not ground_truth and llm_checker:
            # For objective-evidence bugs (no planted flag), the agent's
            # self-reported ``success`` boolean is the only gate. When the
            # agent JSON is truncated or its success field is lost during
            # extraction, a verified exploit is wrongly downgraded. Run the
            # LLM checker whenever objective evidence is present — on
            # verified=True it confirms the agent claim, and on
            # verified=False with non-empty evidence it can rescue a real
            # exploit that the success flag failed to capture.
            if verified or (agent_output.evidence and not agent_output.success):
                llm_check = self._run_llm_checker(
                    agent_output=agent_output,
                    vuln_category=inferred_vuln_category,
                    api_key=api_key,
                    base_url=base_url,
                    model=model,
                )
                verified = bool(llm_check.accepted)
                if not verified:
                    agent_output.evidence.append(
                        f"LLM checker rejected objective evidence: {llm_check.reason}"
                    )
            elif not verified:
                agent_output.evidence.append(
                    "Verification failed: no objective evidence and agent reported failure"
                )
        mitre_mapping = agent_output.mitre_mapping if agent_output else {}
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

        # 推断 v2 枚举字段（agent 明确输出时优先，否则走规则推断）
        vuln_category = VulnCategory(inferred_vuln_category)
        primary_phase = MitrePhase(self._normalize_mitre_phase(
            agent_extra.get("primary_mitre_phase") or self._infer_primary_phase(mitre_mapping)
        ))
        main_service = self.env.main_service
        service_family = resolve_service_family(
            self.env.main_image,
            main_service.name if main_service else "",
            self.env.main_ports,
        )
        # A known runtime database family is more reliable than an Agent's
        # coarse free-text role.  Unknown services retain the existing Agent
        # first/fallback inference behavior.
        service_role = ServiceRole(
            service_role_for_family(service_family)
            or agent_extra.get("service_role")
            or self._infer_service_role(self.env.main_image)
        )
        exploit_complexity = ExploitComplexity(agent_extra.get("exploit_complexity")
                                               or self._infer_complexity(agent_output))
        attack_method = AttackMethod(agent_extra.get("attack_method")
                                     or self._infer_attack_method(agent_output, self.env))

        # 网络需求
        net_reqs = NetworkRequirements(
            needs_callback=agent_extra.get("needs_callback", False),
            callback_type=agent_extra.get("callback_type", "none"),
            needs_ssh=agent_extra.get("needs_ssh", False),
            needs_tool_download=agent_extra.get("needs_tool_download", False),
        )

        # 默认凭据
        creds = None
        auth = requirements.get("authentication", "")
        if auth and "default" in auth.lower():
            creds = DefaultCredentials(
                username=agent_extra.get("default_username"),
                password=agent_extra.get("default_password"),
            )

        # FLAG 注入：运行时写 /flag、/tmp/flag.txt 和 root-only /root/flag.txt。
        # atom.yaml 记录主 CTF-style 路径 /flag。
        flag_inj = FlagInjection(method=FlagMethod.FILE, file_path="/flag")

        # FLAG 验证命令
        flag_cmd = agent_extra.get("flag_verify_command", "")

        # ── v4: exploit_access + capability_grants（从 agent 输出提取）──
        exploit_access, capability_grants = self._build_capability_contract(
            agent_extra, verified, self.env.main_ports,
            env=self.env, vulhub_dir=self.vulhub_dir,
        )
        # Surface capability names the Agent emitted that were dropped because
        # they were not valid CapabilityType values. Previously this was a
        # silent `except: pass`, which hid why an atom ended up with empty
        # grants. We record the dropped names as evidence so the loss is
        # observable and debuggable.
        raw_caps = agent_extra.get("capability_grants") or []
        if isinstance(raw_caps, list):
            valid_types = {c.value for c in CapabilityType}
            accepted = {grant.type.value for grant in capability_grants}
            dropped = [
                str(cap) for cap in raw_caps
                if isinstance(cap, str) and cap not in valid_types
                and cap not in accepted
            ]
            if dropped and agent_output and hasattr(agent_output, "evidence"):
                agent_output.evidence.append(
                    f"capability_grants dropped invalid values: {', '.join(sorted(set(dropped)))}"
                )

        # ── v4: capability_executors（从 agent 轨迹提取可复用命令执行通道）──
        # 只有 agent 真实跑通且轨迹里有"同一通道执行 2+ 不同命令"证据的才生成。
        # 通道不适合 stateless 调用的（需上传文件/探测参数）不会生成。
        capability_executors = {}
        if verified and capability_grants:
            has_exec = any(g.type == CapabilityType.EXECUTE_COMMAND for g in capability_grants)
            if has_exec:
                capability_executors = self._extract_capability_executors(atom_dir)

        # 服务启动（从 deploy.yaml 提取）
        init_file_mappings = self._load_init_file_mappings(atom_dir)
        startup = ServiceStartup(
            wait_seconds=self._extract_wait_seconds(atom_dir),
            health_check=agent_extra.get("health_check"),
            init_tasks=agent_extra.get("init_tasks", []),
            init_files=init_file_mappings,
        )
        readiness_probes = [ReadinessProbe(probe_type=ProbeType.CONTAINER_STATE)]
        readiness_port = self._readiness_port_for_access(
            exploit_access, self.env.main_ports
        )
        if readiness_port is not None:
            readiness_probes.append(
                ReadinessProbe(
                    probe_type=ProbeType.TCP,
                    target=str(readiness_port),
                )
            )
        if startup.health_check:
            readiness_probes.append(
                ReadinessProbe(command=startup.health_check)
            )
        validation_spec = ValidationSpec(readiness=readiness_probes)

        # Capture the current source tree before orchestrated verification.
        # A rebuild must validate the source bundle it will hand to Range,
        # rather than a stale bundle left by an older Atom format.
        source_bundle = self._capture_current_source_bundle(atom_dir)

        # Preserve the effective main-service runtime contract from the
        # original Compose definition.  Range assembly must not have to parse
        # source_bundle/docker-compose.yml or guess an image's command.
        runtime_spec = RuntimeSpec(
            ports=list(self.env.main_ports),
            services=[
                {
                    "name": service.name,
                    "image": service.image,
                    "is_target": service.is_main_target,
                }
                for service in self.env.services
            ],
            command=main_service.command if main_service else None,
            entrypoint=main_service.entrypoint if main_service else None,
            environment=dict(main_service.environment) if main_service else {},
            user=main_service.user if main_service else None,
            source_image=self.env.main_image,
            service_family=service_family,
        )

        # ── verification: native (agent 跑通) + orchestrated (环境重建) ──
        # The native_verification structure is the single shared record both
        # the Agent path and the CVE-Factory PoC path write into. The Agent
        # path records provenance="native_agent"; the PoC backend records
        # provenance="cve_factory_poc" plus witnesses/source_hash/test_results.
        # flag_recovery records whether the planted flag was actually
        # recovered through the exploit, distinct from the boolean verified
        # (which can be true for objective-evidence bugs with no flag).
        timestamp = datetime.now().isoformat()
        flag_attempted = getattr(self, "_flag_required", False) or bool(agent_output and getattr(agent_output, "captured_flag", ""))
        native_verification = {
            "success": bool(verified),
            "mode": "native",
            "provenance": "native_agent",
            "evidence": evidence[:5],
            "captured_flag": evaluation.captured_flag,
            "flag_matched": flag_matched,
            "reason": evaluation.reason,
            "flag_recovery": {
                "attempted": flag_attempted,
                "success": bool(flag_matched),
                "method": "agent_captured_flag" if flag_matched else (
                    "no_flag_required" if not flag_attempted else "flag_not_recovered"
                ),
            },
            "timestamp": timestamp,
        }
        # orchestrated: 用 atom 的 ansible/deploy.yaml 重建最小环境，
        # 验证 runtime_spec 能正确实例化（容器 running + 端口 readiness）。
        # 不重新利用漏洞，只验证环境语义。
        if native_verification["success"]:
            self._orchestrated_readiness_port = readiness_port
            orch = self._run_orchestrated_verification(atom_dir, ground_truth)
        else:
            orch = {
                "success": False,
                "mode": "orchestrated",
                "evidence": ["skipped: native verification failed"],
                "timestamp": timestamp,
            }
        orchestrated_verification = orch
        verification = {
            "native_verification": native_verification,
            "orchestrated_verification": orchestrated_verification,
        }

        exploit_guide_ref = self._generate_exploit_guide(
            atom_dir,
            agent_output,
            service_role=service_role.value,
            exploit_access=exploit_access.model_dump(mode="json"),
            # Only verified grants constrain the guide: inferred/unknown grants
            # are not proof the capability was achieved, so they must not be
            # allowed to appear in the guide's post_exploit.capabilities.
            capabilities=[grant.type.value for grant in capability_grants
                          if grant.evidence_level == EvidenceLevel.VERIFIED],
            requirements=requirements,
            source_bundle=source_bundle,
            evidence=evidence,
            forbidden_values=[ground_truth] if ground_truth else [],
        )

        # verified reflects the native agent result (exploit reproduced +
        # flag matched). Orchestrated environment rebuild is a separate
        # environment-correctness check; its failure used to downgrade
        # verified, which erased the higher-value "native exploit succeeded"
        # fact whenever a compose rebuild hit a transient timing/network issue.
        # We now keep them separate: orchestrated success is recorded in
        # verification.orchestrated_verification and surfaced as
        # environment_ready, but no longer flips verified to False.
        environment_ready = bool(orchestrated_verification.get("success"))
        verification["environment_ready"] = environment_ready

        # ── runtime tool layer (batch 11) ──
        # Build a derived runtime image with base tools on top of the original
        # image. This is an INDEPENDENT stage: its failure never rewrites the
        # native exploit truth (verified) or the orchestrated environment
        # result. runtime_verification is recorded separately so a tool-layer
        # build problem does not masquerade as a native verification failure.
        # Guarded by --build-runtime so the default atomize path is not
        # slowed by a docker build on every run.
        if getattr(self, "_build_runtime", False):
            from clab_builder.atomizer.runtime_builder import (
                build_runtime_image, runtime_verification_record,
            )
            from clab_builder.shared.models.atom import RuntimeStatus, RuntimeBuildSpec
            try:
                # Build runtime with the full atom context (source_bundle +
                # requirements + runtime_spec) so custom-Dockerfile atoms
                # get a real intermediate-image build instead of a FROM
                # docker_image that drops the Dockerfile semantics.
                rt = build_runtime_image(
                    AtomConfig(
                        version=3, cve_id=self.env.cve_id, category=self.env.category,
                        description=short_desc, docker_image=self.env.main_image,
                        ports=self.env.main_ports, vuln_category=vuln_category,
                        primary_mitre_phase=primary_phase, service_role=service_role,
                        exploit_complexity=exploit_complexity, attack_method=attack_method,
                        runtime_spec=runtime_spec, requirements=requirements,
                        source_bundle=source_bundle,
                    ),
                    atom_dir,
                )
                if rt.status == RuntimeStatus.READY:
                    runtime_spec.runtime_image = rt.runtime_image
                    runtime_spec.runtime_status = RuntimeStatus.READY
                    runtime_spec.tool_profile = ",".join(rt.artifacts.tool_profiles) if rt.artifacts else None
                    runtime_spec.tool_profile_version = "1"
                    if rt.resolved_user:
                        runtime_spec.user = rt.resolved_user
                    m = rt.artifacts.manifest if rt.artifacts else {}
                    runtime_spec.runtime_build = RuntimeBuildSpec(
                        context="runtime",
                        dockerfile="runtime/Dockerfile",
                        install_script="runtime/install-tools.sh",
                        base_image_digest=rt.base_image_digest,
                        generated_hash=m.get("generated_hash", ""),
                        intermediate_image=rt.artifacts.base_image_for_runtime,
                        source_dockerfile=rt.artifacts.source_dockerfile,
                    )
                else:
                    runtime_spec.runtime_status = rt.status
                    runtime_spec.runtime_failure_reason = rt.failure_reason
                verification["runtime_verification"] = runtime_verification_record(rt)
            except Exception as exc:  # never let runtime break atom save
                runtime_spec.runtime_status = RuntimeStatus.FAILED
                runtime_spec.runtime_failure_reason = f"runtime build raised: {exc}"
                verification["runtime_verification"] = {
                    "status": "failed",
                    "failure_reason": str(exc),
                }
        else:
            from clab_builder.shared.models.atom import RuntimeStatus as _RS
            runtime_spec.runtime_status = _RS.NOT_REQUESTED

        config = AtomConfig(
            version=3,
            cve_id=self.env.cve_id,
            category=self.env.category,
            description=short_desc,
            docker_image=self.env.main_image,
            ports=self.env.main_ports,
            services=[
                ServiceInfo(name=s.name, image=s.image, is_target=s.is_main_target)
                for s in self.env.services
            ],
            vuln_category=vuln_category,
            primary_mitre_phase=primary_phase,
            mitre_mapping=mitre_mapping,
            service_role=service_role,
            exploit_complexity=exploit_complexity,
            attack_method=attack_method,
            vulnerability_type=vuln_type,
            network_requirements=net_reqs,
            default_credentials=creds,
            flag_injection=flag_inj,
            flag_verify_command=flag_cmd,
            flag_value=ground_truth or None,
            runtime_spec=runtime_spec,
            service_startup=startup,
            validation_spec=validation_spec,
            verified=verified,
            requirements=requirements,
            evidence=evidence[:5],
            llm_check=llm_check.to_dict(),
            timestamp=datetime.now().isoformat(),
            source=str(self.vulhub_dir),
            exploit_access=exploit_access,
            capability_grants=capability_grants,
            capability_executors=capability_executors,
            verification=verification,
            source_bundle=source_bundle,
            exploit_guide=exploit_guide_ref,
        )

        atom_path = atom_dir / "atom.yaml"
        atom_path.write_text(yaml.dump(
            config.model_dump(exclude_none=True, mode="json"),
            default_flow_style=False, sort_keys=False, allow_unicode=True,
        ))
        print(f"  Written: {atom_path}")

        # 清理 workspace（session.json 已在 agent_runner 中直接保存到 workspace）
        workspace = atom_dir / ".workspace"
        if workspace.exists():
            # 移动 session.json 到 atom 根目录
            session_src = workspace / "session.json"
            if session_src.exists():
                shutil.copy2(str(session_src), str(atom_dir / "session.json"))
                print(f"  Session saved: {atom_dir / 'session.json'}")
            self._force_rmtree(workspace)

        return verified, flag_matched

    def _cleanup(self):
        """清理 CVE 容器和 Agent 容器"""
        # Agent is attached to the Compose network. Stop it first; otherwise
        # compose down cannot remove the network and long batches exhaust
        # Docker's predefined address pools.
        agent = getattr(self, "_agent", None)
        if agent:
            try:
                agent.stop()
            except Exception as exc:
                print(f"  [cleanup] agent stop failed: {exc}")

        vulhub_path = Path(self.vulhub_dir).resolve()
        compose_tmp = vulhub_path / ".compose-no-ports.yml"
        compose_file = str(compose_tmp) if compose_tmp.exists() else "docker-compose.yml"
        project_name = self._compose_project_name()
        self._cleanup_compose_project(vulhub_path, compose_file, project_name)

        # 删除本 CVE 专属镜像（释放 /var 空间）；保留基础镜像供后续复用
        main_img = getattr(self.env, "main_image", "") or ""
        # raw_records images are locally verified build artefacts and generally
        # do not exist in a public registry. Removing them makes the dataset
        # impossible to rerun without restoring the original build archive.
        preserve_local_image = self.env.category == "raw_records"
        if main_img and not preserve_local_image:
            try:
                subprocess.run(
                    ["docker", "rmi", main_img],
                    capture_output=True, text=True, timeout=30,
                )
            except Exception as exc:
                print(f"  [cleanup] rmi failed: {exc}")

    # ── v2 字段推断辅助 ─────────────────────────────────

    @staticmethod
    def _container_port_listening(container: str, port: int) -> tuple[bool, str]:
        """Check TCP LISTEN state from inside the container via /proc/net/tcp.

        This mirrors the orchestrator verifier's probe and avoids the per-call
        `docker run busybox nc` overhead + flakiness of the previous
        orchestrated-verification probe. Reading /proc/net/tcp needs no tools
        installed in the target image.
        """
        wanted = f"{port:04X}".upper()
        for proc_file in ("/proc/net/tcp", "/proc/net/tcp6"):
            result = subprocess.run(
                ["docker", "exec", container, "cat", proc_file],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0:
                continue
            for line in result.stdout.splitlines()[1:]:
                fields = line.split()
                if len(fields) >= 4 and fields[1].rsplit(":", 1)[-1].upper() == wanted:
                    if fields[3].upper() == "0A":  # TCP_LISTEN
                        return True, f"port {port} listening"
        return False, f"port {port} not listening"

    @staticmethod
    def _is_slow_init_port(port: int) -> bool:
        """Database/search services commonly need longer to accept connections."""
        return port in {3306, 5432, 9200, 9300, 27017, 9042, 1521, 1433, 6379, 11211}

    def _run_orchestrated_verification(self, atom_dir: Path, flag_value: str) -> dict:
        """用 atom 的 source_bundle/docker-compose.yml 重建最小环境，验证 runtime_spec。

        这个验证测的是"atom 抽取出的环境契约能否被重新实例化"——即 Range
        编排时用同一份 compose/runtime_spec 部署能否成功。不重新利用漏洞，
        只验证容器能起、服务能监听端口。

        稳定性优化（避免用环境抖动抹掉 native 成功事实）：
        - 端口探测改用容器内 /proc/net/tcp 读 LISTEN 状态，替代每次 docker
          run busybox nc 的开销与偶发失败。
        - DB/搜索类慢启动服务给更长探测窗口。
        - 整体失败时重试一次（compose down 后重来），过滤单次时序抖动。
        """
        from datetime import datetime
        timestamp = datetime.now().isoformat()

        compose_src = atom_dir / "source_bundle" / "docker-compose.yml"
        if not compose_src.exists():
            return {
                "success": False, "mode": "orchestrated",
                "evidence": [f"missing {compose_src}"], "timestamp": timestamp,
            }

        for attempt in range(2):  # 最多 2 次：首次 + 一次重试
            result = self._run_orchestrated_attempt(
                atom_dir, compose_src, flag_value, timestamp,
            )
            if result.get("success"):
                if attempt > 0:
                    result["evidence"].insert(0, f"orchestrated passed on retry (attempt {attempt+1})")
                return result
            if attempt == 0:
                print(f"  [orchestrated] attempt 1 failed, retrying: {result.get('evidence', ['?'])[-1:]}")
                # 清理上次尝试残留容器，避免重试时端口冲突
                self._cleanup_orch_project(atom_dir, compose_src, flag_value)
        return result

    def _run_orchestrated_attempt(
        self, atom_dir: Path, compose_src: Path, flag_value: str, timestamp: str,
    ) -> dict:
        """One orchestrated-verification attempt (compose up + readiness probe)."""
        cve_id = self.env.cve_id
        project_name = f"orch{cve_id.replace('-', '').lower()}"[:40]

        # 读取 compose，注入 flag（在主服务环境变量里加 FLAG=flag_value）
        compose_text = compose_src.read_text()
        compose_data = yaml.safe_load(compose_text) or {}
        services = compose_data.get("services", {})
        main_service = None
        for svc_name, svc in services.items():
            if main_service is None:
                main_service = svc_name
            env = svc.setdefault("environment", {})
            if isinstance(env, list):
                if f"FLAG={flag_value}" not in env:
                    env.append(f"FLAG={flag_value}")
            elif isinstance(env, dict):
                env["FLAG"] = flag_value

        evidence: list[str] = []
        tmp_compose = atom_dir / "source_bundle" / ".orch-compose.yml"
        try:
            tmp_compose.write_text(yaml.safe_dump(compose_data, sort_keys=False))
        except OSError as exc:
            return {
                "success": False, "mode": "orchestrated",
                "evidence": [f"failed to write temp compose: {exc}"], "timestamp": timestamp,
            }

        try:
            result = subprocess.run(
                ["docker", "compose", "-p", project_name, "-f", str(tmp_compose), "up", "-d"],
                capture_output=True, text=True, timeout=180,
            )
            if result.returncode != 0:
                evidence.append(f"compose up failed: {result.stderr[-400:]}")
                return {"success": False, "mode": "orchestrated", "evidence": evidence, "timestamp": timestamp}
            evidence.append("docker compose up succeeded")

            time.sleep(3)  # 等容器稳定
            ps = subprocess.run(
                ["docker", "compose", "-p", project_name, "-f", str(tmp_compose), "ps", "--format", "{{.Name}}\t{{.Status}}"],
                capture_output=True, text=True, timeout=30,
            )
            containers = [l for l in ps.stdout.strip().splitlines() if l]
            if not containers:
                evidence.append("no container found after compose up")
                return {"success": False, "mode": "orchestrated", "evidence": evidence, "timestamp": timestamp}

            main_name = None
            main_running = False
            for line in containers:
                name, status = line.split("\t", 1)
                evidence.append(f"container {name}: {status}")
                if main_service and main_service in name:
                    main_name = name
                    main_running = "Up" in status
            if not main_name:
                main_name = containers[0].split("\t")[0]
                main_running = "Up" in containers[0]
            if not main_running:
                evidence.append(f"main container {main_name} not running")
                return {"success": False, "mode": "orchestrated", "evidence": evidence, "timestamp": timestamp}
            evidence.append(f"main container {main_name} running")

            # 端口 readiness：读容器内 /proc/net/tcp 的 LISTEN 状态。比每次
            # docker run busybox nc 更可靠、更快，且不依赖目标镜像装 nc/curl。
            port = getattr(self, "_orchestrated_readiness_port", None)
            if port is None:
                ports = self.env.main_ports or []
                port = ports[0] if ports else None
            if port is not None:
                # DB/搜索类慢启动服务给更长窗口：最多 60 次 × 5s = 300s；
                # 普通服务 24 次 × 5s = 120s。
                attempts = 60 if self._is_slow_init_port(port) else 24
                ready = False
                detail = ""
                for _ in range(attempts):
                    ready, detail = self._container_port_listening(main_name, port)
                    if ready:
                        break
                    time.sleep(5)
                if ready:
                    evidence.append(f"port {port}: {detail}")
                else:
                    evidence.append(f"port {port} not listening after {attempts*5}s ({detail})")
                    return {"success": False, "mode": "orchestrated", "evidence": evidence, "timestamp": timestamp}

            return {"success": True, "mode": "orchestrated", "evidence": evidence, "timestamp": timestamp}

        except subprocess.TimeoutExpired:
            evidence.append("orchestrated verification timed out")
            return {"success": False, "mode": "orchestrated", "evidence": evidence, "timestamp": timestamp}
        except Exception as exc:
            evidence.append(f"orchestrated verification error: {exc}")
            return {"success": False, "mode": "orchestrated", "evidence": evidence, "timestamp": timestamp}
        finally:
            self._cleanup_orch_project(atom_dir, compose_src, flag_value, tmp_compose, project_name)

    def _cleanup_orch_project(
        self, atom_dir: Path, compose_src: Path, flag_value: str,
        tmp_compose: Path | None = None, project_name: str | None = None,
    ) -> None:
        """Tear down one orchestrated-verification compose project."""
        if tmp_compose is None:
            tmp_compose = atom_dir / "source_bundle" / ".orch-compose.yml"
        if project_name is None:
            cve_id = self.env.cve_id
            project_name = f"orch{cve_id.replace('-', '').lower()}"[:40]
        try:
            if tmp_compose.exists():
                subprocess.run(
                    ["docker", "compose", "-p", project_name, "-f", str(tmp_compose), "down", "-v"],
                    capture_output=True, text=True, timeout=60,
                )
        except Exception:
            pass
        if tmp_compose and tmp_compose.exists():
            try:
                tmp_compose.unlink()
            except OSError:
                pass

    @staticmethod
    def _build_source_bundle_manifest(atom_dir: Path):
        """扫描 atom_dir/source_bundle/ 生成 SourceBundle manifest + sha256。

        Delegates to the shared scan_source_bundle so all callers get the
        same material-metadata classification. Kept for backward
        compatibility with tests and scripts that call this name directly.
        """
        from clab_builder.shared.source_bundle import scan_source_bundle
        return scan_source_bundle(atom_dir, source_kind="vulhub")

    @staticmethod
    def _readiness_port_for_access(exploit_access, fallback_ports) -> int | None:
        """Prefer the recorded exploit entry over Compose port ordering."""
        service = getattr(exploit_access, "required_service", {}) or {}
        try:
            port = int(service.get("port"))
            if port > 0:
                return port
        except (TypeError, ValueError):
            pass
        for port in fallback_ports or []:
            try:
                return int(port)
            except (TypeError, ValueError):
                continue
        return None

    def _capture_current_source_bundle(self, atom_dir: Path):
        """Capture a rebuild's source tree, with legacy-bundle fallback."""
        from clab_builder.shared.source_bundle import capture_source_bundle

        source = Path(self.vulhub_dir).resolve()
        if source.is_dir():
            source_kind = "cve_factory" if (
                (source / "tests" / "test_vuln.py").is_file()
                or (source / "task.yaml").is_file()
            ) else "vulhub"
            bundle = capture_source_bundle(source, atom_dir, source_kind=source_kind)
            if bundle is not None:
                return bundle
        return self._build_source_bundle_manifest(atom_dir)

    @staticmethod
    def _force_rmtree(path) -> None:
        """Remove a directory tree, surviving files owned by another uid.

        The agent container (uid 1000) writes .claude_cache subdirs as its own
        uid. When the host user is a different uid, shutil.rmtree raises
        PermissionError on those entries and the whole pipeline aborts. Fall
        back to a root docker container (alpine) to wipe them, then retry.
        """
        path = Path(path)
        if not path.exists():
            return
        try:
            shutil.rmtree(path)
            return
        except (PermissionError, OSError) as exc:
            print(f"  [cleanup] host cannot rmtree {path} ({exc}); wiping via root container")
        abs_path = str(path.resolve())
        try:
            subprocess.run(
                ["docker", "run", "--rm", "-v", f"{abs_path}:/wipe:rw", "alpine:latest",
                 "sh", "-c", "rm -rf /wipe && mkdir -p /wipe"],
                capture_output=True, text=True, timeout=60,
            )
            shutil.rmtree(path)
        except Exception as exc:
            print(f"  [cleanup] forced rmtree failed for {path}: {exc}")

    @staticmethod
    def _extract_capability_executors(atom_dir) -> dict:
        """从 agent 轨迹（session.json）提取可复用命令执行通道。

        扫描 agent 的 Bash 工具调用，找"命令执行锚点"（shell_exec/FROM PROGRAM/
        Runtime.exec/webshell ?cmd=/exploit.py "命令"）。如果 2+ 个调用通过同一
        锚点类型执行了不同命令，说明通道可复用，生成 capability_executor。

        只对真实验证过"可执行任意命令"的 atom 生成 verified=true executor。
        通道不适合 stateless 调用的（需上传文件/探测参数）不会匹配，自然不生成。
        """
        import json as _json
        from clab_builder.shared.models.atom import CapabilityExecutor

        session_path = atom_dir / "session.json"
        if not session_path.exists():
            return {}

        # 加载 agent 的 Bash 命令
        raw = session_path.read_text(encoding="utf-8", errors="replace")
        entries: list = []
        try:
            parsed = _json.loads(raw)
            entries = parsed if isinstance(parsed, list) else [parsed]
        except _json.JSONDecodeError:
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(_json.loads(line))
                except _json.JSONDecodeError:
                    continue

        commands: list[str] = []
        for entry in entries:
            message = entry.get("message", entry) if isinstance(entry, dict) else {}
            for block in message.get("content", []) or []:
                if not isinstance(block, dict):
                    continue
                if block.get("type") != "tool_use" or block.get("name") != "Bash":
                    continue
                cmd = (block.get("input") or {}).get("command", "")
                if cmd:
                    commands.append(cmd)

        if len(commands) < 2:
            return {}

        # 命令执行锚点：(正则, template替换形式)
        # 正则的 group(1) 匹配"被执行的具体命令"
        anchors = [
            (re.compile(r'shell_exec\(["\'](.*?)["\']\)'),
             'shell_exec("{{command_b64}} | base64 -d")'),
            (re.compile(r"FROM\s+PROGRAM\s+'(.*?)'"),
             "FROM PROGRAM '{{command}}'"),
            (re.compile(r'Runtime\.getRuntime\(\)\.exec\(\\*["\'](.*?)\\*["\']\)'),
             'Runtime.getRuntime().exec("{{command_b64}} | base64 -d")'),
            (re.compile(r'[?&]cmd=([^&"\s\\]*)'),
             "?cmd={{command_b64}}"),
            (re.compile(r'(python3?\s+\S+\.py\s+[\d.]+\s+\d+\s+)"([^"]*)"'),
             r'\1"{{command}}"'),
        ]

        for anchor_re, template_form in anchors:
            matched: list[tuple[str, str]] = []
            for cmd in commands:
                for m in anchor_re.finditer(cmd):
                    extracted = m.group(1).strip()
                    # 过滤占位符、空、过长的（>200 字符不像命令）
                    if extracted and not extracted.startswith("{") and len(extracted) < 200:
                        matched.append((cmd, extracted))
            if len(matched) < 2:
                continue
            unique_commands = {c for _, c in matched}
            if len(unique_commands) < 2:
                continue  # 所有命令相同，没有"不同命令"证据

            # 用第一个匹配的完整命令作为 template 基础
            base_cmd = matched[0][0]
            # IP 模板化
            base_cmd = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "{{target_ip}}", base_cmd)
            # 替换第一个锚点匹配为 template 形式
            first_match = anchor_re.search(base_cmd)
            if not first_match:
                continue
            template = base_cmd[:first_match.start()] + template_form + base_cmd[first_match.end():]

            # 验证 template 含 {{command}} 或 {{command_b64}}
            if "{{command}}" not in template and "{{command_b64}}" not in template:
                continue

            # 质量过滤：只保留可安全参数化的单行 stateless 通道。
            # 去掉开头的注释行（agent 常在命令前加 # 说明）
            lines = template.split("\n")
            while lines and lines[0].lstrip().startswith("#"):
                lines = lines[1:]
            template = "\n".join(lines).strip()
            if not template:
                continue
            # 无法安全参数化的通道直接放弃（不生成 executor）：
            # - heredoc / 写文件：结构依赖 << 标记，参数化会破坏
            # - python -c 多行脚本：换行是语法的一部分，不能压缩
            # - 需要先获取 session token 的复杂前置
            if " << " in template or template.startswith("cat >"):
                continue
            if template.startswith(("python3 -c", "python -c")):
                continue
            if template.startswith(("JSESSIONID=", "TOKEN=")):
                continue
            if len(template) > 500:
                continue
            if template.count(";") > 8:
                continue
            # 必须是 curl/psql 等单行命令开头（stateless 可调用）
            if not template.startswith(("curl ", "curl\t", "PGPASSWORD=", "psql ")):
                continue
            # 压缩多余空格但保留换行结构（单行命令无换行，不受影响）
            template = re.sub(r"[ \t]+", " ", template).strip()

            # 自动提取只生成候选（verified=false）。
            # verified=true 必须由专门的 sentinel 验证流程确认：
            # 先跑 exploit steps 建立通道，再执行随机无害命令验证。
            executor = CapabilityExecutor(
                mode="stateless",
                command_template=template,
                shell="/bin/sh",
                verified=False,
            )
            print(f"  [capability_executor] candidate (verified=false): {len(unique_commands)} unique commands via {anchor_re.pattern[:30]}")
            return {"execute_command": executor.model_dump(mode="json")}

        return {}

    @staticmethod
    def _infer_protocol(port) -> str:
        """从端口号推断协议，用于兼容构建 exploit_access。"""
        try:
            p = int(port)
        except (TypeError, ValueError):
            return "tcp"
        return {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
            1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql",
            5432: "postgres", 5900: "vnc", 6379: "redis", 7001: "http",
            8080: "http", 8443: "https", 8888: "http", 9042: "cassandra",
            9200: "elasticsearch", 9300: "elasticsearch", 11211: "memcached",
            27017: "mongodb", 50070: "hadoop",
        }.get(p, "tcp")

    @staticmethod
    def _build_capability_contract(agent_extra, verified, main_ports,
                                   env=None, vulhub_dir: str = ""):
        """从 agent 输出构建 (exploit_access, capability_grants)。

        agent 在新 prompt 下输出 exploit_access / capability_grants /
        exploit_principal。缺失时（老 prompt 兼容）：从已知端口推断
        exploit_access，从 pivot_capability 兼容映射 grants。

        当 agent 返回的 required_service 不完整或为空、且 main_ports 也
        为空时（CVE-Factory task 的 compose 常无 ports 映射），用共享
        service resolver 从 Dockerfile EXPOSE / test endpoint 推断补齐，
        不再回退成空的 required_service: {}。
        """
        from clab_builder.shared.models.atom import (
            ExploitAccess as _ExploitAccess,
            CapabilityGrant as _CapabilityGrant,
            CapabilityType as _CapabilityType,
            EvidenceLevel as _EvidenceLevel,
            PivotCapability as _PivotCapability,
        )

        ea_data = agent_extra.get("exploit_access")
        exploit_access = None
        if isinstance(ea_data, dict):
            required_service = ea_data.get("required_service")
            if not isinstance(required_service, dict) or not required_service:
                # agent 用 flat 字段 required_service_protocol / _port
                required_service = {
                    "protocol": ea_data.get("required_service_protocol"),
                    "port": ea_data.get("required_service_port"),
                }
            exploit_access = _ExploitAccess(
                attack_vector=ea_data.get("attack_vector", "network"),
                privileges_required=ea_data.get("privileges_required", "none"),
                required_service=required_service,
            )
        elif main_ports:
            port = main_ports[0]
            exploit_access = _ExploitAccess(
                attack_vector="network",
                privileges_required="none",
                required_service={
                    "protocol": AtomizerPipeline._infer_protocol(port),
                    "port": port,
                },
            )

        # If the agent returned an incomplete required_service (missing
        # protocol or port) or produced none at all, resolve the authoritative
        # service contract from the source tree instead of leaving it empty.
        # This is the core fix for the 211 atoms with required_service: {}.
        from clab_builder.shared.service_resolver import resolve_service_contract
        from pathlib import Path as _Path
        src_dir = _Path(vulhub_dir).resolve() if vulhub_dir else None
        resolved = resolve_service_contract(env, src_dir)
        if exploit_access is not None:
            rs = exploit_access.required_service or {}
            has_proto = bool(rs.get("protocol"))
            has_port = rs.get("port") is not None
            if (not has_proto or not has_port) and resolved is not None:
                rs = dict(rs)
                if not has_proto:
                    rs["protocol"] = resolved[0]
                if not has_port:
                    rs["port"] = resolved[1]
                exploit_access = _ExploitAccess(
                    attack_vector=exploit_access.attack_vector,
                    privileges_required=exploit_access.privileges_required,
                    required_service=rs,
                )
        elif resolved is not None:
            exploit_access = _ExploitAccess(
                attack_vector="network",
                privileges_required="none",
                required_service={"protocol": resolved[0], "port": resolved[1]},
            )

        # Evidence level: only the capabilities the agent actually verified
        # get VERIFIED. Without per-capability witness mapping (which the
        # current agent output schema does not provide), we cannot prove a
        # specific capability independently — but we can at least point the
        # evidence_ref at the real native evidence record so it is resolvable
        # by the qualification function and audit, instead of an opaque label
        # like "native-replay-01" that nothing can verify.
        #
        # Randomized per-capability witnesses (random command, random file,
        # random credential) are produced by the CVE-Factory PoC backend
        # (batches 7-9), which has the setup to inject and observe them.
        ev_level = _EvidenceLevel.VERIFIED if verified else _EvidenceLevel.INFERRED
        ev_ref = "verification.native_verification.evidence" if verified else \
                 "verification.native_verification.evidence"
        principal = agent_extra.get("exploit_principal") or "service_user"
        cap_list = agent_extra.get("capability_grants") or []
        capability_grants: list[_CapabilityGrant] = []
        if cap_list and isinstance(cap_list, list):
            for cap in cap_list:
                try:
                    capability_grants.append(_CapabilityGrant(
                        type=_CapabilityType(cap),
                        principal=principal,
                        evidence_level=ev_level,
                        evidence_ref=ev_ref,
                    ))
                except (ValueError, KeyError):
                    pass
        if not capability_grants:
            post_exploit = agent_extra.get("post_exploit") or {}
            pivot_raw = post_exploit.get("pivot_capability", "none") if isinstance(post_exploit, dict) else "none"
            try:
                pivot = _PivotCapability(pivot_raw)
            except ValueError:
                pivot = _PivotCapability.NONE
            compat_map = {
                _PivotCapability.SHELL: [
                    _CapabilityType.EXECUTE_COMMAND, _CapabilityType.NETWORK_VANTAGE,
                ],
                _PivotCapability.FULL_TOOLBOX: [
                    _CapabilityType.EXECUTE_COMMAND, _CapabilityType.NETWORK_VANTAGE,
                    _CapabilityType.READ_FILE,
                ],
                _PivotCapability.PORT_FORWARD: [_CapabilityType.NETWORK_VANTAGE],
                _PivotCapability.CREDENTIAL: [_CapabilityType.READ_CREDENTIAL],
            }
            for cap_type in compat_map.get(pivot, []):
                capability_grants.append(_CapabilityGrant(
                    type=cap_type,
                    principal=principal,
                    evidence_level=ev_level,
                    evidence_ref="verification.native_verification.evidence",
                ))
        # Fallback: when the agent emitted no exploit_access and the env has no
        # declared ports (e.g. CVE-Factory tasks whose compose lacks a ports
        # mapping), synthesize a minimal network-vector contract so downstream
        # code that calls exploit_access.model_dump() does not crash on None.
        if exploit_access is None:
            exploit_access = _ExploitAccess(
                attack_vector="network",
                privileges_required="none",
                required_service={},
            )
        return exploit_access, capability_grants

    @staticmethod
    def _infer_vuln_category(vuln_type: str) -> str:
        """从自由文本 vulnerability_type 推断标准分类"""
        vt = vuln_type.upper()
        if "PRIVILEGE" in vt or "LPE" in vt or "ESCALATION" in vt:
            return "LPE"
        if "DESERIALI" in vt:
            return "Deserialization"
        if "LFI" in vt or "FILE INCLUSION" in vt or "PATH TRAVERSAL" in vt:
            return "LFI"
        if "SSRF" in vt:
            return "SSRF"
        if "AUTH" in vt and ("BYPASS" in vt or "EVASION" in vt):
            return "Auth_Bypass"
        if "INFO" in vt or "LEAK" in vt or "DISCLOS" in vt:
            return "Info_Leak"
        if "INJECTION" in vt or "SQLI" in vt or "NOSQL" in vt:
            return "Injection"
        if "PARSING" in vt or "PARSE" in vt:
            return "Parsing"
        # 默认 RCE — 覆盖大部分情况
        return "RCE"

    @staticmethod
    def _normalize_vuln_category(value: str) -> str:
        """Normalize common agent aliases to AtomConfig VulnCategory values."""
        raw = (value or "").strip()
        compact = raw.lower().replace("-", "_").replace(" ", "_")
        aliases = {
            "sqli": "Injection",
            "sql_injection": "Injection",
            "nosqli": "Injection",
            "nosql_injection": "Injection",
            "command_injection": "RCE",
            "code_execution": "RCE",
            "remote_code_execution": "RCE",
            "rce": "RCE",
            "xss": "Injection",
            "xxe": "LFI",
            "path_traversal": "LFI",
            "directory_traversal": "LFI",
            "file_read": "LFI",
            "information_disclosure": "Info_Leak",
            "info_disclosure": "Info_Leak",
            "info_leak": "Info_Leak",
            "auth_bypass": "Auth_Bypass",
            "authentication_bypass": "Auth_Bypass",
            "privilege_escalation": "LPE",
            "lpe": "LPE",
            "deserialization": "Deserialization",
            "parsing": "Parsing",
            "ssrf": "SSRF",
            "lfi": "LFI",
            "rfi": "RFI",
        }
        if compact in aliases:
            return aliases[compact]
        valid = {
            "RCE", "LFI", "RFI", "SSRF", "Deserialization", "LPE",
            "Auth_Bypass", "Info_Leak", "Injection", "Parsing",
        }
        return raw if raw in valid else "RCE"

    @staticmethod
    def _evaluate_agent_success(agent_output, expected_flag: str = "") -> SuccessEvaluation:
        """Evaluate success using one compact rule set.

        The agent must report success. If this run planted a flag, the exact
        flag must be captured. If no flag was planted, objective evidence is the
        success proof.
        """
        if not agent_output:
            return SuccessEvaluation(False, False, reason="missing agent output")

        captured = (agent_output.captured_flag or "").strip()
        if expected_flag:
            flag_matched = captured == expected_flag
            reason = "flag matched" if flag_matched else (
                f"flag mismatch: expected {expected_flag}, got '{captured}'"
            )
            return SuccessEvaluation(flag_matched, flag_matched, captured, reason)

        if not agent_output.success:
            return SuccessEvaluation(False, False, captured, "agent reported failure")

        has_evidence = bool(agent_output.evidence)
        reason = "objective evidence present" if has_evidence else "missing objective evidence"
        return SuccessEvaluation(has_evidence, False, captured, reason)

    def _run_llm_checker(
        self,
        *,
        agent_output,
        vuln_category: str,
        api_key: str,
        base_url: str = "",
        model: str = "",
    ) -> LLMCheckResult:
        """Ask an LLM to judge non-flag objective evidence."""
        if not api_key:
            return LLMCheckResult(
                accepted=False,
                reason="LLM checker enabled but no API key was provided",
                confidence="low",
                model=model,
            )

        prompt = {
            "task": "Judge whether the agent's evidence proves the CVE objective in this local lab.",
            "rules": [
                "Return accepted=true only if the evidence directly proves the vulnerability described by the bug report.",
                "Reject if the proof relies on unrelated RCE, unrelated file reads, shell access, or flag hunting.",
                "Reject if exploit_steps are mostly failed probes rather than a reproducible final path.",
                "Do not require a flag; this checker is only used when no flag was planted.",
            ],
            "output_schema": {
                "accepted": True,
                "reason": "short reason",
                "issues": ["optional issue strings"],
                "confidence": "high|medium|low",
            },
            "cve_id": self.env.cve_id,
            "vuln_category": vuln_category,
            "bug_report": (self.env.readme_content or "")[:8000],
            "agent_result": {
                "success": bool(agent_output.success),
                "vulnerability_type": agent_output.vulnerability_type,
                "evidence": agent_output.evidence,
                "exploit_steps": agent_output.exploit_steps,
                "mitre_mapping": agent_output.mitre_mapping,
                "requirements": agent_output.requirements,
                "captured_flag": agent_output.captured_flag,
            },
        }

        checker_model = model or os.environ.get("LLM_MODEL", "claude-sonnet-4-6")
        try:
            # Prefer the anthropic SDK when available; fall back to the
            # OpenAI-compatible endpoint (the deploy API exposes both
            # /v1 and the Anthropic protocol on the same host). Using
            # openai keeps the checker working in environments where the
            # anthropic package is not installed but the OpenAI-compatible
            # /v1 endpoint is reachable.
            checker_base_url = base_url or os.environ.get("LLM_BASE_URL", "")
            text = ""
            try:
                from anthropic import Anthropic
                kwargs: dict[str, Any] = {"api_key": api_key}
                if checker_base_url:
                    kwargs["base_url"] = checker_base_url
                client = Anthropic(**kwargs)
                response = client.messages.create(
                    model=checker_model,
                    max_tokens=1000,
                    temperature=0,
                    messages=[{
                        "role": "user",
                        "content": (
                            "You are a strict dataset quality checker. "
                            "Respond with JSON only.\n\n"
                            + json.dumps(prompt, ensure_ascii=False, indent=2)
                        ),
                    }],
                )
                text = "\n".join(
                    getattr(block, "text", "")
                    for block in getattr(response, "content", [])
                    if getattr(block, "text", "")
                )
            except ImportError:
                import openai
                endpoint = checker_base_url.rstrip("/") if checker_base_url else ""
                if endpoint and not endpoint.endswith("/v1"):
                    endpoint = endpoint + "/v1"
                client = openai.OpenAI(api_key=api_key, base_url=endpoint)
                response = client.chat.completions.create(
                    model=checker_model,
                    max_tokens=4000,
                    temperature=0,
                    messages=[{
                        "role": "user",
                        "content": (
                            "You are a strict dataset quality checker. "
                            "Respond with JSON only.\n\n"
                            + json.dumps(prompt, ensure_ascii=False, indent=2)
                        ),
                    }],
                )
                content = response.choices[0].message.content
                if isinstance(content, list):
                    content = "".join(
                        str(c.get("text", "")) if isinstance(c, dict) else str(c)
                        for c in content
                    )
                text = str(content or "")
            data = self._extract_checker_json(text)
            return LLMCheckResult(
                accepted=bool(data.get("accepted")),
                reason=str(data.get("reason", "")).strip(),
                issues=[
                    str(item)
                    for item in data.get("issues", [])
                    if isinstance(item, (str, int, float))
                ],
                confidence=str(data.get("confidence", "unknown")),
                model=checker_model,
            )
        except Exception as exc:
            return LLMCheckResult(
                accepted=False,
                reason=f"LLM checker error: {exc}",
                confidence="low",
                model=checker_model,
            )

    @staticmethod
    def _extract_checker_json(text: str) -> dict[str, Any]:
        match = re.search(r"```json\s*(\{[\s\S]*?\})\s*```", text or "")
        candidates = [match.group(1)] if match else []
        if text:
            start = text.find("{")
            end = text.rfind("}")
            if start >= 0 and end > start:
                candidates.append(text[start:end + 1])
        for candidate in candidates:
            try:
                value = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                return value
        return {
            "accepted": False,
            "reason": "LLM checker did not return valid JSON",
            "issues": [text[:500] if text else "empty response"],
            "confidence": "low",
        }

    @staticmethod
    def _infer_primary_phase(mitre_mapping: dict) -> str:
        """从 mitre_mapping 推断主要阶段（取第一个有 techniques 的 key）"""
        phase_order = [
            "initial_access", "execution", "persistence",
            "privilege_escalation", "defense_evasion", "credential_access",
            "discovery", "lateral_movement", "collection",
            "command_and_control", "exfiltration", "impact",
        ]
        for phase in phase_order:
            techniques = mitre_mapping.get(phase, [])
            if techniques:  # 非空列表
                return phase
        # 兜底
        for phase, techniques in mitre_mapping.items():
            if techniques:
                return phase
        return "initial_access"

    @staticmethod
    def _normalize_mitre_phase(value: str) -> str:
        """Normalize common agent phase aliases to MitrePhase values."""
        raw = (value or "").strip()
        compact = raw.lower().replace("-", "_").replace(" ", "_")
        aliases = {
            "recon": "discovery",
            "reconnaissance": "discovery",
            "resource_development": "initial_access",
            "initialaccess": "initial_access",
            "privilege_escalation": "privilege_escalation",
            "privilegeescalation": "privilege_escalation",
            "defense_evasion": "defense_evasion",
            "credential_access": "credential_access",
            "lateral_movement": "lateral_movement",
            "command_control": "command_and_control",
            "command_and_control": "command_and_control",
        }
        if compact in aliases:
            return aliases[compact]
        valid = {
            "initial_access", "execution", "persistence", "privilege_escalation",
            "defense_evasion", "credential_access", "discovery",
            "lateral_movement", "collection", "command_and_control",
            "exfiltration", "impact",
        }
        return compact if compact in valid else "initial_access"

    @staticmethod
    def _infer_service_role(image: str) -> str:
        """从 docker image 名推断服务角色"""
        img = image.lower()
        db_keywords = ["redis", "mongo", "mysql", "postgres", "couchdb", "mariadb", "oracle"]
        mid_keywords = ["weblogic", "tomcat", "solr", "jboss", "wildfly", "glassfish",
                        "nginx", "apache", "goahead", "uwsgi"]
        web_keywords = ["grafana", "jenkins", "drupal", "wordpress", "joomla",
                        "confluence", "phpmyadmin", "mongo-express", "kibana"]
        fw_keywords = ["spring", "django", "laravel", "flask", "rails", "shiro", "struts"]
        file_keywords = ["samba", "ftp", "vsftpd", "proftpd", "nfs"]
        sys_keywords = ["polkit", "ssh", "openssh", "bash"]

        for kw in db_keywords:
            if kw in img:
                return "database"
        for kw in file_keywords:
            if kw in img:
                return "file_service"
        for kw in sys_keywords:
            if kw in img:
                return "system_service"
        for kw in fw_keywords:
            if kw in img:
                return "framework"
        for kw in mid_keywords:
            if kw in img:
                return "middleware"
        for kw in web_keywords:
            if kw in img:
                return "web_application"
        return "web_application"

    @staticmethod
    def _infer_complexity(agent_output) -> str:
        """推断攻击复杂度"""
        if not agent_output or not agent_output.exploit_steps:
            return "medium"
        steps = agent_output.exploit_steps
        tools = (agent_output.requirements or {}).get("tools_needed", [])
        # 需要编译/下载工具 → complex
        compile_tools = ["gcc", "make", "wget", "ysoserial", "maven"]
        if any(t in str(tools) for t in compile_tools):
            return "complex"
        # 多步骤 → medium
        if len(steps) > 3:
            return "complex"
        if len(steps) > 1:
            return "medium"
        return "simple"

    @staticmethod
    def _infer_attack_method(agent_output, env) -> str:
        """推断攻击方式"""
        if not agent_output or not agent_output.exploit_steps:
            return "single_request"
        tools = (agent_output.requirements or {}).get("tools_needed", [])
        steps = agent_output.exploit_steps
        commands = " ".join(s.get("command", "") for s in steps).lower()

        if "ssh" in commands or "sshpass" in str(tools):
            return "ssh_exploit"
        if "ysoserial" in commands or "deseriali" in commands:
            return "deserialization"
        if "nc -l" in commands or "netcat" in commands or "listener" in commands:
            return "reverse_callback"
        if "redis-cli" in commands or "nc " in commands and "6379" in commands:
            return "service_protocol"
        if "curl -x post" in commands or "upload" in commands:
            return "file_upload"
        if len(steps) > 3:
            return "multi_step_http"
        return "single_request"

    def _extract_wait_seconds(self, atom_dir: Path) -> int:
        """从 ansible/deploy.yaml 提取服务等待时间"""
        deploy_path = atom_dir / "ansible" / "deploy.yaml"
        if not deploy_path.exists():
            return 10
        try:
            deploy = yaml.safe_load(deploy_path.read_text())
            for play in (deploy if isinstance(deploy, list) else [deploy]):
                for task in play.get("tasks", []):
                    pause = task.get("ansible.builtin.pause", {})
                    if isinstance(pause, dict) and "seconds" in pause:
                        return int(pause["seconds"])
        except Exception:
            pass
        return 10

    def _load_init_file_mappings(self, atom_dir: Path) -> list:
        """从 vulhub compose volumes 推断 init file 映射并保存到 atom

        扫描 vulhub compose 中的 volumes，与 atom/init/ 目录对照，
        生成 InitFileMapping 列表供 orchestrator 消费。
        """
        from clab_builder.shared.models.atom import InitFileMapping

        init_dir = atom_dir / "init"
        if not init_dir.exists():
            return []

        mappings = []
        for svc in self.env.services:
            for vol in svc.volumes:
                if not isinstance(vol, str) or ":" not in vol:
                    continue
                parts = vol.split(":", 1)
                local_ref = parts[0]
                container_path = parts[1]

                # 本地文件名
                if local_ref.startswith("./"):
                    local_name = local_ref[2:]
                else:
                    local_name = local_ref

                # 检查 init/ 中是否存在
                init_path = init_dir / local_name
                if init_path.exists():
                    mappings.append(InitFileMapping(
                        container_path=container_path,
                        filename=local_name,
                        is_directory=init_path.is_dir(),
                    ))

        return mappings
