"""Atomizer Pipeline - 项目一主流程

从 vulhub CVE 目录到验证后的 atom 输出：
1. 解析 vulhub docker-compose → 生成 ansible/deploy.yaml
2. 启动 CVE 环境（docker-compose）
3. 启动 Agent 容器，传入 writeup
4. Agent 自主执行 exploit 并验证
5. 生成 playbook/sysfield.yaml
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
from .output.sysfield_playbook import SysFieldPlaybookGenerator
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

            # Step 4: 生成 playbook/sysfield.yaml
            print(f"\n[4/5] Generating playbook/sysfield.yaml")
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

        # 3. 注入 FLAG 环境变量到主服务容器
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
                    import shutil
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
        """从 Agent 结果生成 SysField playbook"""
        playbook_dir = atom_dir / "playbook"
        playbook_dir.mkdir(parents=True, exist_ok=True)

        sysfield_playbook = SysFieldPlaybookGenerator().generate(
            cve_id=self.env.cve_id,
            exploit_steps=agent_output.exploit_steps,
            mitre_mapping=agent_output.mitre_mapping,
            target_ip="{{ target_ip }}",
            target_port=cve_info.ports[0] if cve_info.ports else 80,
            vulnerability_type=agent_output.vulnerability_type,
            requirements=agent_output.requirements,
        )
        sysfield_path = playbook_dir / "sysfield.yaml"
        sysfield_path.write_text(sysfield_playbook)
        print(f"  Written: {sysfield_path}")

    def _save_atom(self, atom_dir: Path, agent_output=None):
        """保存 atom.yaml v2 元数据"""
        from datetime import datetime
        from clab_builder.shared.models.atom import (
            AtomConfig, VulnCategory, MitrePhase, ServiceRole,
            ExploitComplexity, AttackMethod, FlagMethod, FlagInjection,
            ServiceInfo, NetworkRequirements, DefaultCredentials, ServiceStartup,
        )

        verified = agent_output.success if agent_output else False
        mitre_mapping = agent_output.mitre_mapping if agent_output else {}
        vuln_type = agent_output.vulnerability_type if agent_output else ""
        requirements = agent_output.requirements if agent_output else {}
        evidence = agent_output.evidence if agent_output else []
        # Agent v2 输出的额外字段（向后兼容：缺失时走推断）
        agent_extra = {}
        if agent_output and hasattr(agent_output, "extra_fields"):
            agent_extra = agent_output.extra_fields or {}

        # 从 README 提取简短描述
        readme = self.env.readme_content
        short_desc = ""
        for line in readme.split("\n"):
            line = line.strip().strip("#")
            if line and len(line) > 10:
                short_desc = line[:200]
                break

        # 推断 v2 枚举字段（agent 明确输出时优先，否则走规则推断）
        vuln_category = VulnCategory(agent_extra.get("vuln_category")
                                     or self._infer_vuln_category(vuln_type))
        primary_phase = MitrePhase(agent_extra.get("primary_mitre_phase")
                                   or self._infer_primary_phase(mitre_mapping))
        service_role = ServiceRole(agent_extra.get("service_role")
                                   or self._infer_service_role(self.env.main_image))
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

        # FLAG 注入
        flag_method = FlagMethod.ENV_VAR
        if attack_method == AttackMethod.SSH_EXPLOIT:
            flag_method = FlagMethod.FILE
        flag_inj = FlagInjection(method=flag_method)
        if flag_method == FlagMethod.FILE:
            flag_inj.file_path = "/root/flag.txt"

        # FLAG 验证命令
        flag_cmd = agent_extra.get("flag_verify_command", "")

        # 服务启动（从 deploy.yaml 提取）
        init_file_mappings = self._load_init_file_mappings(atom_dir)
        startup = ServiceStartup(
            wait_seconds=self._extract_wait_seconds(atom_dir),
            health_check=agent_extra.get("health_check"),
            init_tasks=agent_extra.get("init_tasks", []),
            init_files=init_file_mappings,
        )

        config = AtomConfig(
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
            service_startup=startup,
            verified=verified,
            requirements=requirements,
            evidence=evidence[:5],
            timestamp=datetime.now().isoformat(),
            source=str(self.vulhub_dir),
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

    # ── v2 字段推断辅助 ─────────────────────────────────

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
