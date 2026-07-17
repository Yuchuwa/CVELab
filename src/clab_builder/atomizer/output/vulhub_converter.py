"""Vulhub docker-compose 到 Ansible playbook 转换器

解析 vulhub 的 docker-compose.yml，生成标准的 Ansible playbook。
纯确定性转换，不需要 AI 参与。
"""

import yaml
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass, field


def container_port_from_spec(port_spec: Any) -> int | None:
    """Return the container/internal port from a Docker Compose port spec."""
    if isinstance(port_spec, dict):
        target = port_spec.get("target") or port_spec.get("container")
        if target is None:
            return None
        port_text = str(target)
    else:
        port_text = str(port_spec).split(":")[-1]

    port_text = port_text.split("/", 1)[0].strip()
    if not port_text:
        return None
    try:
        return int(port_text)
    except ValueError:
        return None


@dataclass
class VulhubService:
    """解析后的单个服务"""
    name: str
    image: str
    ports: List[str] = field(default_factory=list)
    expose: List[str] = field(default_factory=list)
    environment: Dict[str, str] = field(default_factory=dict)
    volumes: List[str] = field(default_factory=list)
    depends_on: List[str] = field(default_factory=list)
    command: str | None = None
    entrypoint: str | None = None
    is_main_target: bool = False
    user: str | None = None


@dataclass
class VulhubEnvironment:
    """解析后的 vulhub 环境"""
    cve_id: str
    category: str
    services: List[VulhubService]
    main_service: VulhubService | None = None
    readme_content: str = ""

    @property
    def main_image(self) -> str:
        svc = self.main_service or (self.services[0] if self.services else None)
        return svc.image if svc else ""

    @property
    def main_ports(self) -> List[int]:
        """容器内部端口（供 CLab 内部网络访问用，非宿主机映射端口）

        优先取 compose ``ports`` 的容器侧端口；当 ``ports`` 为空时回退到
        ``expose``（CVE-Factory task 常用 expose 而非 host 映射）。
        """
        svc = self.main_service
        if not svc:
            return []
        result = []
        for p in svc.ports:
            # "8080:80" → 80 (container port), "8080" → 8080
            port = container_port_from_spec(p)
            if port is not None:
                result.append(port)
        if not result:
            for p in svc.expose:
                port = container_port_from_spec(str(p))
                if port is not None:
                    result.append(port)
        return result


class VulhubParser:
    """解析 vulhub docker-compose.yml + README"""

    def parse(self, vulhub_dir: str) -> VulhubEnvironment:
        vulhub_path = Path(vulhub_dir)

        # 解析 docker-compose.yml
        compose_file = vulhub_path / "docker-compose.yml"
        if not compose_file.exists():
            raise FileNotFoundError(f"Not found: {compose_file}")

        with open(compose_file) as f:
            compose = yaml.safe_load(f)

        # 从路径提取 cve_id 和 category
        parts = vulhub_path.resolve().parts
        if "vulhub" in parts:
            idx = list(parts).index("vulhub")
            category = parts[idx + 1]
            cve_id = parts[idx + 2]
        else:
            category = vulhub_path.parent.name
            cve_id = vulhub_path.name

        # 解析服务
        services = []
        main_service = None
        for name, cfg in compose.get("services", {}).items():
            image = cfg.get("image", "")
            # 如果 compose 用 build 而不是 image，从 Dockerfile 提取 FROM
            if not image and cfg.get("build"):
                dockerfile = vulhub_path / (
                    cfg["build"] if isinstance(cfg["build"], str) else cfg["build"].get("dockerfile", "Dockerfile")
                )
                if isinstance(cfg["build"], str):
                    dockerfile = vulhub_path / cfg["build"] / "Dockerfile"
                elif isinstance(cfg["build"], dict):
                    dockerfile = vulhub_path / cfg["build"].get("context", ".") / cfg["build"].get("dockerfile", "Dockerfile")
                else:
                    dockerfile = vulhub_path / "Dockerfile"
                if dockerfile.exists():
                    for line in dockerfile.read_text().splitlines():
                        line = line.strip()
                        if line.startswith("FROM "):
                            image = line.split()[1]
                            break

            svc = VulhubService(
                name=name,
                image=image,
                ports=[str(p) for p in cfg.get("ports", [])],
                expose=[str(e) for e in (cfg.get("expose") or [])],
                environment=self._parse_env(cfg.get("environment")),
                volumes=cfg.get("volumes", []),
                depends_on=cfg.get("depends_on", []),
                command=self._normalize_command(cfg.get("command")),
                entrypoint=self._normalize_command(cfg.get("entrypoint")),
                user=cfg.get("user"),
            )
            if "vulhub/" in svc.image:
                svc.is_main_target = True
                main_service = svc
            services.append(svc)

        if not main_service and services:
            services[0].is_main_target = True
            main_service = services[0]

        # 读取 README
        readme_path = vulhub_path / "README.md"
        readme = ""
        if readme_path.exists():
            readme = readme_path.read_text(encoding="utf-8")

        return VulhubEnvironment(
            cve_id=cve_id,
            category=category,
            services=services,
            main_service=main_service,
            readme_content=readme,
        )

    def _parse_env(self, env: Any) -> Dict[str, str]:
        if isinstance(env, dict):
            return {str(k): str(v) for k, v in env.items()}
        if isinstance(env, list):
            return {
                parts[0]: parts[1]
                for item in env
                if "=" in str(item)
                for parts in [str(item).split("=", 1)]
            }
        return {}

    @staticmethod
    def _normalize_command(value: Any) -> str | None:
        """Normalize Compose string/list command forms for the atom contract."""
        if value is None:
            return None
        if isinstance(value, list):
            # Compose exec-form commands need argument boundaries preserved when
            # they are later rendered into a ContainerLab shell command.
            import shlex
            return shlex.join(str(item) for item in value)
        text = str(value).strip()
        return text or None


class AnsiblePlaybookGenerator:
    """从 VulhubEnvironment 生成 Ansible deploy playbook"""

    def generate(self, env: VulhubEnvironment,
                 network_name: str = "cve-network") -> str:
        prefix = env.cve_id.lower().replace("-", "")
        tasks = []

        # 1. 创建网络
        tasks.append({
            "name": f"Create network {network_name}",
            "community.docker.docker_network": {
                "name": network_name,
                "state": "present",
            }
        })

        # 2. 按依赖顺序启动服务
        for svc in self._topo_sort(env.services):
            container_name = f"{prefix}-{svc.name}"
            docker_cfg = {
                "name": container_name,
                "image": svc.image,
                "state": "started",
                "networks_cli_compatible": True,
                "networks": [{"name": network_name}],
                "restart_policy": "unless-stopped",
            }

            if svc.ports:
                docker_cfg["published_ports"] = svc.ports
            if svc.environment:
                docker_cfg["env"] = svc.environment
            if svc.volumes:
                docker_cfg["volumes"] = svc.volumes
            if svc.command:
                docker_cfg["command"] = svc.command
            if svc.entrypoint:
                docker_cfg["entrypoint"] = svc.entrypoint

            tasks.append({
                "name": f"Start {svc.name} ({svc.image})",
                "community.docker.docker_container": docker_cfg,
            })

            # 主服务：等待就绪
            if svc.is_main_target and svc.ports:
                tasks.append({
                    "name": f"Wait for {svc.name}",
                    "ansible.builtin.pause": {"seconds": 10},
                })

        playbook = [{
            "name": f"Deploy {env.cve_id}",
            "hosts": "localhost",
            "gather_facts": False,
            "tasks": tasks,
        }]

        return yaml.dump(playbook, default_flow_style=False,
                         sort_keys=False, allow_unicode=True)

    def _topo_sort(self, services: List[VulhubService]) -> List[VulhubService]:
        name_map = {s.name: s for s in services}
        visited, result = set(), []

        def visit(name):
            if name in visited:
                return
            visited.add(name)
            svc = name_map.get(name)
            if svc:
                for dep in svc.depends_on:
                    visit(dep)
                result.append(svc)

        for svc in services:
            visit(svc.name)
        return result


def convert_vulhub_to_ansible(vulhub_dir: str, output_path: str,
                               network_name: str = "cve-network") -> str:
    """一站式: vulhub dir → ansible deploy.yaml"""
    env = VulhubParser().parse(vulhub_dir)
    playbook = AnsiblePlaybookGenerator().generate(env, network_name)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(playbook)
    return playbook
