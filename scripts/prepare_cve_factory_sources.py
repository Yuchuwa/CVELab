"""CVE-Factory 任务包 → atomizer 可消费的 source 目录适配层。

CVE-Factory 的 compose 用 bench 框架占位符 (${T_BENCH_*}) 和 build 模式，
atomizer 期望 Vulhub 风格的 docker-compose.yml（image 字段是真实镜像名）。

本脚本做以下转换:
  1. 复制任务包到 data/generated/cve_factory_wave1/<CVE>/
  2. docker-compose.yaml → docker-compose.yml
  3. 展开 ${T_BENCH_*} 占位符为具体值
  4. 给 service 一个可预测的 image 名 (cve-<id>:vuln), 保留 build 字段
  5. 去掉 bench 框架专用的 volumes/healthcheck/environment
  6. 保留 command/entrypoint 让服务正常启动
  7. 生成 README.md (如果没有)
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path

import yaml


def _resolve_bench_vars(value, cve_id: str):
    """递归展开 ${T_BENCH_*} 占位符。"""
    if isinstance(value, str):
        def replacer(m):
            var = m.group(1)
            mapping = {
                "T_BENCH_TASK_DOCKER_CLIENT_IMAGE_NAME": f"cve-{cve_id.lower()}:vuln",
                "T_BENCH_TASK_DOCKER_CLIENT_CONTAINER_NAME": f"cve-{cve_id.lower()}-client",
                "T_BENCH_TEST_DIR": "/tests",
                "T_BENCH_TASK_LOGS_PATH": "/tmp/logs",
                "T_BENCH_CONTAINER_LOGS_PATH": "/tmp/container-logs",
                "T_BENCH_TASK_AGENT_LOGS_PATH": "/tmp/agent-logs",
                "T_BENCH_CONTAINER_AGENT_LOGS_PATH": "/tmp/container-agent-logs",
            }
            return mapping.get(var, m.group(0))
        return re.sub(r"\$\{(\w+)\}", replacer, value)
    if isinstance(value, list):
        return [_resolve_bench_vars(v, cve_id) for v in value]
    if isinstance(value, dict):
        return {k: _resolve_bench_vars(v, cve_id) for k, v in value.items()}
    return value


def _normalize_compose(compose_data: dict, cve_id: str, dst: Path) -> dict:
    """把 bench 风格 compose 转成 atomizer 能消费的形态。"""
    services = compose_data.get("services") or {}
    if not services:
        return compose_data

    new_services = {}
    for svc_name, svc_cfg in services.items():
        cfg = dict(svc_cfg or {})

        # 给一个可预测的 image 名; 保留 build 字段让 compose 本地构建
        image_name = f"cve-{cve_id.lower()}:vuln"
        cfg["image"] = image_name
        if "build" not in cfg:
            cfg["build"] = {"dockerfile": "Dockerfile", "context": "."}
        # CVE-Factory Dockerfiles typically `git clone` from GitHub during
        # build. The build container's default network cannot reach GitHub in
        # this deployment, so build with the host network where GitHub is
        # reachable. This is the key adaptation that lets CVE-Factory tasks
        # build on the host Docker daemon instead of the DinD environment they
        # were designed for.
        build_cfg = cfg["build"]
        if isinstance(build_cfg, dict):
            build_cfg.setdefault("network", "host")
        else:
            cfg["build"] = {"dockerfile": "Dockerfile", "context": ".", "network": "host"}

        # CVE-Factory tasks rarely map host ports; the service port lives in
        # Dockerfile EXPOSE or the test endpoint. Write it as compose `expose`
        # (container-only, no host binding) so VulhubParser.main_ports can
        # resolve a container port and the atom gets a non-empty
        # required_service instead of {}.
        if not cfg.get("ports") and not cfg.get("expose"):
            import re as _re
            ports: list[int] = []
            df = dst / "Dockerfile"
            if df.is_file():
                for line in df.read_text(errors="replace").splitlines():
                    if line.strip().startswith("EXPOSE"):
                        for m in _re.findall(r"\b(\d+)(?:/\w+)?\b", line):
                            try:
                                ports.append(int(m))
                            except ValueError:
                                pass
            if not ports:
                # fall back to the test endpoint
                tests_dir = dst / "tests"
                for tn in ("test_vuln.py", "test_func.py"):
                    tp = tests_dir / tn
                    if not tp.is_file():
                        continue
                    try:
                        text = tp.read_text(errors="replace")[:4000]
                    except OSError:
                        continue
                    m = _re.search(r"APP_URL[^'\"}]*['\"]http://[^:/]+:(\d+)", text)
                    if m:
                        try:
                            ports.append(int(m.group(1)))
                            break
                        except ValueError:
                            pass
                    m = _re.search(r"localhost:(\d+)", text)
                    if m:
                        try:
                            ports.append(int(m.group(1)))
                            break
                        except ValueError:
                            pass
            if ports:
                cfg["expose"] = [str(ports[0])]

        # 去掉 bench 框架专用字段
        cfg.pop("container_name", None)
        cfg.pop("healthcheck", None)
        volumes = cfg.get("volumes")
        if isinstance(volumes, list):
            cfg["volumes"] = [
                v for v in volumes
                if not (isinstance(v, str) and ("T_BENCH" in v or "agent-logs" in v or "container-logs" in v))
            ]
            if not cfg["volumes"]:
                cfg.pop("volumes")

        # 去掉 bench 专用 environment, 保留有意义的
        env = cfg.get("environment")
        if isinstance(env, list):
            cfg["environment"] = [
                e for e in env
                if not (isinstance(e, str) and e.startswith("TEST_DIR="))
            ]
            if not cfg["environment"]:
                cfg.pop("environment")
        elif isinstance(env, dict):
            cfg["environment"] = {
                k: v for k, v in env.items()
                if k != "TEST_DIR"
            }
            if not cfg["environment"]:
                cfg.pop("environment")

        # 保留 restart, command
        new_services[svc_name] = cfg

    compose_data["services"] = new_services
    return compose_data


def main() -> int:
    root = Path("CVE-Factory/cve_tasks")
    tasks_file = Path("data/cve_factory_wave1_tasks.txt")
    out_root = Path("data/generated/cve_factory_wave1")
    out_root.mkdir(parents=True, exist_ok=True)

    prepared = 0
    skipped = 0
    for rel in tasks_file.read_text().splitlines():
        rel = rel.strip()
        if not rel:
            continue
        src = root / rel
        if not src.is_dir():
            skipped += 1
            continue

        cve_id = src.name.upper()
        dst = out_root / cve_id
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst)

        # docker-compose.yaml → docker-compose.yml
        compose_yaml = dst / "docker-compose.yaml"
        compose_yml = dst / "docker-compose.yml"
        if compose_yaml.exists() and not compose_yml.exists():
            compose_yaml.rename(compose_yml)

        # 解析 + 规范化 compose
        if compose_yml.exists():
            data = yaml.safe_load(compose_yml.read_text()) or {}
            data = _resolve_bench_vars(data, cve_id)
            data = _normalize_compose(data, cve_id, dst)
            compose_yml.write_text(
                yaml.dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True),
                encoding="utf-8",
            )

        # 生成 README.md (如果没有)
        readme = dst / "README.md"
        if not readme.exists():
            meta = {}
            task_yaml = dst / "task.yaml"
            if task_yaml.exists():
                meta = yaml.safe_load(task_yaml.read_text()) or {}
            instruction = str(meta.get("instruction", ""))[:500]
            lines = [
                f"# {cve_id}",
                "",
                "Generated from CVE-Factory task.",
                f"- task_path: {rel}",
                f"- category: {meta.get('category', '')}",
                f"- difficulty: {meta.get('difficulty', '')}",
                "",
                "## Description",
                instruction,
            ]
            readme.write_text("\n".join(lines) + "\n", encoding="utf-8")

        prepared += 1

    print(f"prepared: {prepared}, skipped: {skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())