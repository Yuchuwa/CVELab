#!/usr/bin/env python3
"""迁移脚本：修复所有已验证 atom 的端口和 init 文件

修复内容：
1. 端口：从 vulhub compose 重新解析容器内部端口（非宿主机映射端口）
2. Init 文件：从 vulhub compose 的 volumes 拷贝到 atom/init/
3. Init files 映射：更新 atom.yaml 的 service_startup.init_files
"""

import yaml
import shutil
import sys
from pathlib import Path

ATOMS_DIR = Path("data/atoms")


def find_vulhub_compose(atom_data: dict) -> Path | None:
    """找到 atom 对应的 vulhub docker-compose.yml"""
    source = atom_data.get("source", "")
    if not source:
        return None
    compose = Path(source) / "docker-compose.yml"
    return compose if compose.exists() else None


def parse_container_ports(compose_path: Path, main_image: str) -> list[int]:
    """从 compose 解析容器内部端口"""
    with open(compose_path) as f:
        data = yaml.safe_load(f)

    ports = []
    for name, svc in data.get("services", {}).items():
        image = svc.get("image", "")
        if main_image in image or "vulhub/" in image:
            for p in svc.get("ports", []):
                # "8080:80" → 80, "8080" → 8080
                internal = int(str(p).split(":")[-1])
                ports.append(internal)
    return ports


def parse_volumes(compose_path: Path) -> list[dict]:
    """从 compose 解析 volume 挂载

    Returns:
        [{"local_ref": "./safe.cgi", "container_path": "/var/www/html/safe.cgi"}]
    """
    with open(compose_path) as f:
        data = yaml.safe_load(f)

    volumes = []
    for name, svc in data.get("services", {}).items():
        for vol in svc.get("volumes", []):
            if isinstance(vol, str) and ":" in vol:
                parts = vol.split(":", 1)
                local_ref = parts[0]
                container_path = parts[1]
                volumes.append({
                    "local_ref": local_ref,
                    "container_path": container_path,
                })
    return volumes


def copy_init_files(atom_dir: Path, compose_path: Path, volumes: list[dict]) -> list[dict]:
    """拷贝 vulhub volume 文件到 atom/init/

    Returns:
        init_files list for atom.yaml
    """
    init_dir = atom_dir / "init"
    init_dir.mkdir(exist_ok=True)

    vulhub_dir = compose_path.parent
    init_files = []

    for vol in volumes:
        local_ref = vol["local_ref"]
        container_path = vol["container_path"]

        if local_ref.startswith("./"):
            local_name = local_ref[2:]
        else:
            local_name = local_ref

        src = vulhub_dir / local_name
        if not src.exists():
            print(f"    SKIP: {local_name} not found in {vulhub_dir}")
            continue

        dest = init_dir / local_name
        is_dir = src.is_dir()

        if is_dir:
            if dest.exists():
                shutil.rmtree(str(dest))
            shutil.copytree(str(src), str(dest))
            print(f"    DIR: {local_name}/ → {container_path}")
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dest))
            print(f"    FILE: {local_name} → {container_path}")

        init_files.append({
            "container_path": container_path,
            "filename": local_name,
            "is_directory": is_dir,
        })

    return init_files


def migrate_atom(atom_dir: Path) -> bool:
    """迁移单个 atom，返回是否有变更"""
    atom_yaml = atom_dir / "atom.yaml"
    if not atom_yaml.exists():
        print(f"  SKIP: no atom.yaml")
        return False

    data = yaml.safe_load(atom_yaml.read_text())
    cve_id = data.get("cve_id", atom_dir.name)
    main_image = data.get("docker_image", "")
    changed = False

    # 找 vulhub compose
    compose = find_vulhub_compose(data)
    if not compose:
        print(f"  SKIP: vulhub source not found")
        return False

    # 1. 修复端口
    new_ports = parse_container_ports(compose, main_image)
    old_ports = data.get("ports", [])
    if new_ports and new_ports != old_ports:
        print(f"  PORTS: {old_ports} → {new_ports}")
        data["ports"] = new_ports
        changed = True
    elif not new_ports:
        print(f"  PORTS: no ports found in compose (keeping {old_ports})")

    # 2. 拷贝 init 文件
    volumes = parse_volumes(compose)
    if volumes:
        print(f"  VOLUMES: {len(volumes)} volume mounts found")
        init_files = copy_init_files(atom_dir, compose, volumes)
        if init_files:
            # 更新 atom.yaml 的 service_startup.init_files
            startup = data.setdefault("service_startup", {})
            startup["init_files"] = init_files
            changed = True
    else:
        print(f"  VOLUMES: none")

    # 3. 保存
    if changed:
        atom_yaml.write_text(
            yaml.dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True)
        )
        print(f"  SAVED: {atom_yaml}")

    return changed


def main():
    print("=== Atom Migration ===\n")

    migrated = 0
    skipped = 0
    unchanged = 0

    for atom_dir in sorted(ATOMS_DIR.iterdir()):
        if not atom_dir.is_dir():
            continue

        cve_id = atom_dir.name
        print(f"[{cve_id}]")

        try:
            if migrate_atom(atom_dir):
                migrated += 1
            else:
                unchanged += 1
        except Exception as e:
            print(f"  ERROR: {e}")
            skipped += 1

        print()

    print(f"=== Done: {migrated} migrated, {unchanged} unchanged, {skipped} errors ===")


if __name__ == "__main__":
    main()
