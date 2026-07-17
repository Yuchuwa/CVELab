#!/usr/bin/env python3
"""对 8 个已生成 v3 atom 跑 orchestrated 验证，更新 verification + verified。

不重跑 agent。native_verification 已在 migrate_atoms_v3_verification.py 填好。
本脚本跑 _run_orchestrated_verification（用 source_bundle/docker-compose.yml 重建环境），
把结果填入 orchestrated_verification，native+orchestrated 都通过则 verified=True。
"""
import sys
import yaml
from pathlib import Path
from datetime import datetime

sys.path.insert(0, "src")
from clab_builder.atomizer.pipeline import AtomizerPipeline
from clab_builder.shared.models.atom import AtomConfig

CVES = [
    "CVE-2012-1823", "CVE-2013-4547", "CVE-2014-3120", "CVE-2017-10271",
    "CVE-2018-10933", "CVE-2018-16509", "CVE-2019-11043", "CVE-2019-9193",
]

ATOMS_DIR = Path("data/atoms")


class _Env:
    def __init__(self, cve_id, ports, image):
        self.cve_id = cve_id
        self.main_ports = ports
        self.main_image = image


class _PipeStub:
    """最小 stub 绑定 AtomizerPipeline 的实例方法。"""
    _run_orchestrated_verification = AtomizerPipeline._run_orchestrated_verification
    _build_source_bundle_manifest = AtomizerPipeline._build_source_bundle_manifest


def update_one(cve: str) -> None:
    atom_dir = ATOMS_DIR / cve
    atom_path = atom_dir / "atom.yaml"
    if not atom_path.exists():
        print(f"  {cve}: MISSING, skip")
        return
    raw = yaml.safe_load(atom_path.read_text()) or {}
    ports = (raw.get("runtime_spec") or {}).get("ports") or raw.get("ports") or []
    image = raw.get("docker_image") or ""

    pipe = _PipeStub()
    pipe.env = _Env(cve, ports, image)

    flag_value = raw.get("flag_value") or ""
    print(f"  {cve}: running orchestrated verification (ports={ports})...")
    orch = pipe._run_orchestrated_verification(atom_dir, flag_value)

    verification = raw.get("verification") or {}
    verification["orchestrated_verification"] = orch
    raw["verification"] = verification

    # native + orchestrated 都成功才 verified=True
    native_ok = (verification.get("native_verification") or {}).get("success") is True
    orch_ok = orch["success"] is True
    raw["verified"] = bool(native_ok and orch_ok)

    config = AtomConfig(**raw)
    atom_path.write_text(yaml.dump(
        config.model_dump(exclude_none=True, mode="json"),
        default_flow_style=False, sort_keys=False, allow_unicode=True,
    ))
    print(f"  {cve}: orch={orch['success']} verified={config.verified} evidence={orch['evidence'][-1] if orch['evidence'] else ''}")


def main():
    print("=== orchestrated verification for 8 atoms ===")
    for cve in CVES:
        update_one(cve)
    print("=== done ===")


if __name__ == "__main__":
    main()