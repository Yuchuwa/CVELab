#!/usr/bin/env python3
"""离线迁移 8 个已生成 v4 capability 的 atom：补 verification + source_bundle + version=3。

不重跑 agent。从现有 atom.yaml 的 evidence/flag_value 推断 native_verification，
orchestrated_verification 留占位 success=False。扫描 source_bundle/ 生成 manifest。
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


def migrate_one(cve: str) -> None:
    atom_dir = ATOMS_DIR / cve
    atom_path = atom_dir / "atom.yaml"
    if not atom_path.exists():
        print(f"  {cve}: MISSING atom.yaml, skip")
        return
    raw = yaml.safe_load(atom_path.read_text()) or {}

    # 构造 native_verification：agent 已跑通的证据来自 evidence + flag_value
    evidence = raw.get("evidence") or []
    flag_value = raw.get("flag_value") or ""
    has_id = any("uid=" in str(e) for e in evidence)
    has_flag = any("flag{" in str(e) for e in evidence)
    native_success = bool(has_id and has_flag and flag_value)
    timestamp = datetime.now().isoformat()

    verification = {
        "native_verification": {
            "success": native_success,
            "mode": "native",
            "evidence": evidence[:5],
            "captured_flag": flag_value,
            "flag_matched": native_success,
            "reason": "agent confirmed exploitation with id + flag capture" if native_success else "missing id/flag evidence",
            "timestamp": timestamp,
        },
        "orchestrated_verification": {
            "success": False,
            "mode": "orchestrated",
            "evidence": ["orchestrated environment verification not yet implemented"],
            "timestamp": timestamp,
        },
    }

    source_bundle = AtomizerPipeline._build_source_bundle_manifest(atom_dir)
    if source_bundle is None:
        print(f"  {cve}: no source_bundle/ dir, skip")
        return

    # 用现有字段重建 AtomConfig，加上 version=3 + verification + source_bundle
    raw["version"] = 3
    raw["verification"] = verification
    raw["source_bundle"] = source_bundle.model_dump(mode="json")

    config = AtomConfig(**raw)
    atom_path.write_text(yaml.dump(
        config.model_dump(exclude_none=True, mode="json"),
        default_flow_style=False, sort_keys=False, allow_unicode=True,
    ))
    verified_final = config.verified
    sb = config.source_bundle
    print(f"  {cve}: version=3 native={native_success} verified={verified_final} "
          f"poc_materials={len(sb.poc_materials)} hashes={len(sb.hashes)}")


def main():
    print("=== 离线迁移 8 个 atom → v3 (verification + source_bundle) ===")
    for cve in CVES:
        migrate_one(cve)
    print("=== done ===")


if __name__ == "__main__":
    main()