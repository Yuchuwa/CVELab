"""Dataset Saver — 验证通过的场景持久化到 parquet / HuggingFace

流程:
  1. 收集验证通过的场景 (agent_result.success + flags all captured)
  2. 按 scenario hash 去重
  3. 保存为 parquet 格式到本地
  4. 可选 push 到 HuggingFace Hub
"""

import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional


def _scenario_to_record(
    scenario: dict,
    verify_result: dict,
) -> dict:
    """将场景 + 验证结果转换为 flat record"""
    gt = scenario.get("ground_truth", {})
    injections = scenario.get("injections", [])
    agent_result = verify_result.get("agent_result", {})
    flag_verif = verify_result.get("flag_verification", {})

    # 构建攻击路径摘要
    attack_path = []
    for step in gt.get("attack_path", []):
        attack_path.append({
            "step": step["step"],
            "target_node": step["target_node"],
            "cve_id": step["cve_id"],
            "zone": step["zone"],
            "flag_captured": flag_verif.get("per_target", {}).get(step["target_node"], {}).get("match", False),
        })

    return {
        "scenario_name": scenario["name"],
        "scenario_hash": scenario["hash"],
        "template": scenario["template"],
        "cve_ids": json.dumps([inj["cve_id"] for inj in injections]),
        "num_targets": len(injections),
        "all_flags_captured": flag_verif.get("all_captured", False),
        "attack_path": json.dumps(attack_path, ensure_ascii=False),
        "ground_truth": json.dumps(gt, ensure_ascii=False),
        "agent_success": agent_result.get("success", False),
        "agent_evidence": json.dumps(agent_result.get("evidence", []), ensure_ascii=False),
        "verified_at": datetime.utcnow().isoformat(),
        "clab_yaml": json.dumps(scenario.get("clab", {}), ensure_ascii=False),
        "ansible_cve_setup": json.dumps(scenario.get("cve_setup", []), ensure_ascii=False),
        "injections": json.dumps(injections, ensure_ascii=False),
    }


def save_parquet(
    records: list[dict],
    output_path: str,
) -> str:
    """保存为 parquet 文件

    Args:
        records: flat record 列表
        output_path: 输出文件路径 (.parquet)

    Returns:
        保存路径
    """
    try:
        import pandas as pd
    except ImportError:
        raise ImportError("pandas and pyarrow required: pip install pandas pyarrow")

    df = pd.DataFrame(records)

    # 按 hash 去重，保留最新的
    if "scenario_hash" in df.columns:
        df = df.drop_duplicates(subset=["scenario_hash"], keep="last")

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(str(path), index=False, engine="pyarrow")

    print(f"[Dataset] Saved {len(df)} records to {path}")
    return str(path)


def load_parquet(path: str) -> list[dict]:
    """加载 parquet 文件"""
    try:
        import pandas as pd
    except ImportError:
        raise ImportError("pandas and pyarrow required: pip install pandas pyarrow")

    df = pd.read_parquet(path)
    return df.to_dict(orient="records")


def push_to_hf(
    parquet_path: str,
    repo_id: str,
    token: Optional[str] = None,
    split: str = "train",
):
    """推送到 HuggingFace Hub

    Args:
        parquet_path: 本地 parquet 文件路径
        repo_id: HF repo (e.g. "username/cve-scenarios")
        token: HF token (默认用 huggingface-cli login 的缓存)
        split: dataset split name
    """
    try:
        from datasets import Dataset
        from huggingface_hub import HfApi
    except ImportError:
        raise ImportError("datasets and huggingface_hub required: pip install datasets huggingface_hub")

    import pandas as pd

    df = pd.read_parquet(parquet_path)
    ds = Dataset.from_pandas(df)

    api = HfApi(token=token)

    # 确保 repo 存在
    api.create_repo(repo_id=repo_id, repo_type="dataset", exist_ok=True)

    ds.push_to_hub(
        repo_id=repo_id,
        split=split,
        token=token,
    )

    print(f"[Dataset] Pushed {len(df)} records to hf://{repo_id}")


class DatasetManager:
    """管理本地数据集：追加记录、去重、推送"""

    def __init__(self, data_dir: str = "data/dataset"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.parquet_path = self.data_dir / "scenarios.parquet"

    def add_scenario(self, scenario: dict, verify_result: dict) -> bool:
        """添加验证通过的场景到数据集

        Returns:
            是否为新记录（非重复）
        """
        if not verify_result.get("flag_verification", {}).get("all_captured", False):
            print(f"[Dataset] Skipping {scenario['name']}: not all flags captured")
            return False

        record = _scenario_to_record(scenario, verify_result)

        # 加载已有记录
        existing = []
        if self.parquet_path.exists():
            existing = load_parquet(str(self.parquet_path))

        # 去重检查
        existing_hashes = {r["scenario_hash"] for r in existing}
        if record["scenario_hash"] in existing_hashes:
            print(f"[Dataset] Skipping {scenario['name']}: duplicate hash")
            return False

        existing.append(record)
        save_parquet(existing, str(self.parquet_path))
        return True

    def get_stats(self) -> dict:
        """获取数据集统计"""
        if not self.parquet_path.exists():
            return {"total": 0, "by_template": {}}

        records = load_parquet(str(self.parquet_path))
        by_template = {}
        for r in records:
            tpl = r.get("template", "unknown")
            by_template[tpl] = by_template.get(tpl, 0) + 1

        return {
            "total": len(records),
            "by_template": by_template,
        }

    def push(self, repo_id: str, token: Optional[str] = None):
        """推送到 HuggingFace Hub"""
        if not self.parquet_path.exists():
            raise FileNotFoundError("No dataset to push")
        push_to_hf(str(self.parquet_path), repo_id, token=token)
