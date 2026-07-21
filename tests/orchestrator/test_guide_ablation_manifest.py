import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "prepare_guide_ablation_manifest.py"
SPEC = importlib.util.spec_from_file_location("guide_ablation_manifest", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def _row(case_id: str):
    return {
        "case_id": case_id,
        "cves": ["CVE-1", "CVE-2", "CVE-3"],
        "environment_success": True,
        "attack_graph_valid": True,
        "attack_path_reachable": True,
        "guided_trial_evaluated": True,
        "agent_success": True,
        "objective_achieved": True,
        "execution_complete": False,
        "execution_complete_reconciled": True,
        "asset_variants": {"customer-records": "postgresql"},
    }


def test_selection_deduplicates_aliases_for_same_ordered_composition():
    selected = MODULE.select([_row("z-alias"), _row("a-alias")], limit=10)
    assert [row["case_id"] for row in selected] == ["a-alias"]


def test_selection_accepts_reconciled_execution_status():
    assert MODULE._eligible(_row("case-1"))
