import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "prepare_difficulty_credibility_pilot",
    ROOT / "scripts" / "prepare_difficulty_credibility_pilot.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _candidate(case_id, tier, template, *atoms):
    return {
        "case_id": case_id,
        "label": tier,
        "template": template,
        "cves": list(atoms),
    }


def test_atom_disjoint_selector_balances_tiers_and_templates():
    candidates = []
    for partition in ("cal", "test"):
        for tier_index, tier in enumerate(MODULE.TIERS):
            for template_index, template in enumerate(MODULE.TEMPLATE_NAMES):
                candidates.append(
                    _candidate(
                        f"{partition}-{tier}-{template}",
                        tier,
                        template,
                        f"{partition}-atom-{tier_index}-{template_index}",
                    )
                )

    calibration, test, _ = MODULE.select_atom_disjoint_splits(
        candidates,
        calibration_size=12,
        test_size=12,
        seed=7,
        max_atom_reuse=1,
    )

    calibration_atoms = {atom for case in calibration for atom in case["cves"]}
    test_atoms = {atom for case in test for atom in case["cves"]}
    assert calibration_atoms.isdisjoint(test_atoms)
    assert {case["template"] for case in calibration} == set(MODULE.TEMPLATE_NAMES)
    assert {case["template"] for case in test} == set(MODULE.TEMPLATE_NAMES)
    for tier in MODULE.TIERS:
        assert sum(case["label"] == tier for case in calibration) == 3
        assert sum(case["label"] == tier for case in test) == 3


def test_selector_rejects_non_divisible_split_size():
    with pytest.raises(ValueError, match="divisible"):
        MODULE.select_atom_disjoint_splits(
            [_candidate("case", "easy", "dmz_simple", "A")],
            calibration_size=10,
            test_size=12,
            seed=7,
        )
