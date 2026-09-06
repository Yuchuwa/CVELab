import importlib.util
import json
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


def test_dependency_amendment_preserves_frozen_selection(tmp_path):
    atom = tmp_path / "data" / "atoms" / "CVE-A" / "atom.yaml"
    guide = atom.with_name("exploit_guide.yaml")
    template = tmp_path / "templates" / "demo" / "template.yaml"
    for path in (atom, guide, template):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(path.name)

    lock_record = {
        "image": "runtime-a:latest",
        "image_id": "sha256:" + "a" * 64,
        "intermediate_image_id": "sha256:" + "b" * 64,
        "archive_file": "runtime-a.tar.gz",
        "archive_sha256": "c" * 64,
        "previous_base_image_digest": "sha256:" + "d" * 64,
        "previous_runtime_image_digest": "sha256:" + "e" * 64,
    }
    lock_body = {"schema_version": 1, "images": {"CVE-A": lock_record}}
    lock_body["lock_sha256"] = MODULE.canonical_sha256(lock_body)
    lock = tmp_path / "runtime-lock.json"
    lock.write_text(json.dumps(lock_body))

    old_atom_hash = MODULE.sha256_file(atom)
    manifest = {
        "source": {},
        "selection": {"seed": 7, "atom_partitions": {"calibration": ["CVE-A"]}},
        "protocol": {"agent_context": "guided"},
        "cases": [
            {
                "id": "frozen-case",
                "split": "calibration",
                "predicted_success_probability": 0.5,
                "dependency_hashes": {
                    "template": {
                        "path": "templates/demo/template.yaml",
                        "sha256": MODULE.sha256_file(template),
                    },
                    "atoms": {
                        "CVE-A": {
                            "atom_yaml_sha256": old_atom_hash,
                            "guide_sha256": MODULE.sha256_file(guide),
                        }
                    },
                },
            }
        ],
    }
    manifest["manifest_sha256"] = MODULE.canonical_sha256(manifest)
    original_seal = manifest["manifest_sha256"]

    atom.write_text(json.dumps({
        "verification": {
            "runtime_verification": {
                "runtime_image": "runtime-a",
                "runtime_image_digest": lock_record["image_id"],
                "base_image_digest": lock_record["intermediate_image_id"],
                "recovery": {
                    "status": "amended_prequalification",
                    "lock_sha256": lock_body["lock_sha256"],
                    "archive_file": lock_record["archive_file"],
                    "archive_sha256": lock_record["archive_sha256"],
                    "previous_base_image_digest": lock_record[
                        "previous_base_image_digest"
                    ],
                    "previous_runtime_image_digest": lock_record[
                        "previous_runtime_image_digest"
                    ],
                },
            }
        }
    }))

    amended = MODULE.amend_manifest_dependencies(
        manifest, root=tmp_path, runtime_image_lock_path=lock
    )
    repeated = MODULE.amend_manifest_dependencies(
        amended, root=tmp_path, runtime_image_lock_path=lock
    )

    assert amended == repeated
    assert amended["selection"] == manifest["selection"]
    assert amended["cases"][0]["id"] == "frozen-case"
    assert amended["cases"][0]["predicted_success_probability"] == 0.5
    amendment = amended["protocol"]["prequalification_runtime_amendment"]
    assert amendment["amended_from_manifest_sha256"] == original_seal
    assert amendment["selection_preserved"] is True
    assert amended["manifest_sha256"] != original_seal

    guide.write_text("unrelated drift")
    with pytest.raises(ValueError, match="unrelated guide drift"):
        MODULE.amend_manifest_dependencies(
            amended, root=tmp_path, runtime_image_lock_path=lock
        )
