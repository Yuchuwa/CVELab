import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "analyze_compositional_difficulty",
    ROOT / "scripts" / "analyze_compositional_difficulty.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _atom(cve_id="CVE-TEST", method="single_request", complexity="simple"):
    return {
        "cve_id": cve_id,
        "attack_method": method,
        "exploit_complexity": complexity,
        "network_requirements": {},
        "exploit_access": {},
    }


def _guide(step_count=1):
    return {
        "steps": [
            {
                "id": f"step-{index}",
                "command_hint": "curl http://target/",
                "execution": {"external_download": False, "materials": []},
            }
            for index in range(step_count)
        ],
        "requirements": {"callback": "none"},
    }


def _template(name, dependencies, objectives=0):
    slots = []
    for index, depends_on in enumerate(dependencies, 1):
        slots.append({
            "id": f"slot-{index}",
            "zone": f"zone-{index}",
            "depends_on": depends_on,
        })
    return {
        "name": name,
        "zones": {f"zone-{index}": {} for index in range(1, len(slots) + 1)},
        "routers": {},
        "objectives": [{} for _ in range(objectives)],
        "injection_points": slots,
    }


def test_dependency_depths_reject_cycles():
    template = _template("cycle", [["slot-2"], ["slot-1"]])

    with pytest.raises(ValueError, match="cyclic"):
        MODULE.dependency_depths(template)


def test_same_atom_is_harder_at_deeper_dependency_position():
    atom = _atom()
    guide = _guide()

    entry = MODULE.atom_slot_score(atom, guide, slot_id="entry", depth=0)
    deep = MODULE.atom_slot_score(atom, guide, slot_id="deep", depth=2)

    assert deep["success_probability"] < entry["success_probability"]
    assert deep["cost_factor"] > entry["cost_factor"]


def test_parallel_two_target_architecture_is_harder_than_single_target():
    atom_a = _atom("CVE-A")
    atom_b = _atom("CVE-B")
    guides = {"CVE-A": _guide(), "CVE-B": _guide()}
    single = MODULE.score_environment(
        _template("single", [[]]), [atom_a], guides
    )
    dual = MODULE.score_environment(
        _template("dual", [[], []]), [atom_a, atom_b], guides
    )

    assert dual["score"] > single["score"]
    assert dual["architecture"]["root_count"] == 2


def test_dependency_and_objective_raise_architecture_difficulty():
    atoms = [_atom("CVE-A"), _atom("CVE-B"), _atom("CVE-C")]
    guides = {item["cve_id"]: _guide() for item in atoms}
    parallel = MODULE.score_environment(
        _template("parallel", [[], [], []]), atoms, guides
    )
    chained = MODULE.score_environment(
        _template("chained", [[], ["slot-1"], ["slot-2"]], objectives=1),
        atoms,
        guides,
    )

    assert chained["score"] > parallel["score"]
    assert chained["architecture"]["dependency_edges"] == 2
    assert chained["architecture"]["objective_count"] == 1


def test_guide_step_count_is_explicit_in_score_factors():
    short = MODULE.atom_slot_score(
        _atom(), _guide(1), slot_id="entry", depth=0
    )
    long = MODULE.atom_slot_score(
        _atom(), _guide(5), slot_id="entry", depth=0
    )

    assert long["success_probability"] < short["success_probability"]
    assert long["cost_factor"] > short["cost_factor"]
    assert any(
        item["name"] == "guide_steps:5" for item in long["factors"]
    )
