"""Known-answer-test contracts for verifier-backed difficulty cases."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .difficulty import sha256_file, verifier_backed_success

REQUIRED_KAT_CONTROLS = (
    "qualification",
    "oracle",
    "no_op",
    "partial_solution",
    "wrong_evidence",
    "pre_agent",
    "repeat_verdicts",
)
_REQUIRED_BINDINGS = (
    "manifest_sha256",
    "case_dependency_sha256",
    "ground_truth_sha256",
    "scenario_manifest_sha256",
)


def _hash_valid(value: Any) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{64}", str(value or "").lower()))


def _bound_artifact(
    record: Mapping[str, Any], artifact_root: Path
) -> Mapping[str, Any]:
    relative = record.get("artifact_path")
    if not isinstance(relative, str) or not relative:
        return {}
    root = artifact_root.resolve()
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        return {}
    if not path.is_file() or sha256_file(path) != str(
        record.get("artifact_sha256") or ""
    ).lower():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, Mapping) else {}


def _artifact(
    control: Any, artifact_root: Path | None
) -> Mapping[str, Any]:
    if not isinstance(control, Mapping):
        return {}
    return _bound_artifact(control, artifact_root) if artifact_root else control


def _control_result(
    control: Any,
    artifact_root: Path | None = None,
) -> Mapping[str, Any]:
    result = _artifact(control, artifact_root).get("result")
    return result if isinstance(result, Mapping) else {}


def _bindings_match(
    artifact: Mapping[str, Any], expected: Mapping[str, Any] | None
) -> bool:
    if expected is None:
        return True
    actual = artifact.get("bindings")
    return isinstance(actual, Mapping) and all(
        actual.get(key) == value for key, value in expected.items()
    )


def _complete_bindings(artifact: Mapping[str, Any]) -> Mapping[str, Any] | None:
    bindings = artifact.get("bindings")
    if not isinstance(bindings, Mapping) or not all(
        _hash_valid(bindings.get(key)) for key in _REQUIRED_BINDINGS
    ):
        return None
    return bindings


def _control_valid(
    control: Any,
    artifact_root: Path | None = None,
    *,
    control_name: str = "",
    case_id: str = "",
    expected_bindings: Mapping[str, Any] | None = None,
) -> bool:
    artifact = _artifact(control, artifact_root)
    return bool(
        isinstance(control, Mapping)
        and _hash_valid(control.get("artifact_sha256"))
        and artifact
        and _control_result(control, artifact_root)
        and (not artifact_root or artifact.get("control") == control_name)
        and (not artifact_root or artifact.get("case_id") == case_id)
        and _bindings_match(artifact, expected_bindings)
    )


def _valid_rejection(
    control: Any,
    artifact_root: Path | None = None,
    *,
    control_name: str,
    case_id: str,
    expected_bindings: Mapping[str, Any] | None = None,
    require_objective_rejection: bool = False,
) -> bool:
    result = _control_result(control, artifact_root)
    return bool(
        _control_valid(
            control,
            artifact_root,
            control_name=control_name,
            case_id=case_id,
            expected_bindings=expected_bindings,
        )
        and result.get("environment_success") is True
        and not verifier_backed_success(result)
        and (
            not require_objective_rejection
            or result.get("objective_control_applicable") is False
            or result.get("objective_achieved") is False
        )
    )


def assess_case_kat(
    evidence: Mapping[str, Any],
    *,
    artifact_root: str | Path | None = None,
    case_id: str = "",
    expected_bindings: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Assess whether a case has the minimum positive and negative controls."""
    root = Path(artifact_root) if artifact_root is not None else None
    missing = [name for name in REQUIRED_KAT_CONTROLS if name not in evidence]
    checks: dict[str, bool] = {}

    qualification = evidence.get("qualification")
    qualification_artifact = _artifact(qualification, root)
    case_bindings = (
        _complete_bindings(qualification_artifact)
        if root is not None and expected_bindings is not None
        else expected_bindings
    )
    bindings_ready = case_bindings is not None or expected_bindings is None
    if qualification is not None:
        result = _control_result(qualification, root)
        checks["qualification_passed"] = bool(
            bindings_ready
            and _bindings_match(qualification_artifact, expected_bindings)
            and _control_valid(
                qualification,
                root,
                control_name="qualification",
                case_id=case_id,
                expected_bindings=case_bindings,
            )
            and result.get("environment_success") is True
            and result.get("attack_graph_valid") is True
            and result.get("attack_path_reachable") is True
            and result.get("execution_complete") is True
        )
    if "oracle" in evidence:
        checks["oracle_accepted"] = bool(
            _control_valid(
                evidence["oracle"],
                root,
                control_name="oracle",
                case_id=case_id,
                expected_bindings=case_bindings,
            )
            and verifier_backed_success(_control_result(evidence["oracle"], root))
        )
    if "no_op" in evidence:
        checks["no_op_rejected"] = _valid_rejection(
            evidence["no_op"],
            root,
            control_name="no_op",
            case_id=case_id,
            expected_bindings=case_bindings,
        )
    if "partial_solution" in evidence:
        checks["partial_solution_rejected"] = _valid_rejection(
            evidence["partial_solution"],
            root,
            control_name="partial_solution",
            case_id=case_id,
            expected_bindings=case_bindings,
        )
    if "wrong_evidence" in evidence:
        checks["wrong_evidence_rejected"] = _valid_rejection(
            evidence["wrong_evidence"],
            root,
            control_name="wrong_evidence",
            case_id=case_id,
            expected_bindings=case_bindings,
            require_objective_rejection=True,
        )
    if "pre_agent" in evidence:
        result = _control_result(evidence["pre_agent"], root)
        checks["objective_not_pre_satisfied"] = bool(
            _control_valid(
                evidence["pre_agent"],
                root,
                control_name="pre_agent",
                case_id=case_id,
                expected_bindings=case_bindings,
            )
            and result.get("environment_success") is True
            and (
                result.get("objective_control_applicable") is False
                or result.get("objective_achieved") is False
            )
        )
    if "repeat_verdicts" in evidence:
        raw_records = evidence["repeat_verdicts"]
        records = list(raw_records) if isinstance(raw_records, list) else []
        bound_records = [
            _artifact(record, root)
            for record in records
        ]
        states = {
            record.get("terminal_state_sha256")
            for record in bound_records
            if isinstance(record, Mapping)
        }
        verdicts = [
            record.get("verdict")
            for record in bound_records
            if isinstance(record, Mapping)
        ]
        artifacts_bound = all(
            isinstance(record, Mapping)
            and (
                root is None
                or (
                    bound.get("case_id") == case_id
                    and bound.get("control") == "repeat_verdicts"
                    and _bindings_match(bound, case_bindings)
                )
            )
            for record, bound in zip(records, bound_records, strict=True)
        )
        checks["repeat_verdict_stable"] = bool(
            bindings_ready
            and len(records) >= 2
            and len(verdicts) == len(records)
            and all(_hash_valid(record.get("artifact_sha256")) for record in records)
            and artifacts_bound
            and len(states) == 1
            and all(_hash_valid(state) for state in states)
            and all(isinstance(verdict, bool) for verdict in verdicts)
            and all(verdict is verdicts[0] for verdict in verdicts)
        )
    failed = [name for name, passed in checks.items() if not passed]
    return {
        "eligible": not missing and not failed,
        "missing_controls": missing,
        "failed_checks": failed,
        "checks": checks,
    }
