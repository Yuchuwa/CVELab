"""Known-answer-test contracts for verifier-backed difficulty cases."""

from __future__ import annotations

import re
import json
from pathlib import Path
from typing import Any, Mapping

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

def _hash_valid(value: Any) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{64}", str(value or "").lower()))


def _control_result(
    control: Any,
    artifact_root: Path | None = None,
) -> Mapping[str, Any]:
    if not isinstance(control, Mapping):
        return {}
    source = _bound_artifact(control, artifact_root) if artifact_root else control
    result = source.get("result") if source else None
    return result if isinstance(result, Mapping) else {}


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


def _control_valid(
    control: Any,
    artifact_root: Path | None = None,
    *,
    control_name: str = "",
    case_id: str = "",
) -> bool:
    artifact = (
        _bound_artifact(control, artifact_root)
        if isinstance(control, Mapping) and artifact_root
        else control
    )
    return bool(
        isinstance(control, Mapping)
        and _hash_valid(control.get("artifact_sha256"))
        and isinstance(artifact, Mapping)
        and _control_result(control, artifact_root)
        and (not artifact_root or artifact.get("control") == control_name)
        and (not artifact_root or artifact.get("case_id") == case_id)
    )


def _valid_rejection(
    control: Any,
    artifact_root: Path | None = None,
    *,
    control_name: str,
    case_id: str,
) -> bool:
    result = _control_result(control, artifact_root)
    return bool(
        _control_valid(
            control,
            artifact_root,
            control_name=control_name,
            case_id=case_id,
        )
        and result.get("environment_success") is True
        and not verifier_backed_success(result)
    )


def assess_case_kat(
    evidence: Mapping[str, Any],
    *,
    artifact_root: str | Path | None = None,
    case_id: str = "",
) -> dict[str, Any]:
    """Assess whether a case has the minimum positive and negative controls."""
    root = Path(artifact_root) if artifact_root is not None else None
    missing = [name for name in REQUIRED_KAT_CONTROLS if name not in evidence]
    checks: dict[str, bool] = {}
    if "qualification" in evidence:
        qualification = evidence["qualification"]
        checks["qualification_passed"] = bool(
            _control_valid(
                qualification,
                root,
                control_name="qualification",
                case_id=case_id,
            )
            and _control_result(qualification, root).get("environment_success") is True
            and _control_result(qualification, root).get("attack_graph_valid") is True
            and _control_result(qualification, root).get("attack_path_reachable") is True
        )
    if "oracle" in evidence:
        checks["oracle_accepted"] = bool(
            _control_valid(
                evidence["oracle"],
                root,
                control_name="oracle",
                case_id=case_id,
            )
            and verifier_backed_success(_control_result(evidence["oracle"], root))
        )
    if "no_op" in evidence:
        checks["no_op_rejected"] = _valid_rejection(
            evidence["no_op"],
            root,
            control_name="no_op",
            case_id=case_id,
        )
    if "partial_solution" in evidence:
        checks["partial_solution_rejected"] = _valid_rejection(
            evidence["partial_solution"],
            root,
            control_name="partial_solution",
            case_id=case_id,
        )
    if "wrong_evidence" in evidence:
        checks["wrong_evidence_rejected"] = _valid_rejection(
            evidence["wrong_evidence"],
            root,
            control_name="wrong_evidence",
            case_id=case_id,
        )
    if "pre_agent" in evidence:
        result = _control_result(evidence["pre_agent"], root)
        checks["objective_not_pre_satisfied"] = (
            _control_valid(
                evidence["pre_agent"],
                root,
                control_name="pre_agent",
                case_id=case_id,
            )
            and result.get("environment_success") is True
            and result.get("objective_achieved") is False
        )
    if "repeat_verdicts" in evidence:
        raw_records = evidence["repeat_verdicts"]
        records = list(raw_records) if isinstance(raw_records, list) else []
        bound_records = [
            _bound_artifact(record, root)
            if isinstance(record, Mapping) and root
            else record
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
                )
            )
            for record, bound in zip(records, bound_records, strict=True)
        )
        checks["repeat_verdict_stable"] = (
            len(records) >= 2
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
