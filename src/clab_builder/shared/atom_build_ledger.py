"""Tracked Atom build-attempt ledger.

The ledger records that construction started without copying local workspaces,
sessions or other build evidence into Git. Atom lifecycle completion remains
authoritative in ``atom_pool_status`` and the Atom's strict gates.
"""

from __future__ import annotations

import json
import os
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

try:
    import fcntl
except ImportError:  # pragma: no cover - the project runs on Linux
    fcntl = None


LEDGER_SCHEMA_VERSION = 1
ATTEMPT_STATES = frozenset({"started", "failed", "deferred", "completed", "closed"})


def empty_ledger() -> dict[str, Any]:
    return {"schema_version": LEDGER_SCHEMA_VERSION, "attempts": []}


def _validate(payload: Any) -> dict[str, Any]:
    if payload in (None, ""):
        return empty_ledger()
    if not isinstance(payload, dict) or payload.get("schema_version") != LEDGER_SCHEMA_VERSION:
        raise ValueError("Atom build-attempt ledger must use schema_version 1")
    attempts = payload.get("attempts")
    if not isinstance(attempts, list):
        raise ValueError("Atom build-attempt ledger attempts must be a list")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(attempts):
        if not isinstance(item, dict):
            raise ValueError(f"Atom build-attempt {index} must be an object")
        cve_id = str(item.get("cve_id") or "").strip()
        attempt_id = str(item.get("attempt_id") or "").strip()
        state = str(item.get("state") or "").strip().lower()
        if not cve_id or not attempt_id:
            raise ValueError(f"Atom build-attempt {index} requires cve_id and attempt_id")
        if state not in ATTEMPT_STATES:
            raise ValueError(f"Atom build-attempt {attempt_id} has unknown state {state!r}")
        if attempt_id in seen:
            raise ValueError(f"duplicate Atom build-attempt id: {attempt_id}")
        seen.add(attempt_id)
        normalized.append({
            "attempt_id": attempt_id,
            "cve_id": cve_id,
            "state": state,
            "started_at": str(item.get("started_at") or ""),
            "updated_at": str(item.get("updated_at") or item.get("started_at") or ""),
            "owner": str(item.get("owner") or "atomizer"),
            "phase": str(item.get("phase") or "construction"),
            "failure_class": str(item.get("failure_class") or ""),
            "source_kind": str(item.get("source_kind") or ""),
        })
    normalized.sort(key=lambda item: (item["cve_id"], item["started_at"], item["attempt_id"]))
    return {"schema_version": LEDGER_SCHEMA_VERSION, "attempts": normalized}


@contextmanager
def _locked(path: Path, mode: str) -> Iterator[Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open(mode, encoding="utf-8") as handle:
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX if "w" in mode or "a" in mode else fcntl.LOCK_SH)
        try:
            yield handle
        finally:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def load_ledger(path: str | Path) -> dict[str, Any]:
    ledger_path = Path(path)
    if not ledger_path.is_file():
        return empty_ledger()
    with _locked(ledger_path, "r") as handle:
        try:
            payload = json.load(handle)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid Atom build-attempt ledger: {ledger_path}") from exc
    return _validate(payload)


def write_ledger(path: str | Path, payload: dict[str, Any]) -> None:
    ledger_path = Path(path)
    normalized = _validate(payload)
    with _locked(ledger_path, "a+") as handle:
        handle.seek(0)
        handle.truncate()
        json.dump(normalized, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def _update(path: str | Path, updater) -> dict[str, Any]:
    ledger_path = Path(path)
    with _locked(ledger_path, "a+") as handle:
        handle.seek(0)
        raw = handle.read().strip()
        try:
            payload = json.loads(raw) if raw else empty_ledger()
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid Atom build-attempt ledger: {ledger_path}") from exc
        normalized = updater(_validate(payload))
        normalized = _validate(normalized)
        handle.seek(0)
        handle.truncate()
        json.dump(normalized, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    return normalized


def start_attempt(
    path: str | Path,
    cve_id: str,
    *,
    owner: str = "atomizer",
    phase: str = "construction",
    source_kind: str = "vulhub",
    attempt_id: str | None = None,
    started_at: str | None = None,
) -> str:
    attempt_id = attempt_id or uuid.uuid4().hex
    timestamp = started_at or datetime.now(timezone.utc).isoformat()

    def add(payload: dict[str, Any]) -> dict[str, Any]:
        payload["attempts"].append({
            "attempt_id": attempt_id,
            "cve_id": str(cve_id),
            "state": "started",
            "started_at": timestamp,
            "updated_at": timestamp,
            "owner": owner,
            "phase": phase,
            "failure_class": "",
            "source_kind": source_kind,
        })
        return payload

    _update(path, add)
    return attempt_id


def finish_attempt(
    path: str | Path,
    attempt_id: str,
    *,
    state: str,
    failure_class: str = "",
    updated_at: str | None = None,
) -> None:
    if state not in ATTEMPT_STATES:
        raise ValueError(f"unknown Atom build-attempt state: {state!r}")
    timestamp = updated_at or datetime.now(timezone.utc).isoformat()

    def finish(payload: dict[str, Any]) -> dict[str, Any]:
        for item in payload["attempts"]:
            if item["attempt_id"] == attempt_id:
                item["state"] = state
                item["updated_at"] = timestamp
                item["failure_class"] = failure_class
                return payload
        raise KeyError(f"Atom build-attempt not found: {attempt_id}")

    _update(path, finish)


def latest_attempts(path: str | Path) -> dict[str, dict[str, Any]]:
    """Return the latest non-closed attempt summary for each CVE."""
    attempts = load_ledger(path)["attempts"]
    latest: dict[str, dict[str, Any]] = {}
    counts: dict[str, int] = {}
    for item in attempts:
        counts[item["cve_id"]] = counts.get(item["cve_id"], 0) + 1
        if item["state"] == "closed":
            continue
        previous = latest.get(item["cve_id"])
        if previous is None or (item["updated_at"], item["attempt_id"]) > (
            previous["updated_at"], previous["attempt_id"]
        ):
            latest[item["cve_id"]] = dict(item)
    for cve_id, item in latest.items():
        item["attempt_count"] = counts[cve_id]
    return latest
