"""Portable, content-addressed lineage contracts for the SFT artifact chain.

This module intentionally depends only on the Python standard library.  It is
used before model loading or subprocess execution so a clean CPU environment
can validate corpus, split, training, and evaluation inputs.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
from pathlib import Path
from typing import Any, Iterable


SFT_RECORD_SCHEMA_VERSION = "cvelab.sft-record.v1"
CORPUS_MANIFEST_SCHEMA_VERSION = "cvelab.sft-corpus-manifest.v1"
SPLIT_MANIFEST_SCHEMA_VERSION = "cvelab.sft-split-manifest.v1"
TRAINING_RUN_MANIFEST_SCHEMA_VERSION = "cvelab.sft-training-run-manifest.v1"
EVALUATION_MANIFEST_SCHEMA_VERSION = "cvelab.sft-evaluation-manifest.v1"
EVALUATION_RUN_MANIFEST_SCHEMA_VERSION = "cvelab.sft-evaluation-run-manifest.v1"
LINEAGE_VERSION = "1.0.0"
SPLITTER_VERSION = "1.0.0"
SPLIT_NAMES = ("train", "validation", "test")

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_CVE_NUMBER_RE = re.compile(r"(?<!\d)(?:CVE[-_])?(\d{4})[-_](\d{4,})(?!\d)", re.IGNORECASE)
_SECRET_KEY_RE = re.compile(
    r"(?:api[_-]?key|access[_-]?token|password|passwd|secret|authorization|private[_-]?key)",
    re.IGNORECASE,
)


# Use the built-in type so scripts loaded directly and as ``sft.*`` share the
# same exception contract in lightweight test and CLI environments.
ManifestError = ValueError


def canonical_json(value: Any) -> bytes:
    """Return the stable JSON representation used for manifest identities."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: str | os.PathLike[str]) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def content_id(prefix: str, value: Any) -> str:
    """Create an identity without embedding source content in the identity."""
    return f"{prefix}-{sha256_bytes(canonical_json(value))}"


def load_json(path: str | os.PathLike[str]) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"invalid JSON manifest: {path}") from exc
    if not isinstance(value, dict):
        raise ManifestError(f"manifest must contain a JSON object: {path}")
    return value


def write_json(path: str | os.PathLike[str], value: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def load_jsonl(path: str | os.PathLike[str]) -> tuple[list[dict[str, Any]], str]:
    """Load JSONL and return records plus the exact file-byte SHA-256."""
    source = Path(path)
    try:
        raw = source.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise ManifestError(f"cannot read corpus JSONL: {path}") from exc

    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ManifestError(f"invalid JSONL at {path}:{line_number}") from exc
        if not isinstance(value, dict):
            raise ManifestError(f"JSONL record must be an object at {path}:{line_number}")
        records.append(value)
    return records, sha256_bytes(raw)


def _require_schema(manifest: dict[str, Any], expected: str) -> None:
    if manifest.get("schema_version") != expected:
        raise ManifestError(
            f"expected schema_version={expected!r}, got {manifest.get('schema_version')!r}"
        )


def _require_sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ManifestError(f"{field} must be a lowercase SHA-256 hex digest")
    return value


def _require_nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ManifestError(f"{field} must be a non-negative integer")
    return value


def _record_sample_id(record: dict[str, Any], index: int) -> str:
    sample_id = record.get("sample_id")
    if not isinstance(sample_id, str) or not sample_id:
        raise ManifestError(f"record {index} has no non-empty sample_id")
    return sample_id


def validate_sft_records(
    records: Iterable[dict[str, Any]],
    *,
    require_lineage: bool = True,
) -> list[dict[str, Any]]:
    """Validate record shape and stable identities without inspecting secrets."""
    materialized = list(records)
    sample_ids: set[str] = set()
    task_ids: set[str] = set()
    for index, record in enumerate(materialized):
        if not isinstance(record, dict):
            raise ManifestError(f"record {index} must be an object")
        if not isinstance(record.get("messages"), list) or not record["messages"]:
            raise ManifestError(f"record {index} must contain non-empty messages")
        if require_lineage:
            if record.get("schema_version") != SFT_RECORD_SCHEMA_VERSION:
                raise ManifestError(
                    f"record {index} has unsupported schema_version={record.get('schema_version')!r}"
                )
            sample_id = _record_sample_id(record, index)
            if not isinstance(record.get("source_identity"), str) or not record["source_identity"]:
                raise ManifestError(f"record {index} has no source_identity")
            _require_sha256(record.get("source_content_sha256"), f"record {index}.source_content_sha256")
        else:
            sample_id = record.get("sample_id")
            if sample_id is not None and (not isinstance(sample_id, str) or not sample_id):
                raise ManifestError(f"record {index} has invalid sample_id")

        if sample_id is not None:
            if sample_id in sample_ids:
                raise ManifestError(f"duplicate sample_id: {sample_id}")
            sample_ids.add(sample_id)
        task_id = record.get("task_id")
        if task_id is not None:
            if not isinstance(task_id, str) or not task_id:
                raise ManifestError(f"record {index} has invalid task_id")
            if task_id in task_ids:
                raise ManifestError(f"duplicate task_id: {task_id}")
            task_ids.add(task_id)
    return materialized


def _corpus_identity_payload(manifest: dict[str, Any]) -> dict[str, Any]:
    output = manifest.get("output")
    if not isinstance(output, dict):
        raise ManifestError("corpus manifest output must be an object")
    return {
        "converter": manifest.get("converter"),
        "sources": manifest.get("sources"),
        "output_sha256": output.get("sha256"),
        "record_count": output.get("record_count"),
    }


def corpus_id_for_manifest(manifest: dict[str, Any]) -> str:
    """Recompute the converter's corpus ID from public manifest fields."""
    return content_id("sft-corpus", _corpus_identity_payload(manifest))


def _infer_corpus_path(manifest_path: Path, manifest: dict[str, Any]) -> Path | None:
    output = manifest.get("output")
    if not isinstance(output, dict):
        return None
    candidate = output.get("path") or output.get("file_name")
    if not isinstance(candidate, str) or not candidate:
        return None
    path = Path(candidate)
    return path if path.is_absolute() else manifest_path.parent / path


def _validate_source_accounting(
    records: Iterable[dict[str, Any]],
    sources: list[Any],
) -> None:
    """Ensure every emitted record belongs to the declared source ledger."""
    source_index: dict[str, dict[str, Any]] = {}
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            raise ManifestError(f"corpus source {index} must be an object")
        identity = source.get("source_identity")
        if not isinstance(identity, str) or not identity:
            raise ManifestError(f"corpus source {index} has no source_identity")
        if identity in source_index:
            raise ManifestError(f"duplicate corpus source_identity: {identity}")
        _require_sha256(source.get("source_content_sha256"), f"source {identity}.source_content_sha256")
        emitted_count = source.get("emitted_count", 0)
        _require_nonnegative_int(emitted_count, f"source {identity}.emitted_count")
        source_index[identity] = source

    record_counts: dict[str, int] = {}
    for index, record in enumerate(records):
        identity = record.get("source_identity")
        source = source_index.get(identity)
        if source is None:
            raise ManifestError(f"record {index} references undeclared source: {identity!r}")
        if record.get("source_content_sha256") != source["source_content_sha256"]:
            raise ManifestError(f"record {index} source hash disagrees with source ledger")
        record_counts[identity] = record_counts.get(identity, 0) + 1

    for identity, source in source_index.items():
        if source.get("emitted_count", 0) != record_counts.get(identity, 0):
            raise ManifestError(
                f"source {identity} emitted_count disagrees with records: "
                f"declared {source.get('emitted_count', 0)}, "
                f"observed {record_counts.get(identity, 0)}"
            )


def validate_corpus_manifest(
    manifest_or_path: dict[str, Any] | str | os.PathLike[str],
    corpus_path: str | os.PathLike[str] | None = None,
    *,
    records: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Validate a converter report and, when supplied, its exact JSONL bytes."""
    manifest_path: Path | None = None
    if isinstance(manifest_or_path, (str, os.PathLike)):
        manifest_path = Path(manifest_or_path)
        manifest = load_json(manifest_path)
    else:
        manifest = manifest_or_path
    if not isinstance(manifest, dict):
        raise ManifestError("corpus manifest must be an object")
    _reject_secret_fields(manifest)
    _require_schema(manifest, CORPUS_MANIFEST_SCHEMA_VERSION)

    output = manifest.get("output")
    if not isinstance(output, dict):
        raise ManifestError("corpus manifest output must be an object")
    expected_hash = _require_sha256(output.get("sha256"), "output.sha256")
    if manifest.get("corpus_sha256") is not None and manifest["corpus_sha256"] != expected_hash:
        raise ManifestError("corpus_sha256 does not match output.sha256")
    expected_count = _require_nonnegative_int(output.get("record_count"), "output.record_count")
    if manifest.get("n_samples") is not None and manifest["n_samples"] != expected_count:
        raise ManifestError("n_samples does not match output.record_count")
    if not isinstance(manifest.get("sources"), list):
        raise ManifestError("corpus manifest sources must be a list")
    if not isinstance(manifest.get("converter"), dict):
        raise ManifestError("corpus manifest converter must be an object")
    if manifest.get("corpus_id") != corpus_id_for_manifest(manifest):
        raise ManifestError("corpus_id does not match manifest content")

    resolved_corpus_path = Path(corpus_path) if corpus_path is not None else None
    if resolved_corpus_path is None and manifest_path is not None:
        inferred = _infer_corpus_path(manifest_path, manifest)
        if inferred is not None and inferred.exists():
            resolved_corpus_path = inferred

    loaded_records: list[dict[str, Any]] | None = None
    if resolved_corpus_path is not None:
        loaded_records, actual_hash = load_jsonl(resolved_corpus_path)
        if actual_hash != expected_hash:
            raise ManifestError(
                f"corpus content hash mismatch: expected {expected_hash}, got {actual_hash}"
            )
        if len(loaded_records) != expected_count:
            raise ManifestError(
                f"corpus record count mismatch: expected {expected_count}, got {len(loaded_records)}"
            )
        validate_sft_records(loaded_records, require_lineage=True)
        _validate_source_accounting(loaded_records, manifest["sources"])
    elif records is not None:
        loaded_records = validate_sft_records(records, require_lineage=True)
        if len(loaded_records) != expected_count:
            raise ManifestError(
                f"corpus record count mismatch: expected {expected_count}, got {len(loaded_records)}"
            )
        _validate_source_accounting(loaded_records, manifest["sources"])
    return manifest


def load_and_validate_corpus(
    corpus_path: str | os.PathLike[str],
    manifest_path: str | os.PathLike[str],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records, actual_hash = load_jsonl(corpus_path)
    manifest = load_json(manifest_path)
    validate_corpus_manifest(manifest, corpus_path, records=records)
    if actual_hash != manifest["output"]["sha256"]:
        raise ManifestError("corpus content hash mismatch")
    return records, manifest


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _identity_tokens(record: dict[str, Any]) -> tuple[str, ...]:
    """Extract generic case/CVE/source identities, never raw trajectory content."""
    tokens: set[str] = set()
    explicit = _text(record.get("group_key") or record.get("group_id"))
    if explicit:
        tokens.add(f"group:{explicit}")

    case_id = _text(record.get("case_id") or record.get("case") or record.get("scenario_id"))
    task_id = _text(record.get("task_id"))
    if not case_id and task_id:
        case_id = task_id.split(".", 1)[0]
    if case_id:
        tokens.add(f"case:{case_id}")

    cve_values: list[str] = []
    for key in ("cve_id", "cve", "vulnerability"):
        value = record.get(key)
        if isinstance(value, str):
            cve_values.append(value)
        elif isinstance(value, list):
            cve_values.extend(item for item in value if isinstance(item, str))
    identity_text = " ".join([case_id, task_id, _text(record.get("source_identity"))])
    cve_values.extend(_CVE_RE.findall(identity_text))
    cve_values.extend(
        f"CVE-{year}-{number}"
        for year, number in _CVE_NUMBER_RE.findall(identity_text)
    )
    for cve in cve_values:
        tokens.add(f"cve:{cve.upper()}")

    source_identity = _text(record.get("source_identity") or record.get("source_id"))
    if source_identity:
        tokens.add(f"source:{source_identity}")
    else:
        source_hash = _text(record.get("source_content_sha256"))
        if source_hash:
            tokens.add(f"source-sha256:{source_hash}")
    if not tokens:
        sample_id = _text(record.get("sample_id"))
        if sample_id:
            tokens.add(f"sample:{sample_id}")
    return tuple(sorted(tokens))


def _union_find_groups(records: list[dict[str, Any]]) -> tuple[dict[str, str], dict[str, list[str]]]:
    sample_ids = [_record_sample_id(record, index) for index, record in enumerate(records)]
    parent = list(range(len(records)))
    token_owner: dict[str, int] = {}

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    for index, record in enumerate(records):
        for token in _identity_tokens(record):
            owner = token_owner.get(token)
            if owner is None:
                token_owner[token] = index
            else:
                union(index, owner)

    component_tokens: dict[int, set[str]] = {}
    for index, record in enumerate(records):
        root = find(index)
        component_tokens.setdefault(root, set()).update(_identity_tokens(record))

    component_keys = {
        root: "group-" + sha256_bytes(canonical_json(sorted(tokens)))
        for root, tokens in component_tokens.items()
    }
    sample_to_group = {
        sample_id: component_keys[find(index)] for index, sample_id in enumerate(sample_ids)
    }
    groups: dict[str, list[str]] = {}
    for sample_id in sample_ids:
        groups.setdefault(sample_to_group[sample_id], []).append(sample_id)
    for sample_ids_in_group in groups.values():
        sample_ids_in_group.sort()
    return sample_to_group, dict(sorted(groups.items()))


def group_key_for_record(record: dict[str, Any]) -> str:
    """Return the deterministic single-record group identity for diagnostics."""
    tokens = _identity_tokens(record)
    return "group-" + sha256_bytes(canonical_json(list(tokens)))


def _validate_ratios(ratios: dict[str, float] | Iterable[float]) -> dict[str, float]:
    if isinstance(ratios, dict):
        result = {name: ratios.get(name) for name in SPLIT_NAMES}
    else:
        values = list(ratios)
        if len(values) != 3:
            raise ManifestError("split ratios require train, validation, and test values")
        result = dict(zip(SPLIT_NAMES, values))
    if any(not isinstance(value, (int, float)) or value < 0 for value in result.values()):
        raise ManifestError("split ratios must be non-negative numbers")
    if sum(result.values()) <= 0 or abs(sum(result.values()) - 1.0) > 1e-9:
        raise ManifestError("split ratios must sum to 1")
    return {name: float(result[name]) for name in SPLIT_NAMES}


def _assign_groups(groups: dict[str, list[str]], ratios: dict[str, float]) -> dict[str, str]:
    current = {name: 0 for name in SPLIT_NAMES}
    total = sum(len(sample_ids) for sample_ids in groups.values())
    targets = {name: max(total * ratios[name], 1e-12) for name in SPLIT_NAMES}
    available = tuple(name for name in SPLIT_NAMES if ratios[name] > 0)
    ordered = sorted(
        groups,
        key=lambda group: sha256_bytes(f"{SPLITTER_VERSION}:{group}".encode("utf-8")),
    )
    assignments: dict[str, str] = {}
    for group in ordered:
        split = min(
            available,
            key=lambda name: (current[name] / targets[name], SPLIT_NAMES.index(name)),
        )
        assignments[group] = split
        current[split] += len(groups[group])
    return assignments


def _split_identity_payload(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": manifest.get("schema_version"),
        "splitter_version": manifest.get("splitter_version"),
        "corpus_id": manifest.get("corpus_id"),
        "corpus_sha256": manifest.get("corpus_sha256"),
        "record_count": manifest.get("record_count"),
        "ratios": manifest.get("ratios"),
        "groups": manifest.get("groups"),
        "splits": manifest.get("splits"),
    }


def build_split_manifest(
    records: Iterable[dict[str, Any]],
    corpus_manifest: dict[str, Any],
    *,
    ratios: dict[str, float] | Iterable[float] = (0.8, 0.1, 0.1),
) -> dict[str, Any]:
    materialized = list(records)
    ratios_dict = _validate_ratios(ratios)
    validate_corpus_manifest(corpus_manifest, records=materialized)
    sample_to_group, groups = _union_find_groups(materialized)
    group_splits = _assign_groups(groups, ratios_dict)
    splits = {name: [] for name in SPLIT_NAMES}
    for sample_id in sorted(sample_to_group):
        splits[group_splits[sample_to_group[sample_id]]].append(sample_id)
    if materialized and not splits["train"]:
        raise ManifestError("deterministic split produced an empty train split")
    manifest = {
        "schema_version": SPLIT_MANIFEST_SCHEMA_VERSION,
        "splitter_version": SPLITTER_VERSION,
        "corpus_id": corpus_manifest["corpus_id"],
        "corpus_sha256": corpus_manifest["output"]["sha256"],
        "record_count": len(materialized),
        "ratios": ratios_dict,
        "groups": dict(sorted(group_splits.items())),
        "splits": splits,
        "counts": {name: len(splits[name]) for name in SPLIT_NAMES},
        "group_count": len(groups),
    }
    manifest["split_id"] = content_id("sft-split", _split_identity_payload(manifest))
    validate_split_manifest(manifest, materialized, corpus_manifest=corpus_manifest)
    return manifest


def validate_split_manifest(
    manifest_or_path: dict[str, Any] | str | os.PathLike[str],
    records: Iterable[dict[str, Any]] | None = None,
    *,
    corpus_manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if isinstance(manifest_or_path, (str, os.PathLike)):
        manifest = load_json(manifest_or_path)
    else:
        manifest = manifest_or_path
    if not isinstance(manifest, dict):
        raise ManifestError("split manifest must be an object")
    _reject_secret_fields(manifest)
    _require_schema(manifest, SPLIT_MANIFEST_SCHEMA_VERSION)
    if not isinstance(manifest.get("split_id"), str):
        raise ManifestError("split manifest has no split_id")
    _require_sha256(manifest.get("corpus_sha256"), "corpus_sha256")
    record_count = _require_nonnegative_int(manifest.get("record_count"), "record_count")
    ratios = _validate_ratios(manifest.get("ratios", {}))
    if manifest.get("ratios") != ratios:
        raise ManifestError("split ratios are not normalized")

    splits = manifest.get("splits")
    groups = manifest.get("groups")
    if not isinstance(splits, dict) or set(splits) != set(SPLIT_NAMES):
        raise ManifestError("split manifest must contain exactly train, validation, and test")
    if not isinstance(groups, dict):
        raise ManifestError("split manifest groups must be an object")
    all_ids: list[str] = []
    id_to_split: dict[str, str] = {}
    for split in SPLIT_NAMES:
        ids = splits[split]
        if not isinstance(ids, list) or any(not isinstance(sample_id, str) for sample_id in ids):
            raise ManifestError(f"{split} split must be a list of sample IDs")
        for sample_id in ids:
            if sample_id in id_to_split:
                raise ManifestError(f"sample appears in multiple splits: {sample_id}")
            id_to_split[sample_id] = split
            all_ids.append(sample_id)
    if len(all_ids) != record_count:
        raise ManifestError("split counts do not match record_count")
    if len(set(all_ids)) != len(all_ids):
        raise ManifestError("split manifest contains duplicate sample IDs")
    if any(not isinstance(group, str) or not isinstance(split, str) for group, split in groups.items()):
        raise ManifestError("groups must map string identities to split names")
    if any(split not in SPLIT_NAMES for split in groups.values()):
        raise ManifestError("groups contain an unknown split")
    if manifest.get("counts") != {name: len(splits[name]) for name in SPLIT_NAMES}:
        raise ManifestError("split counts field is not consistent with split IDs")
    if manifest.get("group_count") != len(groups):
        raise ManifestError("group_count is not consistent with groups")
    if record_count and not splits["train"]:
        raise ManifestError("split manifest has an empty train split")

    if corpus_manifest is not None:
        validate_corpus_manifest(corpus_manifest)
        if manifest.get("corpus_id") != corpus_manifest.get("corpus_id"):
            raise ManifestError("split manifest corpus_id does not match corpus manifest")
        if manifest.get("corpus_sha256") != corpus_manifest.get("output", {}).get("sha256"):
            raise ManifestError("split manifest corpus_sha256 does not match corpus manifest")
        if record_count != corpus_manifest.get("output", {}).get("record_count"):
            raise ManifestError("split manifest record_count does not match corpus manifest")

    if records is not None:
        materialized = validate_sft_records(records, require_lineage=True)
        if len(materialized) != record_count:
            raise ManifestError("split manifest record_count does not match records")
        sample_to_group, expected_groups = _union_find_groups(materialized)
        expected_ids = set(sample_to_group)
        if expected_ids != set(all_ids):
            raise ManifestError("split manifest does not cover exactly the corpus sample IDs")
        if set(groups) != set(expected_groups):
            raise ManifestError("split manifest groups do not match corpus identities")
        for group, sample_ids in expected_groups.items():
            assigned_splits = {id_to_split[sample_id] for sample_id in sample_ids}
            if len(assigned_splits) != 1:
                raise ManifestError(f"split overlap for group {group}")
            if groups[group] != next(iter(assigned_splits)):
                raise ManifestError(f"split group assignment mismatch for {group}")

    expected_id = content_id("sft-split", _split_identity_payload(manifest))
    if manifest["split_id"] != expected_id:
        raise ManifestError("split_id does not match manifest content")
    return manifest


def _safe_public(value: Any, key: str = "") -> Any:
    if key and _SECRET_KEY_RE.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {
            str(name): _safe_public(item, str(name))
            for name, item in value.items()
            if not _SECRET_KEY_RE.search(str(name))
        }
    if isinstance(value, (list, tuple)):
        return [_safe_public(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def public_arguments(value: Any) -> Any:
    """Keep manifest arguments useful while excluding secret-bearing fields."""
    return _safe_public(value)


def _reject_secret_fields(value: Any, path: str = "manifest") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            if _SECRET_KEY_RE.search(key_text):
                raise ManifestError(f"secret-bearing field is not allowed: {path}.{key_text}")
            _reject_secret_fields(item, f"{path}.{key_text}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_secret_fields(item, f"{path}[{index}]")


def environment_identifiers() -> dict[str, Any]:
    """Return selected reproducibility identifiers, never the full environment."""
    packages: dict[str, str] = {}
    try:
        from importlib import metadata

        for package in ("torch", "transformers", "datasets", "peft", "trl", "accelerate", "vllm"):
            try:
                packages[package] = metadata.version(package)
            except metadata.PackageNotFoundError:
                continue
    except ImportError:  # pragma: no cover - importlib.metadata is in Python 3
        pass
    identifiers: dict[str, Any] = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "implementation": platform.python_implementation(),
        "packages": packages,
    }
    for key in ("CUDA_VERSION", "CUDA_VISIBLE_DEVICES", "NVIDIA_DRIVER_VERSION"):
        value = os.environ.get(key)
        if value:
            identifiers[key.lower()] = value
    revision = os.environ.get("GIT_COMMIT") or os.environ.get("SOURCE_REVISION")
    if revision:
        identifiers["source_revision"] = revision
    return identifiers


def _training_identity_payload(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": manifest.get("schema_version"),
        "code_version": manifest.get("code_version"),
        "arguments": manifest.get("arguments"),
        "corpus": manifest.get("corpus"),
        "base_model": manifest.get("base_model"),
        "tokenizer": manifest.get("tokenizer"),
        "output": manifest.get("output"),
        "environment": manifest.get("environment"),
    }


def build_training_run_manifest(
    *,
    code_version: str | dict[str, Any],
    arguments: dict[str, Any],
    corpus: dict[str, Any],
    base_model: dict[str, Any],
    tokenizer: dict[str, Any],
    output_adapter_path: str,
    environment: dict[str, Any] | None = None,
    status: str = "planned",
    error: dict[str, Any] | None = None,
) -> dict[str, Any]:
    corpus_value = public_arguments(corpus)
    manifest = {
        "schema_version": TRAINING_RUN_MANIFEST_SCHEMA_VERSION,
        "status": status,
        "code_version": public_arguments(code_version),
        "arguments": public_arguments(arguments),
        "corpus": corpus_value,
        "corpus_id": corpus_value.get("corpus_id"),
        "corpus_sha256": corpus_value.get("sha256"),
        "base_model": public_arguments(base_model),
        "tokenizer": public_arguments(tokenizer),
        "output": {"adapter_path": str(output_adapter_path)},
        "output_adapter_path": str(output_adapter_path),
        "environment": public_arguments(environment or environment_identifiers()),
    }
    if error:
        manifest["error"] = public_arguments(error)
    manifest["training_run_id"] = content_id("sft-training", _training_identity_payload(manifest))
    return manifest


def validate_training_run_manifest(
    manifest_or_path: dict[str, Any] | str | os.PathLike[str],
) -> dict[str, Any]:
    manifest = load_json(manifest_or_path) if isinstance(manifest_or_path, (str, os.PathLike)) else manifest_or_path
    if not isinstance(manifest, dict):
        raise ManifestError("training run manifest must be an object")
    _reject_secret_fields(manifest)
    _require_schema(manifest, TRAINING_RUN_MANIFEST_SCHEMA_VERSION)
    for field in ("code_version", "arguments", "corpus", "base_model", "tokenizer", "output", "environment"):
        if field not in manifest:
            raise ManifestError(f"training run manifest is missing {field}")
    if manifest.get("output_adapter_path") != manifest.get("output", {}).get("adapter_path"):
        raise ManifestError("output adapter path aliases do not match")
    if manifest.get("corpus_id") != manifest.get("corpus", {}).get("corpus_id"):
        raise ManifestError("corpus_id aliases do not match")
    if manifest.get("corpus_sha256") != manifest.get("corpus", {}).get("sha256"):
        raise ManifestError("corpus SHA-256 aliases do not match")
    if manifest.get("training_run_id") != content_id("sft-training", _training_identity_payload(manifest)):
        raise ManifestError("training_run_id does not match manifest content")
    return manifest


def _evaluation_identity_payload(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in manifest.items()
        if key not in {"evaluation_id", "evaluation_manifest_sha256"}
    }


def build_evaluation_manifest(
    *,
    case_manifest: str | None = None,
    cases: list[dict[str, Any]] | None = None,
    model: str | None = None,
    adapter_path: str | None = None,
    parameters: dict[str, Any] | None = None,
    case_manifest_sha256: str | None = None,
    base_dir: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    if not case_manifest and cases is None:
        raise ManifestError("evaluation manifest needs case_manifest or cases")
    manifest: dict[str, Any] = {
        "schema_version": EVALUATION_MANIFEST_SCHEMA_VERSION,
        "case_manifest": case_manifest,
        "cases": public_arguments(cases) if cases is not None else None,
        "model": model,
        "adapter_path": adapter_path,
        "parameters": public_arguments(parameters or {}),
    }
    if case_manifest_sha256 is None and case_manifest:
        candidate = Path(case_manifest)
        if not candidate.is_absolute() and base_dir is not None:
            candidate = Path(base_dir) / candidate
        if candidate.exists() and candidate.is_file():
            case_manifest_sha256 = sha256_file(candidate)
    if case_manifest_sha256 is not None:
        _require_sha256(case_manifest_sha256, "case_manifest_sha256")
        manifest["case_manifest_sha256"] = case_manifest_sha256
    manifest["evaluation_id"] = content_id("sft-evaluation", _evaluation_identity_payload(manifest))
    return manifest


def validate_evaluation_manifest(
    manifest_or_path: dict[str, Any] | str | os.PathLike[str],
) -> dict[str, Any]:
    manifest = load_json(manifest_or_path) if isinstance(manifest_or_path, (str, os.PathLike)) else manifest_or_path
    if not isinstance(manifest, dict):
        raise ManifestError("evaluation manifest must be an object")
    _reject_secret_fields(manifest)
    _require_schema(manifest, EVALUATION_MANIFEST_SCHEMA_VERSION)
    if not (
        manifest.get("case_manifest")
        or manifest.get("case_manifest_path")
        or manifest.get("cases_manifest")
    ) and manifest.get("cases") is None:
        raise ManifestError("evaluation manifest needs case_manifest or cases")
    if manifest.get("case_manifest_sha256") is not None:
        _require_sha256(manifest["case_manifest_sha256"], "case_manifest_sha256")
    if manifest.get("cases") is not None:
        if not isinstance(manifest["cases"], list):
            raise ManifestError("evaluation manifest cases must be a list")
        case_ids = []
        for index, case in enumerate(manifest["cases"]):
            if not isinstance(case, dict):
                raise ManifestError(f"evaluation case {index} must be an object")
            case_id = case.get("case_id") or case.get("id")
            if case_id is not None:
                if not isinstance(case_id, str) or not case_id:
                    raise ManifestError(f"evaluation case {index} has invalid id")
                case_ids.append(case_id)
        if len(case_ids) != len(set(case_ids)):
            raise ManifestError("evaluation manifest contains duplicate case IDs")
    if not isinstance(manifest.get("evaluation_id"), str):
        raise ManifestError("evaluation manifest has no evaluation_id")
    if manifest["evaluation_id"] != content_id("sft-evaluation", _evaluation_identity_payload(manifest)):
        raise ManifestError("evaluation_id does not match manifest content")
    return manifest


def build_evaluation_run_manifest(
    *,
    evaluation_manifest: dict[str, Any] | None,
    evaluation_manifest_sha256: str | None,
    arguments: dict[str, Any],
    model: dict[str, Any],
    adapter_path: str | None,
    case_manifest: str | None,
    environment: dict[str, Any] | None = None,
    status: str = "planned",
    error: dict[str, Any] | None = None,
) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "schema_version": EVALUATION_RUN_MANIFEST_SCHEMA_VERSION,
        "status": status,
        "evaluation_id": evaluation_manifest.get("evaluation_id") if evaluation_manifest else None,
        "evaluation_manifest_sha256": evaluation_manifest_sha256,
        "arguments": public_arguments(arguments),
        "model": public_arguments(model),
        "adapter_path": adapter_path,
        "case_manifest": case_manifest,
        "environment": public_arguments(environment or environment_identifiers()),
    }
    if error:
        manifest["error"] = public_arguments(error)
    identity = {
        key: value
        for key, value in manifest.items()
        if key not in {"status", "error"}
    }
    manifest["evaluation_run_id"] = content_id("sft-evaluation-run", identity)
    return manifest


def validate_evaluation_run_manifest(
    manifest_or_path: dict[str, Any] | str | os.PathLike[str],
) -> dict[str, Any]:
    manifest = load_json(manifest_or_path) if isinstance(manifest_or_path, (str, os.PathLike)) else manifest_or_path
    if not isinstance(manifest, dict):
        raise ManifestError("evaluation run manifest must be an object")
    _reject_secret_fields(manifest)
    _require_schema(manifest, EVALUATION_RUN_MANIFEST_SCHEMA_VERSION)
    for field in ("arguments", "model", "environment", "evaluation_run_id"):
        if field not in manifest:
            raise ManifestError(f"evaluation run manifest is missing {field}")
    identity = {
        key: value
        for key, value in manifest.items()
        if key not in {"status", "error", "evaluation_run_id"}
    }
    if manifest["evaluation_run_id"] != content_id("sft-evaluation-run", identity):
        raise ManifestError("evaluation_run_id does not match manifest content")
    return manifest
