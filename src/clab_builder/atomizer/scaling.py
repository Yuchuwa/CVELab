"""Batch/scaling support for first-stage atom generation."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import threading
import time
from concurrent.futures import (
    FIRST_COMPLETED,
    ThreadPoolExecutor,
    wait as futures_wait,
)
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml

from clab_builder.atomizer.pipeline import AtomizerPipeline
from clab_builder.shared.atom_qualification import qualify_atom
from clab_builder.shared.models.atom import AtomConfig


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class AtomScaleRecord:
    """One deduplicated atomization candidate/result row."""

    cve_id: str
    source_type: str
    source_path: str
    status: str = "queued"
    atom_path: str = ""
    error: str = ""
    session_path: str = ""
    has_session: bool = False
    duplicate_of: str = ""
    raw_record_id: str = ""
    image: str = ""
    ports: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = ""
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    # Materialized from atom.yaml after every successful build.  The manifest
    # remains the job ledger; these fields make dataset.jsonl the Range pool
    # index without duplicating the full atom source bundle.
    admission_schema_version: int = 0
    range_admitted: bool = False
    qualification_status: str = "unqualified"
    qualification: dict[str, Any] = field(default_factory=dict)
    range_index: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return self.cve_id.upper()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_cve_id(value: str | None) -> str:
    """Return a canonical CVE id or an empty string."""
    if not value:
        return ""
    match = CVE_RE.search(str(value))
    return match.group(0).upper() if match else ""


def load_raw_records(path: str | Path) -> list[dict[str, Any]]:
    """Load the raw_records_*.json format, including the observed JJH prefix."""
    raw = Path(path).read_text(encoding="utf-8").strip()
    if raw.startswith("JJH"):
        raw = raw[3:].lstrip()
    data = json.loads(raw)
    if not isinstance(data, list):
        raise ValueError(f"raw records must be a JSON list: {path}")
    return [row for row in data if isinstance(row, dict)]


def parse_jsonish(value: Any, default: Any) -> Any:
    """Parse a field that may already be structured or may be JSON text."""
    if value in (None, ""):
        return default
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(str(value))
    except json.JSONDecodeError:
        return default


def discover_vulhub_candidates(vulhub_dir: str | Path) -> list[AtomScaleRecord]:
    """Find Vulhub docker-compose directories that have explicit CVE ids."""
    root = Path(vulhub_dir)
    candidates: list[AtomScaleRecord] = []
    for compose in sorted(root.rglob("docker-compose.yml")):
        cve_id = normalize_cve_id(compose.parent.name)
        if not cve_id:
            continue
        candidates.append(
            AtomScaleRecord(
                cve_id=cve_id,
                source_type="vulhub",
                source_path=str(compose.parent),
                metadata={"category": compose.parent.parent.name},
            )
        )
    return candidates


def discover_raw_record_candidates(
    raw_record_paths: Iterable[str | Path],
    generated_sources_dir: str | Path,
) -> list[AtomScaleRecord]:
    """Load raw record files and materialize runnable compose sources for CVE rows."""
    records: list[AtomScaleRecord] = []
    generated_root = Path(generated_sources_dir)
    for raw_path in raw_record_paths:
        for row in load_raw_records(raw_path):
            cve_id = normalize_cve_id(row.get("cve_id") or row.get("source_record_id"))
            if not cve_id:
                continue

            source_path = materialize_raw_record_source(row, generated_root, cve_id)
            image_name = row.get("image_name") or ""
            image_tag = row.get("image_tag") or ""
            image = f"{image_name}:{image_tag}" if image_name and image_tag else image_name
            records.append(
                AtomScaleRecord(
                    cve_id=cve_id,
                    source_type="raw_records",
                    source_path=str(source_path),
                    raw_record_id=str(row.get("source_record_id") or cve_id),
                    image=image,
                    ports=[str(p) for p in parse_jsonish(row.get("exposed_ports"), [])],
                    metadata={
                        "raw_records_file": str(raw_path),
                        "archive_path": row.get("vuln_archive_path"),
                        "archive_exists": Path(str(row.get("vuln_archive_path"))).exists()
                        if row.get("vuln_archive_path")
                        else False,
                        "analysis_status": row.get("analysis_status"),
                        "is_dockerizable": row.get("is_dockerizable"),
                        "vuln_version_url": row.get("vuln_version_url"),
                        "last_test_build": row.get("last_test_build"),
                        "last_test_start": row.get("last_test_start"),
                        "host_port_map": parse_jsonish(row.get("host_port_map"), {}),
                    },
                )
            )
    return records


def discover_cve_factory_candidates(
    task_root: str | Path,
    generated_sources_dir: str | Path,
    task_paths: Iterable[str] = (),
) -> list[AtomScaleRecord]:
    """Prepare CVE-Factory tasks as regular Atomizer source directories.

    CVE-Factory's task format is only an input source.  It deliberately does
    not bypass the normal Atomizer/LLM native-verification pipeline: a task
    whose test is merely a marker or non-exploitable proof remains unverified
    and cannot enter the Range dataset.
    """
    root = Path(task_root)
    generated_root = Path(generated_sources_dir) / "cve_factory"
    if not root.is_dir():
        return []

    requested = [root / path for path in task_paths]
    task_dirs = requested if requested else sorted({path.parent for name in (
        "docker-compose.yaml", "docker-compose.yml"
    ) for path in root.rglob(name)})

    records: list[AtomScaleRecord] = []
    for task_dir in task_dirs:
        if not task_dir.is_dir() or not task_dir.is_relative_to(root):
            continue
        cve_id = normalize_cve_id(task_dir.name)
        if not cve_id:
            continue
        prepared = prepare_cve_factory_source(task_dir, generated_root / cve_id, cve_id)
        task_yaml = task_dir / "task.yaml"
        task_meta: dict[str, Any] = {}
        if task_yaml.is_file():
            try:
                task_meta = yaml.safe_load(task_yaml.read_text(encoding="utf-8")) or {}
            except (OSError, yaml.YAMLError):
                task_meta = {}
        records.append(AtomScaleRecord(
            cve_id=cve_id,
            source_type="cve_factory",
            source_path=str(prepared),
            metadata={
                "cve_factory_task_path": str(task_dir),
                "cve_factory_relative_path": str(task_dir.relative_to(root)),
                "cve_factory_category": task_meta.get("category", ""),
                "cve_factory_difficulty": task_meta.get("difficulty", ""),
            },
        ))
    return records


def _resolve_cve_factory_vars(value: Any, cve_id: str) -> Any:
    if isinstance(value, str):
        mapping = {
            "T_BENCH_TASK_DOCKER_CLIENT_IMAGE_NAME": f"cve-{cve_id.lower()}:vuln",
            "T_BENCH_TASK_DOCKER_CLIENT_CONTAINER_NAME": f"cve-{cve_id.lower()}-client",
            "T_BENCH_TEST_DIR": "/tests",
            "T_BENCH_TASK_LOGS_PATH": "/tmp/logs",
            "T_BENCH_CONTAINER_LOGS_PATH": "/tmp/container-logs",
            "T_BENCH_TASK_AGENT_LOGS_PATH": "/tmp/agent-logs",
            "T_BENCH_CONTAINER_AGENT_LOGS_PATH": "/tmp/container-agent-logs",
        }
        return re.sub(r"\$\{(\w+)\}", lambda m: mapping.get(m.group(1), m.group(0)), value)
    if isinstance(value, list):
        return [_resolve_cve_factory_vars(item, cve_id) for item in value]
    if isinstance(value, dict):
        return {key: _resolve_cve_factory_vars(item, cve_id) for key, item in value.items()}
    return value


def _cve_factory_exposed_port(task_dir: Path) -> int | None:
    dockerfile = task_dir / "Dockerfile"
    if dockerfile.is_file():
        for line in dockerfile.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip().upper().startswith("EXPOSE"):
                match = re.search(r"\b(\d+)(?:/\w+)?\b", line)
                if match:
                    return int(match.group(1))
    for test_name in ("test_vuln.py", "test_func.py"):
        test = task_dir / "tests" / test_name
        if not test.is_file():
            continue
        text = test.read_text(encoding="utf-8", errors="replace")[:4000]
        match = re.search(r"(?:APP_URL|localhost)[^'\"}]*:(\d+)", text)
        if match:
            return int(match.group(1))
    return None


def prepare_cve_factory_source(task_dir: Path, destination: Path, cve_id: str) -> Path:
    """Adapt one Terminal-Bench task without changing its runtime semantics."""
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(task_dir, destination)
    compose_yaml = destination / "docker-compose.yaml"
    compose_yml = destination / "docker-compose.yml"
    if compose_yaml.exists() and not compose_yml.exists():
        compose_yaml.rename(compose_yml)
    if compose_yml.exists():
        compose = yaml.safe_load(compose_yml.read_text(encoding="utf-8")) or {}
        compose = _resolve_cve_factory_vars(compose, cve_id)
        services = compose.get("services") or {}
        for service in services.values():
            if not isinstance(service, dict):
                continue
            service["image"] = f"cve-{cve_id.lower()}:vuln"
            build = service.get("build")
            if not isinstance(build, dict):
                build = {"dockerfile": "Dockerfile", "context": "."}
            build.setdefault("network", "host")
            service["build"] = build
            service.pop("container_name", None)
            service.pop("healthcheck", None)
            if not service.get("ports") and not service.get("expose"):
                port = _cve_factory_exposed_port(destination)
                if port:
                    service["expose"] = [str(port)]
        compose_yml.write_text(
            yaml.safe_dump(compose, sort_keys=False, allow_unicode=True), encoding="utf-8"
        )
    readme = destination / "README.md"
    if not readme.exists():
        task_meta = {}
        task_yaml = destination / "task.yaml"
        if task_yaml.is_file():
            task_meta = yaml.safe_load(task_yaml.read_text(encoding="utf-8")) or {}
        readme.write_text(
            "\n".join((
                f"# {cve_id}", "", "Generated from CVE-Factory task.", "",
                "## Description", str(task_meta.get("instruction", "")), "",
            )),
            encoding="utf-8",
        )
    return destination


def materialize_raw_record_source(
    row: dict[str, Any],
    generated_root: Path,
    cve_id: str,
) -> Path:
    """Create a small compose/README source tree for a raw record image."""
    source_dir = generated_root / "raw_records" / cve_id
    source_dir.mkdir(parents=True, exist_ok=True)

    image_name = row.get("image_name") or cve_id.lower()
    image_tag = row.get("image_tag") or "latest"
    ports = [str(p) for p in parse_jsonish(row.get("exposed_ports"), [])]
    if not ports:
        host_map = parse_jsonish(row.get("host_port_map"), {})
        ports = [f"{host}:{container.split('/')[0]}" for container, host in host_map.items()]

    service = {
        "image": f"{image_name}:{image_tag}",
    }
    if ports:
        service["ports"] = ports

    compose = {
        "services": {
            "target": service,
        }
    }
    (source_dir / "docker-compose.yml").write_text(
        yaml.dump(compose, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )

    description = [
        f"# {cve_id}",
        "",
        "Generated from raw_records data.",
        f"- source_record_id: {row.get('source_record_id') or ''}",
        f"- image: {image_name}:{image_tag}",
        f"- vuln_version_url: {row.get('vuln_version_url') or ''}",
        f"- vuln_archive_path: {row.get('vuln_archive_path') or ''}",
    ]
    (source_dir / "README.md").write_text("\n".join(description) + "\n", encoding="utf-8")
    return source_dir


def dedupe_candidates(candidates: Iterable[AtomScaleRecord]) -> list[AtomScaleRecord]:
    """Deduplicate by CVE id, preferring Vulhub over generated raw records."""
    priority = {"vulhub": 0, "cve_factory": 1, "raw_records": 2}
    selected: dict[str, AtomScaleRecord] = {}
    for candidate in sorted(candidates, key=lambda c: (priority.get(c.source_type, 99), c.cve_id)):
        key = candidate.key
        if key not in selected:
            selected[key] = candidate
    return list(selected.values())


def load_manifest(path: str | Path) -> list[AtomScaleRecord]:
    manifest_path = Path(path)
    if not manifest_path.exists():
        return []
    records = []
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        records.append(AtomScaleRecord(**row))
    return records


def write_jsonl(path: str | Path, records: Iterable[AtomScaleRecord | dict[str, Any]]) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for record in records:
        row = record.to_dict() if isinstance(record, AtomScaleRecord) else record
        lines.append(json.dumps(row, ensure_ascii=False, sort_keys=True))
    out.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _succeeded_records(records: Iterable[AtomScaleRecord]) -> list[AtomScaleRecord]:
    """Filter records down to verified atoms for the clean dataset export."""
    return [record for record in records if record.status == "succeeded"]


def populate_range_admission(record: AtomScaleRecord, atom_dir: Path) -> None:
    """Materialize an Atom's Range-relevant contract into its dataset row."""
    atom_yaml = atom_dir / "atom.yaml"
    if not atom_yaml.is_file():
        record.admission_schema_version = 1
        record.range_admitted = False
        record.qualification_status = "excluded"
        record.qualification = {"reasons": ["atom.yaml missing"]}
        record.range_index = {}
        return
    try:
        atom = AtomConfig.model_validate(yaml.safe_load(atom_yaml.read_text(encoding="utf-8")) or {})
    except Exception as exc:
        record.admission_schema_version = 1
        record.range_admitted = False
        record.qualification_status = "excluded"
        record.qualification = {"reasons": [f"atom parse failed: {exc}"]}
        record.range_index = {}
        return

    qualification = qualify_atom(atom, atom_dir)
    atom_data = atom.model_dump(mode="json", exclude={"flag_value"})
    verified_grants = [
        grant for grant in atom_data["capability_grants"]
        if grant.get("evidence_level") == "verified"
    ]
    guide = atom_data.get("exploit_guide") or {}
    verification = atom_data.get("verification") or {}
    record.admission_schema_version = 1
    record.range_admitted = qualification.template_candidate
    record.qualification_status = qualification.status
    record.qualification = qualification.to_dict()
    record.range_index = {
        "atom_version": atom.version,
        "source_kind": record.source_type,
        "vuln_category": atom.vuln_category.value,
        "primary_mitre_phase": atom.primary_mitre_phase.value,
        "service_role": atom.service_role.value,
        "attack_method": atom.attack_method.value,
        "exploit_complexity": atom.exploit_complexity.value,
        "exploit_access": atom_data["exploit_access"],
        "capability_grants": verified_grants,
        "capability_types": sorted({grant["type"] for grant in verified_grants}),
        "capability_principals": sorted({grant["principal"] for grant in verified_grants}),
        "services": atom_data["services"],
        "runtime_spec": atom_data["runtime_spec"],
        "network_requirements": atom_data["network_requirements"],
        "post_exploit": atom_data["post_exploit"],
        "source_bundle": atom_data["source_bundle"],
        "guide": {
            "present": bool(guide),
            "ready": guide.get("status") == "ready",
            "path": guide.get("path", ""),
            "provenance": guide.get("provenance", ""),
        },
        "verification": {
            "native_verified": bool((verification.get("native_verification") or {}).get("success")),
            "environment_ready": verification.get("environment_ready"),
            "orchestrated_verified": bool(
                (verification.get("orchestrated_verification") or {}).get("success")
            ),
        },
    }


def export_hf_dataset(path: str | Path, records: Iterable[AtomScaleRecord]) -> str:
    """Export records as a HuggingFace-friendly parquet file."""
    import pandas as pd

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = [record.to_dict() for record in records]
    for row in rows:
        row["ports"] = json.dumps(row.get("ports", []), ensure_ascii=False)
        row["metadata"] = json.dumps(row.get("metadata", {}), ensure_ascii=False, sort_keys=True)
        row["qualification"] = json.dumps(
            row.get("qualification", {}), ensure_ascii=False, sort_keys=True
        )
        row["range_index"] = json.dumps(
            row.get("range_index", {}), ensure_ascii=False, sort_keys=True
        )
    pd.DataFrame(rows).to_parquet(out, index=False)
    return str(out)


def disk_free_gb(path: str = "/var") -> float:
    """Free disk space in GB at the given mount point (default: docker root)."""
    try:
        return shutil.disk_usage(path).free / (1024 ** 3)
    except OSError:
        return float("inf")


class AtomScaleRunner:
    """Discover, deduplicate, run, and record atomization jobs."""

    def __init__(
        self,
        vulhub_dir: str = "data/vulhub",
        raw_records: tuple[str, ...] = (),
        cve_factory_dir: str = "",
        cve_factory_tasks: tuple[str, ...] = (),
        output_dir: str = "data/atoms",
        state_dir: str = "data/atom_scale",
        generated_sources_dir: str = "data/generated",
    ):
        self.vulhub_dir = vulhub_dir
        self.raw_records = raw_records
        self.cve_factory_dir = cve_factory_dir
        self.cve_factory_tasks = cve_factory_tasks
        self.output_dir = Path(output_dir)
        self.state_dir = Path(state_dir)
        self.generated_sources_dir = Path(generated_sources_dir)
        self.manifest_path = self.state_dir / "manifest.jsonl"
        self.dataset_jsonl_path = self.state_dir / "dataset.jsonl"
        self.dataset_parquet_path = self.state_dir / "dataset.parquet"

    def discover(self) -> list[AtomScaleRecord]:
        candidates: list[AtomScaleRecord] = []
        if self.vulhub_dir:
            candidates.extend(discover_vulhub_candidates(self.vulhub_dir))
        if self.raw_records:
            candidates.extend(
                discover_raw_record_candidates(self.raw_records, self.generated_sources_dir)
            )
        if self.cve_factory_dir:
            candidates.extend(discover_cve_factory_candidates(
                self.cve_factory_dir,
                self.generated_sources_dir,
                self.cve_factory_tasks,
            ))
        records = dedupe_candidates(candidates)
        records.sort(key=lambda item: item.cve_id)
        # Preserve historical statuses: if a manifest already exists, do not
        # clobber rows whose work was already completed in a previous run.
        # Only newly-discovered CVE ids are appended as `queued`.
        existing = self._load_historical_records()
        merged: list[AtomScaleRecord] = []
        seen: set[str] = set()
        for candidate in records:
            seen.add(candidate.key)
            prior = existing.get(candidate.key)
            if prior is None:
                merged.append(candidate)
            else:
                # Keep the prior state (queued/running/succeeded/failed/skipped_existing)
                # but refresh source-side metadata in case Vulhub paths/ports moved.
                prior.source_type = candidate.source_type
                prior.source_path = candidate.source_path
                prior.raw_record_id = candidate.raw_record_id or prior.raw_record_id
                prior.image = candidate.image or prior.image
                prior.ports = candidate.ports or prior.ports
                if candidate.metadata:
                    merged_meta = dict(prior.metadata or {})
                    merged_meta.update(candidate.metadata)
                    prior.metadata = merged_meta
                merged.append(prior)
        # Keep historical rows that are not present in the current source scan.
        # This prevents a narrower later invocation (for example omitting
        # --raw-records, moving a source dir, or running a subset) from erasing
        # already completed/failed records from the ledger and dataset.
        for key, prior in existing.items():
            if key not in seen:
                merged.append(prior)
        merged = self._merge_existing_atom_base(merged)
        # Reconcile against on-disk atom artefacts so that any successful runs
        # whose manifest update was lost get re-promoted to skipped_existing.
        merged = [self._reconcile_record(record) for record in merged]
        merged.sort(key=lambda item: item.cve_id)
        # manifest = full ledger (all states); dataset = only verified atoms
        self._persist(merged, export_parquet=False)
        return merged

    def run(
        self,
        api_key: str = "",
        base_url: str = "",
        model: str = "",
        skip_agent: bool = False,
        force: bool = False,
        limit: int | None = None,
        max_turns: int = 80,
        llm_checker: bool = True,
        export_parquet: bool = True,
        workers: int = 1,
        min_disk_gb: float = 5.0,
        cve_filter: tuple[str, ...] = (),
        retry_failed: bool = False,
    ) -> list[AtomScaleRecord]:
        records = list(self._load_historical_records().values()) or self.discover()

        # Reconcile manifest rows against on-disk atom artefacts so that
        # successful runs whose manifest update was dropped (e.g. crash mid-write)
        # are not rerun and overwritten.
        records = [self._reconcile_record(record) for record in records]

        existing_by_key = {record.key: record for record in records}
        completed = self._load_existing_results()
        for key, completed_record in completed.items():
            if key in existing_by_key and not force:
                existing_by_key[key] = completed_record
        records = list(existing_by_key.values())

        if force:
            runnable = list(records)
        else:
            runnable_statuses = {"queued"}
            if retry_failed:
                runnable_statuses.add("failed")
            runnable = [record for record in records if record.status in runnable_statuses]
        if cve_filter:
            wanted = {cve.upper() for cve in cve_filter}
            runnable = [record for record in runnable if record.key in wanted]
        if limit is not None:
            runnable = runnable[:limit]

        updated: dict[str, AtomScaleRecord] = {record.key: record for record in records}
        lock = threading.Lock()

        def _execute(record: AtomScaleRecord) -> AtomScaleRecord:
            return self._run_one(
                record,
                api_key=api_key,
                base_url=base_url,
                model=model,
                skip_agent=skip_agent,
                force=force,
                max_turns=max_turns,
                llm_checker=llm_checker,
            )

        def _handle_done(result: AtomScaleRecord) -> None:
            with lock:
                updated[result.key] = result
                self._persist(updated.values(), export_parquet=export_parquet)

        if workers <= 1:
            for record in runnable:
                _handle_done(_execute(record))
        else:
            # 任务池模型：N 个任务、W 个并行 worker；每完成一个立即落盘并领取新任务，
            # 磁盘剩余不足时暂停领取，等在途任务清理镜像释放空间后再续。
            with ThreadPoolExecutor(max_workers=workers) as pool:
                in_flight: set = set()
                todo = iter(runnable)
                for _ in range(workers):  # 预填充 W 个任务
                    try:
                        in_flight.add(pool.submit(_execute, next(todo)))
                    except StopIteration:
                        break
                while in_flight:
                    done, in_flight = futures_wait(in_flight, return_when=FIRST_COMPLETED)
                    for future in done:
                        _handle_done(future.result())  # 完成一个立即写 manifest
                    while len(in_flight) < workers:  # 空闲槽位 + 磁盘充足 → 领新任务
                        if min_disk_gb > 0 and disk_free_gb() < min_disk_gb:
                            break
                        try:
                            in_flight.add(pool.submit(_execute, next(todo)))
                        except StopIteration:
                            break

        self._persist(updated.values(), export_parquet=export_parquet)
        return sorted(updated.values(), key=lambda item: item.cve_id)

    def write_outputs(
        self,
        records: Iterable[AtomScaleRecord],
        export_parquet: bool = True,
    ) -> None:
        """Write full manifest ledger and a succeeded-only dataset (JSONL + optional parquet)."""
        self._persist(records, export_parquet=export_parquet)

    def _run_one(
        self,
        record: AtomScaleRecord,
        api_key: str,
        base_url: str,
        model: str,
        skip_agent: bool,
        force: bool,
        max_turns: int,
        llm_checker: bool,
    ) -> AtomScaleRecord:
        atom_dir = self.output_dir / record.cve_id
        raw_asset_error = self._prepare_raw_record_image(record)
        if raw_asset_error:
            record.status = "missing_build_asset"
            record.error = raw_asset_error
            record.updated_at = utc_now_iso()
            return record
        if atom_dir.joinpath("atom.yaml").exists() and not force:
            record.status = "skipped_existing"
            record.atom_path = str(atom_dir)
            record.session_path = str(atom_dir / "session.json")
            record.has_session = (atom_dir / "session.json").exists()
            record.updated_at = utc_now_iso()
            return record

        record.status = "running"
        record.started_at = utc_now_iso()
        start = time.monotonic()
        try:
            pipeline = AtomizerPipeline(
                vulhub_dir=record.source_path,
                output_dir=str(self.output_dir),
                max_turns=max_turns,
            )
            result = pipeline.run(
                api_key=api_key,
                base_url=base_url,
                model=model,
                skip_agent=skip_agent,
                llm_checker=llm_checker,
                force=force,
            )
            record.atom_path = str(atom_dir)
            record.session_path = str(atom_dir / "session.json")
            record.has_session = (atom_dir / "session.json").exists()
            record.status = "succeeded" if result.get("success") else "failed"
            record.error = "" if result.get("success") else str(result.get("error", "agent failed"))
        except Exception as exc:
            record.status = "failed"
            record.error = str(exc)
        finally:
            record.finished_at = utc_now_iso()
            record.updated_at = record.finished_at
            record.duration_seconds = round(time.monotonic() - start, 3)
        return record

    @staticmethod
    def _prepare_raw_record_image(record: AtomScaleRecord) -> str:
        """Require the verified local raw-record Docker image to be present."""
        if record.source_type != "raw_records":
            return ""

        try:
            inspect = subprocess.run(
                ["docker", "image", "inspect", record.image],
                capture_output=True, text=True, timeout=20,
            )
        except subprocess.TimeoutExpired:
            return f"timed out checking verified raw-record image: {record.image}"
        if inspect.returncode == 0:
            return ""

        archive_value = str((record.metadata or {}).get("archive_path") or "")
        return (
            f"verified raw-record Docker image is missing: image={record.image}, "
            f"source_archive={archive_value or '<none>'}; restore or rebuild the recorded image"
        )

    def _load_existing_results(self) -> dict[str, AtomScaleRecord]:
        return self._load_historical_records()

    def _load_historical_records(self) -> dict[str, AtomScaleRecord]:
        """Load previous ledger state, using succeeded dataset rows as a recovery source."""
        records = {record.key: record for record in load_manifest(self.manifest_path)}
        for record in load_manifest(self.dataset_jsonl_path):
            prior = records.get(record.key)
            if prior is None or prior.status != "succeeded":
                records[record.key] = record
            elif record.status == "succeeded":
                self._merge_missing_time_fields(prior, record)
        return records

    @staticmethod
    def _merge_missing_time_fields(target: AtomScaleRecord, source: AtomScaleRecord) -> None:
        """Preserve historical timing when one ledger copy has blanks."""
        for field_name in ("started_at", "finished_at", "duration_seconds", "updated_at"):
            if not getattr(target, field_name) and getattr(source, field_name):
                setattr(target, field_name, getattr(source, field_name))

    def _reconcile_record(self, record: AtomScaleRecord) -> AtomScaleRecord:
        """Repair stale manifest rows by inspecting on-disk atom artefacts.

        Two cases are repaired:
        - manifest says queued/running/failed but the atom directory exists with
          atom.yaml present → promote to skipped_existing and treat the prior atom
          as authoritative (so we never re-run and clobber a working flag).
        - atom.yaml exists and records `verified: true` → mark as succeeded so the
          row flows into dataset.jsonl even if the manifest write was lost.
        """
        atom_dir = self.output_dir / record.cve_id
        atom_yaml = atom_dir / "atom.yaml"
        if not atom_yaml.exists():
            return record
        verified = False
        try:
            data = yaml.safe_load(atom_yaml.read_text(encoding="utf-8")) or {}
            verified = bool(data.get("verified"))
        except (OSError, yaml.YAMLError):
            verified = False
        session_path = atom_dir / "session.json"
        has_session = session_path.exists()
        if record.status in {"queued", "running"}:
            record.status = "succeeded" if verified else "skipped_existing"
            record.atom_path = record.atom_path or str(atom_dir)
            record.session_path = record.session_path or (str(session_path) if has_session else "")
            record.has_session = has_session
            if not record.updated_at:
                record.updated_at = utc_now_iso()
        elif record.status == "failed" and verified:
            # On-disk atom is verified — trust the artefact and clear the error.
            record.status = "succeeded"
            record.error = ""
            record.atom_path = str(atom_dir)
            record.session_path = str(session_path) if has_session else record.session_path
            record.has_session = has_session
            record.updated_at = utc_now_iso()
        self._backfill_record_time_from_session(record)
        return record

    def _merge_existing_atom_base(self, records: list[AtomScaleRecord]) -> list[AtomScaleRecord]:
        """Register existing verified atoms so a fresh index can be backfilled.

        This is what makes ``data/atoms/<CVE>/`` the authoritative base while
        keeping ``dataset.jsonl`` a reproducible, derived Range admission index.
        """
        by_key = {record.key: record for record in records}
        if not self.output_dir.is_dir():
            return records
        for atom_yaml in self.output_dir.glob("*/atom.yaml"):
            atom_dir = atom_yaml.parent
            try:
                atom = AtomConfig.model_validate(
                    yaml.safe_load(atom_yaml.read_text(encoding="utf-8")) or {}
                )
            except Exception:
                continue
            key = atom.cve_id.upper()
            record = by_key.get(key)
            if record is None:
                source_lower = atom.source.lower()
                source_type = "cve_factory" if "cve_factory" in source_lower or "cve_factory" in atom.category else "vulhub"
                record = AtomScaleRecord(
                    cve_id=atom.cve_id,
                    source_type=source_type,
                    source_path=atom.source,
                    status="succeeded" if atom.verified else "skipped_existing",
                    atom_path=str(atom_dir),
                )
                by_key[key] = record
            elif atom.verified and record.status in {"queued", "running", "failed", "skipped_existing"}:
                record.status = "succeeded"
                record.error = ""
                record.atom_path = str(atom_dir)
        return list(by_key.values())

    @staticmethod
    def _parse_session_timestamp(value: Any) -> datetime | None:
        if not value:
            return None
        text = str(value)
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            return None

    def _session_time_bounds(self, session_path: Path) -> tuple[datetime, datetime] | None:
        if not session_path.exists():
            return None
        first: datetime | None = None
        last: datetime | None = None
        try:
            lines = session_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return None
        for line in lines:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = self._parse_session_timestamp(event.get("timestamp"))
            if not ts:
                continue
            if first is None or ts < first:
                first = ts
            if last is None or ts > last:
                last = ts
        if first and last:
            return first, last
        return None

    def _backfill_record_time_from_session(self, record: AtomScaleRecord) -> None:
        """Fill missing timing fields for recovered atoms without overwriting job times."""
        if record.status != "succeeded":
            return
        if record.started_at and record.finished_at and record.duration_seconds:
            return
        session_path = Path(record.session_path) if record.session_path else self.output_dir / record.cve_id / "session.json"
        bounds = self._session_time_bounds(session_path)
        if not bounds:
            return
        started, finished = bounds
        if not record.started_at:
            record.started_at = started.isoformat().replace("+00:00", "Z")
        if not record.finished_at:
            record.finished_at = finished.isoformat().replace("+00:00", "Z")
        if not record.duration_seconds:
            record.duration_seconds = round((finished - started).total_seconds(), 3)
        if not record.updated_at:
            record.updated_at = record.finished_at

    def _persist(self, records: Iterable[AtomScaleRecord], export_parquet: bool = True) -> None:
        sorted_records = sorted(records, key=lambda item: item.cve_id)
        for record in sorted_records:
            self._backfill_record_time_from_session(record)
            if record.status == "succeeded":
                atom_dir = Path(record.atom_path) if record.atom_path else self.output_dir / record.cve_id
                populate_range_admission(record, atom_dir)
        # manifest retains ALL historical states (queued/running/succeeded/failed/...)
        write_jsonl(self.manifest_path, sorted_records)
        # dataset exports only verified (succeeded) atoms as clean training data
        succeeded = _succeeded_records(sorted_records)
        write_jsonl(self.dataset_jsonl_path, succeeded)
        if export_parquet:
            export_hf_dataset(self.dataset_parquet_path, succeeded)
