import json
from pathlib import Path

import yaml

from clab_builder.atomizer.output.vulhub_converter import VulhubParser
from clab_builder.atomizer.scaling import (
    AtomScaleRunner,
    dedupe_candidates,
    discover_raw_record_candidates,
    discover_vulhub_candidates,
    load_raw_records,
)


def write_compose(path: Path, image: str = "vulhub/test:latest"):
    path.mkdir(parents=True, exist_ok=True)
    (path / "docker-compose.yml").write_text(
        yaml.dump({"services": {"web": {"image": image, "ports": ["8080:80"]}}})
    )
    (path / "README.md").write_text("# Test CVE\n")


def test_discover_vulhub_candidates_keeps_only_explicit_cves(tmp_path):
    vulhub = tmp_path / "vulhub"
    write_compose(vulhub / "app" / "CVE-2024-12345")
    write_compose(vulhub / "app" / "not-a-cve")

    records = discover_vulhub_candidates(vulhub)

    assert [record.cve_id for record in records] == ["CVE-2024-12345"]
    assert records[0].source_type == "vulhub"


def test_raw_records_loader_and_materialized_source(tmp_path):
    raw_path = tmp_path / "raw_records.json"
    raw_path.write_text(
        "JJH"
        + json.dumps(
            [
                {
                    "source_record_id": "CVE-2024-0001",
                    "cve_id": "CVE-2024-0001",
                    "image_name": "cve-2024-0001",
                    "image_tag": "vuln",
                    "exposed_ports": "[\"18080:80\"]",
                    "host_port_map": "{\"80/tcp\": \"18080\"}",
                },
                {"source_record_id": "GHSA-only", "cve_id": None},
            ]
        )
    )

    loaded = load_raw_records(raw_path)
    assert len(loaded) == 2

    records = discover_raw_record_candidates([raw_path], tmp_path / "generated")
    assert len(records) == 1
    assert records[0].cve_id == "CVE-2024-0001"

    source_path = Path(records[0].source_path)
    compose = yaml.safe_load((source_path / "docker-compose.yml").read_text())
    assert compose["services"]["target"]["image"] == "cve-2024-0001:vuln"
    assert compose["services"]["target"]["ports"] == ["18080:80"]

    env = VulhubParser().parse(str(source_path))
    assert env.cve_id == "CVE-2024-0001"
    assert env.category == "raw_records"


def test_dedupe_prefers_vulhub_over_raw_records(tmp_path):
    vulhub = tmp_path / "vulhub"
    write_compose(vulhub / "app" / "CVE-2024-12345")
    raw_path = tmp_path / "raw_records.json"
    raw_path.write_text(
        json.dumps(
            [
                {
                    "source_record_id": "CVE-2024-12345",
                    "cve_id": "CVE-2024-12345",
                    "image_name": "raw-image",
                    "image_tag": "vuln",
                }
            ]
        )
    )

    records = dedupe_candidates(
        discover_raw_record_candidates([raw_path], tmp_path / "generated")
        + discover_vulhub_candidates(vulhub)
    )

    assert len(records) == 1
    assert records[0].source_type == "vulhub"


def test_runner_discover_writes_unique_dataset(tmp_path):
    vulhub = tmp_path / "vulhub"
    write_compose(vulhub / "app" / "CVE-2024-12345")
    raw_path = tmp_path / "raw_records.json"
    raw_path.write_text(
        json.dumps(
            [
                {
                    "source_record_id": "CVE-2024-22222",
                    "cve_id": "CVE-2024-22222",
                    "image_name": "raw-image",
                    "image_tag": "vuln",
                },
                {
                    "source_record_id": "CVE-2024-22222",
                    "cve_id": "CVE-2024-22222",
                    "image_name": "raw-image",
                    "image_tag": "vuln",
                },
            ]
        )
    )

    runner = AtomScaleRunner(
        vulhub_dir=str(vulhub),
        raw_records=(str(raw_path),),
        output_dir=str(tmp_path / "atoms"),
        state_dir=str(tmp_path / "state"),
        generated_sources_dir=str(tmp_path / "generated"),
    )
    records = runner.discover()

    assert [record.cve_id for record in records] == ["CVE-2024-12345", "CVE-2024-22222"]
    # manifest = full ledger (both queued candidates); dataset = only succeeded (none yet)
    manifest_lines = (tmp_path / "state" / "manifest.jsonl").read_text().splitlines()
    assert len(manifest_lines) == 2
    dataset_lines = (tmp_path / "state" / "dataset.jsonl").read_text().splitlines()
    assert dataset_lines == []


def test_discover_preserves_historical_rows_not_in_current_sources(tmp_path):
    """A narrower later discovery must not erase previous successful rows."""
    vulhub = tmp_path / "vulhub"
    write_compose(vulhub / "app" / "CVE-2024-3001")
    runner = AtomScaleRunner(
        vulhub_dir=str(vulhub),
        raw_records=(),
        output_dir=str(tmp_path / "atoms"),
        state_dir=str(tmp_path / "state"),
        generated_sources_dir=str(tmp_path / "generated"),
    )
    runner.state_dir.mkdir(parents=True)
    historical = {
        "cve_id": "CVE-2024-3002",
        "source_type": "raw_records",
        "source_path": "data/generated/raw_records/CVE-2024-3002",
        "status": "succeeded",
        "atom_path": "data/atoms/CVE-2024-3002",
        "error": "",
        "session_path": "data/atoms/CVE-2024-3002/session.json",
        "has_session": True,
        "duplicate_of": "",
        "raw_record_id": "CVE-2024-3002",
        "image": "cve-2024-3002:vuln",
        "ports": ["80:80"],
        "created_at": "2026-06-21T00:00:00",
        "updated_at": "2026-06-21T00:01:00",
        "started_at": "2026-06-21T00:00:01",
        "finished_at": "2026-06-21T00:00:02",
        "duration_seconds": 1.0,
        "metadata": {},
    }
    (runner.manifest_path).write_text(json.dumps(historical) + "\n")
    (runner.dataset_jsonl_path).write_text(json.dumps(historical) + "\n")

    records = runner.discover()

    assert {record.cve_id for record in records} == {"CVE-2024-3001", "CVE-2024-3002"}
    statuses = {record.cve_id: record.status for record in records}
    assert statuses["CVE-2024-3001"] == "queued"
    assert statuses["CVE-2024-3002"] == "succeeded"
    dataset = [
        json.loads(line)
        for line in runner.dataset_jsonl_path.read_text().splitlines()
        if line.strip()
    ]
    assert [row["cve_id"] for row in dataset] == ["CVE-2024-3002"]


def test_discover_recovers_succeeded_status_from_dataset(tmp_path):
    """dataset.jsonl is a recovery source if manifest was clobbered to queued."""
    vulhub = tmp_path / "vulhub"
    write_compose(vulhub / "app" / "CVE-2024-3003")
    runner = AtomScaleRunner(
        vulhub_dir=str(vulhub),
        raw_records=(),
        output_dir=str(tmp_path / "atoms"),
        state_dir=str(tmp_path / "state"),
        generated_sources_dir=str(tmp_path / "generated"),
    )
    runner.state_dir.mkdir(parents=True)
    stale = {
        "cve_id": "CVE-2024-3003",
        "source_type": "vulhub",
        "source_path": str(vulhub / "app" / "CVE-2024-3003"),
        "status": "queued",
    }
    succeeded = dict(stale)
    succeeded.update({
        "status": "succeeded",
        "atom_path": "data/atoms/CVE-2024-3003",
        "session_path": "data/atoms/CVE-2024-3003/session.json",
        "has_session": True,
    })
    runner.manifest_path.write_text(json.dumps(stale) + "\n")
    runner.dataset_jsonl_path.write_text(json.dumps(succeeded) + "\n")

    records = runner.discover()

    assert {record.cve_id: record.status for record in records} == {
        "CVE-2024-3003": "succeeded"
    }


def test_run_recovers_succeeded_status_from_dataset_without_discover(tmp_path, monkeypatch):
    """Direct API callers get the same dataset recovery as the CLI discover path."""
    vulhub = tmp_path / "vulhub"
    write_compose(vulhub / "app" / "CVE-2024-3004")
    runner = AtomScaleRunner(
        vulhub_dir=str(vulhub),
        raw_records=(),
        output_dir=str(tmp_path / "atoms"),
        state_dir=str(tmp_path / "state"),
        generated_sources_dir=str(tmp_path / "generated"),
    )
    runner.state_dir.mkdir(parents=True)
    stale = {
        "cve_id": "CVE-2024-3004",
        "source_type": "vulhub",
        "source_path": str(vulhub / "app" / "CVE-2024-3004"),
        "status": "queued",
    }
    succeeded = dict(stale)
    succeeded["status"] = "succeeded"
    runner.manifest_path.write_text(json.dumps(stale) + "\n")
    runner.dataset_jsonl_path.write_text(json.dumps(succeeded) + "\n")

    def fail_if_called(record, **kwargs):
        raise AssertionError("succeeded dataset row should not be re-run")

    monkeypatch.setattr(runner, "_run_one", fail_if_called)

    records = runner.run(skip_agent=True, export_parquet=False)

    assert {record.cve_id: record.status for record in records} == {
        "CVE-2024-3004": "succeeded"
    }


def test_runner_run_parallel_dispatches_all_and_persists(tmp_path, monkeypatch):
    """Parallel run() must execute every runnable record exactly once and persist results."""
    import threading

    vulhub = tmp_path / "vulhub"
    cves = ["CVE-2024-1001", "CVE-2024-1002", "CVE-2024-1003", "CVE-2024-1004"]
    for cve in cves:
        write_compose(vulhub / "app" / cve)

    runner = AtomScaleRunner(
        vulhub_dir=str(vulhub),
        raw_records=(),
        output_dir=str(tmp_path / "atoms"),
        state_dir=str(tmp_path / "state"),
        generated_sources_dir=str(tmp_path / "generated"),
    )
    runner.discover()

    seen: set[str] = set()
    counter = {"n": 0}
    counter_lock = threading.Lock()

    def fake_run_one(record, **kwargs):
        with counter_lock:
            counter["n"] += 1
            assert record.key not in seen, f"{record.key} ran twice"
            seen.add(record.key)
        record.status = "succeeded"
        record.atom_path = str(tmp_path / "atoms" / record.cve_id)
        record.updated_at = "2026-06-21T00:00:00"
        return record

    monkeypatch.setattr(runner, "_run_one", fake_run_one)

    results = runner.run(skip_agent=True, export_parquet=False, workers=4)

    assert counter["n"] == len(cves), "not all records executed"
    assert {r.cve_id for r in results} == set(cves)
    assert all(r.status == "succeeded" for r in results)

    # dataset.jsonl must reflect the persisted parallel results
    lines = (tmp_path / "state" / "dataset.jsonl").read_text().splitlines()
    assert len(lines) == len(cves)
    statuses = {json.loads(line)["status"] for line in lines}
    assert statuses == {"succeeded"}


def test_manifest_keeps_all_states_dataset_only_succeeded(tmp_path, monkeypatch):
    """manifest = full ledger (all statuses); dataset.jsonl/parquet = only succeeded rows."""
    vulhub = tmp_path / "vulhub"
    for cve in ["CVE-2024-2001", "CVE-2024-2002", "CVE-2024-2003"]:
        write_compose(vulhub / "app" / cve)

    runner = AtomScaleRunner(
        vulhub_dir=str(vulhub),
        raw_records=(),
        output_dir=str(tmp_path / "atoms"),
        state_dir=str(tmp_path / "state"),
        generated_sources_dir=str(tmp_path / "generated"),
    )
    runner.discover()

    desired = {
        "CVE-2024-2001": "succeeded",
        "CVE-2024-2002": "failed",
        "CVE-2024-2003": "succeeded",
    }

    def fake_run_one(record, **kwargs):
        record.status = desired[record.cve_id]
        if record.status == "failed":
            record.error = "agent failed"
        record.atom_path = str(tmp_path / "atoms" / record.cve_id)
        record.updated_at = "2026-06-21T00:00:00"
        return record

    monkeypatch.setattr(runner, "_run_one", fake_run_one)
    runner.run(skip_agent=True, export_parquet=True, workers=1)

    # manifest: full ledger, all three CVEs in every status
    manifest = [json.loads(line) for line in (tmp_path / "state" / "manifest.jsonl").read_text().splitlines()]
    assert {r["cve_id"]: r["status"] for r in manifest} == desired
    assert len(manifest) == 3

    # dataset.jsonl: only the two succeeded rows
    dataset = [json.loads(line) for line in (tmp_path / "state" / "dataset.jsonl").read_text().splitlines()]
    assert [r["cve_id"] for r in dataset] == ["CVE-2024-2001", "CVE-2024-2003"]
    assert all(r["status"] == "succeeded" for r in dataset)

    # parquet mirrors the succeeded-only dataset
    import pandas as pd
    pdf = pd.read_parquet(tmp_path / "state" / "dataset.parquet")
    assert len(pdf) == 2
    assert set(pdf["cve_id"]) == {"CVE-2024-2001", "CVE-2024-2003"}
    assert set(pdf["status"]) == {"succeeded"}


def test_runner_skips_failed_by_default_until_retry_failed(tmp_path, monkeypatch):
    """Failed records should not consume a normal queued-only batch."""
    vulhub = tmp_path / "vulhub"
    for cve in ["CVE-2024-2101", "CVE-2024-2102"]:
        write_compose(vulhub / "app" / cve)

    runner = AtomScaleRunner(
        vulhub_dir=str(vulhub),
        raw_records=(),
        output_dir=str(tmp_path / "atoms"),
        state_dir=str(tmp_path / "state"),
        generated_sources_dir=str(tmp_path / "generated"),
    )
    records = runner.discover()
    for record in records:
        if record.cve_id == "CVE-2024-2101":
            record.status = "failed"
            record.error = "known failure"
    runner.write_outputs(records, export_parquet=False)

    executed = []

    def fake_run_one(record, **kwargs):
        executed.append(record.cve_id)
        record.status = "succeeded"
        return record

    monkeypatch.setattr(runner, "_run_one", fake_run_one)

    runner.run(skip_agent=True, export_parquet=False)
    assert executed == ["CVE-2024-2102"]

    executed.clear()
    runner.run(skip_agent=True, export_parquet=False, retry_failed=True)
    assert executed == ["CVE-2024-2101"]


def test_generate_flag_is_deterministic_and_unique():
    from clab_builder.atomizer.pipeline import AtomizerPipeline

    f1 = AtomizerPipeline._generate_flag("CVE-2014-6271")
    f2 = AtomizerPipeline._generate_flag("CVE-2014-6271")
    f3 = AtomizerPipeline._generate_flag("CVE-2017-10271")
    assert f1 == f2, "flag must be deterministic for the same CVE"
    assert f1 != f3, "flag must differ across CVEs"
    assert f1.startswith("flag{cve-2014-6271-") and f1.endswith("}")


def test_flag_injection_command_uses_ctf_permissions():
    from clab_builder.atomizer.pipeline import AtomizerPipeline

    cmd = AtomizerPipeline._flag_injection_command("flag{abc}")

    assert "> /flag" in cmd
    assert "chmod 644 /flag" in cmd
    assert "cp /flag /tmp/flag.txt && chmod 644 /tmp/flag.txt" in cmd
    assert "cp /flag /root/flag.txt && chmod 600 /root/flag.txt" in cmd


def test_run_with_backpressure(monkeypatch, tmp_path):
    """run() must not call real docker even with disk backpressure on."""
    from clab_builder.atomizer import scaling

    vulhub = tmp_path / "vulhub"
    for cve in ["CVE-2024-9001", "CVE-2024-9002"]:
        write_compose(vulhub / "app" / cve)

    runner = scaling.AtomScaleRunner(
        vulhub_dir=str(vulhub),
        raw_records=(),
        output_dir=str(tmp_path / "atoms"),
        state_dir=str(tmp_path / "state"),
        generated_sources_dir=str(tmp_path / "generated"),
    )
    runner.discover()

    # neutralize any docker/subprocess calls
    monkeypatch.setattr(scaling, "disk_free_gb", lambda path="/var": 999.0)

    def fake_run_one(record, **kwargs):
        record.status = "succeeded"
        record.atom_path = str(tmp_path / "atoms" / record.cve_id)
        return record

    monkeypatch.setattr(runner, "_run_one", fake_run_one)
    results = runner.run(skip_agent=True, export_parquet=False, workers=2,
                         min_disk_gb=5.0)

    assert {r.cve_id for r in results} == {"CVE-2024-9001", "CVE-2024-9002"}
    assert all(r.status == "succeeded" for r in results)


def test_parallel_persists_after_each_completion(monkeypatch, tmp_path):
    """Completed atoms must be written to the manifest incrementally, not only at the end.

    Regression: an earlier version only persisted during disk-backpressure pauses or
    at the very end, so an interrupted run lost all progress (manifest stayed 'queued').
    """
    from clab_builder.atomizer import scaling

    vulhub = tmp_path / "vulhub"
    for cve in ["CVE-2024-9101", "CVE-2024-9102", "CVE-2024-9103", "CVE-2024-9104"]:
        write_compose(vulhub / "app" / cve)

    runner = scaling.AtomScaleRunner(
        vulhub_dir=str(vulhub),
        raw_records=(),
        output_dir=str(tmp_path / "atoms"),
        state_dir=str(tmp_path / "state"),
        generated_sources_dir=str(tmp_path / "generated"),
    )
    runner.discover()

    monkeypatch.setattr(scaling, "disk_free_gb", lambda path="/var": 999.0)

    import time as _time

    def fake_run_one(record, **kwargs):
        _time.sleep(0.02)  # let workers overlap
        record.status = "succeeded"
        record.atom_path = str(tmp_path / "atoms" / record.cve_id)
        return record

    monkeypatch.setattr(runner, "_run_one", fake_run_one)

    persist_calls = 0
    real_persist = runner._persist

    def counting_persist(records, export_parquet=True):
        nonlocal persist_calls
        persist_calls += 1
        real_persist(records, export_parquet=export_parquet)

    monkeypatch.setattr(runner, "_persist", counting_persist)

    results = runner.run(skip_agent=True, export_parquet=False, workers=2,
                         min_disk_gb=5.0)

    assert all(r.status == "succeeded" for r in results)
    assert len(results) == 4
    # 4 incremental (one per completion) + 1 final: strictly more than the old
    # single end-only persist (1) would have produced.
    assert persist_calls >= 4, f"expected incremental persist, got {persist_calls}"


def test_objective_success_requires_flag_match(tmp_path, monkeypatch):
    """run() success must be True only when captured_flag matches the injected flag."""
    from clab_builder.atomizer.pipeline import AtomizerPipeline
    from clab_builder.atomizer.agent.researcher import AgentOutput
    from clab_builder.atomizer.environment.container import ContainerInfo
    vulhub_root = Path(__file__).parent.parent.parent / "data" / "vulhub"
    log4j_dir = vulhub_root / "log4j" / "CVE-2021-44228"
    if not log4j_dir.exists():
        import pytest
        pytest.skip("vulhub data not found")

    fake_info = ContainerInfo(
        container_id="fake", container_name="fake", container_ip="172.18.0.2",
        image_name="vulhub/log4j:2.14.1", ports=[8983], status="running",
        created_time="2026-01-01 00:00:00",
    )

    ground_truth = AtomizerPipeline._generate_flag("CVE-2021-44228")

    def make_pipeline(outdir):
        p = AtomizerPipeline(vulhub_dir=str(log4j_dir), output_dir=str(outdir))
        return p

    def run_with(captured: str, tag: str):
        p = make_pipeline(tmp_path / f"atoms_{tag}")
        agent_out = AgentOutput(
            cve_id="CVE-2021-44228", success=True, exploit_steps=[],
            evidence=[], mitre_mapping={}, vulnerability_type="RCE",
            captured_flag=captured,
        )
        monkeypatch.setattr(p, "_start_cve_environment", lambda: (fake_info, "cve-net"))
        monkeypatch.setattr(p, "_run_agent", lambda *a, **k: agent_out)
        monkeypatch.setattr(p, "_cleanup", lambda: None)
        return p.run(api_key="k", model="m")

    # matching flag => success + verified
    ok = run_with(ground_truth, "ok")
    assert ok["success"] is True
    assert ok["flag_matched"] is True

    # mismatched flag => not success (even though agent self-reported success)
    bad = run_with("flag{wrong}", "bad")
    assert bad["success"] is False
    assert bad["flag_matched"] is False

    # atom.yaml records the ground-truth flag_value + verified reflects flag match
    import yaml as _yaml
    ok_data = _yaml.safe_load((tmp_path / "atoms_ok" / "CVE-2021-44228" / "atom.yaml").read_text())
    assert ok_data["flag_value"] == ground_truth
    assert ok_data["verified"] is True
    bad_data = _yaml.safe_load((tmp_path / "atoms_bad" / "CVE-2021-44228" / "atom.yaml").read_text())
    assert bad_data["flag_value"] == ground_truth
    assert bad_data["verified"] is False


def test_success_evaluation_is_flag_or_evidence():
    """Success rule is intentionally compact: exact flag when planted, evidence otherwise."""
    from clab_builder.atomizer.pipeline import AtomizerPipeline
    from clab_builder.atomizer.agent.researcher import AgentOutput

    out = AgentOutput(
        cve_id="CVE-TEST",
        success=True,
        exploit_steps=[],
        evidence=["objective proved"],
        mitre_mapping={},
        captured_flag="flag{ok}",
    )

    assert AtomizerPipeline._evaluate_agent_success(out, "flag{ok}").verified is True
    assert AtomizerPipeline._evaluate_agent_success(out, "flag{other}").verified is False
    no_flag = AtomizerPipeline._evaluate_agent_success(out, "")
    assert no_flag.verified is True
    assert no_flag.flag_matched is False

    # A runner can be interrupted after retrieving the flag but before emitting
    # a clean success result. Exact ground-truth match remains authoritative.
    out.success = False
    recovered = AtomizerPipeline._evaluate_agent_success(out, "flag{ok}")
    assert recovered.verified is True
    assert recovered.flag_matched is True


def test_info_leak_success_can_use_leak_evidence_without_flag(tmp_path, monkeypatch):
    """Info_Leak atoms can be verified by objective leak evidence when flag retrieval is not applicable."""
    from clab_builder.atomizer.pipeline import AtomizerPipeline
    from clab_builder.atomizer.agent.researcher import AgentOutput
    from clab_builder.atomizer.environment.container import ContainerInfo
    vulhub_root = Path(__file__).parent.parent.parent / "data" / "vulhub"
    nginx_dir = vulhub_root / "nginx" / "CVE-2017-7529"
    if not nginx_dir.exists():
        import pytest
        pytest.skip("vulhub data not found")

    fake_info = ContainerInfo(
        container_id="fake", container_name="fake", container_ip="172.18.0.2",
        image_name="vulhub/nginx:1.13.2", ports=[80], status="running",
        created_time="2026-01-01 00:00:00",
    )
    agent_out = AgentOutput(
        cve_id="CVE-2017-7529",
        success=True,
        exploit_steps=[],
        evidence=["Range request leaked cached response bytes from the target."],
        mitre_mapping={"collection": ["T1005"]},
        vulnerability_type="Information Disclosure / cache leak",
        captured_flag="",
        extra_fields={
            "vuln_category": "Info_Leak",
            "flag_verify_command": "Flag not reachable: vulnerability leaks cached response bytes, not arbitrary files.",
        },
    )

    p = AtomizerPipeline(vulhub_dir=str(nginx_dir), output_dir=str(tmp_path / "atoms"))
    monkeypatch.setattr(p, "_start_cve_environment", lambda: (fake_info, "cve-net"))
    monkeypatch.setattr(p, "_run_agent", lambda *a, **k: agent_out)
    monkeypatch.setattr(p, "_cleanup", lambda: None)

    result = p.run(api_key="k", model="m", llm_checker=False)
    assert result["success"] is True
    assert result["flag_matched"] is False

    import yaml as _yaml
    atom_data = _yaml.safe_load((tmp_path / "atoms" / "CVE-2017-7529" / "atom.yaml").read_text())
    assert atom_data["vuln_category"] == "Info_Leak"
    assert atom_data["verified"] is True
    assert "flag_value" not in atom_data


def test_auth_bypass_success_does_not_require_flag(tmp_path, monkeypatch):
    """Auth_Bypass/role escalation should be verified by native objective evidence."""
    from clab_builder.atomizer.pipeline import AtomizerPipeline
    from clab_builder.atomizer.agent.researcher import AgentOutput
    from clab_builder.atomizer.environment.container import ContainerInfo

    cve_dir = tmp_path / "vulhub" / "couchdb" / "CVE-2017-12635"
    cve_dir.mkdir(parents=True)
    (cve_dir / "docker-compose.yml").write_text(
        yaml.dump({"services": {"couchdb": {"image": "vulhub/couchdb:2.1.0", "ports": ["5984:5984"]}}})
    )
    (cve_dir / "README.md").write_text(
        "# Apache CouchDB Remote Privilege Escalation\n\n"
        "Submit _users documents with duplicate roles to create an admin user.\n"
    )
    fake_info = ContainerInfo(
        container_id="fake", container_name="fake", container_ip="172.24.0.2",
        image_name="vulhub/couchdb:2.1.0", ports=[5984], status="running",
        created_time="2026-01-01 00:00:00",
    )
    agent_out = AgentOutput(
        cve_id="CVE-2017-12635",
        success=True,
        exploit_steps=[],
        evidence=["Duplicate roles user was created and authenticated as admin."],
        mitre_mapping={"privilege_escalation": ["T1068"]},
        vulnerability_type="Authentication Bypass / Privilege Escalation",
        captured_flag="",
        extra_fields={
            "vuln_category": "Auth_Bypass",
            "flag_verify_command": "No flag: objective is admin role creation.",
        },
    )

    p = AtomizerPipeline(vulhub_dir=str(cve_dir), output_dir=str(tmp_path / "atoms"))
    assert p._should_inject_flag_for_env() is False
    monkeypatch.setattr(p, "_start_cve_environment", lambda: (fake_info, "cve-net"))
    monkeypatch.setattr(p, "_run_agent", lambda *a, **k: agent_out)
    monkeypatch.setattr(p, "_cleanup", lambda: None)

    result = p.run(api_key="k", model="m", llm_checker=False)

    assert result["success"] is True
    assert result["flag_matched"] is False
    import yaml as _yaml
    atom_data = _yaml.safe_load((tmp_path / "atoms" / "CVE-2017-12635" / "atom.yaml").read_text())
    assert atom_data["vuln_category"] == "Auth_Bypass"
    assert atom_data["verified"] is True
    assert "flag_value" not in atom_data


def test_llm_checker_can_reject_non_flag_success(tmp_path, monkeypatch):
    """For non-flag atoms, checker rejection should downgrade verified."""
    from clab_builder.atomizer.pipeline import AtomizerPipeline, LLMCheckResult
    from clab_builder.atomizer.agent.researcher import AgentOutput
    from clab_builder.atomizer.environment.container import ContainerInfo

    cve_dir = tmp_path / "vulhub" / "django" / "CVE-2017-12794"
    cve_dir.mkdir(parents=True)
    (cve_dir / "docker-compose.yml").write_text(
        yaml.dump({"services": {"web": {"image": "vulhub/django:1.11.4", "ports": ["8000:8000"]}}})
    )
    (cve_dir / "README.md").write_text(
        "# Django 500 Debug Page Cross-Site Scripting\n\n"
        "Trigger a duplicate username so the debug page renders unescaped input.\n"
    )
    fake_info = ContainerInfo(
        container_id="fake", container_name="fake", container_ip="172.24.0.2",
        image_name="vulhub/django:1.11.4", ports=[8000], status="running",
        created_time="2026-01-01 00:00:00",
    )
    agent_out = AgentOutput(
        cve_id="CVE-2017-12794",
        success=True,
        exploit_steps=[],
        evidence=["Some unrelated shell output."],
        mitre_mapping={"initial_access": ["T1189"]},
        vulnerability_type="XSS",
        captured_flag="",
        extra_fields={"vuln_category": "Injection"},
    )

    p = AtomizerPipeline(vulhub_dir=str(cve_dir), output_dir=str(tmp_path / "atoms"))
    monkeypatch.setattr(p, "_start_cve_environment", lambda: (fake_info, "cve-net"))
    monkeypatch.setattr(p, "_run_agent", lambda *a, **k: agent_out)
    monkeypatch.setattr(p, "_cleanup", lambda: None)
    monkeypatch.setattr(
        p,
        "_run_llm_checker",
        lambda **kwargs: LLMCheckResult(
            accepted=False,
            reason="evidence does not prove XSS",
            issues=["missing rendered payload"],
            confidence="high",
            model="checker",
        ),
    )

    result = p.run(api_key="k", model="m")

    assert result["success"] is False
    import yaml as _yaml
    atom_data = _yaml.safe_load((tmp_path / "atoms" / "CVE-2017-12794" / "atom.yaml").read_text())
    assert atom_data["verified"] is False
    assert atom_data["llm_check"]["accepted"] is False
    assert "missing rendered payload" in atom_data["llm_check"]["issues"]


def test_llm_checker_bound_method_handles_missing_api_key(tmp_path):
    """The checker must be a normal instance method, not a broken staticmethod."""
    from clab_builder.atomizer.pipeline import AtomizerPipeline
    from clab_builder.atomizer.agent.researcher import AgentOutput

    cve_dir = tmp_path / "vulhub" / "openssh" / "CVE-2018-15473"
    cve_dir.mkdir(parents=True)
    (cve_dir / "docker-compose.yml").write_text(
        yaml.dump({"services": {"sshd": {"image": "vulhub/openssh:7.7", "ports": ["22:22"]}}})
    )
    (cve_dir / "README.md").write_text("# CVE-2018-15473\n")
    agent_out = AgentOutput(
        cve_id="CVE-2018-15473",
        success=True,
        exploit_steps=[],
        evidence=["Observed different server behavior for valid and invalid users."],
        mitre_mapping={},
        vulnerability_type="Username Enumeration",
        captured_flag="",
    )

    p = AtomizerPipeline(vulhub_dir=str(cve_dir), output_dir=str(tmp_path / "atoms"))
    result = p._run_llm_checker(
        agent_output=agent_out,
        vuln_category="Info_Leak",
        api_key="",
        model="checker",
    )

    assert result.accepted is False
    assert "no API key" in result.reason


def test_atom_metadata_normalizes_agent_enum_aliases(tmp_path, monkeypatch):
    """Agent aliases like SQLi/reconnaissance should not break atom saving."""
    from clab_builder.atomizer.pipeline import AtomizerPipeline
    from clab_builder.atomizer.agent.researcher import AgentOutput

    cve_dir = tmp_path / "vulhub" / "db" / "CVE-2024-0005"
    cve_dir.mkdir(parents=True)
    (cve_dir / "docker-compose.yml").write_text(
        yaml.dump({"services": {"web": {"image": "vulhub/test:latest", "ports": ["8080:80"]}}})
    )
    (cve_dir / "README.md").write_text("# CVE-2024-0005 SQL injection\n")
    agent_out = AgentOutput(
        cve_id="CVE-2024-0005",
        success=True,
        exploit_steps=[],
        evidence=["SQL injection confirmed with boolean response difference."],
        mitre_mapping={},
        vulnerability_type="SQLi",
        captured_flag="",
        extra_fields={"vuln_category": "SQLi", "primary_mitre_phase": "reconnaissance"},
    )

    p = AtomizerPipeline(vulhub_dir=str(cve_dir), output_dir=str(tmp_path / "atoms"))
    monkeypatch.setattr(p, "_flag", "", raising=False)
    # v3 要求 native + orchestrated 双验证；单元测试里 mock orchestrated 为成功
    monkeypatch.setattr(
        p, "_run_orchestrated_verification",
        lambda atom_dir, flag_value: {"success": True, "mode": "orchestrated",
                                      "evidence": ["mocked"], "timestamp": "mock"},
    )
    atom_dir = tmp_path / "atoms" / "CVE-2024-0005"
    atom_dir.mkdir(parents=True)

    verified, flag_matched = p._save_atom(
        atom_dir,
        agent_output=agent_out,
        llm_checker=False,
    )

    assert verified is True
    assert flag_matched is False
    import yaml as _yaml
    atom_data = _yaml.safe_load((tmp_path / "atoms" / "CVE-2024-0005" / "atom.yaml").read_text())
    assert atom_data["vuln_category"] == "Injection"
    assert atom_data["primary_mitre_phase"] == "discovery"


def test_compose_dependency_failure_reports_service_logs_and_hint(tmp_path, monkeypatch):
    """Dependency containers that exit after compose up must stop the run before agent starts."""
    import pytest
    from clab_builder.atomizer import pipeline as pipeline_mod
    from clab_builder.atomizer.pipeline import AtomizerPipeline

    vulhub_dir = tmp_path / "vulhub" / "kibana" / "CVE-2019-7609"
    write_compose(vulhub_dir, image="vulhub/kibana:5.6.16")

    inspect_payload = [
        {
            "Id": "target123456789",
            "Name": "/cve-kibana-1",
            "Config": {
                "Image": "vulhub/kibana:5.6.16",
                "Labels": {"com.docker.compose.service": "web"},
            },
            "State": {"Running": True, "Status": "running", "ExitCode": 0, "StartedAt": "now"},
            "NetworkSettings": {"Networks": {"cve_default": {"IPAddress": "172.18.0.2"}}, "Ports": {}},
        },
        {
            "Id": "dep123456789",
            "Name": "/cve-elasticsearch-1",
            "Config": {
                "Image": "elasticsearch:5.6.16",
                "Labels": {"com.docker.compose.service": "elasticsearch"},
            },
            "State": {"Running": False, "Status": "exited", "ExitCode": 78, "StartedAt": "now", "FinishedAt": "now"},
            "NetworkSettings": {"Networks": {"cve_default": {"IPAddress": "172.18.0.3"}}, "Ports": {}},
        },
    ]

    class Result:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(cmd, **kwargs):
        if cmd[:3] == ["docker", "ps", "-a"]:
            return Result(stdout="target123456789\ndep123456789\n")
        if cmd[:2] == ["docker", "inspect"]:
            return Result(stdout=json.dumps(inspect_payload))
        if cmd[:3] == ["docker", "logs", "--tail"]:
            return Result(stderr="bootstrap checks failed: vm.max_map_count [65530] is too low\n")
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(pipeline_mod.subprocess, "run", fake_run)
    p = AtomizerPipeline(vulhub_dir=str(vulhub_dir), output_dir=str(tmp_path / "atoms"))

    with pytest.raises(RuntimeError) as exc:
        p._validate_compose_services("cve-2019-7609")

    msg = str(exc.value)
    assert "compose service dependency failed" in msg
    assert "elasticsearch" in msg
    assert "exit_code=78" in msg
    assert "vm.max_map_count" in msg


def test_reconcile_backfills_missing_time_from_session(tmp_path):
    """Recovered verified atoms should not be persisted with blank timing fields."""
    from clab_builder.atomizer.scaling import AtomScaleRecord, AtomScaleRunner

    atom_dir = tmp_path / "atoms" / "CVE-2024-0001"
    atom_dir.mkdir(parents=True)
    (atom_dir / "atom.yaml").write_text(yaml.dump({"verified": True}))
    (atom_dir / "session.json").write_text(
        "\n".join([
            json.dumps({"timestamp": "2026-06-22T10:00:00.000Z", "type": "start"}),
            json.dumps({"timestamp": "2026-06-22T10:02:03.456Z", "type": "finish"}),
        ])
        + "\n"
    )

    runner = AtomScaleRunner(
        vulhub_dir="",
        output_dir=str(tmp_path / "atoms"),
        state_dir=str(tmp_path / "state"),
    )
    record = AtomScaleRecord(
        cve_id="CVE-2024-0001",
        source_type="vulhub",
        source_path="data/vulhub/test/CVE-2024-0001",
        status="queued",
    )

    repaired = runner._reconcile_record(record)

    assert repaired.status == "succeeded"
    assert repaired.started_at == "2026-06-22T10:00:00Z"
    assert repaired.finished_at == "2026-06-22T10:02:03.456000Z"
    assert repaired.duration_seconds == 123.456


def test_cve_filter_restricts_runnable(tmp_path, monkeypatch):
    """--cve filter must restrict runs to the named CVEs only (not all records)."""
    from clab_builder.atomizer import scaling as scaling
    vulhub = tmp_path / "vulhub"
    for cve in ["CVE-2024-7001", "CVE-2024-7002", "CVE-2024-7003"]:
        write_compose(vulhub / "app" / cve)
    runner = scaling.AtomScaleRunner(
        vulhub_dir=str(vulhub), raw_records=(),
        output_dir=str(tmp_path / "atoms"), state_dir=str(tmp_path / "state"),
        generated_sources_dir=str(tmp_path / "generated"),
    )
    runner.discover()
    executed = []
    def fake_run_one(record, **kwargs):
        executed.append(record.cve_id)
        record.status = "succeeded"
        return record
    monkeypatch.setattr(runner, "_run_one", fake_run_one)
    # force=True would run all 3; cve_filter restricts to 2
    runner.run(force=True, export_parquet=False, workers=1,
               cve_filter=("CVE-2024-7001", "CVE-2024-7003"))
    assert sorted(executed) == ["CVE-2024-7001", "CVE-2024-7003"]


def test_missing_verified_raw_build_asset_is_reported(tmp_path, monkeypatch):
    """A verified raw source is not invalid when its local build artefact is absent."""
    from clab_builder.atomizer.scaling import AtomScaleRecord

    runner = AtomScaleRunner(
        vulhub_dir="",
        output_dir=str(tmp_path / "atoms"),
        state_dir=str(tmp_path / "state"),
    )
    record = AtomScaleRecord(
        cve_id="CVE-2024-9999",
        source_type="raw_records",
        source_path=str(tmp_path / "generated" / "CVE-2024-9999"),
        image="cve-2024-9999:vuln",
        metadata={"archive_exists": False},
    )
    monkeypatch.setattr(
        "clab_builder.atomizer.scaling.subprocess.run",
        lambda *args, **kwargs: type("Result", (), {"returncode": 1, "stderr": "missing"})(),
    )

    result = runner._run_one(
        record,
        api_key="key",
        base_url="",
        model="model",
        skip_agent=False,
        force=False,
        max_turns=80,
        llm_checker=True,
    )

    assert result.status == "missing_build_asset"
    assert "verified raw-record Docker image is missing" in result.error


def test_raw_record_source_archive_does_not_replace_local_image(tmp_path, monkeypatch):
    """The raw-record archive is source context, not a docker-loadable image."""
    from clab_builder.atomizer.scaling import AtomScaleRecord

    archive = tmp_path / "source.tar.gz"
    archive.write_bytes(b"archive")
    record = AtomScaleRecord(
        cve_id="CVE-2024-9998",
        source_type="raw_records",
        source_path=str(tmp_path / "generated" / "CVE-2024-9998"),
        image="cve-2024-9998:vuln",
        metadata={"archive_path": str(archive), "archive_exists": True},
    )
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return type("Result", (), {"returncode": 1, "stderr": ""})()

    monkeypatch.setattr("clab_builder.atomizer.scaling.subprocess.run", fake_run)

    error = AtomScaleRunner._prepare_raw_record_image(record)

    assert "verified raw-record Docker image is missing" in error
    assert str(archive) in error
    assert calls == [["docker", "image", "inspect", "cve-2024-9998:vuln"]]
