"""Synthetic contract tests for the SFT lineage chain."""

import hashlib
import importlib.util
import json
import sys
from argparse import Namespace
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
LINEAGE_PATH = ROOT / "sft" / "lineage.py"
TRAIN_PATH = ROOT / "sft" / "train_sft.py"
EVAL_PATH = ROOT / "sft" / "eval_sft.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def lineage():
    return _load(LINEAGE_PATH, "sft_lineage_test")


@pytest.fixture(scope="module")
def trainer():
    return _load(TRAIN_PATH, "sft_train_lineage_test")


@pytest.fixture(scope="module")
def evaluator():
    return _load(EVAL_PATH, "sft_eval_lineage_test")


def _records(lineage, count=6):
    records = []
    for index in range(count):
        group = index // 2
        records.append(
            {
                "schema_version": lineage.SFT_RECORD_SCHEMA_VERSION,
                "sample_id": f"sample-{index}",
                "task_id": f"case-{group}.hop{index}",
                "case_id": f"case-{group}",
                "source_identity": f"source-{group}",
                "source_content_sha256": hashlib.sha256(f"source-{group}".encode()).hexdigest(),
                "is_resolved": True,
                "messages": [{"role": "user", "content": "synthetic"}],
            }
        )
    return records


def _write_corpus(tmp_path, lineage, records):
    corpus_path = tmp_path / "corpus.jsonl"
    corpus_bytes = b"".join(
        (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8") for record in records
    )
    corpus_path.write_bytes(corpus_bytes)
    manifest = {
        "schema_version": lineage.CORPUS_MANIFEST_SCHEMA_VERSION,
        "record_schema_version": lineage.SFT_RECORD_SCHEMA_VERSION,
        "converter": {"name": "synthetic", "version": "1.0.0", "arguments": {}},
        "sources": [
            {
                "source_identity": source_identity,
                "source_content_sha256": hashlib.sha256(source_identity.encode()).hexdigest(),
                "status": "converted",
                "emitted_count": sum(
                    1 for record in records if record["source_identity"] == source_identity
                ),
            }
            for source_identity in sorted({record["source_identity"] for record in records})
        ],
        "output": {
            "file_name": corpus_path.name,
            "sha256": hashlib.sha256(corpus_bytes).hexdigest(),
            "record_count": len(records),
        },
        "n_samples": len(records),
    }
    manifest["corpus_id"] = lineage.corpus_id_for_manifest(manifest)
    manifest_path = tmp_path / "corpus.manifest.json"
    lineage.write_json(manifest_path, manifest)
    return corpus_path, manifest_path, manifest


def test_corpus_manifest_validates_exact_hash_and_count(tmp_path, lineage):
    records = _records(lineage)
    corpus_path, manifest_path, manifest = _write_corpus(tmp_path, lineage, records)

    loaded = lineage.validate_corpus_manifest(manifest_path, corpus_path)
    assert loaded["corpus_id"] == manifest["corpus_id"]
    assert lineage.load_and_validate_corpus(corpus_path, manifest_path)[0] == records

    corpus_path.write_text(corpus_path.read_text() + "\n", encoding="utf-8")
    with pytest.raises(lineage.ManifestError, match="content hash mismatch"):
        lineage.validate_corpus_manifest(manifest_path, corpus_path)


def test_corpus_manifest_rejects_source_ledger_drift(tmp_path, lineage):
    records = _records(lineage)
    _, _, manifest = _write_corpus(tmp_path, lineage, records)
    records[0] = {**records[0], "source_content_sha256": "b" * 64}

    with pytest.raises(lineage.ManifestError, match="source hash disagrees"):
        lineage.validate_corpus_manifest(manifest, records=records)


def test_group_aware_split_is_deterministic_and_rejects_overlap(tmp_path, lineage):
    records = _records(lineage)
    corpus_path, manifest_path, corpus_manifest = _write_corpus(tmp_path, lineage, records)
    del corpus_path, manifest_path

    split = lineage.build_split_manifest(records, corpus_manifest, ratios=(1 / 3, 1 / 3, 1 / 3))
    assert set(split["splits"]) == {"train", "validation", "test"}
    assert split["split_id"] == lineage.build_split_manifest(
        records, corpus_manifest, ratios=(1 / 3, 1 / 3, 1 / 3)
    )["split_id"]
    assert set(split["splits"]["train"]).isdisjoint(split["splits"]["validation"])
    assert set(split["splits"]["validation"]).isdisjoint(split["splits"]["test"])
    lineage.validate_split_manifest(split, records, corpus_manifest=corpus_manifest)

    corrupted = json.loads(json.dumps(split))
    moved = corrupted["splits"]["train"][0]
    corrupted["splits"]["validation"].append(moved)
    with pytest.raises(lineage.ManifestError, match="multiple splits|counts"):
        lineage.validate_split_manifest(corrupted, records, corpus_manifest=corpus_manifest)


def test_training_manifest_records_public_arguments_without_secrets(tmp_path, lineage, trainer):
    records = _records(lineage, count=2)
    corpus_path, manifest_path, manifest = _write_corpus(tmp_path, lineage, records)
    args = trainer._build_parser().parse_args(
        [
            "--corpus",
            str(corpus_path),
            "--corpus-manifest",
            str(manifest_path),
            "--output",
            str(tmp_path / "adapter"),
            "--validate-only",
        ]
    )
    loaded_records, loaded_manifest, info = trainer.load_validated_corpus(args)
    assert loaded_records == records
    assert loaded_manifest["corpus_id"] == manifest["corpus_id"]
    run = trainer.build_training_run_manifest(args, loaded_manifest, info, status="validated")
    assert run["schema_version"] == lineage.TRAINING_RUN_MANIFEST_SCHEMA_VERSION
    assert run["corpus_id"] == manifest["corpus_id"]
    assert run["corpus_sha256"] == manifest["output"]["sha256"]
    assert run["output_adapter_path"].endswith("adapter")
    assert "api_key" not in json.dumps(run).lower()
    assert "secret-value" not in json.dumps(run)
    assert lineage.validate_training_run_manifest(run)["training_run_id"] == run["training_run_id"]


def test_evaluation_manifest_is_versioned_and_validated(tmp_path, lineage, evaluator):
    case_manifest = tmp_path / "cases.json"
    case_manifest.write_text("{}\n", encoding="utf-8")
    evaluation = lineage.build_evaluation_manifest(
        case_manifest=case_manifest.name,
        model="synthetic-model",
        parameters={"api_key": "secret-value", "cases": 1},
    )
    evaluation_path = tmp_path / "evaluation.json"
    lineage.write_json(evaluation_path, evaluation)
    assert lineage.validate_evaluation_manifest(evaluation_path)["evaluation_id"] == evaluation["evaluation_id"]

    args = Namespace(
        evaluation_manifest=str(evaluation_path),
        manifest=str(tmp_path / "legacy-cases.json"),
    )
    loaded, loaded_path, resolved_case = evaluator._load_evaluation_input(args)
    assert loaded["evaluation_id"] == evaluation["evaluation_id"]
    assert loaded_path == evaluation_path
    assert resolved_case == case_manifest
    assert "secret-value" not in json.dumps(evaluation)


def test_embedded_evaluation_cases_are_materialized_without_default_fallback(
    tmp_path, lineage, evaluator
):
    evaluation = lineage.build_evaluation_manifest(
        cases=[{"id": "embedded-case", "cves": ["CVE-TEST-0001"]}],
        model="synthetic-model",
        parameters={},
    )
    evaluation_path = tmp_path / "evaluation.json"
    lineage.write_json(evaluation_path, evaluation)
    args = Namespace(
        evaluation_manifest=str(evaluation_path),
        manifest=str(evaluation_path),
        output=str(tmp_path / "eval-output"),
        model="synthetic-model",
        adapter=None,
    )

    _, _, case_path = evaluator._load_evaluation_input(args)

    assert case_path.parent == tmp_path / "eval-output"
    assert json.loads(case_path.read_text())["cases"][0]["id"] == "embedded-case"
