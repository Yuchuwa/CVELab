"""LoRA SFT for CVELab attack trajectories.

The default command remains compatible with the historical ``--data`` path,
but reproducible training should pass ``--corpus-manifest`` (or ``--manifest``)
with the corpus JSONL.  ``--validate-only`` exercises the complete lineage
contract without loading a model or starting GPU training.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

if __package__:
    from .lineage import (
        CORPUS_MANIFEST_SCHEMA_VERSION,
        LINEAGE_VERSION,
        ManifestError,
        build_training_run_manifest as _build_lineage_training_run_manifest,
        environment_identifiers,
        load_and_validate_corpus,
        load_json,
        load_jsonl,
        public_arguments,
        sha256_file,
        validate_split_manifest,
        validate_sft_records,
        write_json,
    )
else:
    sys.path.insert(0, os.path.dirname(__file__))
    from lineage import (  # type: ignore[no-redef]
        CORPUS_MANIFEST_SCHEMA_VERSION,
        LINEAGE_VERSION,
        ManifestError,
        build_training_run_manifest as _build_lineage_training_run_manifest,
        environment_identifiers,
        load_and_validate_corpus,
        load_json,
        load_jsonl,
        public_arguments,
        sha256_file,
        validate_split_manifest,
        validate_sft_records,
        write_json,
    )


TRAINER_VERSION = "1.0.0"
DEFAULT_DATA = "data/sft/cve_attack_sft_v1.jsonl"


def load_jsonl_dataset(
    path: str,
    *,
    include_unresolved: bool = False,
    allow_leaks: bool = False,
    records: list[dict[str, Any]] | None = None,
):
    """Load trainer messages while retaining the legacy filtering behavior."""
    if records is None:
        records, _ = load_jsonl(path)
    rows = []
    skipped_unresolved = 0
    skipped_leaks = 0
    for record in records:
        if not include_unresolved and record.get("is_resolved") is False:
            skipped_unresolved += 1
            continue
        if not allow_leaks and record.get("leaks"):
            skipped_leaks += 1
            continue
        rows.append({"messages": record["messages"]})
    print(f"[data] skipped unresolved={skipped_unresolved}, leak-flagged={skipped_leaks}")
    # Keep the optional ML dependency out of manifest and split contract tests.
    from datasets import Dataset

    return Dataset.from_list(rows)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="Qwen/Qwen2.5-7B-Instruct")
    parser.add_argument("--tokenizer", default=None)
    parser.add_argument("--model-revision", default=None)
    parser.add_argument("--tokenizer-revision", default=None)
    parser.add_argument(
        "--trust-remote-code",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    parser.add_argument(
        "--data",
        default=None,
        help=f"Legacy corpus JSONL path (default: {DEFAULT_DATA}); pair with --manifest for lineage",
    )
    parser.add_argument(
        "--corpus",
        default=None,
        help="Corpus JSONL or a converter corpus manifest",
    )
    parser.add_argument(
        "--corpus-manifest",
        "--manifest",
        "--corpus-report",
        dest="corpus_manifest",
        default=None,
        help="Versioned converter corpus manifest",
    )
    parser.add_argument("--split-manifest", default=None)
    parser.add_argument("--split", choices=("train", "validation", "test"), default="train")
    parser.add_argument("--output", required=True)
    parser.add_argument("--run-manifest", "--training-run-manifest", dest="run_manifest", default=None)
    parser.add_argument("--max-seq-length", type=int, default=32768)
    parser.add_argument("--epochs", type=float, default=3.0)
    parser.add_argument("--lr", type=float, default=1e-4)
    parser.add_argument("--lora-r", type=int, default=64)
    parser.add_argument("--lora-alpha", type=int, default=128)
    parser.add_argument("--grad-accum", type=int, default=16)
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="Short run: 2 steps, no adapter save, for a real training smoke",
    )
    parser.add_argument("--max-steps", type=int, default=-1)
    parser.add_argument("--num-gpus", type=int, default=4)
    parser.add_argument("--loss-type", type=str, default="chunked_nll", choices=["nll", "chunked_nll", "dft"])
    parser.add_argument(
        "--include-unresolved",
        action="store_true",
        help="Include samples marked is_resolved=false (default: skip)",
    )
    parser.add_argument(
        "--allow-leaks",
        action="store_true",
        help="Allow samples with converter leak markers (default: skip)",
    )
    parser.add_argument(
        "--allow-legacy-unmanifested",
        action="store_true",
        help="Explicitly allow a corpus JSONL without a converter manifest",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate lineage and write the run manifest without loading a model",
    )
    parser.add_argument(
        "--dtype",
        choices=("auto", "bfloat16", "float32"),
        default="auto",
        help="Model dtype; auto selects bfloat16 only when CUDA is available",
    )
    return parser


def _manifest_corpus_path(manifest_path: Path, manifest: dict[str, Any]) -> Path | None:
    output = manifest.get("output") or {}
    file_name = (
        output.get("path")
        or output.get("file_name")
        or manifest.get("corpus_path")
        or manifest.get("data_path")
    )
    if not isinstance(file_name, str) or not file_name:
        return None
    candidate = Path(file_name)
    return candidate if candidate.is_absolute() else manifest_path.parent / candidate


def _resolve_corpus_paths(args: argparse.Namespace) -> tuple[Path, Path | None, bool]:
    corpus_arg = getattr(args, "corpus", None)
    data_arg = getattr(args, "data", None)
    manifest_arg = getattr(args, "corpus_manifest", None)
    explicit_legacy = bool(getattr(args, "allow_legacy_unmanifested", False))
    used_default = corpus_arg is None and data_arg is None and manifest_arg is None

    corpus_path = Path(corpus_arg or data_arg or DEFAULT_DATA)
    manifest_path = Path(manifest_arg) if manifest_arg else None
    if manifest_path is None:
        try:
            candidate = load_json(corpus_path)
        except ManifestError:
            candidate = None
        if isinstance(candidate, dict) and candidate.get("schema_version") == CORPUS_MANIFEST_SCHEMA_VERSION:
            manifest_path = corpus_path
            inferred = _manifest_corpus_path(manifest_path, candidate)
            if inferred is None:
                raise ManifestError("corpus manifest does not identify its JSONL file")
            corpus_path = inferred
    elif corpus_arg is None and data_arg is None:
        manifest = load_json(manifest_path)
        inferred = _manifest_corpus_path(manifest_path, manifest)
        if inferred is None:
            raise ManifestError("corpus manifest does not identify its JSONL file")
        corpus_path = inferred

    if not corpus_path.is_absolute():
        corpus_path = Path.cwd() / corpus_path
    if manifest_path is not None and not manifest_path.is_absolute():
        manifest_path = Path.cwd() / manifest_path
    legacy = manifest_path is None
    if legacy and not (used_default or explicit_legacy):
        raise ManifestError(
            "a corpus manifest is required for an explicit corpus; use --allow-legacy-unmanifested only for old JSONL"
        )
    return corpus_path, manifest_path, legacy


def load_validated_corpus(args: argparse.Namespace) -> tuple[list[dict[str, Any]], dict[str, Any] | None, dict[str, Any]]:
    """Validate corpus bytes before any optional ML dependency is imported."""
    corpus_path, manifest_path, legacy = _resolve_corpus_paths(args)
    if manifest_path is not None:
        records, manifest = load_and_validate_corpus(corpus_path, manifest_path)
        info = {
            "path": str(corpus_path),
            "manifest_path": str(manifest_path),
            "legacy": False,
            "sha256": manifest["output"]["sha256"],
            "record_count": manifest["output"]["record_count"],
            "corpus_id": manifest["corpus_id"],
        }
        return records, manifest, info

    records, actual_hash = load_jsonl(corpus_path)
    validate_sft_records(records, require_lineage=False)
    info = {
        "path": str(corpus_path),
        "manifest_path": None,
        "legacy": True,
        "sha256": actual_hash,
        "record_count": len(records),
        "corpus_id": None,
    }
    print("[lineage] legacy unmanifested corpus; reproducible corpus identity is unavailable")
    return records, None, info


def _records_for_split(
    records: list[dict[str, Any]],
    manifest: dict[str, Any] | None,
    args: argparse.Namespace,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    split_manifest_path = getattr(args, "split_manifest", None)
    if not split_manifest_path:
        return records, None
    if manifest is None:
        raise ManifestError("--split-manifest requires a versioned corpus manifest")
    split_manifest = load_json(split_manifest_path)
    validate_split_manifest(split_manifest, records, corpus_manifest=manifest)
    selected_ids = set(split_manifest["splits"][getattr(args, "split", "train")])
    selected = [record for record in records if record.get("sample_id") in selected_ids]
    return selected, split_manifest


def _filter_training_records(
    records: list[dict[str, Any]],
    args: argparse.Namespace,
) -> list[dict[str, Any]]:
    """Apply the same eligibility filter used by training before validation."""
    return [
        record
        for record in records
        if (args.include_unresolved or record.get("is_resolved") is not False)
        and (args.allow_leaks or not record.get("leaks"))
    ]


def build_training_arguments(args: argparse.Namespace, *, corpus_info: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build the public, secret-free argument record stored in a run manifest."""
    arguments = {
        key: value
        for key, value in vars(args).items()
        if key not in {"run_manifest"}
    }
    if corpus_info:
        arguments["resolved_corpus"] = {
            "path": corpus_info.get("path"),
            "manifest_path": corpus_info.get("manifest_path"),
            "legacy": corpus_info.get("legacy"),
            "split_manifest_path": corpus_info.get("split_manifest_path"),
            "split_id": corpus_info.get("split_id"),
            "selected_split": corpus_info.get("selected_split"),
        }
    return public_arguments(arguments)


def build_training_run_manifest(
    args: argparse.Namespace,
    corpus_manifest: dict[str, Any] | None,
    corpus_info: dict[str, Any],
    *,
    status: str = "planned",
    error: dict[str, Any] | None = None,
) -> dict[str, Any]:
    tokenizer_name = getattr(args, "tokenizer", None) or args.model
    corpus = {
        "corpus_id": corpus_info.get("corpus_id"),
        "sha256": corpus_info.get("sha256"),
        "record_count": corpus_info.get("record_count"),
        "manifest_path": corpus_info.get("manifest_path"),
        "manifest_schema_version": corpus_manifest.get("schema_version") if corpus_manifest else None,
        "split_id": corpus_info.get("split_id"),
        "split_manifest_path": corpus_info.get("split_manifest_path"),
        "split_manifest_sha256": corpus_info.get("split_manifest_sha256"),
        "selected_split": corpus_info.get("selected_split"),
        "selected_record_count": corpus_info.get("selected_record_count"),
        "training_record_count": corpus_info.get("training_record_count"),
    }
    if corpus_manifest and corpus_info.get("manifest_path"):
        corpus["manifest_sha256"] = sha256_file(corpus_info["manifest_path"])
    return _build_lineage_training_run_manifest(
        code_version={
            "script": "train_sft.py",
            "version": TRAINER_VERSION,
            "lineage_version": LINEAGE_VERSION,
            "source_revision": os.environ.get("GIT_COMMIT") or os.environ.get("SOURCE_REVISION"),
        },
        arguments=build_training_arguments(args, corpus_info=corpus_info),
        corpus=corpus,
        base_model={
            "name": args.model,
            "revision": getattr(args, "model_revision", None),
            "trust_remote_code": getattr(args, "trust_remote_code", True),
            "dtype": getattr(args, "dtype", "auto"),
            "attn_implementation": "sdpa",
        },
        tokenizer={
            "name": tokenizer_name,
            "revision": getattr(args, "tokenizer_revision", None),
            "trust_remote_code": getattr(args, "trust_remote_code", True),
        },
        output_adapter_path=args.output,
        environment=environment_identifiers(),
        status=status,
        error=error,
    )


def _run_manifest_path(args: argparse.Namespace) -> Path:
    value = getattr(args, "run_manifest", None)
    return Path(value) if value else Path(args.output) / "training_run_manifest.json"


def _write_training_manifest(
    path: Path,
    args: argparse.Namespace,
    corpus_manifest: dict[str, Any] | None,
    corpus_info: dict[str, Any],
    *,
    status: str,
    error: dict[str, Any] | None = None,
) -> dict[str, Any]:
    manifest = build_training_run_manifest(
        args,
        corpus_manifest,
        corpus_info,
        status=status,
        error=error,
    )
    write_json(path, manifest)
    return manifest


def _run_training(args: argparse.Namespace, records: list[dict[str, Any]]) -> None:
    # Optional ML imports happen only after all lineage checks have passed.
    import torch
    from datasets import Dataset
    from peft import LoraConfig, get_peft_model
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from trl import SFTConfig, SFTTrainer

    effective_dtype = args.dtype
    if effective_dtype == "auto":
        effective_dtype = "bfloat16" if torch.cuda.is_available() else "float32"

    tokenizer_name = args.tokenizer or args.model
    tokenizer_kwargs = {
        "trust_remote_code": args.trust_remote_code,
    }
    if args.tokenizer_revision:
        tokenizer_kwargs["revision"] = args.tokenizer_revision
    tokenizer = AutoTokenizer.from_pretrained(tokenizer_name, **tokenizer_kwargs)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model_kwargs = {
        "attn_implementation": "sdpa",
        "trust_remote_code": args.trust_remote_code,
    }
    if args.model_revision:
        model_kwargs["revision"] = args.model_revision
    if effective_dtype == "bfloat16":
        model_kwargs["torch_dtype"] = torch.bfloat16
    elif effective_dtype == "float32":
        model_kwargs["torch_dtype"] = torch.float32
    model = AutoModelForCausalLM.from_pretrained(args.model, **model_kwargs)
    model.config.use_cache = False

    lora_config = LoraConfig(
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    ds = Dataset.from_list(
        [
            {"messages": record["messages"]}
            for record in records
            if (args.include_unresolved or record.get("is_resolved") is not False)
            and (args.allow_leaks or not record.get("leaks"))
        ]
    )
    if len(ds) == 0:
        raise ManifestError("no training records remain after filtering")

    if args.smoke:
        max_steps = 2
        save_strategy = "no"
        report_to = "none"
        logging_steps = 1
    else:
        max_steps = args.max_steps if args.max_steps > 0 else -1
        save_strategy = "epoch"
        try:
            import tensorboard  # noqa: F401

            report_to = "tensorboard"
        except ImportError:
            report_to = "none"
        logging_steps = 10

    use_bf16 = effective_dtype == "bfloat16"
    cfg = SFTConfig(
        output_dir=args.output,
        num_train_epochs=args.epochs if not args.smoke else 1,
        max_steps=max_steps,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=args.grad_accum,
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        learning_rate=args.lr,
        warmup_ratio=0.03,
        lr_scheduler_type="cosine",
        logging_steps=logging_steps,
        save_strategy=save_strategy,
        bf16=use_bf16,
        max_length=args.max_seq_length,
        packing=False,
        length_column_name="length",
        completion_only_loss=True,
        report_to=report_to,
        dataloader_num_workers=min(4, os.cpu_count() or 1),
        remove_unused_columns=False,
        optim="adamw_torch",
        adam_beta1=0.9,
        adam_beta2=0.95,
        seed=1,
        loss_type=args.loss_type,
    )

    def _length(example):
        text = tokenizer.apply_chat_template(example["messages"], tokenize=False, add_generation_prompt=False)
        return {"length": len(tokenizer(text, add_special_tokens=False)["input_ids"])}

    print("[data] computing lengths...")
    ds = ds.map(_length, num_proc=min(8, os.cpu_count() or 1))
    trainer = SFTTrainer(
        model=model,
        args=cfg,
        train_dataset=ds,
        processing_class=tokenizer,
    )
    print(f"[train] starting: max_seq_length={args.max_seq_length} smoke={args.smoke}")
    trainer.train()
    if not args.smoke:
        trainer.save_model(args.output)
        tokenizer.save_pretrained(args.output)
        print(f"[done] adapter saved to {args.output}")


def main(argv: list[str] | None = None) -> None:
    args = _build_parser().parse_args(argv)
    records, corpus_manifest, corpus_info = load_validated_corpus(args)
    records, split_manifest = _records_for_split(records, corpus_manifest, args)
    if split_manifest is not None:
        corpus_info = dict(corpus_info)
        corpus_info["selected_split"] = args.split
        corpus_info["selected_record_count"] = len(records)
        corpus_info["split_id"] = split_manifest["split_id"]
        corpus_info["split_manifest_path"] = str(args.split_manifest)
        corpus_info["split_manifest_sha256"] = sha256_file(args.split_manifest)

    eligible_records = _filter_training_records(records, args)
    if not eligible_records:
        raise ManifestError("no training records remain after filtering")
    corpus_info = dict(corpus_info)
    corpus_info["training_record_count"] = len(eligible_records)

    run_manifest_path = _run_manifest_path(args)
    _write_training_manifest(
        run_manifest_path,
        args,
        corpus_manifest,
        corpus_info,
        status="validated" if args.validate_only else "started",
    )
    if args.validate_only:
        print(f"[lineage] validated; run manifest -> {run_manifest_path}")
        return

    try:
        _run_training(args, records)
    except Exception as exc:
        _write_training_manifest(
            run_manifest_path,
            args,
            corpus_manifest,
            corpus_info,
            status="failed",
            error={"type": type(exc).__name__},
        )
        raise
    _write_training_manifest(
        run_manifest_path,
        args,
        corpus_manifest,
        corpus_info,
        status="completed",
    )


if __name__ == "__main__":
    main()
