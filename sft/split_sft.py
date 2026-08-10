"""Create a deterministic, group-aware SFT train/validation/test manifest.

The input corpus is never rewritten.  Groups are formed from case, CVE, and
source identities by :mod:`lineage`; connected identities stay in one split.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

if __package__:
    from .lineage import (
        ManifestError,
        build_split_manifest,
        load_and_validate_corpus,
        load_json,
        write_json,
    )
else:
    sys.path.insert(0, os.path.dirname(__file__))
    from lineage import (  # type: ignore[no-redef]
        ManifestError,
        build_split_manifest,
        load_and_validate_corpus,
        load_json,
        write_json,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus",
        "--input",
        "--corpus-jsonl",
        dest="corpus",
        required=True,
        help="Corpus JSONL or corpus manifest JSON",
    )
    parser.add_argument(
        "--manifest",
        "--corpus-manifest",
        dest="corpus_manifest",
        help="Converter corpus manifest (required when --corpus is JSONL)",
    )
    parser.add_argument("--output", "--out", dest="output", required=True, help="Output split manifest JSON")
    parser.add_argument("--train-ratio", type=float, default=0.8)
    parser.add_argument("--validation-ratio", type=float, default=0.1)
    parser.add_argument("--test-ratio", type=float, default=0.1)
    return parser


def _resolve_inputs(args: argparse.Namespace) -> tuple[Path, Path]:
    corpus_arg = Path(args.corpus)
    manifest_arg = Path(args.corpus_manifest) if args.corpus_manifest else None
    if manifest_arg is None:
        try:
            candidate = load_json(corpus_arg)
        except ManifestError:
            candidate = None
        schema_version = candidate.get("schema_version") if isinstance(candidate, dict) else None
        if isinstance(schema_version, str) and schema_version.startswith("cvelab.sft-corpus-manifest."):
            manifest_arg = corpus_arg
            output = candidate.get("output") or {}
            file_name = (
                output.get("file_name")
                or output.get("path")
                or candidate.get("corpus_path")
                or candidate.get("data_path")
            )
            if not isinstance(file_name, str) or not file_name:
                raise ManifestError("corpus manifest does not identify its JSONL file")
            corpus_arg = Path(file_name)
            if not corpus_arg.is_absolute():
                corpus_arg = manifest_arg.parent / corpus_arg
    if manifest_arg is None:
        raise ManifestError("--manifest/--corpus-manifest is required for a JSONL corpus")
    if not corpus_arg.is_absolute():
        corpus_arg = Path.cwd() / corpus_arg
    if not manifest_arg.is_absolute():
        manifest_arg = Path.cwd() / manifest_arg
    return corpus_arg, manifest_arg


def generate(args: argparse.Namespace) -> dict:
    corpus_path, manifest_path = _resolve_inputs(args)
    records, corpus_manifest = load_and_validate_corpus(corpus_path, manifest_path)
    manifest = build_split_manifest(
        records,
        corpus_manifest,
        ratios=(args.train_ratio, args.validation_ratio, args.test_ratio),
    )
    write_json(args.output, manifest)
    print(f"Wrote {manifest['split_id']} ({manifest['counts']}) -> {args.output}")
    return manifest


def main() -> None:
    args = _build_parser().parse_args()
    try:
        generate(args)
    except ManifestError as exc:
        raise SystemExit(f"split validation failed: {exc}") from exc


if __name__ == "__main__":
    main()
