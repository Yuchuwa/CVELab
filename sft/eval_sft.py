"""Serve and evaluate an SFT adapter with explicit evaluation lineage.

The historical ``--manifest`` option remains the Range case manifest.  New
reproducible runs should pass ``--evaluation-manifest``; that manifest pins the
case manifest and is validated before the batch subprocess starts.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

if __package__:
    from .lineage import (
        EVALUATION_MANIFEST_SCHEMA_VERSION,
        ManifestError,
        build_evaluation_run_manifest,
        environment_identifiers,
        load_json,
        public_arguments,
        sha256_file,
        validate_evaluation_manifest,
        write_json,
    )
else:
    sys.path.insert(0, os.path.dirname(__file__))
    from lineage import (  # type: ignore[no-redef]
        EVALUATION_MANIFEST_SCHEMA_VERSION,
        ManifestError,
        build_evaluation_run_manifest,
        environment_identifiers,
        load_json,
        public_arguments,
        sha256_file,
        validate_evaluation_manifest,
        write_json,
    )


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVAL_VERSION = "1.0.0"

# The same 8 cases used in the decoy ablation / kimi smoke (manifest_sol_smoke8).
DEFAULT_MANIFEST = os.path.join(ROOT, "data/guide_ablation/manifest_sol_smoke8.json")


def cmd_serve(args: argparse.Namespace) -> None:
    """Serve the adapter with vLLM's streaming/tool-call compatible server."""
    adapter = os.path.abspath(args.adapter)
    os.execvp(
        args.vllm,
        [
            args.vllm,
            "serve",
            args.base_model,
            "--dtype",
            "bfloat16",
            "--max-model-len",
            str(args.max_model_len),
            "--gpu-memory-utilization",
            str(args.gpu_memory_utilization),
            "--enable-lora",
            "--max-lora-rank",
            str(args.max_lora_rank),
            "--lora-modules",
            f"{args.model}={adapter}",
            "--enable-auto-tool-choice",
            "--tool-call-parser",
            "hermes",
            "--host",
            "0.0.0.0",
            "--port",
            str(args.port),
        ],
    )


def _load_evaluation_input(args: argparse.Namespace) -> tuple[dict[str, Any] | None, Path | None, Path]:
    explicit = getattr(args, "evaluation_manifest", None)
    legacy_case_manifest = Path(getattr(args, "manifest", DEFAULT_MANIFEST))
    manifest_path = Path(explicit) if explicit else None

    # Accept an evaluation manifest through --manifest as a convenient bridge,
    # while treating ordinary Range manifests as the legacy case input.
    if manifest_path is None:
        try:
            candidate = load_json(legacy_case_manifest)
        except ManifestError:
            candidate = None
        schema_version = candidate.get("schema_version") if isinstance(candidate, dict) else None
        if isinstance(schema_version, str) and schema_version.startswith("cvelab.sft-evaluation-manifest."):
            manifest_path = legacy_case_manifest

    if manifest_path is None:
        return None, None, legacy_case_manifest

    evaluation_manifest = load_json(manifest_path)
    validate_evaluation_manifest(evaluation_manifest)
    _apply_evaluation_pins(args, evaluation_manifest)
    case_manifest_value = (
        evaluation_manifest.get("case_manifest")
        or evaluation_manifest.get("case_manifest_path")
        or evaluation_manifest.get("cases_manifest")
    )
    if isinstance(case_manifest_value, str) and case_manifest_value:
        case_manifest = Path(case_manifest_value)
        if not case_manifest.is_absolute():
            case_manifest = manifest_path.parent / case_manifest
    else:
        # Materialize embedded cases instead of silently falling back to the
        # default legacy case set. This keeps evaluation_id and executed cases
        # aligned even when no external case manifest was supplied.
        cases_path = Path(getattr(args, "output", "evaluation-output")) / ".evaluation_cases.json"
        cases_path.parent.mkdir(parents=True, exist_ok=True)
        cases_path.write_text(
            json.dumps({"schema_version": 1, "cases": evaluation_manifest["cases"]}, indent=2)
            + "\n",
            encoding="utf-8",
        )
        case_manifest = cases_path
    if case_manifest is None:
        raise ManifestError("evaluation manifest must identify a case manifest file for batch evaluation")
    expected_case_hash = evaluation_manifest.get("case_manifest_sha256")
    if expected_case_hash:
        actual_case_hash = sha256_file(case_manifest)
        if actual_case_hash != expected_case_hash:
            raise ManifestError("evaluation case manifest content hash mismatch")
    return evaluation_manifest, manifest_path, case_manifest


def _apply_evaluation_pins(
    args: argparse.Namespace,
    manifest: dict[str, Any],
) -> None:
    """Reject CLI settings that would invalidate an evaluation manifest."""
    pinned_model = manifest.get("model")
    requested_model = getattr(args, "model", None)
    if pinned_model and requested_model and requested_model != pinned_model:
        raise ManifestError(
            f"evaluation manifest pins model {pinned_model!r}, got {requested_model!r}"
        )
    if pinned_model and not requested_model:
        args.model = pinned_model

    pinned_adapter = manifest.get("adapter_path")
    requested_adapter = getattr(args, "adapter", None)
    if pinned_adapter and requested_adapter and os.path.abspath(requested_adapter) != os.path.abspath(pinned_adapter):
        raise ManifestError(
            f"evaluation manifest pins adapter {pinned_adapter!r}, got {requested_adapter!r}"
        )
    if pinned_adapter and not requested_adapter:
        args.adapter = pinned_adapter

    parameters = manifest.get("parameters") or {}
    if not isinstance(parameters, dict):
        raise ManifestError("evaluation manifest parameters must be an object")
    for name in ("cases", "agent_context", "parallel", "max_turns", "agent_timeout"):
        if name not in parameters or not hasattr(args, name):
            continue
        if getattr(args, name) != parameters[name]:
            raise ManifestError(
                f"evaluation manifest pins {name}={parameters[name]!r}, "
                f"got {getattr(args, name)!r}"
            )


def _run_manifest_path(args: argparse.Namespace) -> Path:
    value = getattr(args, "run_manifest", None)
    return Path(value) if value else Path(args.output) / "evaluation_run_manifest.json"


def _evaluation_arguments(
    args: argparse.Namespace,
    *,
    case_manifest: Path,
    evaluation_manifest_path: Path | None,
) -> dict[str, Any]:
    arguments = dict(vars(args))
    arguments["resolved_case_manifest"] = str(case_manifest)
    arguments["evaluation_manifest_path"] = (
        str(evaluation_manifest_path) if evaluation_manifest_path else None
    )
    return public_arguments(arguments)


def _write_run_manifest(
    path: Path,
    args: argparse.Namespace,
    *,
    evaluation_manifest: dict[str, Any] | None,
    evaluation_manifest_path: Path | None,
    case_manifest: Path,
    status: str,
    error: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evaluation_hash = None
    if evaluation_manifest_path and evaluation_manifest_path.exists():
        evaluation_hash = sha256_file(evaluation_manifest_path)
    manifest = build_evaluation_run_manifest(
        evaluation_manifest=evaluation_manifest,
        evaluation_manifest_sha256=evaluation_hash,
        arguments=_evaluation_arguments(
            args,
            case_manifest=case_manifest,
            evaluation_manifest_path=evaluation_manifest_path,
        ),
        model={
            "name": getattr(args, "model", None),
            "base_model": getattr(args, "base_model", None),
            "base_url": getattr(args, "base_url", None),
            "agent_context": getattr(args, "agent_context", None),
        },
        adapter_path=getattr(args, "adapter", None),
        case_manifest=str(case_manifest),
        environment={
            **environment_identifiers(),
            "eval_script": "eval_sft.py",
            "eval_version": EVAL_VERSION,
        },
        status=status,
        error=error,
    )
    write_json(path, manifest)
    return manifest


def cmd_eval(args: argparse.Namespace):
    """Run the Range batch against the served model and record its outcome."""
    evaluation_manifest, evaluation_manifest_path, case_manifest = _load_evaluation_input(args)
    env = dict(os.environ)
    base_url = args.base_url
    model = args.model
    env["OPENAI_API_KEY"] = "local"
    env["OPENAI_BASE_URL"] = base_url
    env["LLM_MODEL"] = model
    env["LLM_API_KEY"] = "local"
    env["LLM_BASE_URL"] = base_url
    env["HF_HUB_OFFLINE"] = "1"
    env["TRANSFORMERS_OFFLINE"] = "1"

    python = getattr(args, "python", sys.executable)
    sudo_executable = getattr(args, "sudo_executable", "sudo")
    batch_script = getattr(
        args,
        "batch_script",
        os.path.join(ROOT, "scripts/verify_enterprise3_guided_batch.py"),
    )
    cmd = [
        sudo_executable,
        "-E",
        "env",
        f"HOME={os.environ.get('HOME', '')}",
        f"PATH={os.environ.get('PATH', '')}",
        f"PYTHONPATH={ROOT}/src",
        "LLM_API_KEY=local",
        f"LLM_BASE_URL={base_url}",
        f"LLM_MODEL={model}",
        "OPENAI_API_KEY=local",
        f"OPENAI_BASE_URL={base_url}",
        python,
        batch_script,
        "--case-manifest",
        str(case_manifest),
        "--max-cases",
        str(args.cases),
        "--agent-context",
        args.agent_context,
        "--agent-runner",
        "openai",
        "--parallel",
        str(args.parallel),
        "--max-turns",
        str(args.max_turns),
        "--agent-timeout",
        str(args.agent_timeout),
        "--live-output",
        "--output",
        args.output,
    ]
    run_manifest_path = _run_manifest_path(args)
    _write_run_manifest(
        run_manifest_path,
        args,
        evaluation_manifest=evaluation_manifest,
        evaluation_manifest_path=evaluation_manifest_path,
        case_manifest=case_manifest,
        status="started",
    )
    print("Running:", " ".join(cmd[:5]), "...")
    try:
        result = subprocess.run(cmd, cwd=ROOT, env=env, check=True)
        if getattr(result, "returncode", 0):
            raise subprocess.CalledProcessError(result.returncode, cmd)
    except Exception as exc:
        _write_run_manifest(
            run_manifest_path,
            args,
            evaluation_manifest=evaluation_manifest,
            evaluation_manifest_path=evaluation_manifest_path,
            case_manifest=case_manifest,
            status="failed",
            error={
                "type": type(exc).__name__,
                "returncode": getattr(exc, "returncode", None),
            },
        )
        raise
    _write_run_manifest(
        run_manifest_path,
        args,
        evaluation_manifest=evaluation_manifest,
        evaluation_manifest_path=evaluation_manifest_path,
        case_manifest=case_manifest,
        status="completed",
    )
    return result


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    serve = sub.add_parser("serve")
    serve.add_argument("--adapter", default=os.path.join(ROOT, "data/sft/adapter_v1"))
    serve.add_argument(
        "--base-model",
        default=os.environ.get("SFT_BASE_MODEL"),
        required=not os.environ.get("SFT_BASE_MODEL"),
    )
    serve.add_argument(
        "--model",
        default=os.environ.get("SFT_MODEL"),
        required=not os.environ.get("SFT_MODEL"),
    )
    serve.add_argument("--vllm", default=os.environ.get("SFT_VLLM") or shutil.which("vllm") or "vllm")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--max-model-len", type=int, default=32768)
    serve.add_argument("--gpu-memory-utilization", type=float, default=0.90)
    serve.add_argument("--max-lora-rank", type=int, default=64)

    evaluate = sub.add_parser("eval")
    evaluate.add_argument(
        "--base-url",
        default=os.environ.get("SFT_BASE_URL"),
        required=not os.environ.get("SFT_BASE_URL"),
    )
    evaluate.add_argument(
        "--model",
        default=os.environ.get("SFT_MODEL"),
        required=not os.environ.get("SFT_MODEL"),
    )
    evaluate.add_argument("--base-model", default=os.environ.get("SFT_BASE_MODEL"))
    evaluate.add_argument("--adapter", default=None)
    evaluate.add_argument("--manifest", default=DEFAULT_MANIFEST, help="Legacy Range case manifest")
    evaluate.add_argument("--evaluation-manifest", "--eval-manifest", default=None)
    evaluate.add_argument("--run-manifest", "--evaluation-run-manifest", dest="run_manifest", default=None)
    evaluate.add_argument("--python", default=os.environ.get("SFT_PYTHON", sys.executable))
    evaluate.add_argument("--sudo-executable", default=os.environ.get("SFT_SUDO", "sudo"))
    evaluate.add_argument(
        "--batch-script",
        default=os.environ.get(
            "SFT_EVAL_SCRIPT",
            os.path.join(ROOT, "scripts/verify_enterprise3_guided_batch.py"),
        ),
    )
    evaluate.add_argument("--cases", type=int, default=8)
    evaluate.add_argument("--agent-context", default="l2")
    evaluate.add_argument("--parallel", type=int, default=2)
    evaluate.add_argument("--max-turns", type=int, default=300)
    evaluate.add_argument("--agent-timeout", type=int, default=3600)
    evaluate.add_argument("--output", default=os.path.join(ROOT, "data/guide_ablation/sft_v1_eval"))
    return parser


def main(argv: list[str] | None = None) -> None:
    args = _build_parser().parse_args(argv)
    if args.cmd == "serve":
        cmd_serve(args)
    else:
        cmd_eval(args)


if __name__ == "__main__":
    main()
