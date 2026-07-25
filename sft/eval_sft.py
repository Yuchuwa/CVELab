"""Phase 3 evaluation: run LoRA-tuned model on Range cases, compare to base.

Serves the LoRA adapter with vLLM's OpenAI-compatible server, then runs the
Range batch script against it. vLLM is required because the Range runner uses
streaming tool calls.

Prerequisites:
  - Phase 2 complete: data/sft/adapter_v1/ exists
  - vllm 0.7.x with CUDA 12 / PyTorch 2.5 compatibility

Usage:
  # Terminal 1: serve the model
  python sft/eval_sft.py serve --adapter data/sft/adapter_v1 --port 8000

  # Terminal 2: run Range eval (must run as root for Docker)
  python sft/eval_sft.py eval --base-url http://172.17.0.1:8000/v1 \
      --model qwen25-7b-lora --cases 8 --output data/guide_ablation/sft_v1_eval
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = "/home/hanlin/miniconda3/envs/playbook/bin/python"
VLLM = "/home/hanlin/miniconda3/envs/playbook/bin/vllm"

# The same 8 cases used in the decoy ablation / kimi smoke (manifest_sol_smoke8).
DEFAULT_MANIFEST = os.path.join(ROOT, "data/guide_ablation/manifest_sol_smoke8.json")


def cmd_serve(args):
    """Serve the adapter with vLLM's streaming/tool-call compatible server."""
    adapter = os.path.abspath(args.adapter)
    os.execv(VLLM, [
        VLLM, "serve", args.base_model,
        "--dtype", "bfloat16",
        "--max-model-len", str(args.max_model_len),
        "--gpu-memory-utilization", str(args.gpu_memory_utilization),
        "--enable-lora", "--max-lora-rank", str(args.max_lora_rank),
        "--lora-modules", f"{args.model}={adapter}",
        "--enable-auto-tool-choice", "--tool-call-parser", "hermes",
        "--host", "0.0.0.0", "--port", str(args.port),
    ])


def cmd_eval(args):
    """Run Range batch against the LoRA-served model."""
    env = dict(os.environ)
    env["OPENAI_API_KEY"] = "local"
    env["OPENAI_BASE_URL"] = args.base_url
    env["LLM_MODEL"] = args.model
    env["LLM_API_KEY"] = "local"
    env["LLM_BASE_URL"] = args.base_url
    env["HF_HUB_OFFLINE"] = "1"
    env["TRANSFORMERS_OFFLINE"] = "1"

    cmd = [
        "sudo", "-E", "env",
        f"HOME={os.environ.get('HOME','')}",
        f"PATH={os.environ.get('PATH','')}",
        f"PYTHONPATH={ROOT}/src",
        f"LLM_API_KEY=local",
        f"LLM_BASE_URL={args.base_url}",
        f"LLM_MODEL={args.model}",
        f"OPENAI_API_KEY=local",
        f"OPENAI_BASE_URL={args.base_url}",
        PY,
        os.path.join(ROOT, "scripts/verify_enterprise3_guided_batch.py"),
        "--case-manifest", args.manifest,
        "--max-cases", str(args.cases),
        "--agent-context", args.agent_context,
        "--agent-runner", "openai",
        "--parallel", str(args.parallel),
        "--max-turns", str(args.max_turns),
        "--agent-timeout", str(args.agent_timeout),
        "--live-output",
        "--output", args.output,
    ]
    print("Running:", " ".join(cmd[:5]), "...")
    subprocess.run(cmd, cwd=ROOT, env=env)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd")

    s = sub.add_parser("serve")
    s.add_argument("--adapter", default=os.path.join(ROOT, "data/sft/adapter_v1"))
    s.add_argument("--base-model", default="Qwen/Qwen2.5-7B-Instruct")
    s.add_argument("--model", default="qwen25-7b-lora")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--max-model-len", type=int, default=32768)
    s.add_argument("--gpu-memory-utilization", type=float, default=0.90)
    s.add_argument("--max-lora-rank", type=int, default=64)

    e = sub.add_parser("eval")
    e.add_argument("--base-url", default="http://172.17.0.1:8000/v1")
    e.add_argument("--model", default="qwen25-7b-lora")
    e.add_argument("--manifest", default=DEFAULT_MANIFEST)
    e.add_argument("--cases", type=int, default=8)
    e.add_argument("--agent-context", default="l2")
    e.add_argument("--parallel", type=int, default=2)
    e.add_argument("--max-turns", type=int, default=300)
    e.add_argument("--agent-timeout", type=int, default=3600)
    e.add_argument("--output", default=os.path.join(ROOT, "data/guide_ablation/sft_v1_eval"))

    args = ap.parse_args()
    if args.cmd == "serve":
        cmd_serve(args)
    elif args.cmd == "eval":
        cmd_eval(args)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
