"""Phase 3 evaluation: run LoRA-tuned model on Range cases, compare to base.

Serves the LoRA adapter as an OpenAI-compatible endpoint using a lightweight
transformers-based FastAPI server, then runs the Range batch script against it.

Prerequisites:
  - Phase 2 complete: data/sft/adapter_v1/ exists
  - pip install fastapi uvicorn

Usage:
  # Terminal 1: serve the model
  python sft/eval_sft.py serve --adapter data/sft/adapter_v1 --port 8080

  # Terminal 2: run Range eval (must run as root for Docker)
  python sft/eval_sft.py eval --base-url http://localhost:8080/v1 \
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

# The same 8 cases used in the decoy ablation / kimi smoke (manifest_sol_smoke8).
DEFAULT_MANIFEST = os.path.join(ROOT, "data/guide_ablation/manifest_sol_smoke8.json")


def cmd_serve(args):
    """Serve LoRA model as OpenAI-compatible API via FastAPI."""
    serve_script = _make_serve_script(args)
    script_path = os.path.join(ROOT, "sft/_serve_server.py")
    with open(script_path, "w") as f:
        f.write(serve_script)
    os.execvp(PY, [PY, script_path, "--adapter", args.adapter,
                   "--base-model", args.base_model, "--port", str(args.port)])


def _make_serve_script(args):
    return '''
import argparse, json, os, sys, torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter", required=True)
    ap.add_argument("--base-model", default="Qwen/Qwen2.5-7B-Instruct")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()

    tok = AutoTokenizer.from_pretrained(args.base_model, trust_remote_code=True)
    if tok.pad_token is None: tok.pad_token = tok.eos_token
    base = AutoModelForCausalLM.from_pretrained(args.base_model, dtype=torch.bfloat16, device_map="cuda:0", trust_remote_code=True)
    model = PeftModel.from_pretrained(base, args.adapter)
    model = model.merge_and_unload()
    model.eval()

    from fastapi import FastAPI
    from pydantic import BaseModel
    import uvicorn
    app = FastAPI()

    class Msg(BaseModel):
        role: str
        content: str = ""

    class ChatReq(BaseModel):
        model: str = "default"
        messages: list[Msg]
        temperature: float = 0.0
        max_tokens: int = 4096
        stream: bool = False
        tools: list | None = None

    @app.post("/v1/chat/completions")
    def chat(req: ChatReq):
        msgs = [{"role": m.role, "content": m.content} for m in req.messages]
        text = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
        inputs = tok(text, return_tensors="pt").to("cuda:0")
        with torch.no_grad():
            out = model.generate(**inputs, max_new_tokens=req.max_tokens, temperature=max(req.temperature,0.01), do_sample=req.temperature>0, pad_token_id=tok.pad_token_id)
        resp = tok.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
        return {"id":"0","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":resp},"finish_reason":"stop"}],"usage":{"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}}

    @app.get("/v1/models")
    def models(): return {"data":[{"id":"qwen25-7b-lora","object":"model","owned_by":"local"}]}

    uvicorn.run(app, host="0.0.0.0", port=args.port)

if __name__ == "__main__":
    main()
'''


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
    s.add_argument("--port", type=int, default=8080)

    e = sub.add_parser("eval")
    e.add_argument("--base-url", default="http://localhost:8080/v1")
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
