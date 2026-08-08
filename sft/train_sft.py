"""LoRA SFT for Qwen3-8B on CVELab attack trajectories.

Usage:
  python sft/train_sft.py --max-seq-length 32768 --epochs 3 --output data/sft/adapter_v1

Smoke (per max-seq-length, short run to check memory):
  python sft/train_sft.py --max-seq-length 8192 --smoke --output /tmp/sft_smoke
"""
from __future__ import annotations

import argparse
import json
import os

import torch
from datasets import Dataset
from peft import LoraConfig, get_peft_model
from transformers import AutoModelForCausalLM, AutoTokenizer
from trl import SFTConfig, SFTTrainer


def load_jsonl_dataset(
    path: str,
    *,
    include_unresolved: bool = False,
    allow_leaks: bool = False,
) -> Dataset:
    rows = []
    skipped_unresolved = 0
    skipped_leaks = 0
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            if not include_unresolved and d.get("is_resolved") is False:
                skipped_unresolved += 1
                continue
            if not allow_leaks and d.get("leaks"):
                skipped_leaks += 1
                continue
            rows.append({"messages": d["messages"]})
    print(f"[data] skipped unresolved={skipped_unresolved}, leak-flagged={skipped_leaks}")
    return Dataset.from_list(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", default="Qwen/Qwen2.5-7B-Instruct")
    ap.add_argument("--data", default="data/sft/cve_attack_sft_v1.jsonl")
    ap.add_argument("--output", required=True)
    ap.add_argument("--max-seq-length", type=int, default=32768)
    ap.add_argument("--epochs", type=float, default=3.0)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--lora-r", type=int, default=64)
    ap.add_argument("--lora-alpha", type=int, default=128)
    ap.add_argument("--grad-accum", type=int, default=16)
    ap.add_argument("--smoke", action="store_true", help="Short run: 2 steps, no save, for memory testing")
    ap.add_argument("--max-steps", type=int, default=-1)
    ap.add_argument("--num-gpus", type=int, default=4)
    ap.add_argument("--loss-type", type=str, default="chunked_nll", choices=["nll", "chunked_nll", "dft"])
    ap.add_argument(
        "--include-unresolved", action="store_true",
        help="Include samples marked is_resolved=false (default: skip)",
    )
    ap.add_argument(
        "--allow-leaks", action="store_true",
        help="Allow samples with converter leak markers (default: skip)",
    )
    args = ap.parse_args()

    os.makedirs(args.output, exist_ok=True)

    # trl SFTTrainer uses transformers Trainer which manages device placement
    # internally via accelerate; no explicit Accelerator needed.

    print(f"[setup] loading tokenizer + model: {args.model}")
    tokenizer = AutoTokenizer.from_pretrained(args.model, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        args.model,
        torch_dtype=torch.bfloat16,
        attn_implementation="sdpa",
        trust_remote_code=True,
    )
    model.config.use_cache = False

    # LoRA
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

    # Dataset
    ds = load_jsonl_dataset(
        args.data,
        include_unresolved=args.include_unresolved,
        allow_leaks=args.allow_leaks,
    )
    print(f"[data] {len(ds)} samples from {args.data}")

    # Training config
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
        bf16=True,
        max_length=args.max_seq_length,
        packing=False,
        length_column_name="length",
        completion_only_loss=True,  # mask prompt, train on assistant turns only
        report_to=report_to,
        dataloader_num_workers=4,
        remove_unused_columns=False,
        optim="adamw_torch",
        adam_beta1=0.9,
        adam_beta2=0.95,
        seed=1,
        loss_type=args.loss_type,
    )

    # Pre-compute lengths (kept for diagnostics; group_by_length disabled in trl 1.9).
    def _len(example):
        text = tokenizer.apply_chat_template(example["messages"], tokenize=False, add_generation_prompt=False)
        return {"length": len(tokenizer(text, add_special_tokens=False)["input_ids"])}
    print("[data] computing lengths...")
    ds = ds.map(_len, num_proc=8)

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


if __name__ == "__main__":
    main()
