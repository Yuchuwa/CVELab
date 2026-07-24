#!/usr/bin/env bash
# Overnight SFT pipeline: 3-stage smoke then full training.
# - smoke 8k/16k/32k (2 steps each) to find max viable seq_len
# - pick the largest non-OOM seq_len
# - launch full 3-epoch training on 4 GPUs in background (nohup)
#
# Usage:  bash sft/run_overnight.sh
# Logs:   /tmp/sft_smoke_*.log, /tmp/sft_train.log
set -uo pipefail

ROOT="/home/hanlin/CVELab"
PY="/home/hanlin/miniconda3/envs/playbook/bin/python"
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
export TOKENIZERS_PARALLELISM=false

mkdir -p "$ROOT/data/sft" /tmp/sft_logs

run_smoke() {
  local seq=$1
  local log="/tmp/sft_smoke_${seq}.log"
  echo "===== SMOKE seq=$seq  ($(date +%H:%M:%S)) ====="
  CUDA_VISIBLE_DEVICES=0 "$PY" "$ROOT/sft/train_sft.py" \
    --smoke --max-seq-length "$seq" --grad-accum 4 \
    --output "/tmp/sft_smoke_${seq}" 2>&1 | tee "$log" | grep -E "loss|train_runtime|Error|OOM|error" | tail -5
  local rc=${PIPESTATUS[0]}
  if [ $rc -ne 0 ]; then
    echo "SMOKE seq=$seq FAILED (rc=$rc)"
    return 1
  fi
  # check for OOM
  if grep -qiE "out of memory|CUDA error|OOM" "$log"; then
    echo "SMOKE seq=$seq OOM"
    return 1
  fi
  echo "SMOKE seq=$seq OK"
  return 0
}

CHOSEN_SEQ=0
for SEQ in 8192 16384 32768; do
  if run_smoke $SEQ; then
    CHOSEN_SEQ=$SEQ
    echo "seq=$SEQ viable, continuing to next"
  else
    echo "seq=$SEQ failed, stopping escalation"
    break
  fi
  sleep 5
done

if [ $CHOSEN_SEQ -eq 0 ]; then
  echo "ALL SMOKES FAILED. Aborting."
  exit 1
fi

echo "===== Chosen max_seq_length=$CHOSEN_SEQ ====="
echo "Launching full training on GPU 0,1,4,5 (nohup background)..."

cd "$ROOT"
CUDA_VISIBLE_DEVICES=0,1,4,5 nohup "$PY" "$ROOT/sft/train_sft.py" \
  --max-seq-length $CHOSEN_SEQ \
  --epochs 3 \
  --grad-accum 4 \
  --output "$ROOT/data/sft/adapter_v1" \
  > /tmp/sft_train.log 2>&1 &

TRAIN_PID=$!
echo "Training PID: $TRAIN_PID"
echo "Log: /tmp/sft_train.log"
echo "Started at: $(date)"
wait $TRAIN_PID
echo "Training finished at: $(date) with rc=$?"
