#!/bin/bash
# Background monitor for sft_v3_train
LOG=/home/hanlin/CVELab/data/sft/adapter_v3_train.log
MON=/home/hanlin/CVELab/data/sft/adapter_v3_monitor.log

while true; do
    echo "===== $(date -Iseconds) =====" >> "$MON"
    if [ -f "$LOG" ]; then
        echo "--- last 20 lines of train log ---" >> "$MON"
        tail -20 "$LOG" >> "$MON" 2>&1
    else
        echo "train log not found" >> "$MON"
    fi
    echo "--- GPU status ---" >> "$MON"
    nvidia-smi --query-gpu=index,temperature.gpu,utilization.gpu,memory.used,memory.total --format=csv,noheader,nounits >> "$MON" 2>&1
    echo "--- tmux session ---" >> "$MON"
    tmux list-sessions -F '#S #W' 2>/dev/null | grep sft_v3_train >> "$MON" 2>&1 || echo "sft_v3_train session not found" >> "$MON"
    echo "" >> "$MON"
    sleep 600
done
