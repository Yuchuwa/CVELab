# SFT 训练计划：攻击轨迹 → 小模型网络攻击能力

> 起始日期：2026-07-24
> 对照基准：CVE-Factory（Qwen3-32B 全参数 SFT，64×H100，4k 轨迹，6.8× 提升）
> 本项目约束：4×RTX A6000-48G，LoRA，~600 条轨迹，目标"比 luna（完成度 10%）好"

---

## 1. 目标与成功判据

### 1.1 研究问题
> LoRA 微调 Qwen3-8B 能否从多 CVE 多跳攻击轨迹中习得网络攻击执行能力，在域内 Range 上超过弱 baseline？

### 1.2 成功判据（分层）
- **P0（最低）**：训练不崩、loss 正常下降、产出可加载的 LoRA adapter
- **P1（核心）**：在域内 Range 上，微调模型的 3f 全通率 / 完成度 > base Qwen3-8B
- **P2（目标）**：微调模型完成度 > luna 的 10%（luna 3f 全通 0/50，完成度 10%）
- **P3（扩展）**：在未参与训练的 CVE 组合上仍有提升（本版不强求，仅记录）

### 1.3 明确不做（本版边界）
- 不做 CVE train/test holdout（同 CVE-Factory 思路，靠评测侧防泄漏）
- 不做 RL/DPO（0-flag 失败轨迹留作后续 DPO 数据，不进 SFT 正样本）
- 不做全参数微调（算力不够，LoRA 足够验证假设）
- 不冲外部 benchmark（域内 Range 评测优先）

---

## 2. 数据管线

### 2.1 数据来源
- 目录：`data/guide_ablation/*/scenarios/`
- 筛选：`agent_context ∈ {l0, l1, l2, no_hint}`（无 flag-hint 泄漏）
- 格式：Claude SDK JSON 数组 session（含 thinking + 完整 tool_result）
- 规模：682 条 session，其中 ≥1 flag 捕获的 346 条轨迹

### 2.2 前缀样本生成（按成功 flag 边界切分）

每条轨迹按**实际成功捕获的 flag 数**生成前缀样本：

| 轨迹类型 | 数量 | 生成样本 | 终点 |
|---|---|---|---|
| 1 flag | 164 | 1 条 | hop1 成功 |
| 2 flags | 26 | 2 条 | hop1 / hop2 成功 |
| 3 flags | 156 | 3 条 | hop1 / hop2 / hop3 成功 |
| **合计** | 346 | **~676 条** | |

切分锚点：ground_truth 的 flag 值在 session 工具结果中首次出现的位置（已验证 100% 可定位，flag 不需注入训练输入）。

### 2.3 转换器 `sft/convert_trajectories_to_sft.py`

（注意：文件位于 `sft/convert_trajectories_to_sft.py`，不是 `scripts/`。）

输入 → 输出流程：

```
verify_result.json (筛 ctx + ≥1 flag match)
  → session.json (Claude 数组格式)
  → ground_truth.json (attack_path + flags)
  → 定位每跳 flag 在 session 的 event index
  → 对每个成功前缀 k 生成一条样本
     1. 注入 system 消息：按 ctx 选 NO_HINT_SYSTEM_PROMPT（从 scenario_runner.py 读常量）
     2. 归一化 Anthropic content-block → OpenAI tool_calls/tool 格式：
        - thinking block → 保留为 assistant 文本前缀（或丢弃，见 2.5）
        - tool_use block → assistant.tool_calls[].function.{name,arguments}
        - tool_result block（在 user role 里）→ 独立 tool 角色消息
     3. 终点：到第 k 个 flag 出现的 event 为止
     4. is_resolved=true（前缀本身是成功子目标）
     5. task_id = validation_round.case_id + f".hop{k}"
  → 输出 SFT JSONL
```

**重要格式约定（2026-07-25 修正）**：`tool_calls[].function.arguments` 必须保持为 Python dict，不能 `json.dumps()` 成字符串。Qwen2.5-Instruct 的 chat template 对 `arguments` 使用 `| tojson`；如果 `arguments` 已经是字符串，会被渲染成双重转义的 JSON 字符串字面量，导致 vLLM `--tool-call-parser hermes` 解析失败。

### 2.4 长度处理（不硬截断尾部）

按优先级处理 >32k 的样本：

1. **完整保留** ≤32k 的样本（554/676 = 82%）
2. **压缩冗长 tool_result**：对 >32k 样本，压缩工具输出
   - 压缩对象：重复命令的相同输出、超长 `ls`/env/源码 dump、重复端口扫描
   - 保留：assistant thinking、命令本身、关键返回行、payload、foothold/cred、flag 附近完整结果
   - 压缩方式：截断到关键尾部 + `[...truncated N chars...]` 标记
3. **压缩后仍 >32k**：暂不纳入第一版（记录但不训练）

最终预期：~600 条高质量 SFT 样本。

### 2.5 thinking 块处理决策

Claude session 含 `thinking` block（reasoning trace）。两个选项：

- **保留**：thinking 作为 assistant 内容，模型学到推理链。代价：token 更长
- **丢弃**：只留 tool_use + text。代价：丢失推理信号

**本版决策**：保留 thinking，但若超长样本压缩后仍超限，优先压缩 thinking（保留首尾、丢中段），再压 tool_result。理由：thinking 是攻击决策的核心信号，但比 tool_use 命令更可压缩。

### 2.6 反泄漏校验

转换器输出后，扫描所有样本的 user/system/assistant 文本，确认无：
- `flag_hint` / `flag_verify_command` / `reference_command` / `success_pattern`
- 任务提示里的字面 `flag{`（agent 在 tool_result 里*发现*的 flag 是合法信号，不算泄漏）

---

## 3. 训练设置

### 3.1 模型与框架

| 项 | 选择 | 理由 |
|---|---|---|
| 基座 | Qwen3-8B | 原生 32k ctx，工具调用强，LoRA 单卡可训 |
| 微调 | LoRA | 4×A6000 算力约束 |
| 框架 | trl SFTTrainer + peft + accelerate | 轻量，HF 生态标准 |
| 并行 | accelerate 多卡 DDP（不用 DeepSpeed，LoRA 不需要 ZeRO） | 简化 |
| 注意力 | sdpa（flash-attn 若装上则用） | 兼容性 |

**需安装**：`pip install trl peft datasets` （transformers/deepspeed/accelerate 已有）

### 3.2 超参数（初版）

```python
# LoRA
lora_rank = 64
lora_alpha = 128
lora_dropout = 0.05
target_modules = ["q_proj","k_proj","v_proj","o_proj","gate_proj","up_proj","down_proj"]

# 训练
max_seq_length = 32768          # 上限，dynamic padding 不固定
per_device_train_batch_size = 1 # micro-batch
gradient_accumulation_steps = 16 # 有效 batch 4×16=64
gradient_checkpointing = True
learning_rate = 1e-4            # LoRA 比 full-ft 高一个量级
warmup_ratio = 0.03
lr_scheduler_type = "cosine"
num_train_epochs = 3
bf16 = True
adam_beta1 = 0.9; adam_beta2 = 0.95

# 数据
packing = False                 # 不 packing，dynamic padding + length bucketing
group_by_length = True         # 按长度分桶减少 padding 浪费
```

### 3.3 显存预算（单卡，32k seq）
- Qwen3-8B BF16 权重：~16GB
- LoRA 参数 + optimizer state：~2-4GB
- 32k seq 激活（gradient checkpointing 后）：~20-28GB
- **预计峰值 38-48GB**，A6000-48G 临界，需 smoke 验证

### 3.4 硬件分配
- GPU 0,1,2,3（组内 NVLink 0-1、2-3）
- 其余 4 卡被占，不用

---

## 4. 执行阶段与验收门

### Phase 0：数据管线（无训练）
**任务**：
1. 写 `sft/convert_trajectories_to_sft.py`（位于 `sft/`，不是 `scripts/`）
2. 跑出 `data/sft/cve_attack_sft_v1.jsonl`
3. 写长度统计 + 反泄漏扫描校验脚本
4. 用 `sft/adapter_smoke_test.py` 或等价的 tokenizer 渲染检查确认 `tool_calls[].function.arguments` 被渲染为 JSON object（不是字符串字面量）

**验收门**：
- [x] 产出 ~600 条 JSONL，schema 符合 `{task_id, is_resolved, messages}`（实际 694 条）
- [x] 长度分布复核：≤32k 占比 ≥80%（实际 694/861 ≈ 80.6%）
- [x] 反泄漏扫描 0 命中
- [x] 抽查 3 条样本人工可读、tool_calls 格式正确
- [x] 用 `apply_chat_template` 验证 `arguments` 渲染为 JSON object
- [ ] 等待训练环境 `trl`/`transformers` 版本修复后重新训练 v2

### Phase 1：环境与 smoke（小步验证）
**任务**：
1. 修复 `trl`/`transformers` 版本兼容问题（当前 `trl 1.9.0` + `transformers 4.48.3` 导入 `SFTConfig` 报错）
2. `pip install trl peft datasets`（playbook env，按兼容版本）
3. 写 `sft/train_sft.py`（trl SFTTrainer + peft 配置）
4. 三档 smoke（各跑 20-50 步）：
   - `max_seq_length=8192` → 验证链路 + loss 下降
   - `max_seq_length=16384` → 测显存
   - `max_seq_length=32768` → 确认单卡峰值不 OOM
5. 训练前/后运行 `sft/adapter_smoke_test.py`：短 prompt + Range prompt 多轮工具调用格式检查

**验收门**：
- [ ] 三档 smoke 都不崩
- [ ] 32k 单卡峰值显存 <46GB（留余量）
- [ ] loss 正常下降（不 NaN/爆炸）
- [ ] 记录 tokens/sec 决定是否调 seq 或 epochs
- [ ] `adapter_smoke_test.py` 在 Range prompt 多轮下通过

### Phase 2：正式训练
**任务**：
1. 按 Phase 1 确认的 seq_len 跑完整 3 epochs
2. 每 epoch 存 checkpoint + 评估 loss
3. 训练日志写 `tb-runs/sft_v2/`

**验收门**：
- [ ] 训练完成，final loss 明显低于初始
- [ ] 产出 `data/sft/adapter_v2/`（LoRA adapter 可加载）
- [ ] 能用 `peft` + transformers 加载并推理
- [ ] `sft/adapter_smoke_test.py` 对 `adapter_v2` 通过（含 Range 多轮）

### Phase 3：域内评测
**任务**：
1. 把 LoRA adapter 挂到 Qwen3-8B，作为 Range Agent 的模型
2. 在同批 CVE 的 Range case 上跑（**不复用训练轨迹本身**，重新生成环境+跑 agent）
3. 对照组：base Qwen3-8B（无 LoRA）
4. 记录：3f 全通率、≥1f 率、avg 完成度、turns、termination

**验收门**：
- [ ] 微调模型完成度 > base Qwen3-8B
- [ ] 微调模型完成度 > luna 的 10%（P2 目标）

---

## 5. 评测协议细节

### 5.1 评测集
- 从训练用 CVE 组合中选 10-15 个 case 重新生成 Range
- **不复用训练时的 scenario 目录**（重新 deploy 保证环境干净）
- 用 `scripts/verify_enterprise3_guided_batch.py` 跑，`--agent-runner openai` 挂微调模型

### 5.2 对照
| 组 | 模型 | 说明 |
|---|---|---|
| A | base Qwen3-8B | 无微调，同 prompt |
| B | Qwen3-8B + LoRA adapter_v1 | 本训练产物 |
| (历史) | luna | 10% 完成度（对照线） |

### 5.3 记录指标
- environment_verified / attack_graph_valid（应全 true，排除环境因素）
- 3f 全通率、≥1f 率、avg 完成度
- agent termination_reason 分布
- 失败分类（环境/Agent planning/payload/timeout）

---

## 6. 风险与缓解

| 风险 | 概率 | 缓解 |
|---|---|---|
| 32k 单卡 OOM | 中 | 降到 16k 或 24k；或只训 ≤16k 样本 |
| 600 条泛化不足 | 中高 | 接受域内验证；后续跑更多 batch 扩量 |
| thinking 压缩损失信号 | 中 | 先全保留跑一次，对比压缩版 |
| tool 格式归一化错 | 中 | 已发生：已修正 `arguments` 为 dict 并加 `adapter_smoke_test.py` 校验 |
| 评测污染（训练轨迹复用） | 高 | 强制重新 deploy 新 Range，不复用 scenario |
| GPU 0-3 跨组 PCIe 慢 | 低 | 可只用 0,1 双卡 NVLink 对 |
| trl/transformers 版本不兼容 | 中 | 已发现，需先修复依赖再训练 v2 |

---

## 7. 产物清单

| 产物 | 路径 |
|---|---|
| 转换器 | `sft/convert_trajectories_to_sft.py` |
| 长度探针 | `scripts/probe_trajectory_split.py`（已写） |
| 训练脚本 | `sft/train_sft.py` |
| adapter smoke test | `sft/adapter_smoke_test.py` |
| 转换器回归测试 | `tests/sft/test_convert_trajectories.py` |
| SFT 数据 | `data/sft/cve_attack_sft_v1.jsonl` |
| 长度报告 | `data/sft/length_report.json` |
| LoRA adapter | `data/sft/adapter_v2/`（待训练） |
| 训练日志 | `tb-runs/sft_v2/` |
| 评测结果 | `data/guide_ablation/sft_v2_eval/` |
| 进度记录 | `docs/WORK_PROGRESS_REPORT.md`（每 phase 追加） |

---

## 8. 执行顺序总结

```
Phase 0 数据管线 ──验收──→ Phase 1 smoke ──验收──→ Phase 2 正式训练 ──验收──→ Phase 3 评测
   (转换器+校验)        (装包+三档smoke)        (3 epochs)            (对照base+luna)
```

每个 phase 结束追加 `docs/WORK_PROGRESS_REPORT.md`，记录事实 + 验收门通过情况。失败分类后再决定是否进下一 phase，不硬冲。
