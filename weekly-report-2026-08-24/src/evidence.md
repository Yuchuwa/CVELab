# 证据索引与边界

以下路径均相对于 `E:\remote_project\CVELab`。

## 代码与提交

| Commit | 内容 |
| --- | --- |
| `0bb17bb` | 新增 empirical difficulty evaluator |
| `0fa5cf2` | 澄清 evaluator flow、隔离和超时注释 |
| `b575c00` | 新增 static expert-prior difficulty pilot |
| `a314caa` | 建立 canonical runtime baseline |
| `a90e5dd` | 冻结 validation1 manifest |
| `debaddf` | 记录 validation1 结果 |
| `bf578f1` | 新增 compositional scorer 和 validation2 manifest |
| `b97dfe9` | 记录 validation2 结果 |

## 主要代码与测试

```text
src/clab_builder/evaluation/
scripts/analyze_static_difficulty_pilot.py
scripts/analyze_compositional_difficulty.py
tests/evaluation/test_difficulty.py
tests/evaluation/test_static_difficulty_pilot.py
tests/evaluation/test_compositional_difficulty.py
```

已记录的 focused evaluation 测试为 **13 passed**（4 + 4 + 5）；静态 pilot 还验证了重复生成的 JSON 和 Markdown SHA-256 一致。

9 月 3 日可信度增强后的 `tests/evaluation/` 为 **41 passed**，新增覆盖：

- objective 缺失 fail-closed；
- invalid run 不进入 Agent 成功率分母；
- Wilson 区间、失败成本和 uncertain tier；
- Brier score、log loss 和 tie-aware Spearman；
- oracle/no-op/partial/wrong-evidence KAT 合同；
- Atom 私有 flag oracle 与模型自报成功分离；
- Agent transport/未执行试验不进入失败分母；
- 按模型与模型家族分别报告；
- Atom-disjoint 12+12 分层抽样。
- KAT 声明 hash 与真实 evidence artifact 的重新计算绑定；
- 至少三个模型家族、calibration-first 随机顺序和 sealed run plan；
- calibration-only 单变量 logistic baseline 与 held-out 增量比较。

## 实验 artifact

```text
data/static_difficulty_pilot.json
docs/STATIC_DIFFICULTY_PILOT.md
data/runtime_baselines/canonical-runtime-2026-08-30.json
data/difficulty_gradient_validation_2026-08-30.json
data/difficulty_gradient_validation_results_2026-08-30.json
data/compositional_difficulty_analysis.json
data/difficulty_gradient_validation2_2026-08-30.json
data/difficulty_gradient_validation2_results_2026-08-30.json
data/difficulty_credibility_pilot_manifest_2026-09-03.json
docs/DIFFICULTY_MEASUREMENT_PROTOCOL.md
scripts/prepare_difficulty_credibility_pilot.py
scripts/analyze_difficulty_credibility.py
docs/WORK_PROGRESS_REPORT.md
```

## 验证配置

```text
models:
  qwen3.6-27b
  qwen3.6-35b-a3b
  qwen3.6-plus
  qwen3.6-flash
max_turns: 30
timeout_seconds: 1800
agent_context: guided
```

## 结果解释边界

- 静态预测在 Agent 运行前冻结，不读取历史 Agent 结果。
- 本书只引用聚合 artifact，不复制 raw trajectory、flag 或 credential。
- CVELab 当前工作区在 8 月 31 日还有未提交变更；这些变更不作为本周完成项，也不影响本书引用的 8 月 28/30 日已提交结果。
- 全量测试套件的总通过数未在本次整理中重新跑完；本书只声明有证据支持的 evaluation focused tests 和实验结果。
- 12+12 credibility manifest 当前是 `draft_prequalification`，尚未完成逐 case
  KAT，也未冻结三个模型家族，因此不代表正式实验已经开始。
