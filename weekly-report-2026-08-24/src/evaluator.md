# 难度评估体系

## 经验评估器

8 月 28 日新增 `src/clab_builder/evaluation/`，把难度评估做成独立于 Atom/Range 构建链路的外部测量。

### 评估对象

- `atom_evaluator.py`：多个模型连接同一个已启动的 Atom 容器，可选 reset 做状态隔离。
- `range_evaluator.py`：每个模型使用 scenario 临时副本，独立 deploy/destroy。
- `difficulty.py`：统一抽取 solution rate、turns、tool calls、wall time，并生成原子写入的独立报告。
- `cli.py`：增加 `difficulty atom` 和 `difficulty range` 命令。

### 评分口径

综合分由两部分组成：

```text
解决率贡献：80%
执行成本贡献：20%
```

难度档位：

| Tier | 分数 |
| --- | --- |
| easy | < 25 |
| medium | 25–50 |
| hard | 50–75 |
| very_hard | ≥ 75 |

默认实验配置为四个固定 Qwen 模型、30 turns、1800 秒超时。评估结果不写入 Atom 或 Range，避免把测量反馈污染被测对象。

## 9 月 3 日可信度增强

为支持下一阶段信度与效度研究，经验评估器已经开始从“单次点估计”升级为
“run-level 证据 + 不确定性”报告：

- `objective_achieved` 缺失时按失败处理，不再 fail-open；
- 环境、API、Verifier 或 evaluator 异常标记为 invalid run，不进入 Agent
  成功率分母；
- 对成功概率报告 Wilson 95% 区间；
- 成功运行和失败运行分别报告 turns、tool calls 与 wall time；
- v1 80/20 分数继续保留用于历史比较，但同时给出 score interval 和
  `tier_uncertain`，不再把一个点 tier 当作精确结论；
- CLI 支持 `--attempts-per-model`，可以对同一模型和 case 做重复测量；
- `--keep-run-artifacts` 模式记录原始 run directory、Verifier 结果与 session
  的 SHA-256 引用；
- 新增 Brier score、log loss、tie-aware Spearman 和 Known-Answer Test
  最小合同。

本次更新没有追溯改写 Validation1/2。历史结果继续使用 schema v1 和原有评分
语义；新报告使用 schema v2。

### 12+12 pilot draft

新增确定性抽样器，从当前可评分候选中生成：

- 12 calibration + 12 held-out test；
- 每个 split 每档 3 case；
- 两个 split 都覆盖 `dmz_simple`、`dmz_dual`、`enterprise_3tier`；
- calibration/test 之间 Atom 零重叠；
- 每个 Atom 在单个 split 中最多出现两次；
- 不读取 Agent 历史结果，也不按 threshold margin 选择；
- matrix、scorer、template、Atom 与 Guide 都记录 SHA-256。

当前 artifact：

```text
docs/DIFFICULTY_MEASUREMENT_PROTOCOL.md
data/difficulty_credibility_pilot_manifest_2026-09-03.json
scripts/prepare_difficulty_credibility_pilot.py
scripts/analyze_difficulty_credibility.py
```

manifest 状态是 `draft_prequalification`。在每个 case 完成
oracle/no-op/partial/wrong-evidence/pre-agent/repeat-verdict KAT，并冻结三个模型
家族之前，不进入正式 Agent 试验。

## 静态专家先验 pilot

8 月 30 日先运行不调用 LLM、不部署 Range、不读取历史 Agent 结果的 metadata-only pilot，用来冻结验证前的预测。

### Rubric

- attack method；
- exploit complexity；
- attack path position；
- callback / authentication requirements；
- exploit materials；
- final objective cost。

阶段成功概率采用乘法组合，并报告最低条件阶段作为瓶颈。

### 结果

- 8 个代表性 Atom：1 easy、6 medium、1 hard。
- 12 个 enterprise_3tier 组合：4 hard、8 very-hard。
- 12 个组合中有 8 个把 application/pivot 阶段判为瓶颈。

第一版 rubric 能区分 exploit mechanism 和 position-sensitive cost，但可能过度惩罚链路长度。这个结果只是冻结的先验假设，不是实测难度。

## 组合难度评分器

第一轮暴露出仅靠 Atom 静态特征无法稳定区分多跳组合，因此新增架构感知的 `analyze_compositional_difficulty.py`。

评分概念为：

```text
score = 80 * (1 - composed_success_probability)
        + 20 * composed_cost_factor
```

其中组合成功概率由以下因素共同决定：

- per-Atom stage probability；
- required target count；
- dependency edges；
- maximum dependency depth；
- parallel roots；
- business objectives；
- Guide steps、command coverage、material transfer 等因素。

### 全量枚举

| Template | 合法组合数 |
| --- | ---: |
| dmz_simple | 39 |
| dmz_dual | 1,178 |
| enterprise_3tier | 1,800 |
| **合计** | **3,017** |

其中 67 个组合被选作 canonical baseline，用于后续验证集筛选和跨模板比较。
