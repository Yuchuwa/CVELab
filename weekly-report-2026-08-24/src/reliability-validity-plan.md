# 下周：信度与效度验证计划

## 研究定位调整

当前的 80/20 权重、25/50/75 阈值、人工阶段概率和 canonical anchor
选择都属于**专家启发式设计**。它们可以作为待验证的 v1 operational score，
但不能因为引用了论文就被表述成已经得到理论证明的科学量表。

论文能够提供的是测量框架、统计模型和验证规范；CVELab 自身仍必须通过独立实验
建立证据。下周工作的主线因此从“继续解释现有常数”调整为：

> 以现有组合评分为候选模型，设计并冻结一项可证伪、可复现的信度与效度验证
> 研究，检验它能否预测未见 Range 的 Agent 成功概率，并且是否优于简单基线。

这里的难度必须绑定实验条件：

```text
difficulty(task | model population, harness, guide, budget, runtime, verifier)
```

结论只适用于上述条件，不宣称任务具有脱离模型和协议的绝对难度。

## 理论依据与对应工作

| 理论或规范 | 对 CVELab 的约束 |
| --- | --- |
| Rasch / Item Response Theory | 将模型能力与任务难度分开估计，不把一次成败直接当作任务固有属性 |
| Generalizability Theory | 分解 task、model、run、Harness 等来源造成的方差，判断分数能推广到什么范围 |
| Messick 统一效度观 | 效度是对分数解释和使用方式的证据链，不是公式本身拥有的标签 |
| *Standards for Educational and Psychological Testing* | 从内容、反应过程、内部结构、与外部变量关系及使用后果组织效度证据 |
| Brier score / log loss | 检验预测成功概率的准确性和校准，而不仅是排序相关 |
| BetterBench / HELM | 要求明确 construct、覆盖范围、限制、多指标结果和可复现 artifact |

因此，下周不应先拟合复杂 IRT。当前 case 和模型数量还不足，直接拟合容易把小样本
噪声包装成精确参数。第一阶段先用重复试验、Beta-Binomial/Wilson 区间和简单
分层模型建立数据基础；样本扩大后再判断是否使用 IRT 或层次 Logistic 模型。

## 要验证的核心主张

正式实验只保留一个主张：

> 在预先冻结的模型群体、Harness、Guide 和预算下，架构感知组合评分能够预测
> held-out Range 的 verifier-backed Agent 成功概率，并且提供目标数量、攻击链
> 深度、Guide 步数等简单指标之外的增量信息。

该主张在测试前可以被明确判错：

- held-out 排序不相关；
- 概率预测未校准；
- 重复运行后难度排序不稳定；
- 换模型家族后整体方向反转；
- 复杂评分不优于“链路越长越难”等简单基线。

如果出现上述结果，应修改或放弃当前评分模型，而不是重新挑 case 或事后调整权重。

## 信度研究

### 1. Verifier 测量信度

每个进入正式实验的 case 都必须通过 Known-Answer Tests：

1. reference/oracle 解法能够稳定通过；
2. no-op 必须失败；
3. 只完成部分攻击路径必须失败；
4. 错误 flag、actor、target 和 objective evidence 必须失败；
5. Agent 执行前 objective 尚未满足；
6. 同一终态重复验证得到相同判定；
7. Verifier 或环境异常记为 invalid run，不记为 Agent failure。

这一步证明测量仪器能够稳定区分成功和失败。没有这一层，后续再复杂的统计分析
也只是对不可靠标签做建模。

### 2. 重测信度

对相同 case、模型和协议分多个批次重复运行，比较批次之间的：

- 成功概率及区间；
- case 难度排序；
- tier；
- 成功成本、失败成本和失败阶段。

Agent 具有随机性，因此不要求每次二值结果完全一致。要检验的是重复采样后得到的
任务难度估计是否稳定。

候选统计量包括：

- 连续难度估计的 ICC；
- 批次间 Spearman 和 Kendall；
- tier 的加权 kappa；
- Beta-Binomial 过度离散；
- task、model、run 方差分量。

### 3. 跨模型家族信度

至少选择三个真正不同的模型家族，分别计算任务排序，不能把多个近缘 Qwen 型号
直接当作独立重复。若不同家族下的排序大体一致，可支持任务层面的稳定性；若差异
很大，则应把结果明确表述为 model-family-conditional difficulty。

## 效度研究

### 1. 内容证据

邀请 2–3 名安全研究人员在不知道现有权重的情况下审查评分维度，判断其是否覆盖：

- 漏洞发现和利用；
- 认证、callback 和材料准备；
- 网络可达性与横向移动；
- 依赖链与路径深度；
- business objective；
- Guide 信息量；
- 搜索、重试、上下文和预算压力。

保存专家的独立判断、分歧和遗漏项，而不是只保留讨论后的共识。可以报告专家一致率
和 Content Validity Index，但不能把专家意见当作唯一 ground truth。

### 2. 反应过程证据

抽样审计 session 和工具结果，检查 Verifier 的成功标签是否对应预期的真实过程：

- Agent 是否真的从允许的执行节点完成攻击；
- flag/objective marker 是否来自对应工具执行；
- 是否存在 Guide、材料或 Ground Truth 泄露；
- 是否把 API、Harness 或环境故障误算成任务困难；
- 失败阶段是否与 transcript 中的实际停止位置一致。

### 3. 构念效度

制作 10–12 组配对任务，每次只改变一个理论上应影响难度的因素：

| 对照 | 处理 | 预注册方向 |
| --- | --- | --- |
| 有 Guide | 无 Guide | 成功率下降 |
| 单跳 | 双跳 | 成功率下降 |
| 无认证 | 有认证 | 成功率下降 |
| 高预算 | 低预算 | 成功率下降 |
| 无 decoy | 有 decoy | 搜索成本上升 |
| 单 objective | 多 objective | 完成率下降 |

评分变化与实测变化都应符合预注册方向。配对设计可以比不同 CVE 的横向比较更直接地
证明评分确实响应预期的难度机制。

### 4. 预测效度

公式、权重和协议冻结后，才运行未参与设计的测试集。主要经验效标使用原始的：

```text
verifier-backed success probability
```

辅助效标为阶段到达率、预算耗尽率、成功成本和失败成本。不能只比较“预测
80/20 分数”和“实测 80/20 分数”，否则共享公式结构会产生循环论证。

主要指标：

- Brier score 和 log loss；
- 概率校准曲线；
- held-out Spearman/Kendall 及区间；
- tier confusion matrix；
- 每个 case 的原始结果和不确定性区间。

### 5. 增量效度

当前评分必须与以下简单基线在同一 held-out 集合上比较：

1. 随机或常数预测；
2. CVSS；
3. CVE 数量；
4. required target 数量；
5. attack path depth；
6. Guide 步数；
7. Atom 静态分数简单求和；
8. 架构感知组合评分。

只有当组合评分在 cluster bootstrap 下稳定优于最佳简单基线，才能声称架构和
组合特征提供了额外价值。若它没有优于 chain depth，就应选择更简单、更可解释的
模型。

### 6. 聚合、区分和外部证据

- **聚合证据**：专家在不知道模型分数时独立排序 case，检查专家排序、评分和
  Agent 实测结果是否收敛。
- **区分证据**：检查分数是否主要由镜像启动时间、API 延迟、CVE 年份、临时环境
  故障或输出格式错误决定；这些变量不应被解释成任务难度。
- **外部证据**：在未见 Atom、未见组合、不同 template 和不同模型家族上复验。
  组合不重叠只能支持“泛化到新组合”，Atom 不重叠才能更有力地支持“泛化到新
  漏洞”。

## 数据集与实验规模

### 最小可行 pilot

- 24 个 case：12 calibration + 12 held-out test；
- 按 template、路径深度和预期区域分层随机抽样；
- 不按 threshold margin 挑选；
- 尽可能保证 calibration/test 之间 Atom-disjoint；
- 3 个不同模型家族；
- 每个 model × case 至少 3 次重复；
- 基础运行量为 `24 × 3 × 3 = 216 runs`。

该 pilot 用于验证流程、估计方差和确定正式研究所需样本量，不用于宣称评分体系已经
被充分验证。

### 正式验证

- 48–60 个 case；
- calibration/test 各占一半；
- 测试集在公式、特征和阈值冻结前不可查看运行结果；
- 根据 pilot 方差做样本量或精度分析；
- case、Atom 和 template 都保留分层信息；
- 运行顺序随机化，保存随机种子。

## 统计与判定规则

所有主指标、排除规则和成功条件必须在测试集运行前预注册：

1. 概率预测以 Brier/log loss 为主，排序相关为辅；
2. 与基线的差值使用 case 配对、按 Atom/template 聚类的 bootstrap 区间；
3. 每个模型家族单独报告，不只报告混合总成功率；
4. 零成功和全成功仍报告区间，不当作精确 0% 或 100%；
5. 区间跨越 tier 边界时标记 `uncertain`，不强制归档；
6. 同一批数据不能同时用于选择权重、调整阈值和报告最终准确率；
7. 所有 case 和负面结果都进入报告，不能只保留符合预期的样本。

ICC、kappa 或相关系数的验收阈值不能在看完结果后选择。pilot 结束后应结合用途、
成本和所需精度确定正式阈值，并把选择理由写入冻结协议。

## 下周具体交付物

下周先完成研究设计和测量基础，不立即宣称效度成立：

1. 《CVELab 难度测量与适用范围规范》；
2. 信度与效度主张、假设和分析计划；
3. calibration/test 分层抽样脚本与冻结 manifest；
4. 简单 baseline 的统一计算接口；
5. case-level oracle/no-op/partial Known-Answer Test 规范；
6. run-level 证据、版本和 SHA-256 归档规范；
7. 12+12 pilot 的模型、重复次数、预算和运行顺序；
8. 一条命令重建区间、基线比较和图表的分析入口。

随后再按“Verifier KAT → 24-case pilot → 方差/功效分析 → 正式 held-out 验证”
推进。历史 Validation1/2 保留为探索性结果，不用于最终效度证明。

## 9 月 3 日启动状态

第一阶段已经开始实施：

- 完成测量协议草案 `docs/DIFFICULTY_MEASUREMENT_PROTOCOL.md`；
- 生成 12+12 `draft_prequalification` manifest；
- 两个 split 均为每档 3 case、覆盖三种 template；
- calibration 使用 16 个 Atom，test 使用 15 个 Atom，两个集合零重叠；
- manifest 重复生成的文件 SHA-256 完全一致；
- 评估器改为 objective fail-closed，区分 valid/invalid run；
- 增加 Wilson 区间、失败运行成本、`tier_uncertain` 和重复 attempt；
- 增加 Brier/log loss、tie-aware Spearman 与 KAT 合同；
- evaluation focused tests 为 41 passed，Ruff 检查通过。
- 已增加 KAT artifact 绑定、冻结运行顺序、calibration-only baseline
  拟合和 held-out 收集/分析框架；尚未执行真实 KAT 或模型试验。

仍未完成、因此不能启动正式 216-run pilot：

- 24 个 case 的实际 KAT qualification；
- 三个模型家族与精确版本冻结；
- 运行顺序随机化和正式 run manifest；
- baseline 从标量特征到 calibration-only 概率映射；
- 受控配对任务与专家盲评。

## 预期可支持的结论

如果上述研究通过，合理口径是：

> CVELab 难度评分不是由论文直接证明，而是在既有测量理论指导下，通过 Verifier
> 正反例、重复测量、受控配对实验、简单基线比较和独立 held-out 测试，获得了
> 指定模型群体与实验协议下的信度和效度证据。

即使验证成功，也不应声称 80/20 是唯一合理权重，或难度分数能够无条件跨模型、
Harness、Guide 和预算迁移。

## 参考资料

1. Cronbach, Gleser, Nanda, and Rajaratnam, *The Dependability of Behavioral
   Measurements: Theory of Generalizability for Scores and Profiles*, 1972.
2. Messick, *Validity of Psychological Assessment: Validation of Inferences
   from Persons' Responses and Performances as Scientific Inquiry into Score
   Meaning*, 1995,
   [APA PsycNet](https://psycnet.apa.org/record/1996-10004-001)。
3. AERA, APA, and NCME, *Standards for Educational and Psychological Testing*,
   2014, [APA](https://www.apa.org/science/programs/testing/standards)。
4. Lord, *Applications of Item Response Theory to Practical Testing Problems*,
   1980.
5. Brown, Cai, and DasGupta, *Interval Estimation for a Binomial Proportion*,
   *Statistical Science* 16(2), 2001.
6. Liang et al., *Holistic Evaluation of Language Models*, 2023,
   [arXiv:2211.09110](https://arxiv.org/abs/2211.09110)。
7. Raji et al., *AI and the Everything in the Whole Wide World Benchmark*,
   NeurIPS Datasets and Benchmarks 2021,
   [proceedings](https://datasets-benchmarks-proceedings.neurips.cc/paper/2021/hash/084b6fbb10729ed4da8c3d3f5a3ae7c9-Abstract-round2.html)。
8. Hardy et al., *BetterBench: Assessing AI Benchmarks, Uncovering Issues,
   and Establishing Best Practices*, NeurIPS 2024,
   [proceedings](https://proceedings.neurips.cc/paper_files/paper/2024/hash/26889e8359e7ef8a7f42909d4c47aaf8-Abstract-Datasets_and_Benchmarks_Track.html)。
9. Hernández-Orallo, *Analysing Results from AI Benchmarks: Key Indicators
   and How to Obtain Them*, 2019,
   [arXiv:1811.08186](https://arxiv.org/abs/1811.08186)。
10. Ge et al., *Agent Psychometrics: Task-Level Performance Prediction in
    Agentic Coding Benchmarks*, 2026, preprint,
    [arXiv:2604.00594](https://arxiv.org/abs/2604.00594)。
