# 研究结论与下一步

## 已完成

- 建立独立 Atom/Range 经验难度评估器。
- 建立 metadata-only 静态专家先验 pilot。
- 建立架构感知的组合难度评分器。
- 建立 7 个 Atom 的 canonical runtime provenance。
- 完成两轮各 32 runs 的四模型验证。
- 将环境 validity、attack graph、attack path、Agent success 和 objective 语义分开记录。

## 当前可以下的结论

### 可以下结论

- 预测排序与实测难度存在较强正相关。
- 所有 8 个验证环境均通过确定性环境和攻击路径检查。
- 组合评分比单纯 Atom 先验更能表达多跳架构摩擦。
- 在当前 guided、四模型、一次运行的实验协议下，easy、medium、hard、very-hard 的均值已出现单调梯度。

### 还不能下结论

- 不能宣称四档 tier 已经完全校准，exact-tier accuracy 只有 62.5%。
- 不能把 very-hard 的 80 分等同于精确难度，它仍可能只是零成功造成的上限饱和。
- 不能把 Agent 失败解释为 Range 环境无效；本轮环境 gate 全部通过。
- 不能把当前 8-case 样本外推为所有 CVE 或所有 template 的难度分布。

## 下周计划

下周不再把主要精力放在事后解释 80/20、25/50/75 或人工阶段概率，而是把现有
评分视为待检验的 v1 假设，建立外部可审查的信度与效度证据链。完整方案见
[下周：信度与效度验证计划](reliability-validity-plan.md)。

优先完成：

1. 冻结难度 construct、适用范围、核心主张、排除规则和分析计划。
2. 设计 12 calibration + 12 held-out case 的分层随机 pilot，不再按预测
   threshold margin 挑选，并尽可能保持 Atom-disjoint。
3. 建立每个正式 case 的 oracle/no-op/partial Known-Answer Test 规范。
4. 选择三个不同模型家族，每个 model × case 至少重复三次，用于估计重测和
   跨模型家族信度。
5. 统一实现 CVSS、CVE 数量、目标数量、路径深度、Guide 步数和简单 Atom 加和
   等 baseline，检验组合评分是否具有增量效度。
6. 设计 10–12 组单因素受控配对任务，验证 Guide、路径深度、认证、预算、
   decoy 和 objective 是否产生预期方向的变化。
7. 先完成实验 protocol、manifest、证据归档和分析入口，再投入正式 LLM
   运行预算。

## 汇报时建议强调

> 当前 80/20 评分是需要验证的工程假设，不是被论文直接证明的科学定律。下周的
> 核心工作是按既有测量理论，通过 Verifier 正反例、重复测量、受控实验、简单
> 基线和独立 held-out 测试，为指定实验协议下的难度解释建立可复核证据。
