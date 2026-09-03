# 本周结论

**汇报周期：2026-08-24 至 2026-08-30**

## 一句话总结

本周将 CVELab 的难度研究从“依赖经验判断”推进到“静态先验评分—规范化运行时—四模型外部验证”的闭环，并通过第二轮架构感知评分解决了第一轮 hard/very-hard 混在成功率天花板的问题。

## 三项主要进展

1. **评估器落地**
   - 新增独立的 Atom/Range difficulty evaluator。
   - 评分结果只写入独立 JSON 报告，不回写 Atom 或 Range。
   - 支持固定四模型、30 turns、1800 秒预算和状态隔离。

2. **评分模型从单点先验升级为组合先验**
   - 第一轮静态 rubric 使用 exploit method、复杂度、认证、callback、材料和目标成本。
   - 第二轮把每个 Atom 阶段概率与架构乘子、依赖深度、并行根、Guide 因子组合。
   - 共枚举 3,017 个合法 CVE × template 组合，并选出 67 个 canonical baseline。

3. **两轮梯度验证**
   - 两轮均为 8 case × 4 model = 32 runs，环境验证全部通过，0 API/环境错误。
   - Validation1 证明总体排序相关，但 hard 和 very-hard 都达到 80 分天花板。
   - Validation2 使四档均值分离：**9.77 → 42.45 → 66.98 → 80.0**。

## 关键数字

| 维度 | 结果 |
| --- | ---: |
| 评估模型 | 4 个 Qwen 模型 |
| 每轮验证集 | 8 cases，2 cases/tier |
| 每轮评估量 | 32 runs |
| Validation2 成功 / 总运行 | 15 / 32 |
| Validation2 API/环境错误 | 0 / 0 |
| 组合评分合法候选 | 3,017 |
| canonical baseline | 67 |
| 规范化 runtime Atom | 7 |
| 两轮验证环境有效性 | 8/8 |

## 本周形成的研究判断

- **当前评分器能可靠表达“相对难度排序”，还不能宣称四档标签已完全校准。** 两轮 exact-tier accuracy 都是 5/8，但 adjacent-tier accuracy 都是 8/8。
- **架构和依赖深度是难度的重要来源。** 第二轮将 dmz_simple、dmz_dual、enterprise_3tier 混合后，hard 与 very-hard 得到区分。
- **环境正确性与 Agent 成功必须分开。** 本轮 8/8 环境、攻击图、攻击路径和 cleanup 都通过，15/32 是 Agent 任务成功；后者反映当前模型和 Guide 条件下的求解难度。

## 汇报范围说明

本书的“已完成结果”只总结 8 月 24 日至 30 日的提交和实验。9 月 3 日新增的
内容单独标记为**下周工作启动状态**，用于记录信度与效度研究的协议、代码基础和
draft manifest，不计入 8 月 24–30 日实验结论，也不表示正式 pilot 已开始。
