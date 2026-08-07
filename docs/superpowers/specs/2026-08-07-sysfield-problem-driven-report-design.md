# sysfield 问题牵引式报告设计说明

## 目标

将 `reports/report.zh.md` 和 `reports/report.en.md` 重写为立场一致的双语科研报告。报告应面向防御者、benchmark 设计者和平台方，说明为了刻画前沿网络安全智能体在真实防御环境中的风险边界，需要怎样的 benchmark 与证据体系。

报告不以优化攻击战术为目的。受控攻击轨迹只是测量手段，用于评估攻击完成度、防御可见性和抗干扰能力。

## 第一性原理叙事

中英文报告必须遵循同一条因果链：

1. **领域变化：** 网络安全智能体评测正在从静态知识和孤立任务，转向真实系统中可执行、长程、连续的行动。
2. **现有缺口：** 现有 benchmark 已经能有效测量 PoC、flag、patch 和 objective，却很少测量真实防御能否观察或扰动攻击过程。
3. **真正挑战：** benchmark 既要构造真实又可判定的靶场，也要分离攻击与防御结果；既要把 signal 严格归因到攻击窗口，也要使用行为化而非靶场私有的检测 GT；还要独立测量干扰效果，而不能把它折叠进攻击成功率。
4. **关键洞察：** 智能体风险不能由单一攻击成功率刻画。防御者需要攻击完成度、防御可见性和抗干扰能力的联合画像。
5. **解决方法：** sysfield 将 CVELab 多层 range、外部攻击验证和 SysArmor 运行时观测组合成统一实验底座，以 model、harness 和 decoy/noise 为实验变量，并用攻击完成度、signal 和 missing signal 构成递进的证据协议。
6. **实验证据：** 实验首先测量智能体能否完成三层攻击以及模型差异，再考察 harness 与 decoy 如何改变能力，随后评估各实验臂是否触发防御 signal，最后分析最容易未被观测的预期攻击行为。
7. **研究边界：** 结论仍受 partial run、observe-only 检测、模型与难度差异、行为规则覆盖范围，以及当前 high-decoy 实验中的 topology-hint 混杂因素限制。

全文反复强调的核心判断是：

> 攻击成功不等于防御失明，攻击失败也不等于风险不存在。

## 研究立场

报告的立场应与 CyberGym、CyberGym-E2E 和 ExploitGym 的负责任表述一致：

- 必须在真实任务中评测智能体，因为合成任务或单一完成度分数无法揭示现实风险和防御需求；
- 引入攻击行为是为了支持安全部署、修复、评估和防御规划；
- 明确认识网络安全能力的 dual-use 属性，但分析落点始终是防御者需要把智能体建模为一种真实攻击压力来源。

报告不得把 sysfield 描述成一种让智能体更有效、更隐蔽或更具攻击能力的方法。检测 miss 应用于改进 benchmark 和防御系统，而不能被转化为规避检测的建议。

## 核心主张

### Core Problem

网络安全智能体，在真实防御环境中仍然有效吗？

这里的“有效”是多维概念：它既包括能否完成攻击目标，也包括攻击过程对运行时防御是否可见，以及面对诱骗或环境干扰时能否维持行动。

### Defender-Centric Gap

现有网络安全智能体 benchmark 主要衡量任务完成度，例如 PoC、flag、patch 或最终 objective，但很少衡量攻击过程在真实防御环境中的可见性与可干扰性。对于网络安全业界而言，这留下了一个关键空白：如果前沿智能体进入真实网络环境，基础运行时防御是否仍能观察到关键攻击行为，诱骗和环境噪声是否仍能有效扰动其行动轨迹。

### Key Insight

对防御者、benchmark 设计者和平台方而言，智能体风险不能由单一攻击成功率刻画；更有用的评测对象，是攻击完成度、防御可见性和抗干扰能力的联合画像。只有把这三者同时纳入评测，才能判断前沿智能体在真实防御环境中的实际风险与防御暴露面。

## 证据架构

实验批次不是研究维度，而是实验变量的具体组合。所有实验均在引入 SysArmor 的真实防御环境中运行，因此防御可见性不是某一个批次独有的属性，而是贯穿全部实验的统一观测层。整体证据架构如下：

| 类型 | 内容 | 作用 |
|---|---|---|
| 实验变量 | model、harness、decoy/noise | 解释智能体能力和行为轨迹为何变化 |
| 统一实验底座 | CVELab Stratified-50、明确记录且在对应对照内受控的 budget 与运行协议、SysArmor | 保证每项对照的攻击结果与防御观测来自同一受控环境 |
| 攻击结果 | t1/t2/t3 flag、三旗全通、objective、timeout、失败阶段 | 衡量多层攻击完成度及不同模型系统的能力差异 |
| 防御结果 | attack-window signal 数量、产生新增 signal 的 case 比例、strict expected-signal hit | 衡量智能体行动是否触发基础运行时防御信号 |
| 防御边界 | missing signal 的类别与分布 | 定位最容易未被观测的预期攻击行为，但不直接把 miss 等同于防御盲区 |

在这一架构中，环境有效性、攻击完成度、业务目标、防御可见性和干扰效果必须分别统计。这种“证据解耦”是评测协议的设计原则，而不是一组独立实验。

报告必须为每个数字保留对应的实验配置，不得把不同模型、harness、L1/L2 context 和 decoy/noise arm 直接聚合成一个成功率。Kimi-K3 与 DeepSeek-V4-Pro 的 L2 实验采用相同参数，区别仅为模型，因此用于测量模型能力差异；DeepSeek L1 none/high-decoy 采用配对设计，用于测量当前 decoy 配置的抗干扰效应。

## 结果组织

实验评估章节按四个层层递进的研究问题展开，而不是复述各批次运行过程。

### RQ1：智能体能否完成多层攻击任务，不同模型之间有何差异？

使用三层 flag 获取率作为最直观的能力测量，并同时报告三旗全通、objective、timeout 与失败阶段。在相同参数、相同 harness 和相同 range 下，只改变 Kimi-K3 与 DeepSeek-V4-Pro，以测量模型能力差异。DeepSeek 当前只完成 40/50，因此现阶段比较必须标注为 partial，不能形成最终模型排名。

### RQ2：智能体能力会被系统条件改变多少？

该问题包含两个方向：

- **正向干预：** harness 能带来多大收益。该对照实验目前待补，在当前报告中只能作为研究问题和未来实验设计，不能提前给出结论。
- **负向干预：** decoy/noise 会造成多大扰动。DeepSeek L1 none/high-decoy 配对实验用于比较 flag、objective、timeout、行动耗时与 decoy interaction。

harness 与 decoy 都用于说明智能体能力不是模型常数，但二者作用机制相反，必须分别报告，不能合并为一个效应量。

### RQ3：智能体行动是否会触发防御信号？

SysArmor 是全部实验共有的观测层。原则上应在所有 `model × harness × interference` 实验臂上横向比较：

- 至少产生一个新增 attack-window signal 的 case 比例；
- signal 总量及每 case 分布；
- strict expected-signal hit；
- attack PASS 与 expected-signal hit 的四象限关系。

当前 Kimi-K3 L2 和 DeepSeek L2 watch-window 结果已经提供可比较的 signal accounting。DeepSeek L1 decoy 实验虽然引入了 SysArmor，但现有汇总尚未提供 attack-window signal 与 expected-signal 字段；在这些数据完成导出前，正文不得为该实验臂虚构 detection 数字。

### RQ4：哪些预期攻击行为最容易未被防御观察到？

对 `missing_signal` 进行分布分析，并在数据允许时按 model、harness、攻击完成阶段和 timeout 状态分层，回答哪些 expected rule 最常缺失，以及缺失模式是否随智能体系统和实际轨迹变化。

这一问题应表述为“最容易未被观测的预期攻击行为”，而不是直接宣称“防御盲区”。missing signal 可能来自智能体没有执行对应行为、行为超出 telemetry 边界、规则没有覆盖，或 case-level expectation 对实际轨迹过强。

四个问题形成如下递进关系：

```text
智能体具备多强的攻击完成能力
  -> 这种能力是否随模型和系统条件变化
  -> 行动过程中是否会被基础防御观察到
  -> 防御最容易在哪些预期行为上保持沉默
```

每个小节先提出问题，再明确适用的实验，随后给出证据，并且只得出证据能够支持的结论。

## 必须保留的结论边界

- SysArmor 实验是 detection/observe 实验，而不是 blocking 实验；结果不能证明攻击已被阻止。
- strict expected-signal miss 不能直接证明防御失明。可能是智能体没有执行预期行为、当前 telemetry 未覆盖该行为，或 case-level expectation 对实际轨迹而言过强。
- signal hit 不能证明攻击成功、攻击严重或防御实现了阻断。
- DeepSeek L2 实验只完成 40/50，仅支持阶段性的跨模型观察。
- Kimi-K3 L2 与 DeepSeek L2 的参数保持一致，仅模型不同；当前仍需使用共同完成 case 或明确分母进行比较，不能把 50/50 与 40/50 当成完整排名。
- harness 收益实验尚未完成，当前报告只能定义其问题、指标和所需对照，不能声称已有实验收益。
- DeepSeek L1 decoy 实验引入了 SysArmor，但当前汇总没有 signal accounting；缺少导出指标不能被写成没有 signal，也不能参与 detection hit 的定量横比。
- Kimi-K3/DeepSeek L2 与 DeepSeek L1 decoy 实验的 context 和实验设计不同；它们回答不同问题，不能直接排名。
- 当前 none/high-decoy 两个 arm 的 worker 并行度不同，high arm 还包含 serialization bug 导致的 topology-hint 差异。因此实验测量的是当前 high 配置的整体 operational effect，而不是 container decoy 的独立因果效应。
- 基于 transcript 的 decoy interaction 只是诊断证据，不是 packet-level provenance。
- 当前结果基于一份 manifest 和有限的模型智能体系统，不能建立普遍适用的模型或防御排名。

## 双语一致性

中英文报告必须具有相同的章节结构、主张、表格、实验数量、限制条件和结论强度。英文版应使用自然的科研英语，而不是逐句直译；但任何一版都不得引入另一版没有的证据。

重写应保留当前草稿中有效的技术内容，删除过期的 `39/50` 数字，纳入截至 2026 年 8 月 7 日的实验汇总，并在实验章节中保留各源实验报告的可追溯入口。

## 验收标准

- 摘要以紧凑形式覆盖问题、缺口、挑战、方法、证据、启示和边界。
- 引言优先建立 defender-centric gap 和 key insight。
- 相关工作把 sysfield 定位为对防御证据维度的补充，而不是 offensive leaderboard。
- 方法章节明确说明各系统组件如何解决前文提出的挑战。
- 实验结果按研究问题组织，并为每项结果保留对应的实验配置和分母。
- RQ1 使用分层 flag 与其他攻击结果回答攻击能力和模型差异。
- RQ2 明确区分待补的 harness 收益实验与已有的 decoy 干扰实验。
- RQ3 把 SysArmor 作为全部实验的统一观测层，只报告已完成 signal accounting 的实验臂。
- RQ4 使用 missing-signal 分布分析防御沉默边界，并避免把 miss 直接等同于盲区。
- 任何主张都不得超出上述结论边界。
- 中英文报告在结构、数字和结论强度上保持一致。
