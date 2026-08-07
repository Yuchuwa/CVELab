# sysfield：真实防御环境中的网络安全智能体评测

**技术报告草稿**

**状态：** 基于 CVELab × SysArmor 当前实验结果的阶段稿

**日期：** 2026 年 8 月 7 日

## 摘要

网络安全智能体评测正在从静态知识和孤立任务转向真实系统中的连续行动。CyberGym、CyberGym-E2E、ExploitGym 等工作已经能够测量真实代码库中的漏洞复现、完整漏洞生命周期和真实利用效果。然而，这些 benchmark 的主要结果仍是 PoC、patch、flag 或最终 objective。它们能说明智能体完成了什么，却很少说明真实防御在过程中看见了什么，以及环境干扰能否改变智能体的行动。

这给防御者留下了一个关键问题：网络安全智能体在真实防御环境中仍然有效吗？回答这个问题不能只看攻击成功率。攻击成功不等于防御失明，攻击失败也不等于风险不存在。一次失败轨迹仍可能留下高价值运行时信号；一次成功轨迹也可能从一开始就被观察到。

这类评测面临四个困难。真实 CVE 环境异构，难以组成稳定、可判定的多阶段任务；model、harness 和环境会同时影响结果；最终攻击结果与防御可见性相关但不能互相替代；expected signal 未出现时，也不能直接判断防御存在盲区。

为此，我们提出 sysfield。它使用四项直接的技术：通过 **CVE 原子化与多层场景编排**构造可复现网络任务；通过**同场景控制变量对照**分离 model、harness 和环境的影响；将**外部攻击结果验证与运行时行为观测相结合**，分别衡量攻击完成度和防御可见性；通过**预期行为覆盖分析**解释 missing signal。CVELab 提供由真实 CVE 组成的三层 range，外部 verifier 判定分层 flag 和 objective，SysArmor 以 observe-only 方式记录攻击窗口内的运行时 signal。

我们在 Stratified-50 上得到三组阶段性证据。Kimi-K3 L2 完成 50/50 个 case，三层 flag 获取率依次为 22/50、18/50 和 16/50，42/50 个 case 产生新增 signal，28/50 命中全部 expected signal。DeepSeek-V4-Pro L2 当前完成 40/50；在两种模型共同完成的 40 个 case 上，Kimi-K3 的三层结果为 18/40、16/40 和 15/40，DeepSeek 为 19/40、10/40 和 6/40，差异主要出现在入口之后的持续推进。DeepSeek L1 的 none/high 对照中，当前 high 配置使 timeout 从 6/50 增至 19/50，平均运行时间从 1,417.6 秒增至 2,428.5 秒；但该配置同时包含 topology hint 差异，因此只能说明整体运行干扰，不能归因于纯 decoy 效应。

这些结果表明，前沿智能体已经能完成一部分真实多层任务，但能力仍依赖模型和系统条件；基础运行时防御在大量成功与失败轨迹中仍能产生结构化证据；最常缺失的是执行工具联网、workload 网络客户端和 shell/interpreter 行为。当前结论限于有限模型、单次实验、partial run、observe-only 防御和行为规则覆盖范围。sysfield 的意义不是帮助智能体更有效地攻击，而是为防御者、评测者和平台方提供一套更完整的风险证据。

## 1. 引言

### 1.1 领域变化：评测对象正在从模型回答转向系统行动

网络安全任务天然适合检验智能体能力。任务有明确目标，工具会返回真实反馈，结果可以由环境状态验证；同时，它要求模型连续完成理解、规划、工具使用、状态维护和错误恢复。随着模型能力提高，安全评测也从知识问答和 CTF，逐步走向真实代码库、远程目标和长程网络行动。

这次变化改变了评测对象。现在被测量的不是孤立模型，而是 `model × harness × tools × environment × budget` 组成的完整智能体系统。同一个模型使用不同工具、上下文管理和执行框架，可能得到不同结果。一个只写模型名称和最终成功率的 benchmark，已经无法完整解释能力来自哪里。

### 1.2 现有缺口：任务完成度不能回答防御看见了什么

现有工作已经显著提高了真实度。CyberGym 在真实代码库中验证 PoC；CyberGym-E2E 串联 discovery、PoC、patch 和回归测试；ExploitGym 区分漏洞触发和真实攻击效果；Cyber Range 则把多个步骤连接成网络行动。这些工作回答了一个重要问题：智能体能够完成多真实的安全任务？

防御者还需要另一个答案：这些行动在真实防御环境中是否可见，又能否被环境中的诱骗和噪声扰动？最终 flag 无法独立回答这个问题。智能体没有拿到最终目标，可能已经执行了危险行为；智能体完成了目标，也不代表防御没有留下证据。把整条轨迹压缩成 PASS 或 FAIL，会同时丢失攻击过程和防御暴露面。

因此，本文研究的核心问题是：

> **网络安全智能体，在真实防御环境中仍然有效吗？**

这里的“有效”有三个维度：能否完成攻击任务，行动是否对运行时防御可见，以及面对诱骗或环境干扰时能否维持推进。三者需要分别测量，再放在同一 case 上解释。

### 1.3 研究问题

本文围绕四个递进问题展开：

- **RQ1：** 智能体能否完成多层网络任务，不同模型的推进能力有何差异？
- **RQ2：** harness 和环境干扰会在多大程度上改变这种能力？
- **RQ3：** 智能体行动是否会触发基础运行时防御信号？
- **RQ4：** 哪些预期攻击行为最容易未被观察到？

前两个问题测量攻击完成能力及其系统依赖，后两个问题测量防御可见性及其边界。它们共同形成面向防御者的风险画像，而不是一张攻击能力排行榜。

### 1.4 核心洞察与贡献

本文的核心洞察是：**智能体风险不能由单一攻击成功率刻画；防御者需要攻击完成度、防御可见性和抗干扰能力的联合画像。**

基于这一判断，本文作出三项贡献：

1. **一个由真实 CVE 组成的多层评测基座。** CVELab 将异构漏洞封装为可独立部署和验证的 atom，再编排为具有阶段性目标的网络场景。
2. **一套同时保留攻击结果与防御证据的评测方法。** 外部 verifier 判定 flag 和 objective，SysArmor 独立记录运行时 signal，同一 case 上的两类结果分别统计。
3. **一组关于模型差异、防御可见性和环境干扰的阶段性证据。** 实验显示，模型差异主要出现在多层持续推进，运行时信号同时存在于成功和失败轨迹，当前 high-decoy 配置能够显著增加智能体的运行成本。

## 2. 相关工作

### 2.1 网络安全智能体评测的六条路线

网络安全 benchmark 不是沿一条统一难度轴发展。不同工作选择了不同任务起点、终点和判定语义。

| 评测路线 | 代表工作 | 主要技术推进 | 主要终点 |
|---|---|---|---|
| 安全知识与交互式挑战 | CyberSecEval、Cybench、InterCode-CTF [1-3] | 分类型任务集、容器化交互、执行反馈和子任务分解 | 正确答案、子任务或 flag |
| 真实漏洞发现与复现 | CyberGym、SEC-Bench Pro、BountyBench、OSS-Fuzz 类评测 [4-6] | 真实代码库重建、隐藏漏洞制品、补丁前后或跨版本可执行验证 | 漏洞发现、PoC 或 patch |
| 漏洞生命周期与利用形成 | CyberGym-E2E、ExploitBench、ExploitGym [7-9] | 端到端任务串联、能力阶梯、two-stage validation 和 mitigation ablation | 回归验证后的 patch、利用原语或未授权执行 |
| 远程目标与多阶段行动 | AutoPen-Bench、CVE-Bench、WebExploitBench、OpenAI Cyber Range、UK AISI 长程评测 [10-14] | 隔离远程目标、黑盒交互、外部状态验证和阶段进度记录 | 远程目标状态、最深步骤或最终 objective |
| 长时程漏洞研究 | VulnLMP [14] | 多方向并行探索和可复现证据验证 | 多日研究产物或受控利用原语 |
| 自主防御与防御产物 | AIxCC、CTI-REALM [15-16] | 可执行漏洞验证、patch 功能测试、CTI 到检测规则的验证流水线 | 修复后的软件或检测规则 |

这些路线不能用原始成功率直接比较。CTF flag、可差分验证的 PoC、未授权执行、长程 objective 和检测规则是不同研究对象。运行时间更长也不等于覆盖更多网络攻击阶段。

### 2.2 代表性技术如何推进评测边界

CyberGym 解决的是规模化真实漏洞复现。它自动重建历史项目，并用补丁前后 differential testing 判断 PoC 是否真正对应目标漏洞 [4]。SEC-Bench Pro 进一步隐藏原始 PoC、补丁和详细报告，再通过跨版本执行验证开放式漏洞发现 [5]。这些技术提高了真实性和去污染能力，但任务通常终止于发现或复现。

CyberGym-E2E 把 discovery、PoC、patch 和回归测试串成完整生命周期，并用可复现环境和功能测试约束 patch [7]。ExploitBench 用阶段性 checkpoint 区分触发、利用原语和代码执行 [8]。ExploitGym 则通过 execution-based evaluation、two-stage validation 和 mitigation ablation，判断智能体是否把指定漏洞转化为真实攻击效果 [9]。这些工作说明，漏洞触发、完整利用和修复是不同能力层级。

AutoPen-Bench、CVE-Bench、WebExploitBench 和 Cyber Range 将评测推进到远程目标或连续网络行动 [10-14]。它们使用隔离目标、外部状态或阶段进度，减少模型自报带来的不确定性。VulnLMP 从另一方向延长研究时间，但长时程漏洞研究并不自动构成多主机行动链 [14]。

AIxCC 和 CTI-REALM 更接近防御任务：前者考察自主漏洞发现和修复，后者考察从威胁情报生成检测规则 [15-16]。但“智能体能生成防御产物”与“已有防御能否观察攻击智能体”仍是两个问题。

公开的模型 system card 和 Fugu-Cyber 等系统结果还揭示了一个横向事实：网络安全成绩依赖 harness、工具和预算，而不是裸模型常数 [14,16]。METR Time Horizon 可以描述任务时间尺度，但不能替代安全阶段覆盖 [17]。

### 2.3 sysfield 的位置

sysfield 不替代上述 benchmark，也不主张自己的攻击任务更强。它补充一个现有工作较少系统测量的维度：**在同一真实网络 case 中，同时保留攻击完成度、运行时防御可见性和环境干扰证据。**

这个位置决定了本文的立场。受控攻击轨迹只是测量工具，目的是帮助防御者、评测者和平台方理解风险边界。missing signal 用于发现 telemetry、规则或 GT 的不足，不用于总结规避检测的方法。

## 3. 研究挑战

### 3.1 异构 CVE 很难组成稳定的多层任务

真实 CVE 依赖不同 runtime、端口、资产和利用前提。单个漏洞可以复现，不代表多个漏洞能够在同一拓扑中稳定连接。多层 benchmark 还必须保证每一层可达、每个目标可判定，并把环境失败与智能体失败分开。

### 3.2 模型和系统条件的影响容易混在一起

一次运行的结果同时受 model、harness、提示信息、工具、预算、噪声和环境状态影响。如果一个对照同时改变多个条件，结果差异就无法清楚归因。跨 benchmark 的排行榜尤其容易把系统差异误写成模型差异。

### 3.3 攻击完成度和防御可见性需要同时测量

最终 flag 说明攻击走到了哪里，却不说明防御记录了什么。signal 命中说明观察到预期行为，也不说明攻击成功、严重或已经被阻断。两类结果必须在同一运行中对齐，但不能合并成一个分数。

### 3.4 missing signal 不是单一含义

expected signal 没有出现，至少有四种可能：智能体没有执行该行为；行为发生在当前 telemetry 边界之外；规则没有覆盖实际变体；case-level expectation 对实际失败轨迹过强。因此，miss 不能直接写成防御盲区。

## 4. sysfield

### 4.1 方法概览

sysfield 用四项技术分别回答上述挑战。

| 挑战 | 技术 | sysfield 中的实现 |
|---|---|---|
| 异构漏洞难以形成稳定任务 | CVE 原子化与多层场景编排 | 将漏洞封装为可部署、可验证、可复用的 atom，再按拓扑和能力依赖组合成 range |
| 多种系统因素同时变化 | 同场景控制变量对照 | 固定 case、预算和运行协议，每次只改变 model、harness 或 interference 条件 |
| 最终结果不能表示防御可见性 | 外部攻击结果验证与运行时行为观测相结合 | verifier 判定 flag/objective，SysArmor 记录 signal，两类结果按 case 对齐并分别统计 |
| signal miss 难以解释 | 预期行为覆盖分析 | 为 case 定义通用 expected behavior，记录 hit 和 missing rule，再结合实际轨迹解释 |

### 4.2 CVE 原子化与多层场景编排

CVE atom 是 sysfield 的最小漏洞单元。每个 atom 保存可重建的 runtime、服务入口、验证语义和场景编排需要的能力信息。atom 必须能够独立部署和验证，才能进入多层场景。

CVELab 根据 slot 需求和能力依赖组合 atom。本文使用的 `enterprise_3tier` 场景包含三个层级：

| 层级 | 场景角色 | 评测语义 |
|---|---|---|
| target 1 | DMZ 入口服务 | 识别入口、完成初始访问并取得第一层 flag |
| target 2 | 应用或中间服务 | 使用已有访问继续推进并取得第二层 flag |
| target 3 | 数据服务 | 到达最终目标并取得第三层 flag |

每个 case 在正式运行前完成环境验证、攻击图验证和路径可达性验证。模型无法通过自报决定结果；外部 verifier 检查每层 flag 和业务 objective。这样，环境资格、攻击完成度和业务目标可以分别记录。

### 4.3 同场景控制变量对照

sysfield 将实验变量分为 model、harness 和 interference 三类。可靠对照需要固定 case manifest、难度、预算、工具权限和验证协议，再改变一个目标变量。

本文已有两种对照。Kimi-K3 与 DeepSeek-V4-Pro 的 L2 实验使用相同协议，仅模型不同，用于观察模型能力差异。DeepSeek L1 的 none/high 实验使用同一份 50-case manifest、模型、runner、seed 和预算，用于观察当前 high 配置带来的运行干扰。

harness 收益是预先定义的研究问题，但对应实验尚未完成。本文不报告 harness uplift，也不从跨批次结果推断该数值。

### 4.4 外部结果验证与运行时行为观测

sysfield 为同一次运行保留两类独立结果：

- **攻击结果：** t1/t2/t3 flag、三旗全通、objective、timeout 和失败阶段；
- **防御结果：** 攻击窗口 signal、是否产生新增 signal、expected-signal hit 和 missing signal。

SysArmor 在所有实验环境中作为运行时观测层。本文只对已经完成 signal accounting 的 L2 实验报告防御指标。L1 none/high 实验虽然引入了 SysArmor，但当前汇总没有导出可比的攻击窗口 signal 字段，因此不参与 detection 数字比较。

SysArmor 当前是 observe-only。它记录行为，但不阻断攻击。因此，本报告只讨论可见性，不报告阻断率或防护成功率。

### 4.5 预期行为覆盖分析

expected signal 描述通用运行时行为，而不是产品名、CVE 编号、固定 IP、端口或实验私有路径。当前 Stratified-50 主要使用以下规则：

| ruleId | 行为语义 |
|---|---|
| `workload_executes_shell_or_interpreter` | workload 内执行 shell 或解释器 |
| `network_client_used_in_workload` | workload 内使用网络客户端 |
| `execution_tool_opens_network_connection` | 执行类工具发起网络连接 |
| `download_by_lolbin` | 使用常见系统工具执行下载 |

watcher 在攻击开始前就绪，并将 signal 分为 pre-attack、attack-window 和 grace-window。strict expected-signal hit 只计算攻击窗口内新增的 expected rule。这样可以降低 baseline 噪声被误算为攻击证据的风险。

对 miss，sysfield 保留具体 missing rule，而不是只写一个二元失败。这个分析提供的是“预期行为覆盖”，不是对真实行为是否发生的独立证明。

## 5. 评测方法

### 5.1 Stratified-50

Stratified-50 包含 50 个 `enterprise_3tier` case，共使用 24 个唯一 CVE。抽样按入口层和中间层的历史难度分层，覆盖 easy/easy、easy/hard、mid/easy、mid/hard、hard/easy 和 hard/hard 六个组合。历史结果只用于分层抽样，不作为本报告的模型成绩。

每个 case 包含三个 CVE slot 和三个阶段性 flag。数据层目前只包含 3 个 CVE 变体，因此集合并不代表所有企业软件和攻击路径。50 个 case 共享 CVE，也不是 50 个统计独立的漏洞样本。

### 5.2 实验臂

| 实验臂 | 主要变量 | 完成度 | 回答的问题 |
|---|---|---:|---|
| Kimi-K3 L2 + SysArmor | model=`kimi-k3` | 50/50 | 完整多层能力与防御可见性 |
| DeepSeek-V4-Pro L2 + SysArmor | model=`deepseek-v4-pro` | 40/50 | 与 Kimi 相同协议下的阶段性模型比较 |
| DeepSeek-V4-Pro L1 none | interference=`none` | 50/50 | 当前 L1 基线 |
| DeepSeek-V4-Pro L1 high | interference=`high` | 50/50 | 当前 high 配置的运行干扰 |
| Harness 对照 | harness | 未运行 | harness 对能力的增益 |

L2 两个模型臂使用 `openai-compatible` SDK、`openai` runner、L2 context、300 turns、3,600 秒 agent timeout、串行执行和相同 SysArmor detection 设置。DeepSeek 当前缺少 case29-31 和 case44-50，因此跨模型结论以共同完成的 40 个 case 为主。

L1 none/high 两臂使用同一 manifest、DeepSeek-V4-Pro、L1 context、300 turns、3,600 秒 timeout、seed 1 和 temperature 0。none 使用 parallel=8，high 使用 parallel=4；两个 arm 固定按 none 后 high 的顺序运行。high 包含 43 个 decoy，同时存在 data-router topology hint 缺失。这个设计只能测量当前 high 实现的整体效果。

### 5.3 指标

攻击完成度通过 t1/t2/t3 flag、三旗全通、objective、timeout 和失败阶段测量。防御可见性通过至少一个新增 signal、attack-window signal frame 总量、strict expected-signal hit 和 attack/visibility 四象限测量。干扰效果通过 flag、objective、timeout、运行时间和 decoy interaction 测量。

signal frame 数量反映运行时观测量，不等同于独立攻击行为数量，也不直接表示风险严重度。不同模型产生的 frame 总量不用于建立检测能力排行榜。

### 5.4 数据来源

本报告使用截至 2026 年 8 月 7 日已落盘的数据。总体汇总见 [Stratified-50 实验汇总](experiments/stratified50-experiment-summary.zh.md)，逐 case 证据见 [Kimi-K3 watch-window 报告](experiments/sysarmor-cvelab-stratified50-kimi-k3-watch.zh.md)、[DeepSeek L2 partial 报告](experiments/sysarmor-cvelab-stratified50-rerun300-case50.zh.md) 和 [DeepSeek L1 none/high 报告](experiments/2026-08-07-deepseek-l1-none-high.md)。

## 6. 实验结果

### 6.1 RQ1：多层任务能否完成，不同模型有何差异？

Kimi-K3 完成全部 50 个 L2 case，其中 16/50 三旗全通，三层 flag 获取率依次为 22/50、18/50 和 16/50，objective 为 17/50。22/50 个 case 以 timeout 结束。这说明前沿智能体已经能够完成一部分真实多层任务，但连续推进仍不稳定。

DeepSeek-V4-Pro 当前完成 40/50 个 L2 case，其中 6/40 三旗全通，三层 flag 为 19/40、10/40 和 6/40。由于它是 partial run，不能与 Kimi 的 50-case 完整结果直接形成最终排名。

在两种模型共同完成的 40 个 case 上，控制变量比较更清楚：

| 模型 | t1 | t2 | t3 / 三旗全通 |
|---|---:|---:|---:|
| Kimi-K3 L2 | 18/40 | 16/40 | 15/40 |
| DeepSeek-V4-Pro L2 | 19/40 | 10/40 | 6/40 |

两种模型在入口层非常接近，DeepSeek 甚至多完成一个 t1；差异在后续层级扩大。Kimi 从 t1 到 t3 减少 3 个 case，DeepSeek 减少 13 个。这组结果支持一个有限结论：**在当前协议和共同 case 上，模型差异主要体现为入口后的持续推进，而不是初始访问。** 单次运行、模型随机性和 DeepSeek 未完成部分仍然限制了结论强度。

### 6.2 RQ2：系统条件会在多大程度上改变能力？

harness 收益实验尚未完成，因此本文不对其效果作定量结论。已有证据来自 DeepSeek L1 的 none/high 对照。

| 指标 | none | high |
|---|---:|---:|
| 三旗全通 | 2/50 | 0/50 |
| t1 / t2 / t3 | 2/50 / 2/50 / 2/50 | 2/50 / 0/50 / 0/50 |
| objective | 1/50 | 0/50 |
| timeout | 6/50 | 19/50 |
| 平均 agent 时间 | 1,417.6 s | 2,428.5 s |
| 中位 agent 时间 | 1,091.7 s | 2,536.5 s |
| decoy interaction | 不适用 | 50/50 |
| 直接接触 decoy | 不适用 | 38/50 |
| decoy hits | 不适用 | 27,230 |

两个 arm 的环境、攻击图、攻击路径和清理均为 50/50，说明差异不是 range 部署失败。high 配置使平均运行时间增加约 71%，timeout 从 6 增至 19；none 中成功的两个 case 在 high 中都失败，没有出现 high-only success。

但这不是纯 decoy 因果效应。high 同时包含 43 个 decoy、不同 worker 并行度和一处 topology hint 序列化差异。可靠结论是：**当前 high 配置显著增加了 L1 智能体的探索和规划成本。** 要单独估计 decoy 效应，还需要修复 topology hint、统一 parallel 并随机化实验顺序。

### 6.3 RQ3：智能体行动是否会触发防御信号？

答案是肯定的，但 signal 覆盖与攻击完成度并不相同。

Kimi 完整 50-case 结果中，42/50 至少产生一个新增 attack-window signal，28/50 命中全部 expected signal，共记录 23,252 个 attack-window signal frame。DeepSeek 当前 40 个 case 中，30/40 产生新增 signal，14/40 命中全部 expected signal，共记录 9,628 个 frame。

在共同 40 个 case 上：

| 模型 | 三旗全通 | 至少一个新增 signal | strict expected hit |
|---|---:|---:|---:|
| Kimi-K3 L2 | 15/40 | 34/40 | 26/40 |
| DeepSeek-V4-Pro L2 | 6/40 | 30/40 | 14/40 |

即使 DeepSeek 只完成 6 个多层任务，30 个 case 仍产生运行时信号。攻击失败不能被解释为没有安全相关活动。

四象限结果进一步说明两类指标不能互相替代：

| 模型 | 攻击成功 / signal hit | 攻击成功 / signal miss | 攻击失败 / signal hit | 攻击失败 / signal miss |
|---|---:|---:|---:|---:|
| Kimi-K3，共同 40 case | 12 | 3 | 14 | 11 |
| DeepSeek-V4-Pro，已完成 40 case | 3 | 3 | 11 | 23 |

Kimi 有 14 个攻击失败但 expected signal 命中的 case，DeepSeek 有 11 个。另一方面，两种模型都有攻击成功但 signal miss 的 case。前者说明失败轨迹仍会暴露，后者说明攻击成功并不保证当前规则覆盖了预期行为。

这些结果只证明 SysArmor 产生了观察证据。它们不证明攻击被阻止，也不能仅凭 signal hit 数量判断哪种攻击更严重。

### 6.4 RQ4：哪些预期行为最容易未被观察到？

共同 40 个 case 的 missing-rule 分布如下：

| missing rule | Kimi-K3 | DeepSeek-V4-Pro |
|---|---:|---:|
| `execution_tool_opens_network_connection` | 12 | 23 |
| `network_client_used_in_workload` | 9 | 18 |
| `workload_executes_shell_or_interpreter` | 6 | 16 |

两种模型最常缺失的都是执行工具联网，其次是 workload 网络客户端和 shell/interpreter 行为。这给规则和 telemetry 改进提供了优先级，但不能直接得出“DeepSeek 更隐蔽”或“SysArmor 在这些行为上失明”的结论。

原因在于 expected rule 描述 case 可能需要的行为，而不是对实际轨迹的逐动作标注。DeepSeek 更早停止推进时，部分行为可能从未发生；其他 miss 也可能来自规则覆盖或采集边界。下一步需要将 missing rule 与工具调用和 workload 事件逐项对齐，才能区分未执行与未观察。

### 6.5 对核心问题的阶段性回答

网络安全智能体在真实防御环境中仍然具备有效攻击能力，但这种能力不是稳定常数。它随模型和系统条件变化，在多层推进中快速衰减，也会受到当前 high 配置的明显干扰。同时，基础运行时防御并未在智能体面前普遍失去可见性：大量成功和失败轨迹都产生了结构化 signal。

因此，真实风险不能用“智能体成功率”或“检测命中率”中的任何一个单独表示。攻击完成度、防御可见性和抗干扰能力必须共同报告。

## 7. 讨论

### 7.1 对防御者：在最终失陷前使用过程证据

实验中相当一部分失败攻击已经触发 expected signal。防御者不应把“没有完成最终目标”当作没有风险，也不需要等待完整攻击链出现后才评估检测价值。过程信号可以用于更早的调查、关联和响应设计。

但 observe-only 结果不等于防护效果。下一步应在相同协议上加入阻断和响应实验，测量 signal 出现后能否降低后续 flag 获取，而不是从当前数据推断阻断能力。

### 7.2 对 benchmark 设计者：同时保留结果和过程

分层 flag 比单一 PASS 更有解释力，因为它显示智能体停在哪一层。运行时 signal 又补充了“行动是否暴露”。两类信息应该在 case 级对齐，但保持独立字段。将它们压成单一总分会掩盖成功但暴露、失败但危险等关键状态。

benchmark 还应把 model、harness、工具、预算和环境作为正式实验配置。当前共同 40-case 结果表明，模型差异会随任务阶段变化；只报告最终成功率无法看出差异发生在入口还是持续推进。

### 7.3 对平台方：harness 和环境都是风险控制面

智能体能力不仅来自模型。harness 决定状态管理、工具调用和恢复能力，环境决定它能看到什么、被什么吸引以及如何消耗预算。当前 high 配置显著增加 timeout，说明环境设计可以改变智能体的运行成本。

这不意味着 decoy 已经被证明具有普遍防护效果。它说明平台方应把工具权限、网络视图、环境反馈、预算和运行时观测纳入部署评估，而不是只按模型版本设定风险等级。

### 7.4 负责任的评测边界

sysfield 在授权、隔离的 range 内使用已知漏洞，报告聚合结果和防御证据，不提供面向开放网络的战术优化。研究目标与 CyberGym、CyberGym-E2E 和 ExploitGym 的负责任立场一致：真实任务用于测清能力和风险，以支持安全部署、防御规划和修复。

## 8. 局限性

1. **DeepSeek L2 仍是 partial run。** 当前只有 40/50，跨模型观察不是完整排名，也没有重复试验估计随机性。
2. **SysArmor 只做 observe-only 观测。** 本文不能证明 signal 会阻断攻击或改善响应结果。
3. **expected signal 不是逐动作 ground truth。** miss 可能来自行为未发生、telemetry 边界、规则覆盖或 expectation 过强。
4. **L1 与 L2 回答不同问题。** L2 用于模型与可见性分析，L1 none/high 用于当前干扰配置分析，二者不能直接排名。
5. **high 对照存在混杂因素。** 两臂 parallel 不同，顺序固定，high 还包含 topology hint 差异；当前结果不是纯 decoy 因果效应。
6. **decoy interaction 来自 transcript 诊断。** 它不是 packet-level provenance，也不能证明每一次文本命中都对应真实网络访问。
7. **harness 实验尚未完成。** 本文只能定义对照问题，不能给出 harness uplift。
8. **任务覆盖有限。** Stratified-50 复用 24 个 CVE，数据层只有 3 个 CVE 变体，不能代表全部漏洞、网络拓扑和 MITRE ATT&CK 阶段。
9. **signal frame 不是独立行为计数。** frame 总量受轨迹长度和重复行为影响，不能直接解释为攻击数量或风险严重度。

## 9. 结论

前沿网络安全智能体已经能够完成部分真实多层任务，但入口成功并不保证持续推进，模型和环境条件都会改变最终能力。与此同时，基础运行时防御仍能在大量成功与失败轨迹中产生结构化证据，当前 high 配置也能显著增加智能体的运行成本。

这些结果支持一个直接结论：下一代网络安全智能体 benchmark 不能只问“攻击是否成功”。它还必须回答防御何时看见了什么、环境如何改变行动，以及缺失信号究竟意味着什么。

> **攻击成功不等于防御失明，攻击失败也不等于风险不存在。**

sysfield 将攻击完成度、防御可见性和抗干扰能力放入同一个可复现评测体系。它的目标不是提高攻击能力，而是让防御者、评测者和平台方更准确地理解前沿智能体的现实风险边界。

## 参考文献

[1] Meta. [CyberSecEval / Purple Llama Cybersecurity Benchmarks](https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks).

[2] Zhang et al. [Cybench: A Framework for Evaluating Cybersecurity Capabilities and Risks of Language Models](https://arxiv.org/abs/2408.08926). 2024.

[3] Yang et al. [InterCode: Standardizing and Benchmarking Interactive Coding with Execution Feedback](https://arxiv.org/abs/2306.14898). 2023.

[4] Wang et al. [CyberGym: Evaluating AI Agents' Real-World Cybersecurity Capabilities at Scale](https://arxiv.org/abs/2506.02548). 2025.

[5] OpenAI. [SEC-Bench Pro](https://deploymentsafety.openai.com/gpt-5-6/sec-bench-pro). 2026.

[6] [BountyBench: Dollar Impact of AI Agent Attackers and Defenders on Real-World Cybersecurity Systems](https://arxiv.org/abs/2412.19127). 2024.

[7] [CyberGym-E2E: Benchmarking End-to-End Cybersecurity Agents](https://arxiv.org/abs/2606.04460). 2026.

[8] Lee and Brumley. [ExploitBench: A Capability Ladder Benchmark for LLM Cybersecurity Agents](https://arxiv.org/abs/2605.14153). 2026.

[9] Wang et al. [ExploitGym: Can AI Agents Turn Security Vulnerabilities into Real Attacks?](https://arxiv.org/abs/2605.11086). 2026.

[10] [AutoPenBench: Benchmarking Generative Agents for Penetration Testing](https://arxiv.org/abs/2410.03225). 2024.

[11] [CVE-Bench: A Benchmark for AI Agents' Ability to Exploit Real-World Web Application Vulnerabilities](https://arxiv.org/abs/2503.17332). 2025.

[12] AgentCyberRange. [WebExploitBench](https://huggingface.co/datasets/AgentCyberRange/WebExploitBench).

[13] OpenAI. [GPT-5 System Card](https://cdn.openai.com/gpt-5-system-card.pdf). 2025.

[14] OpenAI. [GPT-5.6 System Card](https://deploymentsafety.openai.com/gpt-5-6/). 2026.

[15] DARPA. [AI Cyber Challenge](https://aicyberchallenge.com/).

[16] Sakana AI. [Introducing Fugu-Cyber](https://sakana.ai/fugu-cyber-release/). 2026.

[17] METR. [Time Horizon](https://metr.org/time-horizons/).
