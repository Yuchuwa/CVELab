# sysfield：面向真实多层网络靶场的攻防联合智能体评测

**技术报告草稿**
**状态：** 基于 SysArmor × CVELab Stratified-50 防御增强评测协议当前进度的阶段稿
**日期：** 2026 年 8 月 7 日

## 摘要

安全智能体评测正在从“模型知道什么”走向“模型进入系统以后能完成什么”。CyberSecEval、Cybench 和 InterCode-CTF 把安全知识、CTF 与工具交互纳入评测；CyberGym、SEC-Bench Pro、BountyBench 和 CyberGym-E2E 将任务推进到真实开源项目中的漏洞复现、发现和修复；ExploitBench 与 ExploitGym 继续追问从漏洞触发到可执行利用的距离；CVE-Bench、长程 Cyber Range 和 VulnLMP 则把问题推向远程目标、长期探索和多阶段行动。这个谱系共同说明：现代安全评测的对象已经不是孤立模型，而是模型、harness、工具权限、环境、预算和外部验证器组成的行动系统。

sysfield 关注这条谱系中仍然薄弱的一环：当安全智能体在真实多层网络靶场中行动时，我们不仅需要知道它有没有完成最终目标，还需要知道攻击过程是否能被防御系统观察、解释和复核。真实攻防不是只有终局失陷才有意义。一次失败的攻击也可能包含 shell 执行、解释器启动、网络探测、工具下载、横向连接和凭据访问等关键行为；如果评测只记录最终 flag，这些安全证据会被压缩成一个 `FAIL`。

本报告提出并实现一套攻防联合评测口径。CVELab 将真实 CVE atom 组合为可复现的多层网络行动场景，并通过拓扑物化、runtime 准备、资格验证和外部 verifier 保证每个 case 可执行、可判定、可追溯；SysArmor 在 workload 运行时采集行为事件并生成 signal；评估侧把最终目标完成情况与攻击窗口内新增的 expected signal 分开统计。本阶段使用的 CVELab Stratified-50 将多层网络行动具体实例化为三层企业场景，用入口层、应用/中间层和数据层考察智能体的连续推进能力。

截至本文写作时，SysArmor `v0.1.0-rc.5` 防御增强评测协议已完成 39/50 个 case：case1-27 和 case32-43 已完成，case28 正在运行，case29-31 已完成 runtime preparation 并等待串行执行，case44-50 待跑。在已完成的 39 个 case 中，三旗全通为 6/39，strict expected signal hit 为 14/39。阶段性结果显示：多阶段攻击仍然困难，但运行时防御可以在一部分攻击未达成最终目标的场景中留下结构化证据。

本文的核心观点是：下一代安全智能体评测不应只有一条成功率曲线。flag/verifier 衡量攻击链是否完成；attack-window signal 衡量防御系统是否观察到预期攻击行为；当防御没有产生预期 signal 时，missing signal 进一步解释这种“沉默”可能来自 agent 未推进、行为发生在观测边界之外、规则覆盖不足或 GT 过强。只有把这三类证据放在一起，才能解释智能体攻击的真实能力、失败过程和防御可见性。

## 1. 引言

网络安全是前沿智能体能力的高密度观察场。一个安全任务通常有明确目标、真实工具反馈、可验证结果和清楚的失败边界；它要求模型在多轮环境反馈中读代码、跑命令、搜索线索、修正假设，并在预算耗尽前交付外部可验证的结果。相比静态问答，这更接近真实世界中的长期行动。

现有安全智能体评测已经证明，模型可以在真实代码库、漏洞环境和远程目标中完成越来越长的行动链。但这类评测大多仍以最终产物作为核心 oracle，例如 PoC 是否触发、patch 是否通过、flag 是否取得或最终目标是否完成。这个设计对衡量攻击能力是必要的，却不足以回答防御问题。真实世界里，防御系统并不等到攻击者拿完所有 flag 才开始工作；它要在过程中识别行为、产生证据、解释阶段，并尽量在最终失陷前暴露风险。

sysfield 因此把问题推进一步：在多层网络行动中，攻击结果和防御观测应该同时成为评测对象。攻击是否成功是一条线；防御是否看见了攻击行为是另一条线；防御为什么沉默是第三条线。三条线共同决定这个实验对安全研究是否有解释力。

本报告围绕四个研究问题组织。

1. **安全智能体能否稳定完成多阶段攻击？**
   我们考察 agent 是否能从入口目标持续推进到后续层级，并由外部 verifier 确认各阶段 flag。这里的重点不是单个漏洞是否存在，而是模型能否把发现、利用、验证和横向推进串成稳定行动链。

2. **运行时防御系统能否产生可解释 signal？**
   我们不只问“有没有日志”，而是要求 SysArmor 将 workload 内的关键进程、网络和执行行为归纳为有语义的 signal，并能够导出到逐 case 证据文件。

3. **攻击未完成最终目标时，是否仍然有足够检测证据？**
   这一区分非常重要。攻击失败不等于安全无事发生。agent 没拿齐 flag 时，仍可能已经执行过 shell、解释器、网络客户端或可疑连接。我们因此把 attack PASS 与 expected signal hit 分开统计。

4. **当防御系统沉默时，这种沉默意味着什么？**
   检测评估不能止于 hit/miss。对每个 miss，我们记录缺失的 expected ruleId，用于分析沉默究竟来自 agent 未推进、规则覆盖不足、采集链路盲区，还是 GT 对失败轨迹要求过强。

围绕这些问题，本文的阶段性贡献如下。

**第一，构建以 CVELab 为核心的多层网络行动评测基座。** CVELab 将真实 CVE atom 组合成可复现的多层企业靶场，并用拓扑物化、runtime 准备、资格验证、flag 和外部 verifier 保证每个 case 可执行、可判定、可追溯。CVELab Stratified-50 从可组合场景空间中抽取 50 个代表性 case，使 sysfield 能够在有限预算下评估从入口利用到横向推进再到最终目标的连续行动。

**第二，提出攻防联合的双 oracle 评测范式。** sysfield 将攻击智能体、多层 CVE 靶场、外部 verifier 与运行时防御观测放入同一个实验闭环，并显式区分 attack oracle 与 defense oracle。前者回答攻击链是否完成，后者回答攻击过程是否被防御系统观察到。这个设计避免把防御可见性简化为攻击成功率的副产品，使“攻击能力”和“防御证据”能够被并列评估。

**第三，设计面向迁移性的行为化检测 GT。** 本报告将 expected signal 定义为通用运行时行为，而不是绑定具体产品、CVE、IP、端口、flag 路径或实验私有目录。规则关注 shell/interpreter 执行、workload 内网络客户端使用、执行工具发起网络连接等跨场景行为。这样得到的指标更保守，但更能衡量防御系统是否捕捉到可迁移的攻击语义，而不是记住某个靶场的表面特征。

**第四，引入攻击窗口归因的 signal 评估口径。** 为避免静态 before/after 快照把 baseline 噪声误计为攻击命中，sysfield 将观测过程划分为 watcher ready、attack window 与 grace window，并要求 expected ruleId 必须作为攻击窗口内的新增 signal 出现。这个设计把检测结论绑定到真实攻击时段，使 signal 命中能够被解释为“攻击期间发生的防御证据”，而不是运行前后状态差异。

**第五，把“防御沉默”转化为可解释的研究对象。** 在传统成功率口径中，一个未命中的 case 往往只留下一个 ❌：攻击没有被检测到。但在真实防御中，沉默并不是一种单一状态。它可能意味着 agent 根本没有推进到危险行为，也可能意味着攻击行为发生在观测边界之外，可能是规则没有覆盖，也可能是 expected GT 对这条失败轨迹要求过强。sysfield 因此不只记录 hit/miss，而是保存每个 case 缺失的 expected ruleId，把“没有 signal”进一步拆解为可追问、可定位、可改进的检测盲区。这样，失败 case 不再只是分母里的损失，而成为理解防御边界的入口。

## 2. 背景与相关工作

现有 benchmark 已经沿着几条路线推进。

| 路线 | 代表工作 | 主要问题 |
|---|---|---|
| 安全知识与交互式挑战 | CyberSecEval、Cybench、InterCode-CTF | 模型是否具备安全知识，能否在工具环境中解决 CTF/安全任务 |
| 漏洞复现与发现 | CyberGym、SEC-Bench Pro、BountyBench | 模型能否在真实代码库中定位漏洞并生成可验证 PoC |
| 端到端漏洞生命周期 | CyberGym-E2E | 模型能否完成发现、PoC、补丁和回归测试的连续流程 |
| 利用形成 | ExploitBench、ExploitGym | 模型能否从漏洞触发走向利用原语、代码执行或 flag 获取 |
| 远程目标与长程行动 | CVE-Bench、Cyber Range、VulnLMP | 模型能否在远程或长期环境中完成探索、利用和多阶段推进 |

这些工作各自解决了关键问题。CyberGym 强调真实项目和规模化漏洞复现；CyberGym-E2E 把漏洞生命周期串起来；ExploitBench 细分利用能力标志；ExploitGym 把“能触发 bug”推进到“能完成攻击”；Cyber Range 和 CVE-Bench 则让智能体面对更像真实部署的远程环境。它们共同把安全评测从纸面知识推向可执行行动。

与这些工作相比，sysfield 不试图替代漏洞生命周期或 exploit 评测，而是补上防御观测这一维度。它关注 agent 在多层网络行动中的过程证据：攻击链是否完成、攻击期间是否出现语义化运行时信号、以及防御没有产生预期信号时这种沉默如何解释。

## 3. CVELab 基准构造

CyberGym-E2E 的核心结构是先说明 benchmark 如何从真实漏洞数据构造出来，再说明 agent 如何被评估。sysfield 采用相同思路：CVELab 不是一个临时实验目录，而是将真实 CVE atom 转化为多层网络行动 case 的基准构造层；SysArmor defended run 是在这个基准之上的防御观测扩展。

### 3.1 术语与设计目标

本文使用四个固定术语。

| 术语 | 含义 |
|---|---|
| CVE atom | 一个可部署、可验证的漏洞服务单元，包含 runtime、服务入口、exploit guide、验证语义和必要资产 |
| range case | 由多个 CVE atom 组合出的多层网络行动场景，包含拓扑、目标、flag 和 verifier |
| CVELab Stratified-50 | 从 CVELab 可组合场景空间中抽样得到的 50 个正式 case，用于报告级实验 |
| 防御增强评测协议 | 当前报告级 defended protocol：L2、`--max-turns 300`、`--agent-timeout 3600`、SysArmor detection 与攻击窗口 signal 口径 |

CVELab 的设计目标是：真实、可复现、可判定、可分层。真实意味着 case 来自真实 CVE atom，而不是纯合成题；可复现意味着 runtime、拓扑和资产可以重新物化；可判定意味着结果由外部 verifier 和 flag 判断，而不是模型自报；可分层意味着同一场景包含入口、中间和数据目标，可以观察 agent 是否能从初始访问推进到后续目标。

### 3.2 从 CVE atom 到 Stratified-50

CVELab 的场景构造从 CVE atom 开始。每个 atom 需要至少满足三类条件：服务能够在受控 runtime 中启动，漏洞入口能够被网络访问或业务流程触达，验证器能够判定目标是否完成。通过这些 atom，CVELab 进一步生成 enterprise-style 多层组合。

本阶段的 Stratified-50 具体采用三层实例：

| 层级 | CVELab slot | 评测作用 |
|---|---|---|
| 入口层 | `dmz-web` | 考察初始识别、入口利用和第一阶段 flag |
| 应用/中间层 | `app-service` | 考察继续利用、凭据使用、横向推进或业务链路 |
| 数据层 | `data-store` | 考察最终目标访问、数据读取和第三阶段 flag |

`CVELab/data/stratified_50_ranges.json` 记录了 50 个 case。每个 case 包含 `id`、三个 CVE、`slot_atoms`、`service_families` 和 `asset_variants`。当前 50 个 case 覆盖 24 个唯一 CVE，并统一使用 `dmz-web`、`app-service`、`data-store` 三个 slot。Stratified-50 的目的不是穷尽所有组合，而是在有限实验预算下覆盖不同入口漏洞、中间阶段和数据层后端，避免只评估少数易利用路径。

### 3.3 Qualification 与正式运行

CVELab 将环境资格验证和 agent trial 分开。qualification run 只验证 runtime 物化、服务就绪、网络连通和 verifier 条件；agent trial 必须引用冻结的 parent qualification run。这个设计把 infrastructure failure 与 agent failure 分离，避免把镜像缺失、服务未启动或拓扑错误误计为模型攻击失败。

每次正式运行写入不可变 `run_manifest.json`，记录 case manifest hash、selected case IDs、git commit、dirty marker、agent context、runner、model label 和精确 batch command；`case_index.json` 则作为可刷新索引，记录 qualification outcome 与 agent outcome。这个 manifest 层是防御增强评测协议能够被追溯和复核的基础。

## 4. 任务格式与攻防联合评测协议

在 CVELab 构造的 range case 之上，sysfield 定义攻防联合评测协议。该协议的目标不是把防御观测混入攻击成功率，而是并行保留 attack oracle、defense oracle 和 defensive silence evidence。

### 4.1 攻防联合实验闭环

一次 defended run 包含五个角色：

| 角色 | 职责 |
|---|---|
| CVELab range | 生成多层网络拓扑、目标服务、漏洞组合和 flag |
| 攻击智能体 | 在授权靶场内使用工具探索、利用、验证和推进 |
| Verifier | 独立判定 target-1/2/3 flag 或业务目标是否真实命中 |
| SysArmor | 在目标 workload 内以 observe 模式采集运行时事件并生成 signal |
| Exporter | 导出攻击窗口 signal，并按 expected ruleId 评估命中和缺失 |

攻击侧和检测侧共享同一次运行，但互不泄漏答案。模型看不到 flag、verifier 输出或 SysArmor signal；检测评估也不依赖模型声称自己做了什么。

### 4.2 攻击窗口归因

当前协议显式定义 signal 生命周期：

```text
watcher ready
    -> attack start
    -> agent attack
    -> attack finish
    -> grace window
    -> watcher stop
```

对应统计字段为：

| 字段 | 含义 |
|---|---|
| `pre_attack_count` | attack start 之前采到的 signal frame |
| `attack_window_count` | attack start 到 attack finish 之间采到的 signal frame |
| `grace_window_count` | attack finish 后 grace window 内采到的 signal frame |
| `new_attack_signal_count` | 相对 pre-attack 新增的攻击窗口 signal frame |
| `expected_signal_hit` | expected ruleId 是否全部出现在新增攻击窗口 signal 中 |
| `missing_signal` | 未在新增攻击窗口 signal 中出现的 expected ruleId |

这个设计把检测 oracle 绑定到实际攻击期间，避免 baseline 噪声污染结论。当前已完成的 39 个 case 中，`pre_attack_count` 均为 0，说明 watcher ready 后进入攻击窗口的流程符合预期。

### 4.3 行为化检测 oracle

expected signal 是 case-level GT。每个 case 的 expected ruleId 来自其漏洞组合与预期攻击路径的行为 union，但标签只使用通用行为语义。目前主要包含：

| ruleId | 语义 |
|---|---|
| `workload_executes_shell_or_interpreter` | workload 内执行 shell 或解释器 |
| `network_client_used_in_workload` | workload 内使用 curl、wget、nc、python 等网络客户端 |
| `execution_tool_opens_network_connection` | 执行类工具发起网络连接 |

我们刻意不加入 product-specific、CVE-specific 或 magic-path 规则。规则如果写成“访问 Elasticsearch”“读取 `/flag`”或“命中 `/opt/cvelab/**`”，短期命中率可能更好，但它证明的是靶场记忆，不是防御系统观察到了可迁移攻击行为。

## 5. 实验评估

### 5.1 实验设置

本阶段使用防御增强评测协议，固定条件如下：

| 项目 | 设置 |
|---|---|
| 靶场 | CVELab Stratified-50 |
| 场景形态 | 多层网络靶场；本阶段实例为三层企业场景 |
| 防御组件 | SysArmor `v0.1.0-rc.5` |
| 传感器 | Tetragon backend，container scope |
| Runner / SDK | `openai-compatible` |
| 模型 | `deepseek-v4-pro` |
| 难度 | L2 |
| 最大轮数 | `--max-turns 300` |
| Agent 超时 | `--agent-timeout 3600` |
| 并行度 | `--parallel 1` |
| 防御模式 | `--sysarmor --sysarmor-detection` |

固定串行运行是本轮的重要实验约束。此前调试显示，同一宿主机并发多个 defended case 时，多个 Tetragon 实例可能共享 `/sys/fs/bpf/tetragon/*`，触发 BPF pinned map、health check 或 signal 归因竞态。为了让每个 signal 都能明确归属到对应 case，本轮牺牲吞吐量，优先保证证据干净。

完整逐 case 表见 `reports/experiments/sysarmor-cvelab-stratified50-rerun300-case50.zh.md`。

### 5.2 当前结果

截至 2026 年 8 月 7 日 10:07 CST，防御增强评测协议进度如下：

| 范围 | 状态 |
|---|---|
| case1-27 | completed |
| case28 | running |
| case29-31 | runtime prepared |
| case32-43 | completed |
| case44-50 | pending |

已完成 39 个 case 的汇总结果：

| 指标 | 结果 |
|---|---:|
| 已完成 case | 39/50 |
| 三旗全通 | 6/39 |
| 攻击 FAIL | 33/39 |
| expected signal hit | 14/39 |
| pre-attack signal 非零 case | 0/39 |

三旗全通的 case 为：case4、case5、case6、case7、case35、case40。

### 5.3 RQ1：多阶段攻击仍然不稳定

当前结果显示，agent 能够在部分场景中建立入口能力，但稳定推进到后续层级仍然困难。6/39 的三旗全通率不表示失败 case 没有攻击行为；它说明从入口利用到中间层、数据层的连续行动仍然是主要瓶颈。

日志中常见失败模式包括：入口服务识别后无法收敛到有效 PoC，拿到局部访问但未能结构化提交 flag，横向网络不可达，工具缺失，WebSearch/WebFetch 返回空，以及长时间探索后超时。这与 CyberGym-E2E、ExploitBench 和 ExploitGym 的共同趋势一致：任务越接近端到端，瓶颈越从单点漏洞知识转移到发现、串联、验证和预算管理。

### 5.4 RQ2/RQ3：攻击失败仍可能被防御观察

检测结果必须与攻击结果分开读。在 39 个已完成 case 中，14 个 case 的 expected ruleId 在攻击窗口新增 signal 中被覆盖。也就是说，即使多数 case 没有完成全部 flag，SysArmor 仍能在一部分失败攻击中观察到预期行为。

这个结果的价值不在于声称“检测率已经高”，而在于建立了一个可复核的检测 oracle。每个命中都可以追溯到具体 signal frame、ruleId、target 和攻击窗口。它让我们可以区分四类结果：

| 情况 | 解释 |
|---|---|
| 攻击成功且 signal 命中 | 攻击链完成，防御侧观察到预期行为 |
| 攻击成功但 signal 未命中 | 攻击达成目标，但当前规则或采集链路漏掉了预期行为 |
| 攻击失败但 signal 命中 | 最终目标未完成，但攻击过程已经产生可解释证据 |
| 攻击失败且 signal 未命中 | 可能未触发预期行为，也可能检测覆盖不足 |

第三种情况尤其重要。它说明安全智能体评测不能把失败攻击简单丢弃；这些失败轨迹恰恰可能包含防御系统需要学习和解释的中间行为。

### 5.5 RQ4：解释防御为什么沉默

对于未命中的 case，我们记录 `missing_signal`，而不是只给一个 ❌。当前未命中的 ruleId 主要集中在：

| missing ruleId | 可能解释 |
|---|---|
| `execution_tool_opens_network_connection` | agent 没有在 workload 内触发执行工具联网，或该行为没有被当前规则捕捉 |
| `network_client_used_in_workload` | 网络客户端行为可能发生在 attacker 容器、外部环境或未覆盖进程中 |
| `workload_executes_shell_or_interpreter` | 攻击路径可能没有进入 workload 执行，或 shell/interpreter 规则覆盖不足 |

这些 missing signal 是下一轮规则设计和传感器验证的入口。更重要的是，它们让“没有告警”变得可以解释：未命中究竟是 agent 没做到、规则没有覆盖、采集链路没有看到，还是 expected GT 对该 case 的失败路径要求过强。这样，防御沉默不再是一个黑盒结果，而是一组可以继续追问的假设。

### 5.6 评测系统本身是研究对象

本轮实验暴露的工程问题不是背景噪声，而是真实安全智能体评测的一部分。我们需要处理 SysArmor 版本一致性、Tetragon container ID 匹配、非 root 镜像注入、runtime 资产缺失、agent finalization、Web 工具返回空、日志与 verifier 不一致，以及 watcher 采集窗口定义。这些问题共同说明：真实评测的可信度来自协议冻结、证据保存和失败归因，而不是只运行一个 benchmark 脚本。

## 6. 讨论

### 6.1 为什么不是只报告 flag？

flag 是攻击成功 oracle，但不是防御 oracle。一个 agent 没有拿齐 flag，仍然可能执行过 shell、发起网络连接、读取敏感文件或触发反连模式。如果评测只报告 `PASS/FAIL`，这些行为会消失。对防御研究而言，这些中间行为往往比最终 flag 更接近真实告警场景。

sysfield 因此把攻击能力、防御可观测性和防御沉默拆成三条曲线。攻击曲线衡量 agent 能否完成目标；检测曲线衡量防御能否在过程中产生语义化证据；missing-signal 曲线解释当前规则体系和观测边界在哪里保持沉默。

### 6.2 为什么 GT 必须行为化？

靶场评测很容易过拟合。如果规则绑定 `/flag`、固定路径、产品名或 CVE 编号，就会得到漂亮但不可迁移的结果。我们当前使用通用行为 ruleId，牺牲了一部分短期命中率，但保留了向其他靶场和真实 workload 迁移的可能性。

一个较低但干净的 expected signal hit，比一个依赖 magic path 的高命中率更有研究价值。这是本文的 taste 选择：指标不只是要好看，更要能说明问题。

### 6.3 裸 harness 对照是下一步关键

当前 defended 结果不能直接回答 SysArmor 是否改变了攻击成功率。SysArmor 可能引入额外开销、改变 timing、影响服务稳定性，也可能几乎不影响攻击过程。要回答这个问题，必须用相同 case、模型、runner、prompt、预算和 verifier 跑 bare harness，并与 defended harness 做配对比较。

下一阶段建议报告两类效应：

| 维度 | 指标 |
|---|---|
| 攻击侧效应 | 三旗全通率、t1/t2/t3 flag、终止原因、时间、工具调用 |
| 防御侧效应 | attack-window signal、expected signal、missing signal、ruleId 分布 |

只有配对实验完成后，才能严谨讨论“裸 harness + SysArmor 之间效果差别”。

## 7. 局限性

当前报告是阶段稿，结果尚未覆盖完整 case1-50。case28 正在运行，case29-31 已完成 runtime preparation 并等待串行执行，case44-50 待跑，因此本文的定量结果以 39 个 completed case 为分母。

第二，本轮只覆盖一个模型、一个 runner、一个难度等级和一个 defended 配置。结果不能外推到其他模型、Claude Code runner、L0/L1、更多预算或裸 harness。

第三，expected signal GT 仍然是人工设计的行为标签。它避免了产品和路径耦合，但仍可能漏掉某些真实攻击行为，也可能要求了 agent 在具体失败路径中没有实际执行的动作。

第四，SysArmor 当前以 observe 模式评估可观测性，不评估阻断、处置或对抗规避能力。

## 8. 结论与未来工作

我们预计安全智能体评测会沿三条线发展。

第一，任务会从单点漏洞转向长程行动。CyberGym、CyberGym-E2E、ExploitBench 和 ExploitGym 已经展示了从复现、修复到利用的能力阶梯；CVE-Bench、Cyber Range 和多层靶场会继续把问题推进到凭据、横向移动、业务目标和长期状态管理。

第二，评测对象会从模型转向系统。模型、harness、工具权限、知识包、预算、网络出口和验证器都会显著影响结果。未来报告如果只写模型名和成功率，会越来越难解释。

第三，防御评测会从日志存在性转向语义化 signal。更有价值的不是“有没有事件”，而是事件能否映射到攻击阶段、进程链、网络行为和可迁移的检测规则，并在最终失陷之前给出证据。

sysfield 的定位正是在这三条线的交点：真实多层网络行动、可控智能体系统、以及运行时防御证据。

## 9. 复现材料

主要实验表：

- `CVELab/reports/experiments/sysarmor-cvelab-stratified50-rerun300-case50.zh.md`

当前 GT 与导出脚本：

- `CVELab/data/experiments/stratified-50/sysarmor-case0/expected-signals-case1-50.json`
- `CVELab/scripts/export_sysarmor_signals.py`

关键运行目录：

- `CVELab/data/experiments/stratified-50/runs/trial-sysarmor-rc5-general-case1-10-l2-20260804-a/`
- `CVELab/data/experiments/stratified-50/runs/trial-sysarmor-rc5-general-case11-20-l2-20260805-b/`
- `CVELab/data/experiments/stratified-50/runs/trial-sysarmor-rc5-general-case18-50-l2-20260806-e/`
- `CVELab/data/experiments/stratified-50/runs/trial-sysarmor-rc5-general-case32-50-l2-20260806-g/`
- `CVELab/data/experiments/stratified-50/runs/trial-sysarmor-rc5-general-case28-31-l2-20260807-h/`

## 参考资料

[1] CyberGym: Evaluating AI Agents' Real-World Cybersecurity Capabilities at Scale. Local archive: `.archive/paper/cybetgym.md`.

[2] CyberGym-E2E: Scalable Real-World Benchmark for AI Agents' End-to-End Cybersecurity Capabilities. Local archive: `.archive/paper/cybergym-e2e-paper.md` and `.archive/paper/cybetgym-e2e.md`.

[3] ExploitGym: Can AI Agents Turn Security Vulnerabilities into Real Attacks? Local archive: `.archive/paper/exploitgym.md`.

[4] Related benchmarks discussed in CyberGym-E2E and prior sysfield notes: CyberSecEval, Cybench, InterCode-CTF, ExploitBench, CVE-Bench, SEC-Bench Pro, BountyBench, VulnLMP, and long-horizon Cyber Range evaluations.

[5] SysArmor × CVELab Stratified-50 防御增强评测表. `CVELab/reports/experiments/sysarmor-cvelab-stratified50-rerun300-case50.zh.md`.
