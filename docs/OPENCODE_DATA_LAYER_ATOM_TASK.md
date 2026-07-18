# OpenCode 任务：通用 Data-layer Atom 供给

## 背景与边界

`enterprise_3tier` 已有三条完整 Guided Range anchor：基线 B0、仅替换
DMZ 的 B1、仅替换 app-service 的 B2。当前模板的 `customer-records`
资产、初始化命令和私有验证仍采用 PostgreSQL/5432 与 `psql`，因此旧的
“B3 必须寻找 PostgreSQL/5432 CVE”只是严格单变量对照的临时限制，**不是**
Atom 池或项目的长期要求。

本任务的目的是扩充可被未来通用 data-layer 契约消费的高可信 Atom；不应为了
迎合现有 PostgreSQL 实现，伪造服务元数据或持续投入低价值 PostgreSQL 候选。

本文件只约束 Atom 侧工作。Range 模板、匹配器、资产初始化、业务目标和
Guided 验证由 Codex 负责。

## 工作目标

### A. 建立 data-layer 候选队列

从候选池中筛选真实承担数据存储职责的 Atom，不限制 PostgreSQL 协议。优先：

1. `service_role: database`，具有真实可读写的数据服务；
2. 稳定的 `execute_command`，其次是 `read_file` 或可验证的数据读取；
3. 可自动化的利用路径与可靠启动环境；
4. 与已验证 data-store Atom 存在服务或利用方式差异。

可接受的服务族包括 PostgreSQL、MySQL/MariaDB、Elasticsearch、CouchDB、
Redis 等，但必须如实记录实际协议、端口、认证方式和数据访问方式。`SSH`、
普通 Web 服务或系统服务不能仅因“可存文件”就标为 database。

每个候选须做实时价值评估：预期 capability、自动化稳定性、环境可靠性、
与现有池的多样性价值。跳过“低能力且高调试复杂度”的候选，不重复消耗时间。

交付一份候选表，至少包含：

```text
CVE | service_role | protocol/port | authentication model
expected verified capabilities | expected data operation
MITRE phase | environment risk | automation risk
diversity value | priority | selection/rejection rationale
```

### B. 构建少量高价值 data-layer Atom

在候选表确定后，优先构建 1–3 个最高价值且稳定的 Atom，而不是一次无差别批量
构建。每个完成的 Atom 必须具备：

```text
version: 3
完整且自包含的 source_bundle / manifest
native verification 成功记录
完整 runtime_spec 与 runtime image
runtime smoke 和服务 readiness 成功
verified capability_grants
v2、ready 状态 exploit Guide
```

Guide 必须如实说明：

- 目标服务协议、端口、认证模型；
- 最终成功利用步骤与成功信号；
- 利用后 principal、verified capabilities 和可复用命令通道（如有）；
- 数据读取/写入的实际方式；
- 所需工具与 source_bundle 中的攻击材料。

Guide 不得含真实 flag、原始实验 IP、外部绝对路径、失败尝试或无关探测噪声。

### C. 等待并适配 Codex 发布的 data-layer Range 契约

Codex 会先审计并定义 Range 侧的通用 data-layer 资产/目标契约。**在该契约
发布之前，不要自行新增 Atom schema 字段，也不要修改 matcher、模板或 Range
代码。**

契约发布后，对 A/B 中已完成的 Atom 补充或核对该契约要求的元数据。目标是让
Range 能根据 Atom 声明的真实服务访问方式选择对应的资产初始化与验证 adapter，
而不是将所有 Atom 伪装为 PostgreSQL。

### D. 验收后补充：数据服务语义与数据操作证据

`CVE-2015-1427` 的验收发现两个共享 Atom 构建问题。后续 data-layer Atom 在交接
Range 前必须满足本节；不要通过编辑单个 `atom.yaml` 绕过。

1. **服务语义由共享构建逻辑正确归类。** 当前 `_infer_service_role()` 未把
   Elasticsearch 等真实数据服务识别为 `database`，并且 Agent 自报的
   `web_application` 可覆盖推断结果。应设计并实现基于已解析服务镜像、服务身份与
   端口的通用归类/一致性校验，使确定的数据服务不被错误标为普通 Web 应用。补充
   至少一个 Elasticsearch 与一个既有非数据库 Web 服务的回归测试；Guide 的 target
   service role 必须与最终 Atom 角色一致。

2. **数据操作必须有原生证据。** 不能因 Guide 写有 `SET`、`_search` 或 SQL 命令，
   就宣称 Atom 可承载业务数据资产。对准备进入 data-layer Range 的 Atom，native
   evidence 必须可追溯地证明至少一次目标服务内的数据写入/创建和读取/查询，或在
   候选队列中明确标为“仅服务/RCE 候选，未证明 data operation”。该规则应由共享
   审核或候选准入流程执行，不增加 CVE 特判。

完成后重新生成/审核受影响 Atom 的结构化事实并更新候选队列与
`docs/WORK_PROGRESS_REPORT.md`。在这两项完成前，Atom 只能是
`structure-healthy` research candidate，不得标为 Range `template-candidate`。

## 明确禁止

- 不修改 `templates/enterprise_3tier/template.yaml`；
- 不修改 `src/clab_builder/orchestrator/`；
- 不修改 matcher 或放宽 service-access 规则来接纳不相容的 Atom；
- 不为单个 CVE 写特判；
- 不运行 Range、ContainerLab scenario 或 Guided Agent 实验；
- 不将 `CVE-2018-10933` 等 SSH/22 Atom 伪装成 PostgreSQL data-store。

## 与 Codex 的交接

OpenCode 每交付一个候选或完成 Atom，应提供：

```text
Atom 路径
候选评估/选择理由
source_bundle 完整性结果
native + runtime 验证摘要
runtime image 与 digest
Guide 状态及已知限制
实际协议/端口/认证/数据操作说明
```

Codex 只在 Atom 合约验收后执行：

```text
Range slot preflight
→ environment-only 验证
→ 每个新组合一次 Guided Agent trial
→ 记录环境、攻击图、Agent 和业务目标结果
```

## 完成定义

本任务完成不以某一个 PostgreSQL CVE 找到为条件，而以：

1. 有可追溯的数据服务候选队列；
2. 至少交付一个真实、可复现、高可信的 data-layer Atom；
3. 没有破坏 Atom/Range 职责边界；
4. 已准备好在 Codex 发布通用 data-layer 契约后进行元数据适配。
