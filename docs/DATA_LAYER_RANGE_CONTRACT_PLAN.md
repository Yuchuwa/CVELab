# Range 通用 Data-layer 契约：阶段一审计与实施设计

## 目标与非目标

目标是在不改变现有 PostgreSQL 基线语义的前提下，使 `enterprise_3tier`
未来能选择不同真实数据库服务的 Atom。Range 应根据 Atom 已声明的服务协议与
端口选择匹配的资产初始化、资产验证和私有目标断言，而不是要求所有 data-store
Atom 伪装成 PostgreSQL/5432。

本设计**不**在本阶段实现“Agent 必须使用 app-db-credential”的资产绑定实验。
该问题需要把凭据写入真实服务认证配置、向 Agent 提供公共任务说明并验证
`assets_used`，应作为后续独立阶段，不能与服务 adapter 改造混在一起。

## 审计结论

### 当前 PostgreSQL 绑定的位置

`templates/enterprise_3tier/template.yaml` 同时固定了：

1. `customer-records.required_service_access = postgres/5432`；
2. `data-store.required_service_access = postgres/5432`；
3. `customer-records` 的 `psql` setup/verify 命令；
4. `read-customer-records` 的私有 `psql` reference command 与 canary。

因此 PostgreSQL Atom 是当前模板的有效候选，SSH/22 Atom 被拒绝也是正确行为。
这种拒绝来自服务语义，不是 Agent、网络或 runtime 的失败。

### 已经通用、无需重写的机制

- `cve_matcher.service_access_matches()` 已在 Atom
  `exploit_access.required_service` 与槽位契约之间执行协议/端口匹配；
- `ScenarioAssembler.validate_asset_bindings()` 会在生成前再次验证资产所需服务；
- `_generate_asset_playbook()` 已经通用地在资产声明的服务容器中执行 setup/verify
  命令；它不包含 PostgreSQL 分支；
- `_compile_objectives()` 已经将私有 `reference_command` / `success_pattern`
  与 Agent 的公共 objective 视图分离；
- `ScenarioVerifier._verify_objectives()` 根据私有 assertion 验证 Agent 返回的
  结构化业务证据。

结论：需要替换的是模板中“一种数据库服务、一组命令”的单一声明，而不是放宽
matcher 或重写部署、网络、Guided Agent 验证流程。

## 最小契约设计

### 1. 引入 template-side `DataServiceAdapter`

一个 adapter 表示“某资产在一种实际服务协议上的可初始化、可验证实现”。它是
模板侧的业务/运维知识，不是 Atom 对漏洞能力的声明。

```yaml
id: postgres-customer-records
service_access: {protocol: postgres, port: 5432}
asset_setup_command: "..."
asset_verify_command: "..."
reference_command: "... {{target_ip}} ..."
success_pattern: "CVELAB-CANARY"
```

最小字段：

| 字段 | 作用 |
|---|---|
| `id` | 稳定 adapter 标识，写入场景元数据供追溯。 |
| `service_access` | 一个精确协议/端口对；不能以独立 protocols/ports 列表造成错误组合。 |
| `asset_setup_command` | 在 data-store 服务容器内创建 canary。 |
| `asset_verify_command` | 确认资产已正确初始化。 |
| `reference_command` | verifier 私有的、从声明 actor 执行的业务断言。 |
| `success_pattern` | verifier 私有的成功判据。 |

adapter 由 `ScenarioAsset` 持有；目标引用该 asset 时自动继承已选择 adapter 的私有
assertion。模板中的 `ObjectiveDef.goal`、`actor_ref`、`evidence_field` 仍是公共
业务描述，不因数据库协议泄漏验证 oracle。

### 2. 匹配与选择规则

Range 在匹配 data-store 前，从引用该 slot 的资产收集 adapter 的精确
`service_access` 对；Atom 只要满足其中任意**一对**即可成为候选。选定 Atom 后：

```text
Atom exploit_access.required_service
→ 唯一匹配的 asset adapter
→ selected adapter 写入 scenario.yaml / ground_truth
→ selected adapter 生成 asset setup / verify
→ selected adapter 提供私有 objective assertion
```

若没有 adapter 匹配、或多 adapter 同时匹配，场景生成必须失败并报告契约冲突；
不得退化为 PostgreSQL 命令，也不得由 Agent 猜测初始化方式。

现有 `InjectionPoint.required_service_access` 保留为单一服务槽位和旧模板兼容字段。
data-layer 多 adapter 的可选集合应由资产 adapter 推导，避免同一协议/端口信息在
slot 与 asset 中重复维护。

### 3. Atom 与 Range 的职责边界

Atom 继续只声明事实：

```text
service_role
exploit_access.required_service (协议/端口)
capability_grants
runtime tool profile
exploit Guide
```

Atom 不声明 `psql`、`mysql`、HTTP 资产初始化命令，也不声明 Range 业务 canary。
这些是模板 adapter 的职责。Guide 中可以描述 Agent 利用漏洞所需的客户端或协议，
但 Guide 仍是建议，不得成为 adapter 选择的硬门。

### 4. data-layer Atom 准入不由 adapter 替代

adapter 只能说明模板如何在一个服务上创建和验证业务资产，不能把普通 Web Atom
“变成”数据服务。进入 data-layer slot 的 Atom 必须先通过 Atom 侧的共享服务语义
分类与数据操作 evidence admission。当前 `CVE-2015-1427` 暴露：Atom pipeline 的
service-role 推断未覆盖 Elasticsearch，且 native evidence 未独立记录索引 CRUD；
在该共享问题修复前，它只能作为 `structure-healthy` research candidate。

Range 不应根据 CVE 名称、镜像字符串或 Guide 文本在运行时补判服务角色。这样既
避免 CVE 特判，也让 Atom/Ranges 的责任边界保持稳定。

## 实施顺序（Codex）

1. 在 `shared/models/template.py` 增加 adapter 的受类型约束模型，并保留旧字段的
   完整 backward compatibility。
2. 修改 `ScenarioAssembler`：根据候选 Atom 的服务契约解析唯一 adapter；将选中
   adapter 作为已解析运行时数据，而不是复制回 Atom。
3. 让资产 setup/verify 和目标私有 assertion 从解析后的 adapter 读取；保留旧
   PostgreSQL 单 adapter 模板的生成产物语义。
4. 在 `scenario.yaml`、`ground_truth.json` 和 match report 记录 adapter ID 与
   service access，供实验追溯。
5. 保持 Agent 输入只包含公共 objective；不复制 `reference_command`、
   `success_pattern` 或任何凭据/flag oracle。

## 必须新增的测试

1. 现有 PostgreSQL `enterprise_3tier` 生成结果不回归；
2. 相同 data-store 槽位可解析两个不同协议/端口 adapter，且只选择与 Atom 精确
   匹配的一项；
3. 无匹配 adapter 时，生成阶段失败且错误说明实际/期望服务契约；
4. setup/verify 使用 selected adapter 的命令，而不是静态 PostgreSQL 命令；
5. 私有 reference command 和 success pattern 不进入 `agent_objectives` 或 Agent
   workspace input；
6. 已选择 adapter 的 ID、服务契约和资产 ID 写入 scenario metadata；
7. legacy 模板中没有 adapter 时继续使用现有 `metadata.setup_command` /
   `metadata.verify_command` 与 `ObjectiveDef` 字段。

## 后续门槛

adapter 改造完成后，才接入 OpenCode 交付的非 PostgreSQL database Atom：

```text
Atom 合约验收
→ adapter 匹配 preflight
→ environment-only
→ 一次 Guided Agent trial
```

`app-db-credential` 对真实服务认证的绑定、Agent 的 `assets_used` 回报和对应私有
验证，另列为 adapter 稳定后的下一阶段；它不是本次服务可插拔改造的前置条件。
