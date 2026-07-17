# Atom/Range 修复对齐记录

## 本轮结论

本轮没有修改 Atom 构建流程、Atom 数据文件或任何具体 CVE 的 Guide。只扩展了
Atom/Range 共用的 Guide 数据模型，使后续 Atom 构建可以声明每一步的执行上下文；
`atomizer/pipeline.py`、Atom 输出器和 `data/atoms/*` 均保持不变。

Guide 兼容策略分两级：

- v1 Guide 保留迁移兼容，生成和运行时报告为 `unknown_legacy`，不把未知依赖伪装成通过；
- v2 Guide 的每个步骤必须声明 `execution.scope`、工具类型、材料交付方式，且禁止运行时外部下载。
  Range preflight 在已部署节点检查工具；缺失工具只有在 Guide 明确声明离线材料和
  `channel_transfer` 时才标记为 `repairable`，否则标记为 `incompatible`。

因此，Range 不会为某个 CVE 临时安装依赖或改写命令；它只消费 Atom 声明的可复现契约。
现有 v1 Guide 需要由 Atom 构建侧后续重新生成并审核为 v2，才能进入严格兼容模式。

当前池的只读审计（2026-07-15）显示：236 个 Atom 目录中，43 个 Guide 能通过
现有 v1 结构检查、190 个没有 Guide、3 个因材料引用未使用 `source_bundle/`
前缀而被拒绝；尚未有 v2 Guide 进入池。三组 enterprise_3tier 试点均已成功生成，
但其 Guide 预检状态为 `unknown_legacy`，因此不能被解释为已完成执行环境契约验证。

Range 侧直接消费现有 Atom v3 字段：

- `source_bundle.dockerfiles`：声明需要在 ContainerLab 部署前构建的 Dockerfile；
- `requirements.tools_needed`：Guide 执行时的工具需求；
- `network_requirements`：执行环境的网络需求；
- `exploit_guide.requirements.tools/materials`：Guide 的工具和材料需求；
- `exploit_guide.post_exploit.command_channel`：foothold 的命令通道信息。
- `exploit_guide.steps[].execution`：步骤实际在哪个节点执行、需要哪些工具、材料如何
  进入执行节点，以及是否允许离线转移。

如果后续 Atom 扩充要增加执行上下文，应继续使用上述字段，或在新增字段时保持默认值和 v3 兼容。Range 侧会把这些信息作为执行上下文传给 Agent，不会把它们转换成静态命令模板。

## 本轮修改文件

- `src/clab_builder/orchestrator/composer/cve_matcher.py`
  - 统一服务协议/端口匹配函数，供槽位匹配和资产前置检查共同使用。
- `src/clab_builder/shared/models/template.py`
  - `ScenarioAsset` 增加可选 `required_service_access`，用于声明资产 setup/verify 所依赖的协议和端口。
- `templates/enterprise_3tier/template.yaml`
  - `data-store` 和 `customer-records` 声明 PostgreSQL/5432 契约。
- `src/clab_builder/orchestrator/composer/scenario_assembler.py`
  - 对资产服务契约做通用 preflight；
  - 将 Atom 声明的 Dockerfile 转为 Range runtime build manifest；
  - 生成的目标节点使用构建后的本地镜像。
- `src/clab_builder/orchestrator/composer/verifier.py`
  - 部署前构建 runtime images；
  - Agent 控制网络使用不重叠的小网段并在接入后重新检查攻击路径；
  - 记录 runtime materialization 和 post-transport reachability 结果。
- `src/clab_builder/orchestrator/composer/scenario_runner.py`
  - Agent prompt 不再假设 attacker 是完整 Kali 或拥有外网下载能力；
  - 注入执行主机、工具需求、材料和命令通道上下文。

## 对 opencode 的要求

当前无需回退或同步 Atom 构建代码。新增 Atom 或重建 Guide 时需要确保：

1. `source_bundle.dockerfiles` 路径真实存在且构建上下文完整；
2. `requirements.tools_needed` 只填写 Agent 实际需要的工具；
3. Guide 中的材料、命令通道和能力声明与 Atom 的 verified grants 一致；
4. 不把机器本地绝对路径写入 Guide 或 source bundle 契约。
5. 新 Guide 使用 `version: 2`，每个步骤填写 `execution`；工具使用
   `executable`、`python_module`、`php_extension` 或 `perl_module` 之一。
6. 需要从攻击者/foothold 转移的 PoC 必须声明 `source_bundle/...` 材料和
   `delivery: channel_transfer`，不能依赖 apt、pip、curl 下载或宿主机路径。

Range 侧本轮新增的检查和开关：

- 生成阶段写入 `scenario.yaml.guide_compatibility`；
- 部署后在真实 actor/target 容器中执行只读工具检查；
- CLI 使用 `--strict-guide-compatibility` 时，`incompatible`/`unknown_legacy` 会阻止
  Agent 启动；默认迁移模式仍允许 v1，但结果会保留预检状态；
- `repairable` 只是一份给 Agent 的受控适配计划，不代表已经替工具安装或执行成功。
