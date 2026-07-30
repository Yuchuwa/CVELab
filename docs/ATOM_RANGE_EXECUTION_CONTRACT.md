# Atom → Range 执行契约

本文档定义 Range 编排消费的 Atom v3 要求。默认 Guided Range 消费
`exploit_guide.yaml`，SysField 仅保留兼容模式。

## 1. Guided Range 的正式产物

`atom.yaml` 通过以下字段引用正式 Guide：

```yaml
exploit_guide:
  path: exploit_guide.yaml
  format_version: 2
  provenance: native_agent
  status: ready
```

Guide 是给攻击 Agent 的结构化参考，必须描述成功利用步骤、前置条件、成功
信号、利用后能力、命令通道和材料。`command_hint` 只用于参考，不保证可以
被 Range exporter 直接替换执行。

Range 生成器会校验步骤依赖、材料清单、原生 IP、绝对路径和 flag 泄漏。这些是
Guide 完整性/安全门槛；状态为 `review_required` 的迁移 Guide 不可进入 Guided
Range。Guide 与 Atom 的 principal、能力、端口、协议或服务角色差异只记录为
诊断，不作为 Range 选择和生成的硬约束。

## 2. SysField 兼容模式

SysField playbook 仍可用于显式兼容验证。正式 step 除 `executor.command` 外，
还应声明：

```yaml
requirements:
  tools: [curl]
  python_modules: []
  materials: [source_bundle/poc.png]
  shell: /bin/sh
```

`requirements` 必须与实际命令一致。Guided Range 不依赖 SysField 的机械命令
替换逻辑。

## 3. Guided 模式的能力和 foothold 契约

`capability_grants` 描述 Atom 原生验证后获得的能力。Guided Range 不再把
`capability_executors.command_template` 当作机械命令替换接口；该字段只保留为
兼容和参考信息。

需要作为上游 foothold 的 Atom，可以在 Guide 中声明可复用的命令通道，供 Agent
理解如何继续行动：

```yaml
post_exploit:
  capabilities: [execute_command, read_file]
  command_channel:
    type: http_request
    established_by: [exploit]
    invocation_hint: "通过已建立的漏洞通道发送后续命令请求"
    reusable: true
```

`reusable: true` 只是经验提示，不是 Range 的正式 pivot 合约。正式的多跳可达性
由模板 `depends_on`、Atom 的 verified `capability_grants`、capability closure
和 ContainerLab 网络隔离共同决定。Guide 没有写 reusable channel 时，只产生
诊断，不会覆盖这些正式事实。

## 4. PoC 材料必须可追溯并可传递

Guide 中引用的每个材料必须存在于 Atom 的 `source_bundle`，并在步骤或
`requirements.materials` 中声明。Guide 的 procedure 必须说明材料是在 attacker
侧使用、内联到 payload，还是通过已建立的命令通道传递。

Atom `source_bundle` 中实际不存在 Guide 引用的材料时，Guide 完整性检查失败。
材料已经存在但没有直接挂载到当前 foothold 时，运行时只记录 transfer/adaptation
诊断，并把信息交给 Agent；这不再阻止 Guided Agent 启动。

## 5. Guide 与 Range 正式事实的优先级

Agent 输入同时包含两类信息：

- **Range authoritative context**：实际 IP/端口、actor、依赖节点、网络路径、
  verified capability、正式工具和材料挂载路径；
- **Guide advisory context**：原生环境中的利用步骤、success signal、命令通道、
  建议工具和 fallback。

二者冲突时，Agent 必须以 Range authoritative context 为准，调整 Guide 中的
地址、端口、编码和执行主机。

## 6. 成功不能只依赖 exit code

每个 exploit step 应至少提供一种真实成功证据：输出匹配、目标文件存在或内容
匹配、目标服务状态变化，或 session/capability 建立确认。

HTTP 客户端返回 `exit_code=0` 只表示请求发送成功，不能单独证明漏洞利用成功。

## 7. Runtime 复验要求

正式 playbook 或 Guide 必须在声明的 shell、工具和 Python 依赖下复验：

- 嵌套 JSON/EL/SOAP payload 必须通过真实 `/bin/sh -c` 执行；
- tools 与命令中的实际程序一致；
- Python 模块名称与安装包名称分别记录；
- 材料路径必须来自 `source_bundle`，不能依赖机器本地绝对路径。

## 8. 验证结果语义

Guided 验证结果必须区分：

- `environment_verified`：ContainerLab、网络、服务和资产初始化正确；
- `attack_graph_valid`：依赖、能力、资产和隔离关系合法；
- `guided_trial_success`：本次 Agent 是否走通攻击路径；
- `objective_achieved`：最终业务目标是否完成。

Agent 成功率是场景难度和攻击能力指标，不单独等价于 Range 质量。

此外，结果中单独记录：

- `guide_integrity.valid`：Guide 是否可安全加载；
- `guide_advisories.overall_status`：Guide 与当前 Range 的工具、材料和语义差异；

`guide_advisories` 不参与 Agent 启动门控。

## 9. Guided Range 业务目标契约

模板中的 `ObjectiveDef` 同时包含 Agent 任务和验证器断言，但两者必须在场景
生成时分成两个视图：

```yaml
objectives:
  - id: read-customer-records
    asset: customer-records
    goal: "通过已建立的 foothold 读取客户记录，并提交读取到的 marker"
    evidence_field: evidence
    verification_mode: agent_evidence
    actor_ref: app-service
    reference_command: "..."   # verifier/SysField only
    success_pattern: "..."     # verifier only
```

`scenario.yaml` 保留完整 assertion，`agent_workspace/input.json` 只能包含
`agent_objectives`：目标 ID、目标描述、目标节点、授权 foothold 和证据字段，不能
包含 `reference_command`、`success_pattern` 或 Ground Truth flag。

Agent 必须按 objective ID 返回结构化证据：

```json
{
  "objective_results": {
    "read-customer-records": {
      "achieved": true,
      "actor_node": "target-2",
      "target_node": "target-3",
      "evidence": "读取到的业务结果",
      "actions": ["..."],
      "failure_reason": ""
    }
  }
}
```

Guided 验证器只在对应 objective 的 `evidence` 字段中匹配私有断言，并检查
actor/target 绑定；不能在整个 Agent JSON 或普通日志中搜索成功模式。没有结构化
objective 结果时，业务目标必须判定为失败。
