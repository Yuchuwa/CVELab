# CVELab RangeFactory 工作进展

## 1. 与 AgentCyberRange 的关系

[AgentCyberRange](https://arxiv.org/abs/2606.14295) 主要面向在多主机、真实服务环境中评估 Agent 的自主攻击能力，提供攻击执行、环境编排、结果收集和评估能力。

CVELab 的定位更偏向“攻击场景生产系统”：它把单个 CVE 转换为可复用的攻击 Atom，再组合成可部署、可验证的 ContainerLab Range。因此，两者可以形成上下游关系：

```text
CVELab：生成和验证 Range
        ↓
AgentCyberRange / SysField：执行 Agent 攻击并评估能力
```

## 2. CVELab 的额外贡献与优势

相比只提供执行和评估环境，CVELab 增加了以下能力：

1. **CVE 原子化**：通过 Agent 从 Vulhub/CVE 环境中提取运行时配置、服务信息、漏洞利用步骤、PoC 材料、目标验证方式、攻击前置条件和利用后能力。
2. **可复用 Atom 池**：每个 CVE 被标准化为可组合的 Atom，可根据资产角色、服务、攻击前置条件和攻击能力复用于不同 Range。
3. **模板化场景编排**：通过 `enterprise_3tier` 等模板定义 DMZ、业务服务、数据服务等槽位，再生成 ContainerLab 拓扑和多阶段攻击路径。
4. **确定性的参考攻击路径**：每个 Range 生成 SysField playbook，用于证明环境、Atom 插入、攻击步骤和最终目标均可执行。Agent 成功率只作为能力指标，不作为 Range 正确性的唯一标准。
5. **全链路可追溯**：Range 中每个步骤可以追溯到 Atom、模板槽位、注入点、执行节点、能力依赖、PoC 材料和执行结果。

## 3. Atom 模型中的关键字段

### 3.1 `exploit_access`：攻击前置条件

`exploit_access` 描述“利用漏洞之前需要具备什么访问条件”：

```yaml
exploit_access:
  attack_vector: network
  privileges_required: none
  required_service:
    protocol: http
    port: 80
```

字段含义：

- `attack_vector`：攻击向量，例如 `network`、`local`；
- `privileges_required`：利用前所需权限，例如 `none`、`user`、`root`；
- `required_service`：依赖的服务信息，通常包括协议和端口，用于与模板资产匹配。

它回答的是：攻击者能否到达目标服务、目标服务是否满足协议和端口要求、利用前是否需要已有权限。

### 3.2 `capability_grants`：利用后的能力

`capability_grants` 描述“漏洞利用成功后攻击者能够做什么”：

```yaml
capability_grants:
  - type: execute_command
    principal: service_user
    evidence_level: verified
    evidence_ref: native_replay
```

每条授权包括：

- `type`：能力类型，目前包括 `execute_command`、`read_file`、`write_file`、`network_vantage`、`read_credential`、`authenticate`；
- `principal`：能力所属身份，例如 `service_user`；
- `evidence_level`：`verified`、`inferred` 或 `declared`；
- `evidence_ref`：能力证据来源，例如 native replay 记录。

两者不能互相替代：

```text
exploit_access    = 利用前能否进入
capability_grants = 利用后能做什么
```

例如，一个 Web RCE Atom 可能要求网络访问 HTTP/80，并在成功后授予 `execute_command` 和 `read_file` 能力。前者决定它能否作为入口，后者决定它能否支撑后续阶段。

## 4. 当前 Atom 池统计

以下数字为当前直接扫描 `data/atoms/*/atom.yaml` 的结果：

| 项目 | 数量 |
|---|---:|
| Atom 目录 | 279 |
| 含 `atom.yaml` 的 Atom | 236 |
| v2 Atom | 199 |
| v3 Atom | 37 |
| `verified=true` | 113 |
| `verified=false` | 123 |
| verified v2 | 78 |
| verified v3 | 35 |

`data/atom_pool_status.*` 台账仍记录 109 个 verified Atom，与当前文件实际统计的 113 个不一致，后续需要同步台账。

### 4.1 按 MITRE 阶段

在 113 个 verified Atom 中：

| 阶段 | 数量 |
|---|---:|
| `initial_access` | 105 |
| `execution` | 6 |
| `credential_access` | 2 |

### 4.2 按服务角色

| 服务角色 | 数量 |
|---|---:|
| `web_application` | 91 |
| `middleware` | 15 |
| `database` | 4 |
| `system_service` | 2 |
| `file_service` | 1 |

### 4.3 按漏洞类别

| 漏洞类别 | 数量 |
|---|---:|
| RCE | 84 |
| LFI | 22 |
| Auth Bypass | 2 |
| Deserialization | 2 |
| Info Leak | 1 |
| SSRF | 1 |
| Injection | 1 |

### 4.4 按 `exploit_access`

113 个 verified Atom 当前全部是 `attack_vector: network`，且全部是 `privileges_required: none`。

只有 8 个 Atom 明确填写了协议和端口：

| 协议/端口 | 数量 |
|---|---:|
| HTTP/80 | 3 |
| HTTP/8080 | 1 |
| HTTP/7001 | 1 |
| HTTP/9200 | 1 |
| TCP/9000 | 1 |
| PostgreSQL/5432 | 1 |
| SSH/22 | 1 |

这说明当前 Atom 池的访问前置条件还不够完整，很多 Atom 只有“网络可达”描述，没有明确依赖哪个服务端口。

### 4.5 按 `capability_grants`

在 113 个 verified Atom 中：

- 没有明确 `capability_grants`：102 个；
- 至少有一条能力授权：11 个；
- 已验证能力记录总数：27 条。

| 已验证能力 | Atom 数量 |
|---|---:|
| `execute_command` | 11 |
| `read_file` | 11 |
| `write_file` | 5 |

当前没有 verified Atom 明确提供 `network_vantage`、`read_credential` 或 `authenticate`。同时，当前 113 个 verified Atom 的 `post_exploit.pivot_capability` 都是 `none`。因此，现有池子能够支持大量初始 RCE 场景，但还不足以支撑丰富的横向移动、凭据访问、持久化和数据收集链路。

## 5. RangeFactory 改造思路

整体流程为：

```text
CVE 环境
→ Agent 原子化
→ 高可信 Atom
→ exploit_access / capability_grants / depends_on 匹配
→ 模板槽位编排
→ ContainerLab 部署
→ SysField 参考攻击路径
→ 环境和最终目标验证
→ Agent 能力评估
```

- `exploit_access` 判断 Atom 是否满足槽位的进入条件；
- `capability_grants` 判断 Atom 是否满足后续阶段的能力需求；
- `depends_on` 和 capability closure 表达多阶段攻击中的能力传递；
- SysField playbook 负责确定性验证；
- Agent 验证用于衡量攻击难度和 Agent 能力。

当前 matcher 已支持基于 verified `capability_grants` 的直接匹配：当槽位声明 `required_capabilities` 时，Atom 必须拥有全部对应的 verified 能力；没有显式 grants 的旧 Atom 使用 `pivot_capability` 兼容视图。`kill_chain_phase` 仅用于攻击链角色标注，主机范围和真实可达性由闭包、依赖和网络隔离处理。

`capability_closure` 不是 Atom 或模板中的字段，而是一个确定性的能力推理模块。它将 Atom 的 verified 能力转换为带有主机和身份范围的 `CapabilityFact`，再根据显式规则计算能力和资产闭包。目前的主要规则是：

```text
execute_command → read_file
execute_command → network_vantage
read_file + 主机/身份权限匹配 → 获得文件或凭据资产
```

该模块已经接入 `ScenarioPipeline.generate()`：每个已选 Atom 先形成带 host scope 的闭包，再用于下游 `depends_on`、`required_assets` 和 `network_vantage` 可达性判断。闭包仍是有限的确定性规则，不替代 Agent 推理。

## 6. 当前完成情况

### 已完成或基本完成

- Atom v2/v3 结构整理；
- `runtime_spec`、`source_bundle`、`flag_spec`、`validation_spec` 标准化；
- ContainerLab 场景模板及部署流程；
- Atom 和 Range 的 SysField playbook 生成；
- 环境验证与 Agent 评估解耦；
- `enterprise_3tier` 场景环境部署验证。
- Range ground truth 已记录依赖槽位、依赖节点、攻击链角色、执行主机、能力授权和 Atom MITRE 标注；不再生成无真实前置的旁路 pivot。
- Range SysField exporter 已要求依赖步骤提供经验证的 `execute_command` stateless adapter，并支持命令模板替换；缺少 adapter 时生成直接失败。
- `enterprise_3tier` 模板已加入 canary asset setup/verify、最终目标断言和 attacker→DMZ→App→Data 的隔离规则。

### 当前未闭环问题

1. 当前 Atom 池仍缺少可执行的 `capability_executors.execute_command` 合约，因此多跳 enterprise Range 会在 playbook 生成期诚实失败；这需要 Atom 构建侧补齐，Range 侧不再创建伪 pivot；
2. 下游 Atom 的 PoC 材料传递仍需由 Atom 合约声明 `material_staging` 或可调用的写文件能力，不能假设预置节点已经拥有材料；
3. SysField runner 已能按步骤事件和最终 objective 失败，但真实 ContainerLab + SysField 多跳端到端验证仍需在 adapter 完整后执行；
4. 工具/模块依赖已进入 playbook step 元数据和 Atom handoff 合约，尚未覆盖所有现有 Atom；
5. 仍需同步 Atom 池台账，并按模板槽位缺口补充高可信的横向移动、凭据访问和数据访问能力。

因此，当前阶段可以概括为：CVELab 已具备从 CVE Atom 生成 ContainerLab Range 的完整骨架，环境部署链路基本成立；下一步重点不是继续堆叠漏洞数量，而是让 Atom 的前置条件、能力授权、攻击材料和多阶段执行语义真正进入匹配与验证闭环。

---

## Guided Range pilot implementation update (2026-07-14)

本轮已完成 Guided Range 第一轮实现：

- Guided/SysField 结果增加 `range_build_verified`、`guided_trial_evaluated`、
  `guided_trial_success` 和 `objective_achieved`，保留旧字段兼容读取；
- Guide 校验现在检查 verified capability、可复用 command channel、材料文件、
  native IP/flag 泄漏和目标服务一致性；
- `enterprise_3tier` 的 `app-db-credential` 已增加 setup/verify 命令；
- 固定三跳 pilot 已生成：`CVE-2012-1823 → CVE-2018-16509 → CVE-2019-9193`；
- 三个 pilot Guide 已按原生证据重新整理，不再使用旧迁移 Guide 的原始 IP 和探测步骤；
- 新增研究执行协议：`docs/GUIDED_RANGE_RESEARCH_PROTOCOL.md`。

验证状态：

- Guide 结构校验和 48 个相关测试通过；
- pilot 场景文件生成通过，7 个 ContainerLab 节点均成功创建并运行；
- 当前执行环境的 `sudo nsenter` 非交互权限不足，base 网络配置未能执行，因此尚未运行
  Guided Agent；该结果归类为环境权限失败，不归因于 Atom 或 Guide。

### Pilot failure analysis and Range-side fixes (2026-07-14)

最近一次 pilot 的环境、资产和攻击图均验证通过，Agent 已对 target-1 确认 RCE，
但未捕获 flag。根因是场景组装器把所有 Atom 的 flag 固定挂载到 `/flag.txt`，而
pilot Atom 的 `flag_spec.primary_path` 为 `/flag`，导致攻击通道成立但 flag 读取失败。

已修复：

- 按 Atom 的 `flag_spec.primary_path` 生成 ContainerLab flag bind；
- 按 Atom 的 flag 方法生成正确的 `flag_hint`，传给 Guided Agent；
- Agent 启动前自动创建仅连接 attacker 的控制网络，添加 LLM API 主机路由并进行
  TCP 预检；
- 控制网络在 Range 销毁后自动清理；
- transport、Docker 文件复制和 Agent 进程失败均产生明确诊断。

相关 orchestrator 测试 214 项通过。真实三跳 E2E 需在具备非交互 sudo/nsenter 权限的
宿主环境中重新执行。

后续一次验证暴露了控制网络接入时的 `eth1` 接口名冲突：ContainerLab 已占用
`eth0/eth1`，Docker 默认网络接口前缀再次选择了 `eth1`。控制网络创建逻辑已改用
独立的 `ctl` 接口前缀，避免与数据面接口冲突。

随后发现 attacker 容器缺少 `CAP_NET_ADMIN`，容器内 `ip route` 会返回
`Operation not permitted`。现已增加宿主机 `nsenter` 到 attacker 网络命名空间的
路由配置回退，并将异常记录为 `agent_transport`，不再抛出未分类 traceback。
