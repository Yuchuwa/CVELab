# CVELab RangeFactory 设计：从 CVE 到可验证企业攻击图

## 1. 文档定位与术语

本文描述 CVELab 的目标架构、当前实现边界，以及从 atom 到企业场景的设计机制。文中明确区分“已经实现的能力”和“下一阶段设计”，避免把目标模型误写成现状。

CVELab 的核心定位是：

> 将经过验证的 CVE 环境转换为可复用的攻击能力组件，并在网络、身份、资产和攻击依赖约束下，生成可部署、可验证、可解释的企业攻防场景。

### 1.1 核心术语

| 术语 | 定义 |
| --- | --- |
| **CVE** | 公开漏洞的身份标识与描述；它本身不等于可部署场景。 |
| **atom** | 一个可部署、可验证、可复用的 CVE 攻击能力组件。 |
| **exploit primitive** | atom 成功利用后授予的最小、稳定、可观察且不依赖某次企业实例的安全效果。 |
| **capability** | 攻击者在特定主机、身份和网络视角下可执行的基础操作。 |
| **baseline asset** | 模板中企业原本就运行的主机或服务。 |
| **scenario asset** | 某次场景中的具体凭据、配置、代码、数据库或数据集等有价值对象。 |
| **template** | 可复用、参数化的标准企业环境定义，包括网络、正常资产、atom 插入点和目标。 |
| **scenario** | 模板选定具体 atom 后的物化实例，包括生成的 ContainerLab 拓扑、初始化数据和验证产物。 |
| **injection point** | 模板中允许 atom 接入的逻辑位置，包含 zone、服务角色和攻击依赖约束。它不是“必须替换某个服务”的指令。 |
| **attack graph** | 由“攻击能力 → 场景资产 → 新攻击能力”关系组成的有向图。 |
| **native verification** | 在 atom 原始 Vulhub/源环境中验证漏洞可利用性。 |
| **orchestrated verification** | 在 CVELab 重新编排出的最小 ContainerLab 环境中验证运行时和环境语义。 |

最重要的建模原则是：

```text
场景资产是攻击图中的节点；atom 是使攻击者状态发生转换的边。
```

因此，CVE 不是简单“塞进某个网段的一个容器”。atom 的职责是授予经过验证的基础能力；具体凭据、数据和下一跳关系由场景定义。

### 1.2 设计边界

- 标准企业环境是通用企业基线，不是某一种应用的专属拓扑；多个门户、Web 服务、内部应用和辅助系统可以同时存在。
- atom 的插入不以“是否与某个核心服务业务相关”为条件，而以网络位置、服务角色、利用前置条件和攻击图约束为条件。
- ContainerLab 是 CVELab 场景的运行时与部署后端，应继续使用；Docker Compose 只在 atom 原始材料和 native verification 中出现。
- ATT&CK、CAPEC、CVE/CWE/CPE 等标准用于描述、标注和统计；实际编排硬约束由 CVELab 的运行时 capability contract 提供。

## 2. 当前实现

### 2.1 Atom 实现基础

当前保留的 v3 atom 具备以下结构：

- `runtime_spec`：镜像、服务、端口、command、entrypoint、environment 和初始化文件；
- `flag_spec`：flag 注入路径和验证语义；
- `validation_spec`：readiness 以及可选 deterministic replay；
- `source_bundle`：compose、README、Dockerfile、初始化文件和攻击侧 PoC 材料，并保存内容哈希；
- 原生验证记录及编排验证记录。

`source_bundle` 中的 Compose 是原始漏洞环境的来源材料，不是企业场景的拓扑格式。atom 被插入场景时，编排器读取其运行时契约，将服务节点、启动语义、初始化文件和验证任务转换为 ContainerLab/Ansible 产物。

### 2.2 模板与场景的当前实现

当前 `templates/<template-name>/` 目录由三个互补文件组成：

| 文件 | 当前职责 |
| --- | --- |
| `template.yaml` | 逻辑模板：`zones`、`routers`、`transits`、`isolation_rules`、`injection_points`，以及 atom 匹配和依赖约束。 |
| `clab.yaml` | 基础 ContainerLab 拓扑，定义已有节点和链路。当前 `enterprise_3tier` 基础拓扑包含 attacker 和三台路由器。 |
| `ansible/base.yaml` | 为已部署节点配置数据面 IP、路由和 ACL。 |

当前生成链路是：

```text
template.yaml + 基础 clab.yaml
        ↓
按 injection_points 选择 atom
        ↓
复制基础拓扑，新增 atom 节点并连接到对应 zone router
        ↓
输出场景 clab.yaml、Ansible、CVE setup、ground truth 和元数据
        ↓
ContainerLab 部署与验证
```

`ScenarioPipeline` 依据模板的插入顺序和 `depends_on` 逐个匹配 atom；`ScenarioAssembler` 负责把 atom 运行时契约物化为新的 ContainerLab 节点和链路。自动选择和显式指定现在共用同一套 slot 校验，matcher 会检查漏洞类别、服务角色、声明的服务访问条件、上游 `verified` capability 和场景资产；`kill_chain_phase` 只作为攻击链角色标注，不把 Atom 的 MITRE phase 当作深层槽位硬门槛。旧 atom 仍通过 `pivot_capability` 兼容视图接入。

### 2.3 当前已验证能力与已知限制

当前已经验证：

- v3 atom 的运行时语义和 source bundle 管理；
- native verification 与 orchestrated verification 的分层；
- ContainerLab 多网段、路由、ACL 和 DMZ → App → Data 的多跳 pivot；
- 环境正确性验证与 Agent 成功验证分离；
- 场景 attacker 不接收 `ground_truth.flag`，atom PoC 材料通过自包含 bundle 提供。

当前仍然存在的限制：

- `enterprise_3tier` 基础 `clab.yaml` 主要是 attacker/router 骨架，正常业务资产模型仍需补充；
- atom 池仍明显偏向 RCE、initial access 和 web application；
- capability contract 已在 atom 模型、显式/自动 slot 校验和资产闭包中生效，但目前只有少量 anchor atom 显式声明，剩余 atom 仍使用 `pivot_capability` 兼容视图；
- `exploit_access` 只有在 injection point 声明 `required_service_access` 时才作为硬匹配条件；现有 atom 池仍需继续补齐协议、端口和认证证据；
- 资产、凭据和业务目标的因果链属于下一阶段场景机制，不应倒写为当前已完成能力。

## 3. Atom 设计机制

### 3.1 Atom 的职责与边界

atom 描述漏洞本身在某个运行时中稳定授予的能力，不枚举某个企业实例中可能出现的全部后果。

同一个 Web RCE 在不同场景中可能：

```text
场景 A：读取应用配置，获得数据库密码。
场景 B：读取 CI 配置，获得部署 token。
场景 C：仅获得低权限 shell，没有可用凭据。
```

因此，以下内容属于场景，而不是 atom 的固有后置条件：

```text
本次使用的数据库密码、token、SSH key 和用户账号；
这些值所在的具体路径；
哪个上游资产泄露了它们；
本次 IP、子网、路由、业务数据和最终目标。
```

atom 可以声明的结果应是最小 exploit primitive，例如：

```text
以 service user 身份在目标主机执行命令；
通过目标服务向任意 HTTP 地址发起请求；
读取应用可读范围内的文件；
获得低权限应用管理员会话；
将本地低权限身份提升为 root。
```

### 3.2 运行时契约

一个可进入场景编排的 atom 至少应保留：

```yaml
runtime_spec:
  service: target
  image: verified-image
  ports: [80]
  command: null
  entrypoint: null
  environment: {}
  init_files: []

source_bundle:
  # 原始 compose、Dockerfile、初始化文件和攻击侧材料

flag_spec: {}
validation_spec: {}
```

运行时契约必须保留原始环境的启动语义。场景编排不能只复制镜像和端口而丢失 command、entrypoint、environment、初始化顺序或攻击侧 PoC 材料。

### 3.3 利用前置条件：`exploit_access`

atom 保存漏洞固有、相对稳定的利用条件：

```yaml
exploit_access:
  attack_vector: network         # 可映射 CVSS AV
  privileges_required: none      # 可映射 CVSS PR
  user_interaction: none         # 可映射 CVSS UI
  attack_requirements: none      # 可映射 CVSS AT
  required_service:
    protocol: http
    port: 80
  local_execution_required: false
```

这些条件用于判断 atom 是否能被当前攻击者状态和插入点满足；injection point 可通过 `required_service_access` 约束其中的攻击向量、权限、用户交互、协议、端口和本地执行要求。它们不包含某次场景的具体秘密值、IP 或资产路径。

### 3.4 能力授予：`capability_grants`

第一版使用小型、封闭且可验证的能力集合：

| Capability type | 含义 |
| --- | --- |
| `execute_command` | 在目标主机以指定身份执行命令。 |
| `read_file` | 读取指定权限范围内的文件。 |
| `write_file` | 写入指定权限范围内的文件。 |
| `database_query` | 以指定数据库权限执行读写查询。 |
| `outbound_request` | 令目标服务代为发起网络请求，例如 SSRF。 |
| `authenticated_session` | 获得某应用中的指定角色会话。 |
| `privilege_transition` | 从低权限身份转换到高权限身份。 |
| `service_control` | 控制、重启或修改目标服务。 |
| `network_vantage` | 从目标主机及其连接网络发起网络访问。 |

每条能力必须携带目标和边界，而不是只有字符串：

```yaml
capability_grants:
  - type: execute_command
    host_scope: target_host
    principal: service_user      # root | service_user | application_admin | unknown
    evidence_level: verified
    evidence_ref: native-replay-01

  - type: network_vantage
    host_scope: target_attached_networks
    evidence_level: verified
    evidence_ref: orchestrated-network-01
```

### 3.5 证据等级与标准映射

每条 capability 使用以下证据等级：

```text
verified  ：由 native/orchestrated replay 或明确运行时探针证明。
inferred  ：由 CVE 描述、PoC 或规则推断，只用于排序或人工审核。
unknown   ：无法证明，不参与硬匹配。
```

编排器只有在 `verified` capability 满足硬依赖时才允许选择下游 atom；`inferred` 不能被当作事实。

外部标准各自承担不同职责：CVE/CWE/CPE 描述漏洞身份和适用性，CVSS 描述通用利用条件，CAPEC 描述攻击模式，ATT&CK 描述对抗行为，STIX 提供可选交换格式。它们不能替代 CVELab capability contract，也不能单独决定攻击链是否可达。

参考：

- [CVE Record 内容要求](https://www.cve.org/resourcessupport/allresources/cnarules)
- [CVSS v4.0 specification](https://www.first.org/cvss/v4.0/specification-document)
- [CAPEC attack patterns](https://capec.mitre.org/about/index.html)
- [MITRE ATT&CK resources](https://attack.mitre.org/resources/)
- [STIX 2.1 introduction](https://oasis-open.github.io/cti-documentation/stix/intro.html)

### 3.6 Atom 验证

atom 的“verified”至少要分解为两类事实：

1. **Native verification**：在原始 Vulhub/源环境中证明漏洞确实可利用，并记录 exploit primitive 的证据。
2. **Orchestrated verification**：在最小 ContainerLab 场景中证明 runtime、部署、readiness、网络连接和材料仍然成立。

`replay` 可以是诊断证据，但不能单独替代环境正确性验证。Agent 失败也不能自动等同于 atom 构造失败，必须区分结构问题、环境重建问题、验证模型不匹配和 exploit automation 不稳定。

## 4. 场景编排设计机制

### 4.1 模板和场景的分工

模板定义企业“原本是什么样”；场景定义将哪些 atom 插入其中后形成的具体实例。

标准企业模板不是某个应用的专用容器集合。它可以同时拥有多个正常门户、Web 服务、内部 API、数据库、文件共享和管理服务；atom 默认是新增漏洞节点，不替换或覆盖这些基线资产。

### 4.2 标准企业环境的定义方式

继续使用现有模板目录和 ContainerLab 文件，不创建 Docker Compose 形式的第二套场景配置：

```text
templates/<template-name>/
├── template.yaml       # 逻辑定义和编排约束
├── clab.yaml           # 基础 ContainerLab 拓扑
└── ansible/base.yaml   # 数据面 IP、路由和 ACL
```

`template.yaml` 下一阶段应在现有 `zones`、`routers`、`transits`、`isolation_rules`、`injection_points` 基础上补充企业资产和目标语义：

```yaml
baseline_assets:                  # 企业原有、正常运行的 ContainerLab 节点
  - id: public-portal
    role: web_portal
    zone: dmz
    node_ref: public-portal       # 对应 clab.yaml 的 topology.nodes
  - id: internal-api
    role: application_server
    zone: app
    node_ref: internal-api

injection_points:                 # atom 的逻辑承载位置
  - id: dmz-web
    zone: dmz
    required_service_role: [web_application, middleware, framework]
    required_service_access:
      protocols: [http]
      ports: [80, 8080]
    depends_on: []
  - id: data-store
    zone: data
    required_assets: [app-db-credential]

  - id: app-service
    zone: app
    asset_host_refs: [internal-api]

assets:                            # 场景级凭据、配置、源码和数据
  - id: customer-records
    owner: customer-db
    access_requires: [app-db-credential]

objectives:                        # 最终业务效果及验证方式
  - asset: customer-records
    validation: canary_row_read
```

字段边界：

- `zones`、`routers`、`transits`、`isolation_rules` 和基础 `clab.yaml` 定义网络、路由、ACL 和可达性；
- 每个包含多个节点的 zone 使用 ContainerLab 管理的二层 bridge，router 只配置一个 zone 接口，避免同一子网在 router 上出现多个 point-to-point 接口；
- `baseline_assets` 定义企业本来就运行的节点，并通过 `node_ref` 对应基础 ContainerLab 拓扑；
- `injection_points` 定义 atom 可接入的 zone、服务角色和攻击依赖，不表示替换基线资产；
- `required_assets` 声明下游插入点必须先拥有的场景资产；只有 closure 计算出的资产才能满足该条件；
- `asset_host_refs` 声明当前攻陷能力可以作用于哪些基线节点，用于把 atom 的 host scope 与资产位置连接起来；
- `assets` 和 `objectives` 定义该场景的具体世界，秘密值在实例化时写入真实节点，不直接提供给 Agent；
- `template.yaml`、`clab.yaml` 和 `ansible/base.yaml` 通过稳定的 node/zone/asset ID 对齐，避免多份事实漂移。

### 4.3 Atom 插入机制

atom 插入沿用当前 CVELab 的实现：

1. 读取模板的 `injection_points`；
2. 根据服务角色、漏洞类别、`required_service_access`、能力和 `depends_on` 匹配 atom；显式指定 CVE 也必须通过同一校验；
3. 将 atom 运行时契约转成 ContainerLab 节点定义；
4. 将新节点连接到插入点对应的 zone router；
5. 生成对应的初始化、readiness、flag 和验证任务。

这里不引入额外的 insertion mode，也不要求 atom 与某个基线服务存在业务语义关联。插入是否合法只由模板槽位、网络可达性、服务角色、atom 前置条件和攻击图依赖决定。

### 4.4 场景资产与能力闭包

具体 artifact 属于场景，因为场景负责定义企业世界：

```yaml
assets:
  - id: app-db-credential
    type: database_credential
    owner: internal-api
    location:
      kind: file
      node_ref: internal-api
      path: /opt/app/config.yaml
    readable_by: [service_user]
    grants: [database_access: customer-db]

  - id: customer-records
    type: sensitive_dataset
    owner: customer-db
    access_requires: [app-db-credential]
    validation: canary_row_read
```

场景生成时随机化 credential 和数据，并写入真实服务配置、数据库或代码仓库；验证器检查 Agent 是否经由真实攻击动作取得资产或其实际效果。

当前 `enterprise_3tier` 首条业务链路由模板资产和目标断言定义：数据库 canary 由独立的 asset-setup 在 `data-store` 服务容器内初始化，reference objective 再从最后一个具备执行能力的 actor 查询它。凭据资产的位置和访问主体仍由模板显式声明，不写入 Agent 输入。

编排器不要求 atom 穷举所有 artifact，而计算有限、显式的能力闭包。当前已实现的第一组规则是：

```text
execute_command(host=H, principal=root)
  ⇒ read_file(host=H, scope=arbitrary_path)
  ⇒ write_file(host=H, scope=arbitrary_path)
  ⇒ network_vantage(host=H, networks=H.attached_networks)

execute_command(host=H, principal=service_user)
  ⇒ network_vantage(host=H, networks=H.attached_networks)
  ⇒ read_file(host=H, scope=files readable by service_user)
```

### 4.5 攻击 Playbook 统一与参考路径验证

攻击 playbook 与拓扑文件严格分离：

```text
clab.yaml                         ContainerLab 拓扑
ansible/*.yaml                    环境部署、网络和资产初始化
atom/playbook/sysfield.yaml       单 atom 的正式攻击 playbook
scenario/sysfield/playbook.yaml   Range 的正式攻击 playbook
```

atom 的攻击 playbook 不是由 Agent 直接写 YAML。Agent 输出经过确认的
`exploit_steps`，随后由 `SysFieldPlaybookGenerator` 转换为 SysField 格式。
历史 `exploit.yaml` 仅作为兼容格式保留，Range 编排不再读取它。

Range playbook 由 `SysFieldExporter` 确定性生成，输入为：

```text
ground_truth.attack_path
+ scenario.yaml / match_report
+ selected atom 的 sysfield.yaml
+ source_bundle 的 PoC 挂载
+ template objectives
```

编排器不重新选择 atom，也不使用 Agent 生成攻击命令。它按攻击路径合并
atom 步骤，替换目标地址、actor 地址和 PoC 路径，保留 atom、slot、
`exploit_access`、`capability_grants` 和依赖来源。未知变量、缺失 playbook、
缺失 PoC 材料或不可执行步骤会使生成失败；不能退化成连通性检查。

每个 Range playbook 必须包含最终 objective assertion。flag 目标使用最终
攻击路径的可执行验证命令；业务目标在 objective 中声明
`reference_command` 和可选 `success_pattern`。该命令由最后一个具备相应能力
的 actor 执行，并以退出码/输出匹配证明目标成立。

Range 验证顺序为：

```text
ContainerLab deploy
→ base / asset setup / CVE setup / readiness
→ SysField reference playbook
→ final objective assertion
→ optional Agent evaluation
→ destroy
```

`reference_path_verified` 是 Range 正确性的硬门槛；Agent 成功率只作为独立
的攻击能力评估指标，不映射为 Range 质量的同义词。

Guided Agent 模式使用另一条验证路径：

```text
ContainerLab deploy
→ base / asset setup / CVE setup / readiness
→ attack graph / network reachability
→ 将 Atom Guide 作为 Agent advisory context
→ Agent 自适应执行多跳攻击
→ flags / business objective verification
→ destroy
```

Guided 模式下，Guide 不是 Range 的正式匹配器或 pivot 合约。Atom 的
`exploit_access`、verified `capability_grants`、模板 `depends_on`、资产闭包和
ContainerLab 网络关系决定场景是否合法；Guide 只提供原生环境中的利用顺序、
成功信号、工具和命令通道提示。Guide 与重建 Range 的端口、principal、能力或
执行主机不一致时记录 advisory，Agent 以实际 Range 上下文为准。只有 Guide
缺失、损坏、材料引用不存在、包含原始 IP/flag 或外部绝对路径等完整性问题，
才阻止 Guided Agent 启动。

攻击者状态更新为：

```text
C_next = closure(
  C_current
  ∪ verified_atom_capabilities
  ∪ scenario_asset_access_policies
  ∪ network_reachability
)
```

能力闭包必须是小型、显式、可测试的规则，不以 LLM 推理替代安全语义。

### 4.5 场景编排流程

当前自动编排已经按以下受约束流程构造场景；更复杂的状态传播仍属于后续扩展：

```text
1. 加载企业模板、基础 ContainerLab 拓扑、ACL、初始入口和业务目标。
2. 选择满足初始可达性和 injection point 服务访问契约的 entry atom。
3. 将 atom 的 verified capability 加入攻击者状态。
4. 按网络可达性和资产访问策略推导可获得的场景资产。
5. 选择服务访问契约已满足、且前置能力和资产已满足的下游 atom。
6. 重复能力 → 资产 → 下一跳，直到满足目标或无可行路径。
7. 物化 ContainerLab 拓扑、随机化资产值并写入真实节点配置。
8. 使用 ContainerLab/Ansible 部署，验证服务、ACL、因果路径和最终目标。
```

### 4.6 三层企业链示例

```text
Attacker
  └─[Atom A: public Web RCE]
       grants: execute_command(service_user) on DMZ Web
       ↓
DMZ Web asset policy
  service_user 可读 /opt/app/config.yaml
  produces: internal_api_token
       ↓
  └─[Atom B: authenticated internal API exploit]
       requires: internal_api_token + app-network reachability
       grants: execute_command(service_user) on Internal API
       ↓
Internal API asset policy
  application config produces: app_db_credential
       ↓
  └─[Atom C: database/local objective]
       requires: app_db_credential + data-network reachability
       grants: database_query or root
       ↓
Customer data canary / business objective
```

A/B/C 的漏洞能力来自 atom；token、数据库凭据和数据集来自场景；ACL 决定路径是否存在；资产访问策略决定能力能否变成下一跳 artifact。

## 5. 验证目标与实施路线

### 5.1 场景真实性验证

每个生成场景至少验证：

| 验证项 | 含义 |
| --- | --- |
| Runtime fidelity | 所有 atom 保留启动语义并通过 readiness。 |
| Native fidelity | atom 在原始环境中已验证漏洞效果。 |
| Orchestration fidelity | atom 在新 ContainerLab 拓扑中仍可部署并满足环境验证。 |
| No-shortcut property | 攻击者不能绕过 ACL 直达深层资产。 |
| Causal reachability | 下游前置条件仅由初始状态或上游真实能力/资产满足。 |
| Asset-effect validity | 最终数据、凭据或管理权限效果真实可验证。 |
| Reference-path validity | 生成的 Range SysField playbook 在已部署 ContainerLab 中完整执行，并通过最终目标断言。 |
| Agent separation | 环境正确、确定性 replay、Agent 成功是独立结果。 |

### 5.2 分阶段路线

**Phase 0：保持当前基础并修正台账**

- 保持 v3 runtime/source bundle/validation/dual verification 完整性；
- 保持环境验证与 Agent 成功分离；
- 同步 atom 迁移后的测试、状态台账和统计产物；
- 不把完整 artifact 清单加入 atom。

**Phase 1：最小 capability contract（已完成第一版）**

- 在 atom 中增加 `exploit_access` 与 `capability_grants`；
- 每条能力携带 `verified/inferred/unknown` 状态和证据引用；
- 编排硬匹配只使用 `verified` 能力，并由显式指定和自动选择共用；
- injection point 可通过 `required_service_access` 声明协议、端口和认证条件；
- 将 `pivot_capability` 兼容映射为 `execute_command + network_vantage`（已完成，待继续迁移 atom）。

成功标准已在 matcher 单测和显式/自动场景测试中覆盖：错误服务访问、错误角色、能力不足和资产不足都会被拒绝。

**Phase 2：模板资产关系与最小 artifact 链（第一条链路已完成）**

- 在模板中定义 `baseline_assets`、场景 `assets`、访问策略和业务目标；
- 先支持 `database_credential`、`api_token`、`ssh_private_key`、`source_repository`、`sensitive_dataset`；
- 生成时随机化秘密值并写入真实服务配置、数据库或代码仓库；
- 只允许经能力闭包和资产访问策略可达的 artifact 满足下游前置条件；
- 最终验证真实业务 canary，而非只验证统一 `/flag.txt`。

`enterprise_3tier` 已完成 `internal-api 配置凭据 → customer-db → canary row` 的 ContainerLab 运行时验证；后续工作是扩展资产类型和能力传播规则。

**Phase 3：自动候选治理与 atom 池扩展（下一阶段）**

- 为自动候选增加更丰富的解释性评分和拒绝原因；
- 将剩余 atom 的 `exploit_access`、`capability_grants` 和证据记录补齐；
- 按模板缺口扩展 credential access、lateral movement、privilege escalation、persistence 和 collection 类型 atom；
- 在扩展模板前先完成 atom-slot 覆盖率和高可信 anchor 台账。

**Phase 3：企业角色与攻击行为多样性**

逐步补充 credential access、local privilege escalation、authenticated session、file/source/config exposure、database access、persistence 和 collection，并扩展 customer portal、internal API、GitLab、CI/CD、identity provider、database、file share、monitoring 和 management plane 等模板资产。

**Phase 4：生成式 benchmark 对接**

区分 execution/replay protocol 与 discovery/red-team protocol；前者用于环境和攻击图验证，后者用于评测 Agent 的侦察、发现和路径规划，并通过 ATT&CK/CAPEC 标签控制训练、验证和 OOD 分布。

### 5.3 非目标与表述边界

当前和近期阶段不应宣称：

- 任意 CVE atom 可自由放入任意企业位置；
- 自动生成场景天然比人工策展 range 更真实；
- ATT&CK tactic 可以直接决定攻击链可达性；
- atom 能完整预测利用后所有可能获得的 artifact；
- 当前以 RCE 为主的 atom 池已经覆盖完整 APT 生命周期。

更准确的研究主张是：

> CVELab 将标准化漏洞身份与 TTP 标签，同经验证的运行时 exploit capability 分离；它通过模板级资产关系、ContainerLab 网络隔离和显式能力闭包，自动生成可追溯、可验证、受攻击依赖约束的 CVE 企业攻击图。

这使 CVELab 与固定人工 benchmark 形成互补：人工 range 可以追求单个场景的深度；CVELab 追求经验证场景分布的可扩展生成、可控变化和攻击图可解释性。
