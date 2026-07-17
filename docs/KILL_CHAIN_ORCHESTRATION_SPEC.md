# 攻击链编排语义规范 (阶段 0 设计, v2)

> 状态：设计规范 (阶段 0, 第二版)。第一版被推翻，原因见第 1.1 节。
> 配套 PoC：`scripts/poc_kill_chain_matching.py`。
>
> 设计目标：把"按拓扑层插入 CVE"的平铺编排，升级为"前置可达性驱动的
> 攻击链 DAG"编排，让企业环境真实性与攻击场景真实性同时被编排语义覆盖。

## 1. 问题陈述与第一版的错误

### 1.1 现状问题

当前编排轴是**拓扑层**(`injection_point`)。`cve_matcher.match` 对每个 slot
做三个条件的 AND 过滤，其中 `primary_mitre_phase ∈ required_mitre` 是 OR
列表匹配。由此产生两类语义错位：

1. **软绕过**：深层 slot 的 `required_mitre` 含 `initial_access` 时，纯入口
   漏洞直接命中深层目标。例如 enterprise_3tier 的 `data-store` 声明
   `required_mitre=[initial_access, execution, privilege_escalation]`，而
   `CVE-2019-9193`(database/execution/RCE) 这类入口样本能命中"最深层数据
   区目标"，攻击链退化成"三层都是入口 RCE"。
2. **硬空缺**：slot 的 `required_mitre` 不含 `initial_access`(如 app-service
   要 `lateral_movement/persistence`)，但池子里这些 phase 为 0 → slot 直接
   匹配失败。当前模板靠把 `initial_access` 塞进深层 slot 来"绕过"硬空缺，
   结果回到软绕过。

### 1.2 第一版的根本错误(已被推翻)

第一版试图用"漏洞的 MITRE phase 类型"当**硬卡口**去筛"这个漏洞能不能放
深层 slot"——规定 objective 阶段只能放 collection/exfiltration/impact 类
漏洞，禁止 initial_access。

**这是错的**。漏洞类型(怎么打进来)和它在攻击链里的角色(承担什么任务)是
两个维度。技术上，一个 RCE 攻陷数据库后 `SELECT *` 就是数据窃取、
`DROP TABLE` 就是破坏——"数据窃取/破坏"是利用后的**动作**，不是漏洞类型
本身。MITRE ATT&CK 里 initial_access 是"怎么打进来"，collection 是"打进来
之后做什么"，几乎不存在"专门用来窃取数据"的 CVE。如果硬卡漏洞类型，
objective 层会因池子没有 collection 类 CVE 而**永远填不上**，系统直接不可
用。用户正是指出这一点推翻了第一版。

### 1.3 第二版的根本转向

真正区分"入口层"和"目标层"的，**不是漏洞类型，而是到达这个 slot 的前置
条件**：

- entry 层：从外网直接能打，不需要任何前置。
- objective 层：前面已经横移了几跳，攻击者得先拿到上游立足点/凭据才能
  触及这个目标。同一个 RCE 放 entry 是"从外网首次打入"，放 objective 是
  "攻击链终点——但得先穿过前几层才摸得到"。

因此本版的**硬约束改为"前置可达性 + 拓扑位置"**：
- 一个 slot 可达 ⇔ 它没有 `depends_on`，或它所有上游 slot 都已解析出
  具备横移能力的 atom。
- 一个 atom 能进某 slot ⇔ 满足现有的 service_role/vuln_category 约束，
  **且** 该 slot 可达。不再硬卡 MITRE phase 类型。

漏洞的 MITRE phase **降级为软提示**：标注这个漏洞最自然的攻击链位置，
在 agent prompt 里给线索，但不作为 matcher 硬过滤。

## 2. 攻击链阶段角色(软提示, 非硬卡口)

仍给每个 injection_point 标一个 `kill_chain_phase`，但它的语义从"硬过滤
规则"变成"软提示 + 拓扑位置声明"。定义 4 个阶段角色：

| 阶段角色 | 拓扑位置 | 攻击链语义 | 典型 MITRE phase(仅提示) |
|---|---|---|---|
| `entry` | 外网可达区 | 攻击者首次立足，无前置 | initial_access, execution |
| `foothold` | 内网第一层 | 在已立足点上强化控制 | persistence, privilege_escalation, credential_access, execution |
| `pivot` | 内网中转层 | 横向移动到更深层 | lateral_movement, discovery, credential_access, execution |
| `objective` | 最深层 | 攻击链终点 | 任意 phase(RCE 打下最终目标也是 objective 的合理达成) |

### 2.1 与第一版的区别

| 维度 | 第一版(已推翻) | 第二版(本版) |
|---|---|---|
| 阶段政策性质 | 硬卡口: atom phase 不在政策集合 → 拒绝 | 软提示: 不拒绝, 仅标注 |
| objective 允许的漏洞 | 仅 collection/exfiltration/impact | 任意(RCE 当最终目标也合法) |
| 深层 slot 的硬约束 | 漏洞 MITRE phase 类型 | 前置可达性(depends_on + 上游能力) |
| 系统可用性 | 池子无 collection 类 → objective 永远空 | RCE 可填各层, 不卡死 |

### 2.2 kill_chain_phase 的三个用途(都是软的)

1. **拓扑位置声明**：标明这个 slot 在企业网络里的位置(entry=外网可达，
   objective=最深)。模板扩展时强制声明，避免"任意层填任意 CVE"。
2. **agent prompt 线索**：告诉 agent 这个目标的攻击链角色("这是攻击链
   终点，前面应已立足")，帮 agent 理解为什么需要先打上游。
3. **缺口分析标注**：阶段 1 分析池子时，按 slot 的阶段角色统计"哪些阶段
   角色的 slot 缺能当跳板的 atom"，而非"缺某类漏洞"。

### 2.3 唯一的硬过滤: 前置可达性

一个 slot 可被填充的**必要条件**：

```
slot 可达 ⇔ slot.depends_on 为空
         OR 对每个上游 slot u:
              u 已解析出 atom a_u
              且 a_u.post_exploit.pivot_capability ≠ NONE
```

即：要么没上游(入口层)，要么所有上游都已被能当跳板的 atom 填上。上游
atom 只能拿 flag 不能横移(`pivot_capability=NONE`) → 下游不可达 → matcher
拒绝下游的任何 atom。

这跟漏洞是 RCE 还是 collection **无关**，只跟"上游能不能当跳板"有关。

## 3. 依赖与可达性(主约束)

### 3.1 产出类型分类(保留, 用途明确)

atom 攻陷后能向下游提供的能力，沿用第一版的 4 类，但**只用于可达性硬校验
和 prompt 描述，不再和漏洞类型绑定**：

| 产出类型 | 含义 | 粗粒度代理 |
|---|---|---|
| `shell` | 目标主机交互式 shell | `pivot_capability = SHELL/FULL_TOOLBOX` |
| `credential` | 抓到的凭据 | `pivot_capability = CREDENTIAL` |
| `port_forward` | 端口转发/隧道 | `pivot_capability = PORT_FORWARD` |
| `none` | 仅 flag，不能横移 | `pivot_capability = NONE` |

### 3.2 可达性匹配规则(match_kill_chain v2)

```
对 slot S 和候选 atom 列表:
  1. 先做现有 match() 的 service_role / vuln_category 过滤(保留, 向后兼容)
  2. 若 S 无 kill_chain_phase → 直接返回步骤 1 结果(退化兼容)
  3. 若 S 无 depends_on → 返回步骤 1 结果(入口层, 可达)
  4. 若 S 有 depends_on:
       对每个上游 slot u:
         若 u 未解析 → 不硬拒(交给调用方拓扑序保证)
         若 u 的 atom pivot_capability == NONE → S 不可达 → 返回空
       所有上游都非 NONE → 返回步骤 1 结果
  5. MITRE phase 不参与硬过滤(仅 soft annotation)
```

关键：**第 5 步去掉了第一版的 phase 硬政策**。这是 v2 的核心改动。

### 3.3 拓扑位置如何约束

`kill_chain_phase` 标的拓扑位置(entry/外网可达)由模板的 `isolation_rules`
天然保证：attacker → app/data 在 enterprise_3tier 里是 deny 的，所以 app/
data slot 即使填了 initial_access 漏洞，攻击者从外网也**打不到**——必须先
经 dmz-web 横移。网络隔离规则本身就是"拓扑位置"的硬实现，无需 matcher
再卡漏洞类型。

这点很重要：**拓扑位置约束由网络层(isolation_rules)保证，不由 matcher
卡漏洞类型保证**。matcher 只管可达性(上游能不能当跳板)。

## 4. 现有模板的 slot → 阶段映射方案 (v2)

### 4.1 dmz_simple (单层 DMZ, 1 slot)

| slot | kill_chain_phase | depends_on | required_mitre(建议) |
|---|---|---|---|
| dmz-target-1 | `entry` | 无 | 保留原 [initial_access, execution] |

说明：入口层，无依赖。填任意 RCE/initial_access atom 都合法。

### 4.2 dmz_dual (单层 DMZ, 2 slot 并行)

| slot | kill_chain_phase | depends_on | required_mitre(建议) |
|---|---|---|---|
| dmz-target-1 | `entry` | 无 | 保留原 |
| dmz-target-2 | `entry` | 无 | 保留原 |

说明：两个都是外网可达入口，互不依赖。攻击链语义如实暴露：这是"多入口
打靶"不是"多阶段渗透"。两个都填 RCE 合法。

### 4.3 enterprise_3tier (三层网络, 3 slot 递进)

| slot | zone | kill_chain_phase | depends_on | required_mitre(建议) |
|---|---|---|---|---|
| dmz-web | dmz | `entry` | 无 | [initial_access, execution] |
| app-service | app | `foothold` | [dmz-web] | 保留原 [lateral_movement, execution, persistence] |
| data-store | data | `objective` | [app-service] | 保留原, **不必移除 initial_access** |

说明(与第一版的关键差异)：
- `app-service`/`data-store` 仍标 foothold/objective 并依赖上游，但
  `required_mitre` **不必移除 initial_access**。data-store 填
  `CVE-2019-9193`(database/RCE) 现在是**合法**的——它是攻击链终点，攻击者
  得先穿过 dmz-web + app-service 才摸得到它。这正是真实 APT 的样子。
- 软绕过的修复**不再靠"从 required_mitre 删 initial_access"**，而是靠
  `depends_on` + 网络隔离：即使 data-store 填了入口类 RCE，attacker 从外网
  也打不到 data 区(隔离规则 deny)，必须先拿 dmz-web 当跳板。攻击链递进由
  可达性保证，不靠漏洞类型卡口。
- `app-service` 仍要求 `lateral_movement/persistence` 是个**真实缺口**
  (池里 0 个)，这个缺口是模板设计本身的硬约束。v2 下有两种处理：(a) 放宽
  app-service 的 required_mitre 让 RCE 也能填(像 data-store)，(b) 保持硬
  要求、定向补池。这是阶段 1 要决策的模板设计问题，不是 matcher 问题。

### 4.4 v2 下的缺口重新定义

缺口不再是"缺某类漏洞类型"，而是：

1. **可达性缺口**：某深层 slot 的上游没有能当跳板的 atom
   (`pivot_capability=NONE`)。需补的是"攻陷后能横移"的 atom，不论它是什么
   漏洞类型。
2. **角色缺口**(软)：某阶段角色 slot 想体现特定攻击动作(如真想有一个
   persistence 环节)但池里没有。这是**模板设计者是否要这种环节**的问题，
   不是系统可用性的硬要求。

阶段 1 缺口分析按这两类分别统计，不再按"MITRE phase 计数"。

## 5. ground_truth DAG 结构

### 5.1 现状(同第一版)

`ground_truth.attack_path` 是平铺列表，消费方按顺序遍历，agent prompt 仅
口头提示"target-N 可能用作 pivot"，无显式依赖。

### 5.2 新结构

每个节点新增三个字段，把列表升级为带依赖的 DAG(列表表示 + 引用依赖，
便于现有消费方渐进迁移)：

```json
"attack_path": [
  {
    "step": 1,
    "injection_point": "dmz-web",
    "kill_chain_phase": "entry",
    "target_node": "target-1",
    "cve_id": "CVE-XXXX",
    "zone": "dmz",
    "flag": "flag{...}",
    "depends_on": [],
    "provides": ["shell"],
    "mitre_phase": "initial_access"
  },
  {
    "step": 2,
    "injection_point": "app-service",
    "kill_chain_phase": "foothold",
    "target_node": "target-2",
    "depends_on": ["target-1"],
    "provides": ["credential"],
    "mitre_phase": "execution"
  },
  {
    "step": 3,
    "injection_point": "data-store",
    "kill_chain_phase": "objective",
    "target_node": "target-3",
    "depends_on": ["target-2"],
    "provides": [],
    "mitre_phase": "initial_access"
  }
]
```

新增字段：
- `kill_chain_phase`：阶段角色(从 injection_point 继承, 软提示)。
- `depends_on`：上游**节点名**列表(slot 的 depends_on 解析为具体 target-N)。
- `provides`：攻陷后向下游提供的能力(取自第 3.1 节, 由 pivot_capability
  映射)。注意 objective 节点 `provides` 通常为空(终点)。
- `mitre_phase`：atom 的 primary_mitre_phase, **纯标注**, verifier 不用它
  做硬判定。

### 5.3 消费方改造影响面

1. **`scenario_runner.build_prompt`**：升级为显式依赖描述——"target-2 依赖
   target-1，先攻陷 target-1 获得 shell/credential 才能到达 target-2"。这是
   攻击真实性传递的关键点。kill_chain_phase 作为线索告诉 agent 各目标的
   攻击链角色。
2. **`verifier._evaluate_agent`**：引入可达性判定——若 target-1 未拿下，
   target-2 不可达，agent 没打 target-2 不算失败。按 DAG 拓扑序评估。
3. **`verifier._verify_environment`**：环境层(容器/readiness)每个 target 独立
   验证，**无需改造**。

### 5.4 向后兼容

- 无 `kill_chain_phase` 的模板 → ground_truth 不含新字段，所有消费方原行为。
- 无 `depends_on` 的节点 → 退化为平铺。
- `mitre_phase`/`provides` 缺失 → 消费方按原逻辑处理。

## 6. 数据模型变更摘要

### 6.1 InjectionPoint (template.py) — PoC 已落地

- `kill_chain_phase: Optional[str] = None`(语义: 软提示 + 拓扑位置声明)
- `depends_on: Optional[List[str]] = None`(语义: 可达性主约束)

### 6.2 match_kill_chain (cve_matcher.py) — 需按 v2 修订

PoC 第一版实现了 phase 硬政策(`KILL_CHAIN_PHASE_POLICY` 做 `required ∩ policy`
交集过滤)。v2 要**移除 phase 硬政策**，只保留：
1. 现有 match() 的 service_role / vuln_category 过滤
2. depends_on 可达性校验(上游 pivot_capability ≠ NONE)

`KILL_CHAIN_PHASE_POLICY` 表保留但降级为**软提示查表**(给 prompt 生成用)，
不再用于 matcher 拒绝。

### 6.3 待落地

- `scenario_assembler.assemble()`：生成 ground_truth 写入
  kill_chain_phase/depends_on/provides/mitre_phase。
- `scenario_runner.build_prompt()`：按依赖描述攻击链 + 阶段角色线索。
- `verifier._evaluate_agent()`：可达性判定。

## 7. 与项目"两种真实性"的对应(v2)

- **企业环境真实性**：由 `kill_chain_phase`(拓扑位置声明) +
  `isolation_rules`(网络隔离硬实现)共同保证。深层 slot 即使填入口类漏洞，
  外网也打不到，必须横移——网络层而非漏洞类型层保证真实性。
- **攻击场景真实性**：由 `depends_on` + 上游 `provides` 能力 + DAG 顺序共同
  保证。攻击链递进 = 上游立足点 → 下游可达，不依赖漏洞类型多样性。RCE 能
  在各层复用，系统可用性不受池子"缺 collection 类"影响。

## 8. 阶段 0 完成定义(v2)

本规范定义了：
- [x] 推翻第一版的理由(漏洞类型 ≠ 攻击链角色)
- [x] kill chain 阶段角色(4 阶段, 降为软提示, 不再硬卡口)
- [x] 主约束 = 前置可达性(depends_on + 上游 pivot_capability) + 拓扑位置
  (isolation_rules)
- [x] 3 模板 slot→阶段映射(v2: 不删 required_mitre 的 initial_access)
- [x] 缺口重新定义(可达性缺口 + 角色缺口, 不再按漏洞类型计数)
- [x] ground_truth DAG 结构 + 消费方改造影响面 + 向后兼容

留待后续：
- PoC 代码按 v2 修订(移除 phase 硬政策) — 阶段 4 切片
- 现有 109 atom 按新语义的覆盖矩阵(阶段 1, 按可达性/角色统计)
- CVE-Factory 定向补池清单(阶段 1 产出后)
- matcher/ground_truth/consumer 代码改造(阶段 4)