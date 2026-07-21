# 方向 4 阶段 2 交接：任务 A 已合并，接口确认与后续任务

> 创建：2026-07-20
> 来源：任务 A（L0/L1/L2 三档）已落地完成，方向 4 阶段 1 已完成。
> 依据：`docs/AGENT_INPUT_LEVEL_INTERFACE.md`、`docs/DECOY_PLAN_A.md` §"与任务
> A 的接口确认清单"、任务 A 实际落地代码（
> `scenario_runner.py` / `verifier.py` / `scenario_assembler.py`）。

本文档逐条回答方向 4 的 5 个接口确认清单，并给出阶段 2 的具体任务清单。方向 4
阶段 2 可据此立即开工。

---

## 0. 前提：任务 A 已合并，阶段 2 可启动

任务 A 已完成以下共享层改动（详见 `docs/WORK_PROGRESS_REPORT.md` 2026-07-20
"L0/L1/L2 三档实现落地"条目）：

- `scenario_runner.py`：L0/L1/L2 三档 prompt 结构 + level-aware hygiene 审计
  + SYSTEM_PROMPT 删除搜 PoC 指示；
- `verifier.py`：`_run_agent` 按档位裁剪 target payload + `_build_topology_hint`
  + `_is_credential_material` + `AGENT_CONTEXTS` 扩展；
- `scenario_assembler.py`：`assemble` 加 `agent_context` 参数，PoC bind mount
  按档位+材料类型条件化；
- `scenario.py` / `cli.py` / batch runner：`agent_context` 全链贯通。

方向 4 阶段 2 在上述合并版本上叠加，无 git 冲突。

---

## 1. 逐条回答接口确认清单

### 接口 1：L1/L2 拓扑块从哪个数据源取主机 IP（含 decoy 写哪里）

**答案**：

- 任务 A 的拓扑块由 `verifier.py::_build_topology_hint`（2099 行附近）构建，数据源：
  - `subnets`：从 `scenario.yaml` 的 `network_subnets` 列表读取；
  - `hosts`：**目前只从 `ground_truth["attack_path"]` 取 chain node**
    （`node (ip, zone: <zone>)` 格式）；
  - `pivot_hosts`：从 `ip_alloc` 取 `*router*` 节点的多 eth 接口。
- `decoy` IP 写在哪里：**写进 `ground_truth` 的新字段 `noise_nodes`**（你阶段 2
  §2.2 已计划）。`_build_topology_hint` 需要扩展，把 `noise_nodes` 的 IP/zone 也
  追加进 `hosts` 列表，与 chain node 同列、不加任何"decoy"标记。
- `ip_alloc` 侧：你的 assembler 拓扑注入把 decoy IP 分配进 `ip_allocations` 后，
  `_build_topology_hint` 不直接用 `ip_alloc` 取 target/decoy IP（它用
  `ground_truth.attack_path` + `noise_nodes`），所以你只需保证 `noise_nodes`
  里有 IP 即可。`ip_allocations` 主要给 verifier 的 readiness/attack-path 检查用。

**你要做的协调改动**：扩展 `verifier.py::_build_topology_hint`，在遍历
`attack_path` 之后追加遍历 `ground_truth.get("noise_nodes", [])`，把每个 decoy 的
`name (ip, zone: <zone>)` 追加进 `topology["hosts"]`。**不要给 decoy 加任何
"decoy"标签**——与 chain node 同列即可。这是唯一需要碰 verifier.py 的地方，
改动局部、通用。

### 接口 2：L2 "Services and known vulnerabilities" 块的 CVE 来源（decoy 不进）

**答案**：

- 任务 A 的该块由 `scenario_runner.py::_format_vulnerabilities_block`（319 行）渲染，
  **数据源是 `input_data["targets"]`**（即 verifier `_run_agent` 构建的 target 列表）。
- verifier 的 `_run_agent`（2248 行附近）的 `targets` **只来自
  `ground_truth["attack_path"]`**（level 模式裁剪后只保留
  `node_name/ip/zone` + l2 的 `cve_id/service_family`）。decoy 不在 attack_path，
  **天然不会进 `targets`，也就不会进 vulnerabilities 块**。
- **你无需做任何额外排除**。只要 decoy 不进 `attack_path`（你阶段 2 §2.2 已保证
  decoy 只进 `noise_nodes`），vulnerabilities 块自动只有 chain node 的 CVE。

**结论**：接口 2 无需协调，天然满足。

### 接口 3：input.json hygiene 审计规则（decoy IP 通过拓扑块进 input 不被误杀）

**答案**：

- 任务 A 的 hygiene 审计由 `scenario_runner.py::audit_no_hint`（212 行附近）实现，
  forbidden 模式集见 `LEVEL_FORBIDDEN_*`（222 行附近）。规则是**字段名/flag oracle
  关键字**匹配，不是 IP 值匹配：
  - `LEVEL_FORBIDDEN_BASE`：`/flag`、`flag_hint`、`flag_verify_command` 等；
  - `LEVEL_FORBIDDEN_ALL`（l0/l1/l2 通用）：`depends_on_nodes`、`execution_host`、
    `required_capabilities`、`readiness_probes`、`required_tools`、
    `environment_tools`、`execution_context`；
  - `LEVEL_FORBIDDEN_L0` 额外禁 `cve_id`/`ports`/`service_family`/`service_role`；
  - `LEVEL_FORBIDDEN_L1` 额外禁 `cve_id`；l2 只用 `LEVEL_FORBIDDEN_ALL`。
- **decoy IP 是数值（如 `192.168.100.4`），不是上述任何字段名/关键字**，通过拓扑
  块进入 input.json 的 `topology.hosts` 列表，不会被 hygiene 误杀。
- **但要注意一个边界**：decoy 节点的 `noise_nodes` 字段名本身不在 forbidden 列表，
  但 `noise_nodes` 若作为 `input_data` 的顶层 key 出现会被
  `serialized = json.dumps(input_data)` 序列化进审计文本。当前 forbidden 列表不含
  `noise_nodes` 字符串，所以**不会被拒**。不过为干净起见，建议 `noise_nodes`
  **不进 input.json**（只留在 `ground_truth.json` 供 verifier 用），拓扑块只把 decoy
  IP 混进 `topology.hosts` 列表——这样 input.json 里根本不出现 `noise_nodes` 字段名，
  hygiene 完全无感。

**结论**：`noise_nodes` 不进 input.json，decoy IP 只通过 `topology.hosts` 进入，
hygiene 不误杀。接口 3 无需特殊处理。

### 接口 4：PoC bind 条件化代码位置（拓扑注入插入点是否冲突）

**答案**：

- 任务 A 的 PoC bind 条件化在 `scenario_assembler.py::assemble` 的 **395-410 行**
  （attacker node binds 循环），位置基本未变，只是加了 `level` 分支判断。
- 你的拓扑注入在 §2.1 计划的 **479-487 行**（injection point 循环里加 clab node），
  以及 `_allocate_ips` 的 `zone_targets` 追加。
- 两段代码在 `assemble` 函数内**相邻但不重叠**：PoC bind 在 attacker 节点处理
  （函数前段），拓扑注入在 target 节点循环（函数中段）。任务 A 已合并，你直接在
  合并后的版本上叠加，**git 无冲突**。
- **插入点提醒**：你的 decoy 节点要在 `injection point 循环之后、_allocate_ips 调用
  之前`把 decoy 节点名追加进 `zone_targets`（你 §2.1 已正确识别），否则 decoy 会
  被当独立点对点链路。任务 A 没动 `zone_targets`/`_allocate_ips`，逻辑现成。

**结论**：接口 4 无冲突，按你 §2.1 计划执行即可。

### 接口 5：`agent_context` 取值扩展与 `--noise-level` 的正交关系

**答案**：

- 任务 A 的 `AGENT_CONTEXTS = (guided, no_guide, no_hint, l0, l1, l2)`。
  `no_hint` 是 l2 的 legacy alias。
- 你的 `--noise-level` 参数（`none` / `baseline`）与 `agent_context` **正交**：
  同一 `agent_context` 下可有/无 decoy。实验单元为：
  - L1 × {无 decoy (noise_level=none), 有 decoy (noise_level=baseline)}
  - L2 × {无 decoy, 有 decoy}
  - L0 不给拓扑，decoy 对 L0 无显式影响（但你仍可在 L0 部署 decoy，只是拓扑块不
    展示——这符合论文 L0 语义）。
- **fingerprint 必须把 `noise_level` 纳入**（你 §2.4 已计划），避免 `--resume` 跨
  noise_level 混模式。参照任务 A 把 `agent_context` 纳入 fingerprint 的做法
  （batch runner 的 `_worker_spec` / `batch_state.json` / `summary.json` 都记
  `agent_context`），你同样把 `noise_level` 加进这些地方。
- **batch runner 的 `--agent-context` choices 现已含 l0/l1/l2**，你的
  `--noise-level` 是独立参数，两者可自由组合。

**结论**：接口 5 正交，按你 §2.4 计划加 `--noise-level` 参数 + fingerprint 纳入。

---

## 2. 方向 4 阶段 2 任务清单（基于上述接口确认）

按 `docs/DECOY_PLAN_A.md` §2 执行，以下是基于任务 A 已合并版本的精确化：

### 2.1 assembler 拓扑注入（`scenario_assembler.py`）
- 在 injection point 循环之后，遍历 `template.noise_levels[noise_level]`，为每个
  `NoiseService` 生成 clab node（`kind: linux, image, env, cmd`）；
- 链接到其 zone 的 router（`_next_eth` 取下一个 eth，与 target 共享 zone LAN）；
- 在 `_allocate_ips` 调用前，把 decoy 节点名追加进 `zone_targets[zone]`，复用
  现有 bridge 逻辑——target 用 .2/.3，decoy 用 .4/.5/.6...；
- decoy 节点名前缀 `decoy-`，不挂任何 bind、不挂 flag、不进 injections/attack_path/
  agent_objectives/capability_closure；
- cve_setup 阶段给每个 decoy 加 TCP readiness probe（同 target 的 probe 逻辑）。
- **改动位置**：`assemble` 函数中段（479-487 附近）+ `_allocate_ips` 的
  `zone_targets` 追加。不碰 395-410 的 PoC bind（任务 A 领地）。

### 2.2 ground_truth 记 `noise_nodes`
- `ground_truth` 新增 `noise_nodes` 字段（非 `attack_path`），每个 decoy 记
  `{name, zone, ip, ports, image}`；
- **不进 Agent input.json 的 targets 列表**（verifier 的 `_run_agent` 只从
  `attack_path` 取 targets，天然排除 decoy）。

### 2.3 verifier 扩展拓扑块（**接口 1 的唯一协调改动**）
- 扩展 `verifier.py::_build_topology_hint`：在遍历 `attack_path` 之后，追加遍历
  `ground_truth.get("noise_nodes", [])`，把每个 decoy 的
  `name (ip, zone: <zone>)` 追加进 `topology["hosts"]`，与 chain node 同列、不加
  任何 decoy 标记；
- 这是唯一需要碰 `verifier.py` 的地方，改动局部、通用（不针对特定 CVE/模板）。
- 新增诊断性检查（非硬门）：扫 Agent session 的 bash 命令文本，匹配 decoy IP/端口
  出现次数，记入 `observed_progress.decoy_interactions` 或新字段。不做密码学级
  provenance，只做文本统计。

### 2.4 batch runner / matrix 适配
- `scripts/verify_enterprise3_guided_batch.py`：加 `--noise-level` 参数（默认
  `none`），把 `noise_level` 纳入 fingerprint / batch_state / summary / worker_spec
  （参照任务 A 对 `agent_context` 的处理），避免 `--resume` 跨 noise_level 混模式；
- `scripts/generate_enterprise3_matrix.py`：case 记录 `noise_level`，但 decoy 不
  影响 case 合法组合数（不参与 slot 匹配，只是部署期装饰），case ID 仍由 CVE
  三元组决定；
- `pipeline.generate` 已接受 `agent_context`，需再加 `noise_level` 参数透传给
  `assemble`（`assemble` 按 `template.noise_levels[noise_level]` 取 decoy 列表）。

### 2.5 L2 vulnerabilities 块（**无需协调**）
- decoy 不进 `attack_path`，verifier 的 `_run_agent` 只从 `attack_path` 取
  targets，`_format_vulnerabilities_block` 只渲染 `targets`——decoy 天然不进该块。
- 无需额外排除逻辑。

### 2.6 回归测试
- 新增 `tests/orchestrator/test_noise_nodes.py`：assembler 生成 decoy 节点+IP 分配、
  decoy 不进 attack_path/targets、`noise_level=none` 向后兼容、
  `_build_topology_hint` 含 decoy hosts 但无 decoy 标记、decoy_interactions 诊断
  统计；
- 现有 orchestrator 回归全通过（5 个既有失败与本改动无关：pandas 缺失 +
  CVE-2014-6271 verified 状态漂移 + atom-pool 漂移，2026-07-18 条目已记录）。

### 2.7 smoke
- 从现有 no-hint 71 条 manifest 选 4-8 条，用 `agent_context=l2 --noise-level
  baseline` 重跑，对比 `noise_level=none` 基线；
- 记录成功率 + decoy_interactions，写入 `data/scenarios_enterprise3_decoy_smoke/`；
- 完成后看成功率决策（DECOY_PLAN_A §"完成后的决策点"）：降到 ~45% 或更低→方案 A
  够；仍 >50%→上方案 B；下降 <5pp→直接方案 B。

---

## 3. 边界保护（重复强调，必须遵守）

- 不改 `scenario_runner.py` 的 `build_prompt` / SYSTEM_PROMPT / `audit_no_hint`
  forbidden 列表（任务 A 领地）；若必须改，先回协调；
- 不在 prompt 或 input.json 加 decoy 声明文本（论文硬约束）；
- `noise_nodes` 字段不进 input.json，decoy IP 只通过 `topology.hosts` 进入；
- 不改 matcher / capability_closure / 模板 injection_points/assets/objectives/
  isolation_rules；
- 不为 decoy 写 CVE-specific 或模板特判——decoy 生成逻辑必须通用，任何模板声明
  `noise_levels` 都能消费；
- 不引入需要外网 pull 的镜像。

---

## 4. 完成后的决策点与下一步

跑完 smoke 后按 `DECOY_PLAN_A.md` §"完成后的决策点"判断：

- 若 L2-with-decoy 成功率降到 ~45% 或更低：方案 A 足够，方向 4 暂停，配合方向 2
  的 Atom 异构度扩充重新生成 no-hint matrix 做大规模验证；
- 若仍 >50%：升级方案 B（zone 级输入，把 target IP/端口从 input 移除），需先与
  本会话协调 `build_prompt` 改动（那是任务 A 领地）；
- 若下降 <5pp：说明 Agent 仍能靠 input 直接点名跳过 decoy，直接上方案 B。

无论结果如何，把 smoke 结果与决策追加到 `docs/WORK_PROGRESS_REPORT.md` 带日期
条目（含成功率、decoy_interactions 统计、与无 decoy 基线对比、失败分类）。

---

## 5. 参考证据

- 任务 A 实现记录：`docs/WORK_PROGRESS_REPORT.md` 2026-07-20 "L0/L1/L2 三档实现
  落地"条目；
- 接口契约：`docs/AGENT_INPUT_LEVEL_INTERFACE.md`；
- 方向 4 计划：`docs/DECOY_PLAN_A.md`；
- 论文三档：`2606.14295v2.pdf` §3.3 / Figure 15 / §A.3；
- 任务 A 落地代码：`scenario_runner.py`（`_format_vulnerabilities_block` 319 行、
  `audit_no_hint` 212 行、`LEVEL_FORBIDDEN_*` 222 行）、`verifier.py`
  （`_build_topology_hint` 2099 行、`_run_agent` 2248 行 targets 只来自
  `attack_path`）、`scenario_assembler.py`（PoC bind 条件化 395-410 行）。