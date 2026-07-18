# RangeFactory 工作进展

> 最近更新：2026-07-15
> 对照 `docs/RANGEFACTORY_DESIGN.md` 的分阶段路线

---

## 本轮（2026-07-15）核心更新

### Atom 构建链路修复（共享层，非 case-by-case）

针对重跑暴露的系统性问题，在 atom 构建共享代码修了 4 个缺口：

1. **exploit_guide / capability_grants 一致性（agent_runner prompt + pipeline）**
   - agent prompt 增加一致性约束：`capabilities ⊆ capability_grants`、`principal == exploit_principal`、`reusable command_channel` 仅在有 `execute_command` 时声明
   - pipeline `_generate_exploit_guide`：guide 校验失败若是 reusable-channel 不匹配，自动降级 `reusable=false` 重试，不再静默丢弃
   - 影响：之前 LFI/SSRF 类漏洞因 agent 误声明 reusable channel 导致 guide 被静默丢弃，现在能正确生成 ready guide

2. **verified 解耦 orchestrated（pipeline + atom model）**
   - `verified` 只反映 native agent 结果（漏洞可利用），orchestrated 重建结果独立记为 `verification.environment_ready`
   - 模型 `_normalize_contract` 同步：native 成功即保持 verified，orchestrated 失败不再降级
   - 影响：之前 orchestrated 偶发失败（端口探测超时/compose 时序）会抹掉 native 成功事实，现在不会

3. **objective-evidence 类漏洞的 LLM checker fallback（pipeline `_save_atom`）**
   - 对不注入 flag 的 Info_Leak/Auth_Bypass/SSRF 类，agent `success=False` + 有 evidence 时也触发 LLM checker 仲裁，而非直接判 verified=False
   - `_run_llm_checker` 增加 openai SDK fallback（anthropic SDK 缺失时走 OpenAI 兼容 /v1 端点）
   - 影响：之前这类 atom 因 agent JSON 截断/SDK 缺失被系统性误杀，现在 evidence 被独立仲裁

4. **orchestrated 验证稳定性（pipeline `_run_orchestrated_verification`）**
   - 端口探测改用容器内 `/proc/net/tcp` 读 LISTEN 状态，替代每次 `docker run busybox nc`
   - DB/搜索类慢启动服务（5432/9200/3306/27017/6379 等）给 300s 探测窗口，普通服务 120s
   - 整体失败重试一次，过滤单次 compose 时序抖动
   - 影响：`environment_ready` 信号可信，不再因测量噪声误杀

5. **cleanup 权限修复（pipeline `_force_rmtree`）**
   - `rm -rf /wipe/*` 改 `rm -rf /wipe`，能删掉 `.claude_cache/backups` 里的隐藏文件（uid 1000 owned）
   - cleanup 失败不再阻断 run 的 success 判定

### 测试
- 新增 `tests/atomizer/test_silent_skip_fixes.py`（11 个测试覆盖上述修复）
- 更新 `tests/orchestrator/test_atom_contract.py`（verified 解耦契约）
- 全套 114 passed，无回归

### 工具
- `scripts/generate_exploit_guides.py`：用 LLM 从 native evidence + session 命令生成 ready guide（脱敏 flag、规范化 `{{target_ip}}` 占位符、校验）
- `scripts/rerun_capability_backfill.py`：批量重跑补 capability_grants，带备份保护、并行（--workers）、per-atom 详细日志、失败原因提取

---

## Atom 池现状（2026-07-15，缺口 A 修复后）

**缺口 A 已修复**：`--skip-agent` 结构性回填不再标 verified=True（pipeline 显式强制 verified=False）；存量 67 个虚假 verified atom 按标准批量降级（verified=True + 无 evidence + 无 grants + 无 ready guide → verified=False，并记录 downgrade_reason）。

按五字段客观状态（native_success + evidence + capability_grants + guide_ready + version）分四级：

| 级别 | 标准 | 数量 | Range 可用性 |
|---|---|---|---|
| **A-Mid** | 完整链 + execute_command | 37 | 可作链路中间节点/末端 |
| **A-End** | 完整链 + 无 execute_command（LFI 类）| 6 | 可作末端/独立 |
| **B** | native 验证过但无 grants（Info_Leak/Auth_Bypass/SSRF 类）| 4 | 漏洞可利用但能力契约不完整，Range 链路用不上 |
| **C** | ~~verified=True 但无 evidence~~ | **0**（已清理）| — |
| **D** | verified=False（含降级的 67 个 + 原本 unverified 122 个）| 189 | 不可用 |
| **合计** | | 236 | |

**池子现在账实相符**：verified=True 的 47 个都真跑过 native 验证（A 级 43 + B 级 4），台账数字和实际可用数对得上。

### A 级（43 个）= 当前真正可进 Guided Range 的池子

- **A-Mid 37 个**：有 execute_command + read_file，能闭包 network_vantage，可作 enterprise_3tier 的 dmz-web/app-service 中间层。service_role：web_application 31 / middleware 4 / system_service 1 / database 1
- **A-End 6 个**：CVE-2010-2861、CVE-2015-5531、CVE-2017-1000028、CVE-2017-14849、CVE-2018-18778、CVE-2023-26360。全是 LFI（目录遍历/任意文件读），正确地只有 read_file，作末端节点

### B 级（5 个）= 验证链路通了但 Range 用不上

CVE-2014-0160、CVE-2015-5254、CVE-2017-12636、CVE-2017-7494、CVE-2017-8386
- 多是 Info_Leak/Auth_Bypass/SSRF 或 unstable 类，漏洞本质无命令执行能力（grants=[] 正确）
- CVE-2014-0160 经 LLM checker 仲裁，verified=True 有独立背书，但无 grants + guide materials 一致性问题，进不了 Guided Range
- 这类是"验证链路通了但 Range 链路用不上"——价值在于验证模型修复，不在扩池

### C 级（66 个）= 虚假繁荣，待清理

`--skip-agent` 结构性回填的，从未真跑过 agent native 验证，verified=True 是误继承。这是缺口 A（pipeline 让 --skip-agent 回填标 verified=True）的直接后果。
- 待修缺口 A：pipeline 的 skip_agent 分支显式标 verified=False，新构建不再产生 C 级
- 存量 66 个需统一降级（按标准批量，非 case-by-case）

### 已知数据偏差
- CVE-2012-2122、CVE-2016-1897 在恢复操作中被误退回 v2（无 evidence），实际应是 B 级。这两个是台账 unstable，价值低，未专门修复

---

## 重跑实况

### 第一批（18 个有 evidence 的空 grants atom）— 成功
- 3 workers 并行，15/18 成功补 capability_grants + 重新生成 guide → 升 A 级
- 3 个 RESTORED（agent 跑通但没声明 grants，备份恢复原状）
- 验证了层次 1/2/3 + B 优化（orchestrated 稳定性）全部生效

### 第二批（63 个 structure_only）— 放弃全量重跑
- 这批从未真验证过，第一次真跑 agent 大多跑不通（Spring/Rails/WebLogic 等复杂框架漏洞，agent 在 max-turns 内收敛不了）
- 失败主因是 exploit 自动化难度，不是环境/API 问题（耗时 90-268s 证明 agent 在正常跑）
- 结论：不应盲目全量重跑 structure_only atom，需按 CVE 价值筛选

### B 级重跑（8 个）— 1 个升 A 级
- CVE-2017-17562 升 A 级（execute_command + read_file + guide）
- CVE-2014-0160 经 LLM checker 仲裁 verified=True，但仍 B 级（无 grants）
- 其余 unstable 类重跑失败，备份恢复原状

---

## Phase 0：保持当前基础并修正台账

**状态：已完成**

已保持的能力：
- v3 atom 的 `runtime_spec` / `source_bundle` / `validation_spec` / 双阶段验证（native + orchestrated）
- 环境验证与 Agent 成功验证分离
- `source_bundle` 收紧：attacker 只挂 PoC 材料白名单，排除 compose/README 泄漏
- ACL 已落地到运行时 `iptables FORWARD DROP`，attacker 不能直达 app/data
- entry 类 slot 增加 attacker 侧连通性验证，挡住"管理网监听"假阳性
- 9 个高置信 atom 的 `pivot_capability` 已手工修正为 `shell`

---

## Phase 1：最小 capability contract

**状态：第一版已完成，atom 迁移基本完成**

### 已实现

| 设计要求 | 代码位置 | 状态 |
|---|---|---|
| atom 模型增加 `exploit_access` | `atom.py:184` | 已实现 |
| atom 模型增加 `capability_grants` | `atom.py:194, 336` | 已实现 |
| 每条能力携带 `evidence_level`（verified/inferred/unknown） | `atom.py:128` | 已实现 |
| injection point 增加 `required_service_access` | `template.py:39, 67` | 已实现 |
| matcher 硬匹配 `exploit_access` vs `required_service_access` | `cve_matcher.py:83-130` | 已实现 |
| matcher 硬匹配 `required_assets`（资产闭包） | `cve_matcher.py:149-154` | 已实现 |
| `pivot_capability` 兼容映射为 `execute_command + network_vantage` | `atom.py:489-514` | 已实现 |
| `validate_atom_for_slot`（显式+自动共用校验） | `cve_matcher.py:133-157` | 已实现 |
| `rank_candidates`（按 capability 排序） | `cve_matcher.py:175` | 已实现 |
| `match_report`（编排可解释性输出） | `scenario.py:129` | 已实现 |
| `CapabilityType` 9 种能力枚举 | `atom.py` | 已实现 |
| `EvidenceLevel` 3 级证据 | `atom.py` | 已实现 |

### v4 构建流程改造（本轮完成）

| 改动 | 位置 | 状态 |
|---|---|---|
| SYSTEM_PROMPT 增加 capability capture + guide 一致性约束 | `agent_runner.py` | 已完成 |
| agent 输出 JSON schema 增加 `exploit_principal`/`exploit_access`/`capability_grants` | `agent_runner.py` | 已完成 |
| `_save_atom` 从 agent 输出提取 `ExploitAccess` + `CapabilityGrant` | `pipeline.py` | 已完成 |
| `_generate_exploit_guide` reusable channel 自动降级 | `pipeline.py` | 已完成 |
| objective-evidence 类 LLM checker fallback + openai SDK | `pipeline.py` | 已完成 |
| verified 解耦 orchestrated | `pipeline.py` + `atom.py` | 已完成 |
| orchestrated 端口探测 /proc/net/tcp + 慢启动自适应 + 重试 | `pipeline.py` | 已完成 |
| cleanup `_force_rmtree` 隐藏文件删除修复 | `pipeline.py` | 已完成 |
| 37 个 atom 已有完整 capability_grants + ready guide（A-Mid）| `data/atoms/*` | 已完成 |

### 测试覆盖
- `test_capability_closure.py`：闭包规则单测
- `test_atom_contract.py`：`exploit_access` / `capability_grants` + verified 解耦单测
- `test_silent_skip_fixes.py`：本轮 4 个共享层修复的回归测试
- 全套 114 passed

---

## Phase 2：模板资产关系与最小 artifact 链

**状态：第一条链路已完成，扩展待做**

（详见上一版，enterprise_3tier internal-api 配置凭据 → customer-db → canary row 运行时验证已完成）

待做：
- 扩展资产类型：`api_token`、`ssh_private_key`、`source_repository`
- 扩展能力闭包规则：`write_file`、`database_query`、`outbound_request`、`authenticated_session`、`privilege_transition`
- 更多模板的资产链

---

## Phase 3：自动候选治理与 atom 池扩展

**状态：进行中**

### 当前优先级
1. 修缺口 A（pipeline 让 --skip-agent 不标 verified），清理 C 级 66 个虚假 verified
2. 用 A 级 43 个推进 Range 编排实验（不再纠结 C 级重跑）
3. 按 CVE 价值筛选扩展新 atom（见 AGENTS.md 扩池原则）

### CVE-Factory 扩池现状

| 项目 | 状态 |
|---|---|
| 567 个 direct-fit 候选已扫描 | 已完成 |
| 20 个 wave1 source 已准备 | 已完成 |
| 适配层 `prepare_cve_factory_sources.py` | 已完成最小版本 |
| 实际 atomize 验证 | 已验证 1 个能 build + 启动 + agent 探测 |
| 端口暴露适配 / PoC 提取 / 验证标准映射 | 待做 |

---

## 端到端验证结果

### 三层企业网络（enterprise_3tier）

| 验证项 | 结果 |
|---|---|
| 环境验证（deploy + base + ACL + readiness） | 5/5 稳定通过 |
| Agent full 验证（含分层 pivot） | 2 次真实通过 |
| 批量 5 个 full | 累计 2/5 |
| 失败主因 | 80 turns 超时（已调到 120）+ CVE-2017-10271 专项问题 |

### 最有代表性的成功案例

`enterprise3-mainline-full`：三层 pivot 链真实通过
- target-1（CVE-2018-16509）→ target-2（CVE-2012-1823）→ target-3（CVE-2014-6271）

`enterprise3-batch-003-rerun`：120 turns + 优化 prompt 后通过
- target-1（CVE-2012-1823）→ target-2（CVE-2014-3120）→ target-3（CVE-2019-9193）

---

## 当前活跃任务

1. 修缺口 A：pipeline `--skip-agent` 回填标 verified=False，清理 C 级 ✅ 已完成
2. 用 A 级 43 个推进 Range 编排实验
3. 按 CVE 价值筛选扩展新 atom（LPE/credential/lateral/persistence/collection 类，填补模板多样性缺口）

---

## 2026-07-16 更新：glm5.2 适配 + CVE-Factory 源打通

### glm5.2 agent runner（摆脱 claude_agent_sdk 绑定）

DeepSeek API 余额耗尽后切到 glm5.2，但 glm5.2 不支持 Claude 协议。实现 OpenAI 协议 agent runner 替代：

- **`openai_agent_runner.py`**：用 openai SDK + stream + function calling 实现 agent 循环，复用 agent_runner.py 的 SYSTEM_PROMPT/build_prompt/extract_json/extract_flag/redact_secrets
  - 关键：glm5.2 在 PKU 网关上 **tool_calls 只在 stream 模式返回**（非 stream 被吞），所以必须 stream=True 聚合
  - 自实现 bash/read_file/write_file 工具 + turns 计数 + session.json 保存（和原 runner 同格式）
- **`researcher.py` 协议选择**：`_uses_openai_protocol(model)` 按模型名自动选 harness——glm-5.x → openai runner，deepseek/claude → 原 claude_agent_sdk runner。设 OPENAI/ANTHROPIC/LLM 三套环境变量，openai 协议时容器启动后 pip3 install openai
- **测试**：CVE-2012-1823 用 glm5.2 端到端跑通 A 级 atom（execute_command+read_file+guide ready）。29 个单元测试无回归

### CVE-Factory 源打通（network: host 适配）

CVE-Factory 的 Dockerfile 在 build 时 `git clone github`，容器内 build 网络访问不通 github（exit 128）。解决方案：**不用 DinD，宿主机直接 build，给 compose build 加 `network: host`** 让 build 容器用宿主网络访问 github。

- **`prepare_cve_factory_sources.py`** 适配层加 `build.network: host`（自动给所有 CVE-Factory task 配置）
- **pipeline pull 修复**：compose 同时有 image+build（CVE-Factory 风格）时不再 pull 本地标签，改 pull Dockerfile 的 base image
- **`_build_capability_contract` 兜底**：agent 没输出 exploit_access 且无 ports 时返回默认 ExploitAccess（修 None crash）
- **试跑 4 个 easy RCE**：1/4 成功——CVE-2021-32568 (MrDoc) 升 A 级（execute_command+read_file+write_file+guide ready，Range 可加载），3 个失败（agent 没收敛/build 问题）
- CVE-Factory 567 候选池大，1/4 成功率意味着潜在 ~140 个可成，比 Vulhub 剩余 12 个容量大

### APT 阶段缺口的判断

CVE-Factory 567 个本质是 web 应用 bug-fix 训练任务（单 web 容器），**不覆盖系统级 LPE/credential/lateral/persistence/collection**。之前扫到的"credential_access 93 个"是 web 认证模块关键词误匹配，不是系统级凭据访问。要填真 APT 阶段需要别的源（自建内核 LPE/多主机 AD 环境）或调整阶段定义（web 变体也算）。当前优先扩 A-Mid 数量。

---

## 2026-07-16 更新：v2 exploit_guide 适配（响应 Range 侧需求）

### 背景

Range 侧（codex）扩展了 `shared/models/exploit_guide.py` 加 v2 guide 格式：每个 step 声明 `execution`（scope: actor/target、tools 带 kind 分类、materials 带 delivery 模式、external_download 禁止、fallback_ids）。Range preflight 用这些做工具检查 + 材料交付规划。v1 guide 无 execution，Range 标 `unknown_legacy` 不算正式可用。

### atom 侧适配

1. **`generate_exploit_guides.py` v2 适配**：prompt 要求 LLM 填 execution 字段（scope/tools/materials/external_download/fallback_ids），schema 示例改 v2，materials 统一用 `source_bundle/<file>` 前缀。HARD RULES 加 v2 execution 要求
2. **agent_runner system prompt**：codex 已加 v2 execution 要求（第 274-286 行 + schema 示例 v2）
3. **pipeline `_generate_exploit_guide`**：天然兼容 v2——降级逻辑只改 command_channel 不动 steps/execution；v2 校验在模型层 + validator 已就绪
4. **存量 44 个 v1 guide**：批量标 `review_required`（按 v1 标准降级，不删），然后用 v2 适配后的 generate_exploit_guides.py 全部重生成成 v2

### 结果

- **47 个 guide 全部 v2 化**（status=ready，format_version=2），可进 Guided Range
- 0 个 review_required / unknown_legacy
- v2 guide 每个 step 有 execution 声明（scope/tools/materials/external_download=false）
- 测试：CVE-2018-16509 v2 guide Range 能加载，execution 字段完整

### 注意

v2 guide 的 execution 字段质量依赖 LLM 生成质量（scope/tools/materials 是否准确）。当前是批量 LLM 生成，未经逐个语义审核。Range preflight 会在部署时校验 execution 声明的工具是否真的在节点上，不匹配会标 incompatible——这层校验由 Range 侧负责。

---

## 2026-07-16 更新：Guide 契约收紧（响应 Range 侧需求）

### 背景

Range 侧要求 47 个 ready v2 guide 的能力/材料/质量满足严格契约。本轮收紧通用生成与校验逻辑，不降标准保留 ready。

### 修改

1. **能力受 capability_grants 约束**（`exploit_guide.py` `generate`）：调 `validate_exploit_guide` 时传入 `declared_capabilities=set(capabilities)`；Guide 声明未在 verified grants 中的能力 → 校验失败。pipeline 传 capabilities 时只取 `evidence_level == VERIFIED` 的 grant（过滤 inferred）。
2. **保留 source_bundle 嵌套路径**（`generate_exploit_guides.py`）：`Path(m).name` 扁平化改为保留相对路径（`source_bundle/www/index.php` 不丢 `www/`）。生成前校验材料在磁盘存在，缺失则失败标 review_required。
3. **不把 transcript 探测命令当正式路径**（`generate_exploit_guides.py` `extract_session_commands`）：过滤 ping/nmap/port-scan/whoami/ls 等纯探测命令，只传 exploit 相关命令给 LLM 参考。Guide 步骤仍由 LLM 按 prompt 约束只保留成功路径。
4. **失败标 review_required**（`generate_exploit_guides.py` `main`）：guide 校验失败时把 atom.yaml 的 ref.status 降级为 review_required，不遗留 stale ready。
5. **版本**：atom v3 + guide format_version 2 不变。v1 guide 写入自动降级 review_required。

### 47 个 atom 审核结果

用新契约对 47 个 ready guide 重新校验（`scripts/audit_ready_guides.py`，调 Range 的 `_load_atom_guide` 走完整 validate）：**47 ready, 0 downgraded**。现有 guide 的能力声明都与 verified grants 一致，全部通过新校验。

### 测试

新增 8 个回归测试（`tests/orchestrator/test_exploit_guide.py`）：
- 能力一致性：未在 verified grants 的能力被拒 / 有 verified grant 通过 / unverified grant 不进 guide
- source_bundle 路径：嵌套路径不扁平化 / 扁平化形式被拒
- Guide 质量：native IP 拒绝 / 真实 flag 拒绝 / 无 success_signal 拒绝
- 版本兼容：atom v3 + guide v2 读写 / v1 写入降级 review_required

全套 40 passed，无回归。

### 交付

- 修改文件：`exploit_guide.py`、`pipeline.py`、`generate_exploit_guides.py`、`test_exploit_guide.py`、新增 `scripts/audit_ready_guides.py`
- 47 个 atom 审核结果：47 ready, 0 review_required
- 无降级 atom（现有 guide 与 verified grants 一致）
- 无需 Range 侧处理的契约问题

---

## 2026-07-17 更新：Runtime-ready 变体与 data-layer 供给

### 记录规则

- `docs/WORK_PROGRESS_REPORT.md` 是 Atom 与 Range 的协作进度日志。
- Atom 的 native/source-bundle/Guide/runtime 事实与 Range 的环境、攻击图、
  Guided Agent、业务目标结果必须分开记录；候选、拒绝项和已完成 Atom 不得混写。
- 最新 data-layer Atom 工作边界以
  `docs/OPENCODE_DATA_LAYER_ATOM_TASK.md` 为准：Atom 侧建立真实数据服务候选并
  构建少量高价值 Atom；Range 侧通用 data-layer 契约由 Codex 后续发布。

### 已完成 Atom runtime 记录

| Atom | 原定槽位/实际服务 | 状态 | runtime image | 证据与限制 |
|---|---|---|---|---|
| CVE-2019-17558 | app-service，Solr HTTP/8983 | runtime-ready | `cvelab-runtime-2019-17558-9a0ecf29fcdb` | native/orchestrated 成功、Guide v2 ready、完整 smoke 与服务 readiness 通过；source bundle hash `b7d46a4107fff9b7`。 |
| CVE-2021-42013 | dmz-web，Apache HTTP/80 | runtime-ready | `cvelab-runtime-2021-42013-3d625bc3c037` | native/orchestrated 成功、Guide v2 ready、完整 smoke 与服务 readiness 通过；共享 builder 保留原 Dockerfile，source bundle hash `533840f5546f481b`。 |
| CVE-2018-10933 | system_service，libssh SSH/22 | runtime-ready，但不属于 data-layer | `cvelab-runtime-2018-10933-b8be86362f9f` | native/orchestrated 成功、Guide v2 ready、完整 smoke 与 SSH readiness 通过；source bundle hash `c475304681ad8397`。因非数据服务，禁止作为 enterprise_3tier data-store 伪替换。 |

共享 runtime 修复：`remote-protocol` Profile 现在只安装和 smoke Atom 实际声明的
remote logical tools；此前仅需要 Paramiko 的 Atom 会被无关的 Impacket/PySMB 包
阻断。`tests/shared/test_runtime_tools.py` 与
`tests/atomizer/test_runtime_builder_flow.py` 共 38 项通过。

### Range 状态与交接

- Codex 的最新 data-layer 任务确认：B0、仅替换 DMZ 的 B1、仅替换 app 的 B2 已有
  完整 Guided Range anchor；OpenCode 不运行 Range、ContainerLab 或 Guided Agent。
- OpenCode 已对 `CVE-2022-22965 -> CVE-2018-16509 -> CVE-2019-9193` 完成一次
  environment-only 基线检查：runtime image digest、服务 readiness、攻击路径与隔离
  规则均通过。该结果只证明 Range 环境，不替代 Codex 的 Guided 结论。
- 旧的 B3 PostgreSQL/5432 单变量搜索已确认没有非基线可接受候选：
  `CVE-2018-1058` 依赖外部超级用户 `pg_dump`，`CVE-2021-23222` 是客户端 MITM，
  `CVE-2022-24128` 无可证实后利用能力。均未构建，也未修改模板或 matcher。

### 候选治理与 data-layer 下一步

- 旧的按 enterprise_3tier 槽位整理的候选清单位于
  `data/enterprise_3tier_next_atom_queue.md`。其中的 future/rejected 条目不是高质量
  Atom；只有明确标记为 verified 的条目才可进入后续 Atom 验收。
- 当前优先任务切换为通用 data-layer 候选队列：真实 PostgreSQL、MySQL/MariaDB、
  Elasticsearch、CouchDB、Redis 等数据服务均可评估，必须如实记录协议、端口、
  认证模型、数据操作和已验证能力，不能把 SSH 或普通 Web 服务标为 database。
- 在 Codex 发布通用 data-layer Range 契约前，不新增 Atom schema 字段，不改模板、
  matcher、orchestrator 或 verifier。完成 Atom 验收后交给 Codex 执行 slot preflight、
  environment-only 和一次 Guided Agent trial。

### 通用 data-layer 候选队列与首个 Atom

- 已建立 `data/data_layer_atom_candidate_queue.md`。队列按真实数据服务记录协议、
  端口、认证、数据操作、能力证据、自动化/环境风险和优先级；旧的
  `data/enterprise_3tier_next_atom_queue.md` 已标记为历史 PostgreSQL/5432 B3 缺口。
- `CVE-2015-1427`：Elasticsearch 1.4.2，HTTP/9200，无认证。它是当前首个完成的
  通用 data-layer Atom，分类为 `structure-healthy` / data-layer candidate，尚非
  template-anchor。
  - native 与 orchestrated 验证已有成功记录：root `execute_command`、`read_file`，
    服务端口 9200 可达；Guide v2 status `ready`，先创建索引文档再通过 `_search`
    执行 Groovy RCE。
  - source bundle 自包含且 manifest hash 未变，聚合 hash：`40c670cd24909f4b`。
  - runtime image：`cvelab-runtime-2015-1427-cb72d50a9a0c`；runtime digest：
    `sha256:49186dafb5edc77d87a0ac235975fc0f50eeb61bdb709d057f1a344985017896`。
    runtime contract、全量 smoke 与 Elasticsearch/9200 service readiness 均通过。
  - 已知限制：当前 Atom 的历史 `service_role` 仍为 `web_application`，虽然实际
    服务是 Elasticsearch 数据服务。未作单 Atom matcher/template 特判；待 Codex
    发布通用 data-layer 契约后，以共享规则核对或纠正该服务语义。
  - 下一所有者：Codex。在通用 data-layer 契约发布后执行 slot preflight、
    environment-only 和一次 Guided Agent 验证。

---

## 2026-07-18 更新：CVE-2015-1427 data-layer Atom 验收（Codex）

### 验收范围与结论

- 已核对 `data/data_layer_atom_candidate_queue.md`、历史 PostgreSQL B3 队列、
  `atom.yaml`、v2 Guide、runtime manifest 和 source-bundle hashes；候选治理和
  Atom/Range 责任边界记录符合 `OPENCODE_DATA_LAYER_ATOM_TASK.md`。
- `CVE-2015-1427` 通过 Atom schema 与 Guide schema 解析；`verified=true`，
  native evidence 记录 root `execute_command` 与 `read_file`，runtime status 和
  runtime verification 均为 `ready`，9200 service readiness 为真，source bundle
  hashes 无不一致。
- 相关 runtime、matcher 与 assembler focused tests：**96 passed**。
- 分类结论：**structure-healthy / data-layer research candidate**；尚不是
  `template-candidate` 或 `template-anchor`，本次没有运行 Range、
  environment-only 或 Guided Agent。

### 未通过提升门槛的共享问题

1. Atom 目前的 `service_role=web_application`，Guide 也继承该值；但服务镜像和
   9200 contract 表明它是 Elasticsearch 数据服务。根因是共享 Atom service-role
   推断的 database keyword 未覆盖 Elasticsearch，而不是应在 Range 中为该 CVE
   特判。
2. native evidence 证明了 RCE 与 flag 文件读取；Guide 的“创建文档”步骤不等于
   原生验证记录已独立证明索引数据的创建与查询。因此“可作业务数据资产”的数据
   操作仍需通用证据门槛，不能仅由 Guide 描述推断。

### 下一所有者

- **OpenCode**：在共享 Atom 构建/审核逻辑中处理数据服务的语义分类和数据操作
  evidence admission；不修改单个 Atom 或 Range 模板作为绕过。
- **Codex**：按 `DATA_LAYER_RANGE_CONTRACT_PLAN.md` 实现 template-side
  DataServiceAdapter 与相应 Range 测试；该工作可与 OpenCode 的修复并行，但在
  上述两项 Atom 事实补齐前不得把 CVE-2015-1427 接入 Range。

---

## 2026-07-18 更新：第一版通用 Range 编排实现（Codex）

### 范围修正

- 本阶段目标改为批量扩展 Atom 与 Range 组合；不把 CRUD/data-operation witness、
  真实凭据绑定或 Agent 资产使用证明作为 Atom 或 Range 的首轮准入门槛。
- `service_family` 仅是从 runtime image、服务名和端口推断的兼容元数据，用于避免
  在不兼容服务中执行资产初始化命令；它不是 Agent 声明，也不表示业务数据能力已获证明。

### 已完成的共享实现

- 新建 Atom 会将 `runtime_spec.service_family` 写入 Atom；旧 Atom 在 Range 读取时
  自动回退推断，因此未批量修改历史 `atom.yaml`。
- `enterprise_3tier` 的 `customer-records` 改为 template-owned service variants：
  PostgreSQL/5432 与 Elasticsearch/HTTP 9200 分别生成 setup、verify 与私有 objective
  assertion；`app-db-credential` 不再阻塞 data-store 选择。
- 自动匹配与显式 CVE 都在生成前使用同一 variant 兼容检查。生成结果、ground truth、
  match report、验证结果记录所选 variant 和运行时服务元数据；Agent 输入仅接收公开 hint。
- 新增无部署 matrix 生成器与 manifest 驱动的批量运行入口。matrix 记录可接受组合和
  被拒绝分支；实际部署仍须通过显式 `--max-cases` 限制规模。

### 验证与下一步

- 聚焦测试：**151 passed**（service resolver、matcher、template、assembler、verifier）。
- 生成期 smoke：PostgreSQL 与 Elasticsearch 指定三跳组合均成功解析对应 variant；
  公开 Agent objective 不含 reference command、success pattern 或 canary。
- matrix smoke 成功生成并被 batch runner 的 `--generate-only` 模式读取；尚未运行本轮
  Elasticsearch ContainerLab environment-only 或 Guided Agent，下一所有者为 Codex。

---

## 2026-07-18 更新：enterprise_3tier 通用 variant 首批环境验证

- 批次：`data/scenarios_enterprise3_matrix/summary.json`，5 个 matrix case，
  `environment_only=true`，均由真实 ContainerLab 部署后清理。
- 结果：5/5 `success=true`、`environment_verified=true`、
  `environment_success=true`、`attack_graph_valid=true`、
  `attack_path_reachable=true`、`range_build_verified=true`；所有 asset setup/verify
  均通过。
- 后端覆盖：4 个 Elasticsearch/HTTP 9200 `customer-records` variant（包含
  `CVE-2015-1427`），1 个 PostgreSQL/5432 variant（`CVE-2019-9193`）。
- Runtime 事实：`CVE-2015-1427` 与 `CVE-2019-9193` 均选择并验证本地 runtime image；
  `CVE-2014-3120` 通过 source-image fallback 完成环境验证，不能因此宣称它具备
  runtime-ready 资格。
- 本批未运行 Guided Agent，`guided_trial_*` 与 `objective_achieved` 为 false 是
  environment-only 的预期结果，不是失败。下一步应选择一个 PostgreSQL 和一个
  Elasticsearch 组合各运行一次 Guided Agent 验证，再扩大 environment-only matrix。

---

## 2026-07-18 更新：批量扩展执行边界与后续计划

- 已将近期工作统一为“高可信 Atom 批量供给 + 覆盖优先 Range 批量编排”，不再针对
  上述五个 case 或任一 CVE 做通过率定制优化。
- OpenCode 的下一工作是基于能力、自动化稳定性、多样性、环境可靠性评估并构建一批
  Atom；仅允许通用 Atom-side 修复，失败候选按类别记录并跳过。
- Codex 的下一工作是实现 bounded matrix 的覆盖优先抽样，并按
  `generate-only → environment-only → representative Guided-Agent` 的分层流程
  执行通用 Range 验证。
- 较早记录中关于“data-operation evidence admission”或“先为单一数据层候选补齐事实
  才能接入 Range”的表述，已被当前第一阶段范围修正取代：这些研究项保留到后续阶段，
  不再阻塞 Atom 供给或 Range 批量组合。

---

## 2026-07-18 更新：批量 Atom 供给 Wave 2026-07-18

### 选择依据

本批按候选池整体的 capability、自动化稳定性、服务族多样性和环境可靠性
评估，不针对某一个 Range case 做适配。详细批次状态见
`data/atom_batch_2026-07-18_status.md`。

### 接受候选

- `CVE-2022-0543`：Redis 5.0.7，RESP/TCP 6379，无认证；native evidence 已
  证明 root `execute_command` 与 `read_file`，Guide v2 `ready`。
- source bundle 自包含，aggregate hash `926550b0b05e55db`，manifest/hash 校验
  通过。
- runtime image：`cvelab-runtime-2022-0543-e422f13fd5b6`。
- base digest：`vulhub/redis@sha256:495ae9193570b0104163be0533a506479d1bf6df97cde0e74551ea0f94a6383f`。
- runtime digest：`sha256:fcb14f42a918acbe68a1269b7ff9ea6979594238c52963fa53d4890e91d3bcc0`。
- runtime smoke 和 Redis/6379 service readiness 通过；Atom 分类为
  `structure-healthy` / runtime-ready data-service candidate。
- 当前限制：`exploit_access.required_service` 为空，权威 audit 仍为
  `review_required`；未新增 CVE 分支或 Range 特判，暂不称为 template-candidate。

### 本批 deferred/rejected

- `CVE-2019-0193`：environment/build risk；精确 `vulhub/solr:8.1.1` image 不在
  本机，不能用 8.2.0 替代。
- `CVE-2016-3714`：validation-model mismatch；source bundle 中 `index.php`
  文件/目录冲突，破坏自包含 Compose materialization。
- `CVE-2016-3088`：environment/build risk；漏洞入口 HTTP/8161 与当前 runtime
  首探 61616 不一致，不能把 broker readiness 当作 exploit-service readiness。
- `CVE-2017-10271`：deferred for a later service/template family；WebLogic 旧启动
  与 data-plane binding 风险未解决。
- `CVE-2019-20933`：validation-model mismatch；当前仍为 v2/unverified，缺 source
  bundle、ready Guide 和 verified capability。
- `CVE-2017-12635`：deferred for a later service/template family；无 native 成功
  与完整 v3 contract。

### Range 交接边界

本批没有修改或运行 Range template、matcher、composer、verifier、generated
scenario 或 Guided Agent。Codex 后续负责重新生成覆盖优先 matrix，并执行
`generate-only → environment-only → representative Guided Agent`；Range 结果
必须与上述 Atom native/runtime 事实分开记录。

---

## 2026-07-18 更新：coverage-first Range matrix 选择（Codex）

- `scripts/generate_enterprise3_matrix.py` 已从“递归过程按字典序提前截断”改为：先枚举
  全部合法组合，再在显式 `--max-cases` 预算内按 slot-Atom 与 asset variant 的新增覆盖量
  做确定性贪心选择。该规则不读取 Range 历史成败，也不含 CVE、模板或生成场景特判。
- Manifest 现在记录完整合法组合数、选择策略、每个 case 的 slot-Atom 映射和运行时服务族，
  使后续环境/Guided 批次可追溯其覆盖范围。
- 当前池 smoke：从 **2,106** 个合法组合中选择 5 个时，首批覆盖不同的 dmz/app/data
  Atom，并同时包含 PostgreSQL 与 Elasticsearch `customer-records` variant。
- 回归：matrix selection 新增 2 个单元测试；与既有 service resolver、matcher、template、
  assembler、verifier 聚焦测试合计 **153 passed**。
- 下一步：等待 OpenCode 的 Atom 供给批次；交付后重新生成 matrix，以同一通用选择规则
  执行分层批量验证。Guided 结果只用于识别跨组合共享失败类别。

---

## 2026-07-18 更新：OpenCode 首批 Atom 供给交接验收（Codex）

- OpenCode 已完成候选整体评估与首个可接受交付：`CVE-2022-0543`（Redis 5.0.7 / RESP
  6379）。Atom 为 v3，source bundle aggregate hash 为 `926550b0b05e55db`；native 与
  已有 orchestrated 记录成功，runtime image、digest、完整 smoke 与 service readiness
  均为 ready。verified capability 为 root `execute_command`、`read_file`。
- Guide v2 文件未显式写出 `status`，但共享 `ExploitGuide` schema 的默认值为 `ready`；
  因此其当前 Guide 解析状态为 ready，而非需要为该 Atom 添加专用字段。
- Atom 仍是 `structure-healthy` / runtime-ready Redis data-service candidate，尚非
  `template-candidate`：其 `exploit_access.required_service` 为空，且当前
  `enterprise_3tier.customer-records` 仅有 PostgreSQL 与 Elasticsearch variant。
  这是当前模板兼容范围的正常结果，不是缺陷，也不应通过 CVE 特判绕过。
- 无部署 matrix smoke 在当前 Atom 池中仍产生 **2,106** 个合法现有组合；Redis Atom 的
  拒绝原因仅为通用 `asset_service_variant_incompatible` 或既有 slot/dependency 条件，未被
  错误选入 PostgreSQL/Elasticsearch 数据层。
- 首批延期候选均已按 environment/build risk、validation-model mismatch 或 deferred
  service/template family 记录。当前没有证据需要修改 Range 代码；下一步由 OpenCode
  按同一批量价值评估继续供给 Atom，Codex 在 Atom 池扩大后重建 coverage-first matrix。

---

## 2026-07-18 更新：Atom 重建共享契约复核与修复（Codex）

- 复核后修正了先前的笼统表述：精确 `vulhub/solr:8.1.1` image 不可得不是当前
  runtime builder 的代码 defect。builder 已使用声明的精确 source image，不能用其他
  版本替代；该候选只有在精确镜像可拉取或可从原始材料构建时才能重建。
- 已修复 source-bundle 的共享时序缺陷：Atom rebuild 现在会在 orchestrated
  environment verification **之前**重新捕获原始源树。验证的 bundle 因此不再依赖旧
  Atom 遗留目录；原始源中为文件的路径会替换旧 bundle 中同名目录。
- 已修复多端口服务的共享 readiness 契约：native/orchestrated verification 和 runtime
  smoke 现在优先探测 `exploit_access.required_service.port`，只有缺失时才回退 Compose
  的第一个端口。该规则适用于所有多端口 Atom，不针对 ActiveMQ 或任一 CVE。
- 回归：source-bundle stale-directory/file replacement、pipeline readiness selection、
  runtime readiness selection 新增覆盖；相关测试 **21 passed**。扩展 Atomizer 测试中
  35 passed / 2 skipped，另有 1 个既有 parquet 测试因环境缺少 `pandas` 失败，与本次
  修改无关。

---

## 2026-07-18 更新：数据集生产阶段一已定义

- 本周目标已明确为百级高可信 Atom 与 500–1000 条完成 Guided-Agent 验证、保留完整
  结果记录的 Range 实验；通过数量仍与环境/攻击图/Agent/objective 各项结果分开报告。
- 阶段一将先生成不修改 Atom 的重建审计与批次清单，再由 OpenCode 使用共享流水线完成
  有界重建 wave，最后由 Codex 做 Atom contract 验收和无部署 matrix 重建。
- 详细责任边界、分类、交付物与验收标准见
  `docs/STAGE1_ATOM_RECONSTRUCTION_PLAN.md`。该计划禁止按单个 Range/CVE 写特判，
  且不把业务数据证据作为当前 Atom 准入门槛。

---

## 2026-07-18 更新：阶段一 A1/A2 重建审计与首批 wave 已交付（Codex）

- 已执行只读 `scripts/audit_atom_reconstruction.py --max-wave 25`，生成：
  `data/atom_reconstruction_audit.json`、
  `data/atom_reconstruction_audit.csv`、
  `data/atom_reconstruction_wave.json`。
- 审计覆盖 **239** 个 Atom：`range_ready=5`、
  `rebuild_runtime_or_bundle=42`、`full_reconstruction=192`。本地 source-image
  可见性单独记录，不因“当前未本地缓存”自动判为 source unavailable。
- 首批 wave 包含 **25** 个由相同 value/risk 规则排序的重建候选；每条均包含分类、原因、
  service/access、verified capability、native/environment/Guide/runtime 状态和本地镜像
  可见性，供 OpenCode B1 消费。它不是从任一失败 Range 手选的 CVE 清单。
- 审计脚本回归 **2 passed**；该脚本只读取 Atom 文件和本地 Docker image visibility，未
  调用 LLM、未拉取镜像、未修改任何 Atom。
- 下一所有者：OpenCode 按 `data/atom_reconstruction_wave.json` 执行 B1，逐项记录完整
  重建结果；Codex 随后进行 A4 contract 验收和 matrix 重建。

### Phase 1 handoff check

- 已核对第一阶段执行顺序：Codex A1/A2 先生成不修改 Atom 的
  `data/atom_reconstruction_audit.json/csv` 与 bounded reconstruction-wave
  manifest，随后 OpenCode 执行 B1。
- 当前工作区尚未提供上述 reconstruction audit 或 selected-wave manifest；现有
  `data/atom_batch_2026-07-18_status.md` 与历史候选队列不是该阶段的 machine-readable
  handoff，不能替代 A1/A2 结果。
- 因此 OpenCode 尚未启动新的 Phase 1 Atom 重建，也未从旧队列擅自挑选 CVE；否则会绕过
  计划要求的整体池审计、分类和确定性 wave 选择。
- 下一所有者：Codex，交付 A1/A2 audit 与 selected-wave manifest 后，OpenCode 执行
  `rebuild_runtime_or_bundle` 或 `full_reconstruction`，并分别记录 native、runtime、
  Guide 与失败分类。

### 2026-07-18 correction: A1/A2 handoff is now present

- 上述“当前工作区尚未提供 audit/wave manifest”的表述已过时：Codex 已生成
  `data/atom_reconstruction_audit.json`、`.csv` 和
  `data/atom_reconstruction_wave.json`，首个 wave 为 25 条。
- Codex 沙箱无法访问 Docker socket，因此这次审计中的
  `source_image_local=unknown` 是权限边界事实，不是镜像不可得结论。OpenCode 应在其
  实际 Docker 上下文重跑相同命令，以获得 `present/not_local` 记录后执行 B1。
- 聚焦回归现为 reconstruction audit、readiness contract、source-bundle **11 passed**。

---

## 2026-07-18 更新：OpenCode B1 首批 runtime rebuild 结果

- 已消费 `data/atom_reconstruction_wave.json` 的 25 条 bounded wave；使用共享
  `scripts/migrate_runtime_tools.py --build --force` 执行 runtime artifact、image、logical
  tool smoke 和 original-compose readiness。未重跑 native agent，未修改 native evidence、
  source provenance 或 Guide classification。
- 当前结果为 **21/25 runtime-ready，4/25 runtime deferred**。ready 条目仍记录为
  `structure-healthy` / runtime-ready，不自动升级为 template-anchor；native、source-bundle、
  Guide 和 Range 结果必须继续独立验收。
- ready 结果包括 `CVE-2017-15715`、`CVE-2018-12613`、`CVE-2019-11043` 等旧 Debian
  候选，以及 `CVE-2019-17558`、`CVE-2023-4450` 两个此前暴露 smoke 超时的候选。
- 四个 deferred 均为共享 runtime/tooling 结果：`CVE-2017-17405` 缺旧 Debian 的
  `python3-pyftpdlib`，`CVE-2018-2894` 的 RHEL/Oracle yum image 缺 `requests` 与
  `psycopg2` 模块，`CVE-2020-10199` 的 UBI dnf image 缺 `postgresql` 包，
  `CVE-2021-32568` 仅 `python3_psycopg2` smoke 失败且已有 compose 缺失记录。未将这些
  结果改写为 Agent 或 native 失败。

### B1 共享层修复

- `runtime_builder` 的 smoke 命令使用 `docker run --entrypoint sh`，避免继承原始服务
  `ENTRYPOINT` 后导致 `command -v` 实际启动服务并超时。
- EOL Debian 安装 fallback 现在识别 `httpredir.debian.org` 等 legacy source，使用
  `/etc/os-release`/任意 `deb` 源提取 codename，并创建旧镜像缺失的 man 目录；不包含 CVE
  特判。
- image-only runtime 通过实际基础 image 探测 `apt/apk/dnf/yum`，避免 Oracle/RHEL image
  被错误生成为 apt 安装脚本。
- 回归：`tests/atomizer/test_runtime_builder_flow.py` 与
  `tests/shared/test_runtime_tools.py` 合计 **40 passed**。

### B1 交接

- 机器可读/批次记录：`data/atom_reconstruction_audit.json`、
  `data/atom_reconstruction_wave.json`、`data/atom_batch_2026-07-18_status.md`。
- 下一所有者：Codex 执行 A4 Atom contract 验收，并在不混淆 native/runtime/Guide 结果的
  前提下重建 coverage-first Range matrix。

---

## 2026-07-18 更新：阶段一 A4 runtime contract 验收与稳定批量矩阵（Codex）

- A4 复核 `data/atom_reconstruction_wave.json` 的 25 条 B1 条目：Atom 中的
  `runtime_status`、runtime image、runtime verification `status` 与 `service_ready`
  字段相互一致，结果为 **21 runtime-ready / 4 runtime-deferred**，与 B1 交付一致。
  四个 deferred 仍仅表示 runtime tool/profile 不兼容，不改写其 native 或 Guide 事实。
- runtime-ready 不是 template qualification 的同义词。本 wave 当前有 **11** 个
  `template-anchor`、**3** 个 `template-candidate`、**9** 个 runtime-ready 但
  `review_required` 的 Atom；后者均缺失 network `required_service` 的权威元数据。
  该缺口已显式保留，不为任一 CVE 或 Range 增加特判。
- 修复批量入口的共享契约：`generate_enterprise3_matrix.py` 现在只接受完整已验证
  runtime image contract（而非 verifier 的按需重建兼容回退）。单场景生成仍保留旧
  fallback，故本修改不改变历史 Range 的兼容行为。
- 重建后的 `data/range_matrices/enterprise_3tier.json` 含 **23** 个 batch-ready Atom、
  **816** 个合法三元组；另外 **18** 个 Guide/环境可用但 runtime contract 未 ready 的
  Atom 被列入 `runtime_deferred_atoms`，不会混入首批稳定批量实验。矩阵本身无部署、无
  LLM 调用。
- 回归：matrix selection、runtime builder、readiness、source bundle、reconstruction
  audit 聚焦测试 **28 passed**，`git diff --check` 通过。
- 下一所有者：Codex 基于该 matrix 执行受限规模的 `generate-only → environment-only`
  批量验证；OpenCode 按相同共享 runtime/tool profile 契约继续处理后续 wave，不把
  deferred 条目误标为 Range 或 Agent 失败。

### A4 生成期抽样

- 从稳定 matrix 的 coverage-first 前 20 个组合执行了 `generate-only`：**20/20**
  生成并通过 Range preflight。该检查只覆盖选 Atom、依赖/能力闭包、资产 variant 与
  私有 objective binding；未部署 ContainerLab，未调用 LLM。
- 批量 runner 新增通用 `--offset`，可与 `--max-cases` 将 manifest 切成不重叠分片；
  每个 `summary.json` 记录 offset。offset=20 的 one-case generate-only smoke 已通过，
  使 environment-only/Guided 阶段可中断恢复且不重复首批组合。
- 新增 `scripts/collect_enterprise3_agent_queue.py`：只从 environment-only shard
  summary 中选择同时满足 `environment_success`、`range_build_verified`、
  `attack_graph_valid`、`attack_path_reachable` 的组合，生成 Guided-Agent manifest；
  其余组合保留失败阶段与缺失条件，不做 case-by-case 重选。回归 **5 passed**。

---

## 2026-07-18 更新：enterprise_3tier environment-only shard-000（Codex）

- 第一环境分片为 matrix offset 0 的 20 个组合：**20/20** 完成 deploy、base、asset setup/
  verify、CVE readiness 与 runtime materialization；`environment_success=true`、
  `attack_graph_valid=true` 均为 **20/20**。这说明当前主机与串行 ContainerLab 运行没有
  出现资源或清理不稳定。
- **18/20** 同时达到 `range_build_verified=true` 与
  `attack_path_reachable=true`。两条失败均为 `attack_path_reachability`，共享同一个
  构造类：其 Atom runtime image 通过 Compose-based readiness，但其 `runtime_spec` 和
  source compose 都未声明启动 command；Range 生成的 ContainerLab node 因此没有显式
  启动 image 的默认 service command，容器处于 running 状态但漏洞端口拒绝连接。
- Docker image inspection 已确认该类 image 的默认 `Cmd` 存在，而当前 Atom runtime
  contract 没有捕获它。根因是“Compose-only startup capture 与 ContainerLab startup
  semantics 不等价”，不是模板、路由、某个 CVE 或某个 Range 的特判问题。该 Atom 在
  当前 816-case matrix 中出现 96 次，故必须先在共享 Atom runtime contract 中修复，
  不能继续扩大批量后再逐例过滤。
- 下一修改方向：共享 runtime builder 在 Compose 未覆盖 command 时采集 image config 的
  default `Cmd`，并以 Range-compatible启动方式验证；Range 仅消费这个已记录 contract。
  修复后用原 20-case shard 重跑验证回归，再扩大 environment-only 分片。

### 共享 startup contract 修复

- `runtime_builder` 现通过 Docker image inspect 读取 `Config.Cmd`；仅当 Compose/runtime
  contract 未声明 command 时，将其以 shell-safe 形式写入 `runtime_spec.command`。Compose
  明确 command 仍优先，不会被 image default 覆盖。
- `pipeline` 与 `migrate_runtime_tools.py` 都回写该 resolved command；Range assembler 已有
  通用 runtime command 消费路径，因此生成的 ContainerLab target 会显式带上 `cmd`。
  runtime verification 同时记录 `resolved_command` 供追溯。
- 新增 image-Cmd argv 解析、默认 command 回写、Compose 优先和 ContainerLab command 发射
  的回归；runtime builder 与 assembler 聚焦测试 **62 passed**。

### 2026-07-18 correction: startup hypothesis rejected by rerun

- 重跑 shard-000 后，两个 `attack_path_reachability` false 仍存在；生成的 ContainerLab
  nodes 已显式含 image default command，且目标节点本机的 TCP/7001 readiness 为 true。
  因此“未捕获 image default Cmd”不是这类失败的充分根因。
- 已撤回上述未带来可观察改善的 startup-contract 代码变更，避免把未经证实的复杂度留在
  Atom/Range 流水线中。现有攻击路径验证正确地揭示的是跨节点服务可达性与本机 readiness
  不等价。
- 当前研究决策：不以 100% environment-only 通过率为目标；保留失败记录，由
  environment gate 排除其 Guided-Agent trial，继续批量验证其余环境通过组合。只有同类
  failure 在更大批次中形成显著分布时，才重新评估是否值得做共享契约研究。

---

## 2026-07-18 更新：Range batch 强制串行执行（Codex）

- shard-001 使用 `--parallel 2` 后出现交错的 deploy/setup 日志；首个完成的场景正常，
  后续 Ansible 报 `Non-blocking file handles detected: <stdin>`。这是同一 Python
  process 内 ThreadPool 并发运行 ContainerLab/Ansible 的执行器问题，不是 Atom、模板或
  Range 语义失败。
- 已移除 batch runner 的 ThreadPool 执行分支，`--parallel` 仅保留兼容参数且只接受
  `--parallel 1`；其他值会在启动前明确拒绝。每个 Range 现完整经历
  `generate → deploy → setup → verify → destroy` 后，才启动下一个。
- 新增 serial-only 回归。此前 shard-001 的并发结果不进入 Atom/Range 成功率统计；应以
  串行方式从 offset 20 重跑，覆盖该污染分片。

---

## 2026-07-18 更新：enterprise_3tier environment-only shard-001 串行重跑（Codex）

- 以 offset 20 执行的 **24** 个组合已在 serial runner 下完成；未出现此前并发运行时的
  Ansible `Non-blocking file handles` 或 setup 假失败。结果可进入环境验证统计。
- **23/24** 达到 `environment_success=true` 与 `attack_graph_valid=true`；**20/24** 同时
  达到 `attack_path_reachable=true` 与 `range_build_verified=true`。与 shard-000 合计为
  **38/44** 可进入 Guided-Agent 队列；这不是 Agent 成功率。
- 三个攻击路径失败共享同一 app-service Atom `CVE-2017-10271`，但 data-store 分别为
  Elasticsearch 与 PostgreSQL。目标节点自身 TCP/7001 readiness 均通过，而 DMZ target
  到 app target 的 TCP/7001 均为 `ConnectionRefused`。证据表明这是“本机 readiness 与
  数据面 service exposure 不等价”的重复 runtime/Range contract 类，而不是 data-store
  variant 或路由隔离失败。当前按研究决策由 environment gate 排除，不为该 Atom 设特判。
- 另有一条 deploy failure；同一 app Atom 在本分片另外两个 data-store variant 均通过，
  且该 data-store 在其余六个组合中通过。现有 `verify_result.json` 仅保留 `Deploy failed`
  而未保存 ContainerLab stderr，故不能把它归因于任何 Atom 或编排类。后续应在共享 verifier
  中持久化 deploy return code/stdout/stderr，供批量失败分类；在获得证据前不做修复。

---

## 2026-07-18 更新：Phase 2 / Reconstruction Wave 002（OpenCode）

### 选择与执行

- 按 `docs/OPENCODE_PHASE2_WAVE002_TASK.md` 重新执行 Docker-capable audit，得到 239 条
  当前 Atom 记录；分类为 32 条 `rebuild_runtime_or_bundle`、192 条
  `full_reconstruction`、15 条 `range_ready`。
- 新增通用 selector `scripts/select_atom_reconstruction_wave.py`，从 wave audit 与 B1
  ledger 可复现选择 25 条，并明确排除 B1 的 21 条 runtime-ready、4 条 deferred、当前
  `range_ready` 以及低边际 capability/access 条目。selector 回归测试 **2 passed**。
- 选择结果和全部排除理由分别记录在：
  `data/atom_reconstruction_wave_002.json`、`.csv`；审计记录在
  `data/atom_reconstruction_audit_wave_002.json`、`.csv`。

### Atom 结果

- 14 条 `rebuild_runtime_or_bundle` 中 13 条通过 runtime image、完整 logical-tool
  smoke 和 service readiness；`CVE-2013-4547` 因 port 80 未 readiness deferred。
- 11 条 `full_reconstruction` 中，`CVE-2026-24061`、`CVE-2026-21858`、
  `CVE-2025-32433` 完成 native、self-contained source bundle、Guide、runtime 和
  orchestrated 首阶段 gates，分类为 `template-anchor`。
- 其余 9 条分别按 environment/build risk、runtime tool/profile compatibility、
  exploit automation instability 或 validation-model mismatch 记录；没有把 Agent
  成功文本、runtime-ready 或历史事实单独升级为 accepted Atom。
- 完整逐条结果见 `data/atom_reconstruction_wave_002_results.json`，交接表见
  `data/atom_reconstruction_wave_002_handoff.md`。
- `data/atom_pool_status.json/.csv/.md` 已更新：当前管理池 113 条，
  `template_ready=103`；失败层级保持 native、Guide、runtime、orchestrated 分离。

### 共享 Atom-side 修复

- `runtime_builder._detect_image_package_manager` 现在将 cold image pull 或慢启动造成的
  `docker run` timeout 视为探测失败并继续使用 provenance-preserving image heuristics，
  不再中断整条 runtime rebuild。新增回归后 runtime builder/shared runtime focused tests
  为 **41 passed**。
- 未修改 Range template、matcher、composer、verifier、generated scenario 或 Guided Agent
  prompt。

### 下一所有者

- Codex：独立执行 A4 contract audit，核对 wave-002 的 schema/source bundle/native/Guide/
  runtime/orchestrated 事实，并在不改 Atom 特判的前提下重新生成 no-deploy Range matrix。

---

## 2026-07-18 更新：Range 多进程批执行器（Codex）

- 批执行器已从同一 Python 进程内的并发改为父协调器 + 独立 Python worker。公开接口为
  `--parallel N`（默认 4，接受任意 `N >= 1`）；worker 使用 `Popen`、`start_new_session` 与
  `stdin=DEVNULL`，不再使用线程或进程池。
- 每批持久化随机 `run_id`；物理 lab 名为
  `e3-<run-id 前 8 位>-<case-id hash>`，因此相同逻辑 case 在不同输出目录或批次中不会
  共享 ContainerLab/Docker 容器名。`batch_state.json`、`summary.json`、worker spec 与结果
  均采用原子写入；`--resume` 仅接受 fingerprint 相同的输出目录，并保留已完成研究结果。
- 场景生成与 runtime 预热在父进程串行完成；worker 强制 `runtime_policy=verify_only`，不会
  并发重建同一 runtime image。每个 worker 获得私有 `ANSIBLE_HOME`、local/remote temp 目录。
- 批模式使用共享、持久的 `cvelab-range-mgmt` 管理网络候选池及按 case 预租约的 Agent
  control bridge；ContainerLab deploy/destroy 仅在宿主生命周期锁内串行，Ansible、Agent 与
  验证阶段可以并行。固定数据面 IP 仍在各 Lab 独立 network namespace 中复用。
- 仅将 deploy、worker、control transport、cleanup 等基础设施失败自动重试一次；攻击路径、
  Agent 或 objective 失败作为 completed 的研究结果保存。中断会向 worker process group
  发送信号并对已知 topology/control lease 做精确 janitor cleanup。
- 已通过批脚本和 Verifier focused tests **68 passed**，并完成 `--parallel 4`、两 case 的
  generate-only 冒烟：状态文件有效，两个 case 均生成唯一物理 lab 目录。下一步需要在 sudo
  Docker/ContainerLab 环境按 `parallel=2 → 4 → 8` 执行真实 environment-only 递进验收，
  通过后再运行 4/8 路 Guided-Agent 压测。

### 2026-07-18 补充：首次 2 路 environment-only smoke

- 使用 `b00-baseline` 与 `b01-dmz-middleware` 启动 2 路批次后，`b00-baseline` 已完成
  deploy、base、asset setup/verify、CVE setup、environment-only result 与 destroy，未重现
  Ansible `Non-blocking file handles`。这是独立 worker + `DEVNULL` 隔离在真实环境中的首个
  正向证据。
- `b01-dmz-middleware` 未产生 scenario 目录或 worker log，仅产生较早的结果记录；因此它是
  生成/预调度阶段失败，不是并行 deploy、网络或 Ansible 冲突。后续读取确认其 Atom
  `CVE-2014-3120` 的实际 runtime 是 Elasticsearch HTTP/9200；共享服务解析器将其有效角色
  归类为 `database`，而 `dmz-web` 只接受 web/middleware/framework。该 legacy case 因而被
  生成期合法拒绝，不能用于并行调度 smoke。
- 同时发现 sudo batch 的原子 JSON 文件默认 mode 为 `0600`，阻碍非特权用户读取
  `summary.json`、state 和 result。已在 batch runner 与 verifier 的原子写入逻辑中通用修复：
  若存在 `SUDO_UID/SUDO_GID`，结果归属调用 sudo 的研究者并设为 `0644`。该修复不改变任何
  Atom、模板或单个 Range；后续批次可直接由普通用户读取与 `--resume`。

### 2026-07-18 补充：2 路真实并行环境验收通过

- `parallel=2` 使用 `b00-baseline` 与 `b02-dmz-web-variant` 完成。两个 worker 启动时间相差
  小于 0.001 秒；两条结果均为 `environment_success=true`、`attack_graph_valid=true`、
  `attack_path_reachable=true`、`range_build_verified=true`、`execution_complete=true`。
- 每条 worker 的 destroy 日志均显式移除了其 run-id/case-hash 唯一命名的 attacker、三个
  target 和三个 router 容器；没有容器重名、网络 overlap、Ansible stdin 或 control-network
  清理错误。
- 修复后，生成 topology 持久化 `cvelab-range-mgmt` 的管理网络配置，destroy 不再因默认 IPv6
  管理网重解析而输出错误。该 2 路验收构成下一步 4 路 environment-only 压测的基线。

### 2026-07-18 补充：4 路真实并行 environment-only 压测

- 从 enterprise_3tier matrix 启动 4 个 worker；启动时间跨度约 0.08 秒，四条 case 均完成
  deploy、Ansible、结果持久化和唯一 lab cleanup，未出现容器/网络/Ansible 的执行器伪失败。
- 其中 2 条达到 `range_build_verified=true`；另 2 条达到
  `environment_success=true` 与 `attack_graph_valid=true`，但因
  `attack_path_reachability=false` 被正确排除。两条均含 `CVE-2017-10271`，且失败边为进入
  该服务的 TCP/7001：节点本地 readiness 显示 listening，而跨数据面连接被拒绝；其他攻击边
  与所有 isolation probes 均正确。这复现既有的“本机 readiness 与数据面 exposure 不等价”
  共享 runtime/Range contract 类，不归因为并行执行器。
