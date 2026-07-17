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