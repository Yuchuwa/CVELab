# CVE 重建状态台账

更新时间：2026-07-08

## 状态说明
- **full_pass**：已完成完整重跑验证，`native_success=true` 且 `orchestrated_success=true`
- **full_fail**：已完成完整重跑验证，但未通过；需要专项分析/修复
- **structure_only**：已完成 v3 结构性回填（source_bundle/runtime/validation/flag），但尚未做完整重跑验证

## 一、完整重跑验证通过（full_pass）

| CVE | service_role | vuln_category | phase | 备注 |
|---|---|---|---|---|
| CVE-2012-1823 | web_application | RCE | initial_access | PHP-CGI 基准样本，链路稳定 |
| CVE-2018-16509 | web_application | RCE | initial_access | 依赖 `poc.png`，已验证 source_bundle + attacker 挂载可用 |
| CVE-2017-8386 | system_service | RCE | execution | 依赖 `id_rsa`，已验证 source_bundle + attacker 挂载可用 |
| CVE-2013-4547 | web_application | RCE | initial_access | 完整重跑通过 |
| CVE-2019-11043 | web_application | RCE | initial_access | 审计时 readiness 偏弱，但完整重跑通过 |
| CVE-2018-10933 | system_service | RCE | initial_access | libssh 样本通过 |
| CVE-2014-3120 | middleware | RCE | initial_access | 中间件/搜索服务样本通过 |
| CVE-2019-9193 | database | RCE | execution | 数据层高价值样本通过 |
| CVE-2017-10271 | web_application | RCE | initial_access | WebLogic/XMLDecoder 风格样本通过 |

## 二、完整重跑验证失败（full_fail）

| CVE | service_role | vuln_category | phase | 失败层级 | 失败原因 |
|---|---|---|---|---|---|
| CVE-2017-12794 | web_application | Injection | initial_access | native=pass / orchestrated=fail | 依赖 Django debug/错误页暴露，当前 deterministic replay 模型不适配 |
| CVE-2012-2122 | database | RCE | initial_access | native=fail / orchestrated=skip | MySQL 概率型身份绕过，agent 自动 exploit 不稳定 |
| CVE-2017-12636 | database | RCE | initial_access | native=fail / orchestrated=skip | CouchDB 路线耗尽 max turns，agent 未稳定收敛 |
| CVE-2015-5254 | web_application | RCE | initial_access | native=fail / orchestrated=skip | ActiveMQ/OpenWire 协议型 payload 构造复杂，agent 超时 |
| CVE-2017-7494 | file_service | RCE | initial_access | native=fail / orchestrated=skip | Samba/SMB exploit 自动化不稳定，agent 超时 |

## 三、仅完成结构性回填（structure_only）

说明：下列样本已完成 v3 结构性回填：
- `source_bundle` 补齐
- `runtime_spec` / `validation_spec` / `flag_spec` 升级
- `verified` 状态已保留

但尚未进行完整重跑验证。

### 3.1 第一批 20 个演练样本中，除 full_pass/full_fail 外的 structure_only
- CVE-2010-2861
- CVE-2014-0160
- CVE-2015-1427
- CVE-2015-3337
- CVE-2015-5531
- CVE-2016-1897
- CVE-2023-26360
- CVE-2025-24813

### 3.2 其余 verified v3 样本
其余 **100 个左右** verified v3 atom 当前处于 `structure_only` 状态，详见：
- `data/verified_v3_structure_audit.json`
- `data/verified_v3_structure_audit.csv`
- `data/verified_v3_component_grouping.md`

其中：
- verified v3 总量：114
- 结构审计建议继续作为高置信模板组件：99
- 建议保留但先观察：13
- 建议暂时降级 / 专项修复：2（已列入 full_fail）

## 四、专项问题记录

### 1. source_bundle / attacker-side PoC 素材
已修复：
- `source_bundle` 现在会捕获 compose/readme/dockerfile/init 之外的剩余源目录文件
- 场景级 attacker 现在会挂载 `/vulhub/<CVE>/` 到各 atom 的 `source_bundle/`
- 已确认 `id_rsa` / `poc.png` 等素材可在场景级 agent 中使用

### 2. 场景级 flag 偷看问题
已修复：
- agent 输入不再包含 `ground_truth`
- `extract_known_flags` / `_recover_agent_flags` 改为按 `flag{...}` 形态提取，再由 verifier 用 GT 比对
- 已验证场景级 agent 不再通过 `scenario_input.json` 偷看 flag

### 3. `--skip-agent` 污染 verified 的问题
已修复：
- 结构性回填时保留旧的 verified truth
- 已将 114 个 verified atom 全量升级到 v3 且保持 `verified=true`

## 五、下一步建议

1. 继续从 `structure_only` 组里挑高价值样本做完整重跑验证
2. 对 `full_fail` 组按失败类型分别专项处理：
   - debug/错误页型验证语义不适配
   - 概率型/协议型 exploit 自动化不稳定
3. 后续模板扩展优先使用 `full_pass` 组作为锚点样本

---

## 六、2026-07-18 批量 Atom 供给补充记录

本节为 superseding runtime/batch snapshot，不改写前述历史重建结果。

- 批次状态文件：`data/atom_batch_2026-07-18_status.md`
- 本批选择：`CVE-2022-0543`。Redis 5.0.7 / RESP 6379，native/orchestrated
  事实已成功，Guide v2 ready，runtime image、digest、完整 smoke 与 6379
  service readiness 已通过。
- runtime image：`cvelab-runtime-2022-0543-e422f13fd5b6`
- runtime digest：`sha256:fcb14f42a918acbe68a1269b7ff9ea6979594238c52963fa53d4890e91d3bcc0`
- source bundle aggregate hash：`926550b0b05e55db`
- 分类：`structure-healthy`；runtime-ready data-service candidate；由于
  `exploit_access.required_service` 仍为空，暂不升级为 template-candidate。
- 本批 deferred/rejected：`CVE-2019-0193`（精确镜像缺失）、`CVE-2016-3714`
  （bundle 文件/目录冲突）、`CVE-2016-3088`（readiness 端口契约风险）、
  `CVE-2017-10271`（WebLogic 数据面绑定风险）、`CVE-2019-20933`（v2/无
  bundle/Guide/native capability）、`CVE-2017-12635`（无 native 成功与完整 v3）。
- 以上失败分类分别记录为 environment/build risk、validation-model mismatch
  或 deferred service/template family；没有重复强行重试。

---

## 七、2026-07-18 Phase 2 / Reconstruction Wave 002

本节为 wave-002 独立记录，不改写前述历史结果。选择依据和全部排除项见：

- `data/atom_reconstruction_audit_wave_002.json`
- `data/atom_reconstruction_wave_002.json`
- `data/atom_reconstruction_wave_002_results.json`
- `data/atom_reconstruction_wave_002_handoff.md`

- 选择：25 条，包含 `14 rebuild_runtime_or_bundle` 与 `11 full_reconstruction`。
- Runtime 路径：13 条 runtime image、完整 smoke 和 service readiness 通过；
  `CVE-2013-4547` 因 port 80 service readiness 失败而 deferred。
- Full 路径：`CVE-2026-24061`、`CVE-2026-21858`、`CVE-2025-32433` 通过
  native、Guide、runtime 和 orchestrated 首阶段 gates，分类为
  `template-anchor`。
- Runtime rebuild 通过项使用既有 native/orchestrated/Guide 事实和本轮 runtime
  证据，分类为 `template-candidate`，不冒充 fresh full rebuild anchor。

### Wave-002 deferred / rejected

| CVE | 失败层级 | 分类 | 事实 |
|---|---|---|---|
| CVE-2013-4547 | runtime | environment/build risk | runtime smoke 后 port 80 未 readiness |
| CVE-2021-40438 | runtime/Guide | environment/build risk; validation-model mismatch | 隔离 Docker 配置后 native/orchestrated 通过，但 runtime 无 service-port contract，Guide schema 拒绝结构化 endpoint |
| CVE-2022-24706 | native | validation-model mismatch | Agent 证明 RCE，但 native flag recovery 读到的值缺首字符，未通过 verifier |
| CVE-2021-42392 | native/Guide | exploit automation instability | JNDI/LDAP payload 在 80 turns 内未收敛，未生成 Guide |
| CVE-2014-0160 | Guide | validation-model mismatch | native/orchestrated/runtime 通过，但 Agent Guide material schema 校验失败 |
| CVE-2024-1561 | runtime | runtime tool/profile compatibility | `python3_psycopg2` smoke 失败 |
| CVE-2018-1273 | native/Guide | exploit automation instability | Agent 工具执行失败，未捕获 flag，未生成 Guide |
| CVE-2017-12794 | orchestrated/runtime | environment/build risk | native/Guide 通过，但 host port 冲突且 runtime `python3_requests` smoke 失败 |
| CVE-2024-45507 | Guide | validation-model mismatch | native/orchestrated/runtime 通过，但 Agent material/execution Guide schema 校验失败 |
