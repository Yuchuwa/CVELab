# AGENTS.md

## Project Overview

**CVE Scenario Lab Builder** - 一个从 CVE 原子化到复杂网络攻防环境编排的全自动生成系统。

包含两个子项目：
- **atomizer** (项目一): Agent 驱动的单 CVE 原子化 - 从 CVE 信息生成 Ansible 配置 + 攻击 playbook
- **orchestrator** (项目二): 多 CVE 编排 - 从原子化 CVE 组合多阶段多节点的攻防环境

两个项目通过 `data/atoms/` 目录解耦：项目一写入，项目二消费。

## Project Structure

```
src/clab_builder/
├── cli.py              # Click CLI 入口 (clab-builder)
├── atomizer/           # 项目一: 单 CVE 原子化
│   ├── agent/          #   Agent 系统 (LLM + 工具调用)
│   ├── environment/    #   CVE 容器管理
│   ├── output/         #   Ansible 配置 + Playbook 生成
│   └── pipeline.py     #   流程编排
├── orchestrator/       # 项目二: 多 CVE 编排
│   ├── parser/         #   ContainerLab YAML 解析
│   ├── generator/      #   拓扑配置生成
│   ├── validator/      #   环境验证 (5 层网络测试)
│   └── composer/       #   Ground Truth 组合 (待实现)
├── shared/             # 共用模块
│   ├── catalog/        #   CVE 原子库 (32 个 verified catalog)
│   ├── models/         #   Pydantic 数据模型
│   ├── config/         #   配置管理
│   └── utils/          #   子网管理、日志等
data/
├── catalogs/verified/  # CVE 元数据 YAML (32 个)
└── atoms/              # 项目一产出 / 项目二消费
templates/basic/        # 拓扑模板
```

## CLI

```bash
clab-builder atom run <cve-id>      # Agent 驱动 CVE 原子化
clab-builder atom list              # 列出已生成的 atom
clab-builder scenario generate ...  # 编排多 CVE 场景
clab-builder scenario validate ...  # 验证部署的环境
clab-builder catalog list           # 列出 CVE catalog
```

## Key Technical Details

- Python 3.12+, uv 包管理, Click CLI, Pydantic 数据模型
- Agent 使用 LLM API (Anthropic 或兼容 API)
- Docker 隔离: CVE 环境容器 + Agent 容器独立运行
- ContainerLab 管理网络拓扑
- config.py 使用延迟加载，不再导入时 sys.exit

## Current State & Near-Term Priorities

### Current understanding of the project

The project is now in a **transition period from legacy atoms to high-confidence atoms**.

There are two distinct validation layers that must stay conceptually separate:

1. **Native verification**
   - Runs against the original Vulhub/docker-compose environment.
   - Proves the CVE can actually be exploited in its original lab.
   - Agent may use Vulhub-shipped PoC materials such as `id_rsa`, `poc.png`, etc.

2. **Orchestrated environment verification**
   - Runs against the CLab-rebuilt environment produced from `atom.yaml`.
   - Proves the atom can be instantiated into a scenario runtime without losing startup semantics or materials.
   - This layer should validate **environment correctness** (deploy/base/cve-setup/container-running/readiness), not re-prove the exploit with a brittle one-line replay command.

### Important lessons already learned

- A `verified=true` atom must not only mean “the Vulhub lab was exploitable once”.
- Old atoms frequently lost runtime semantics (`command`, `entrypoint`, `environment`) when abstracted.
- Old `source_bundle/` contents were incomplete and often missed attacker-side PoC materials like `id_rsa` or `poc.png`.
- Scenario-level attacker validation previously leaked `ground_truth.flag` into the agent input and therefore could produce false CAPTURED results.
- Scenario-level attacker containers need access to **self-contained atom PoC materials** via `source_bundle`, not via external absolute Vulhub paths.

### Current project direction

Near-term work should prioritize the **atom pool** before aggressively expanding scenario realism.

Priority order:
1. Rebuild the existing verified atom pool into a consistent high-confidence format.
2. Expand the verified atom pool with better category / phase / role diversity.
3. Only after the pool is healthier, expand templates and raise scenario realism.

### Definition of a high-confidence atom

A high-confidence atom should satisfy all of the following:
- Complete `runtime_spec`
- Complete `source_bundle` including attacker-side PoC materials
- Valid `flag_spec` / `validation_spec`
- Reliable native verification record
- Reliable orchestrated environment verification record
- No dependency on external ad-hoc host paths at scenario runtime

### Practical rule for current development

When working on atom rebuild / migration:
- Treat `source_bundle` completeness as a first-class requirement.
- Treat scenario attacker accessibility to PoC materials as part of atom usability.
- Keep environment verification and agent success logically separate.
- Prefer self-contained atoms over shortcuts that depend on machine-local absolute source paths.

### Root-cause requirement for diagnosis and fixes

When locating or fixing a problem, do not patch a specific Atom, CVE, or generated
Range as a case-specific workaround. Trace the failure to the shared Atom construction
code or shared Range construction/orchestration/verification code, and implement the
fix at that reusable layer. A specific Atom or Range may be used as a reproducer, but
its data files, template values, and generated artifacts must not receive a special
case unless the user explicitly requests a data correction. Any diagnosis must state
which generic construction contract was violated and how the regression test covers
the class of failures rather than only the reproducing case.

### Strategic constraint for future APT-style templates

Current verified atoms are still heavily skewed toward:
- `initial_access`
- `RCE`
- `web_application`

This means the project can already support **layered exploit scenarios**, but not yet a truly broad set of **multi-stage APT-style templates** covering privilege escalation, credential access, lateral movement, persistence, and collection with balanced service roles.

Because of this, **atom diversity expansion is a prerequisite for realistic template expansion**.


### CVE value assessment before spending effort (mandatory)

The candidate CVE pool is large (567+ direct-fit candidates from CVE-Factory
plus Vulhub). There is no reason to spend heavy effort on a single troublesome
CVE. Before every atom build attempt and every code change that targets a
specific CVE, **first assess the value of the target CVE against all available
candidates** and pick the highest-value one. This assessment is real-time and
does not need to be written to a file — it is a decision gate you apply each
time you are about to invest significant effort.

A CVE's value is multi-dimensional. Weigh at least:

1. **Estimated capability** — what capability_grants can it realistically
   provide? `execute_command` is the most valuable (unlocks read_file +
   network_vantage via closure, usable as a chain middle node). `read_file`
   alone is terminal-only. Pure Info_Leak / Auth_Bypass / SSRF with no
   command execution and no file read has the lowest Range value — its
   exploit may be real but the Range consumption chain cannot use it.

2. **Debug complexity** — how stable is the exploit under automated agent
   reproduction? A single-request RCE that the agent reproduces in one curl
   is high value. A probabilistic bypass (e.g. CVE-2012-2122), a
   protocol-payload constructor (e.g. ActiveMQ OpenWire), or a multi-stage
   deserialization that the agent rarely converges on within max-turns is low
   value — even if the CVE is famous, the automated pipeline cannot reliably
   verify it.

3. **Diversity contribution** — does it fill a missing MITRE phase or service
   role? Another `initial_access` web RCE adds little when we already have 37
   A-Mid atoms. A privilege_escalation / credential_access / lateral_movement
   / persistence / collection atom is high value even if the exploit is
   moderately harder, because it unlocks template diversity the pool currently
   lacks.

4. **Environment reliability** — does the vulhub image build and start
   cleanly? Images that need fragile plugins, external registries (gcr.io),
   or long DB init windows cost disproportionate pipeline time and fail
   orchestrated verification for reasons unrelated to the exploit.

Decision rule: **skip low-value CVEs ruthlessly.** A CVE that is both
low-capability (no execute_command/read_file) and high-debug-complexity
(probabilistic/protocol/multi-stage) should not be retried repeatedly. Move
to a higher-value candidate. The pool is large enough that no single CVE is
worth more than one or two focused attempts.

When a build or rerun fails, classify the failure before retrying:
- **environment problem** (image pull / build / port probe): fixable, retry
  makes sense
- **agent exploit instability** (max-turns exceeded, payload not found): low
  retry value — the CVE is hard to automate; prefer a different candidate
- **validation-model mismatch** (Info_Leak/Auth_Bypass with no flag path):
  the shared validation contract may need a fix, but only fix it if the
  affected class is broadly useful, not for one CVE


### Current working status (2026-07)

The project has now completed a full **structure rebuild** of the current verified atom pool and established an initial **atom pool management model**.

#### What has already been completed

1. **Verified atom pool structure rebuild**
   - All currently retained verified atoms have been migrated to `version: 3`.
   - `source_bundle` now captures compose/readme/dockerfile/init files plus attacker-side PoC materials such as `id_rsa`, `poc.png`, sample images, etc.
   - `runtime_spec`, `validation_spec`, and `flag_spec` are now consistently present.
   - `--skip-agent` rebuild flow has been fixed so structure-only rebuilds no longer silently destroy prior verified truth.

2. **Scenario-level verification hardening**
   - `replay_ok` is no longer a hard gate for `environment_success`; replay remains diagnostic only.
   - Scenario attacker no longer receives raw `ground_truth.flag` values in its input.
   - Flag recovery fallback no longer searches agent text using GT flag values as needles.
   - Scenario attacker now mounts atom `source_bundle` at `/vulhub/<CVE>/` so attacker-side PoC materials can be used inside scenarios.

3. **Completed end-to-end scenario proof**
   - `enterprise3-demo` (template: `enterprise_3tier`) was successfully generated and verified end-to-end.
   - The scenario uses:
     - `CVE-2012-1823`
     - `CVE-2018-16509`
     - `CVE-2017-8386`
   - Environment verification passed.
   - Agent evaluation passed without GT-flag leakage.

4. **Initial full rebuild validation samples**
   Full rebuilds were already run on a small but informative subset.

   **Full rebuild pass anchors:**
   - `CVE-2012-1823`
   - `CVE-2018-16509`
   - `CVE-2017-8386`
   - `CVE-2013-4547`
   - `CVE-2019-11043`
   - `CVE-2018-10933`
   - `CVE-2014-3120`
   - `CVE-2019-9193`
   - `CVE-2017-10271`

   **Known full rebuild failures requiring special handling:**
   - `CVE-2017-12794` — validation model mismatch (debug-page / indirect flag exposure style)
   - `CVE-2012-2122` — probabilistic DB bypass, native exploit unstable
   - `CVE-2017-12636` — CouchDB route / native agent instability
   - `CVE-2015-5254` — protocol-payload construction instability (OpenWire)
   - `CVE-2017-7494` — SMB exploit automation instability

#### Important operational distinction

The project now needs to distinguish three different notions of “usable atom”:

1. **structure-healthy**
   - The atom has complete schema/runtime/source_bundle and can be managed as a project asset.

2. **template-candidate**
   - The atom is structurally healthy and suitable to be considered in template design / slot mapping.

3. **template-anchor**
   - The atom has also passed a fresh full rebuild under the current native + orchestrated validation chain and can serve as a high-confidence template baseline.

These must not be conflated.

#### Current pool-management rule

Do **not** treat “agent validation failed” as automatically meaning “atom construction failed”. Failures must be separated into:
- structure problems
- environment rebuild problems
- validation-model mismatch
- exploit automation instability

This distinction is now mandatory for planning future work.

#### Management artifacts already maintained

The following files should be treated as current project bookkeeping sources:
- `data/cve_rebuild_status.md`
- `data/verified_v3_structure_audit.json`
- `data/verified_v3_structure_audit.csv`
- `data/verified_v3_component_grouping.md`
- `data/atom_pool_status.json`
- `data/atom_pool_status.csv`
- `data/atom_pool_status.md`

#### Immediate next priority

The next stage should prioritize **template-slot mapping and gap analysis** for the rebuilt atom pool, rather than blindly increasing the number of agent rebuild runs.

Reason:
- The pool is now structurally healthy enough to support planning work.
- The biggest remaining problem is no longer schema quality, but **diversity**.
- Current verified v3 atoms are still heavily concentrated in:
  - `RCE`
  - `initial_access`
  - `web_application`

Therefore, future work should focus on:
1. mapping current atoms into template slots,
2. identifying missing roles / stages,
3. selectively introducing new atoms from CVE-Factory to fill those gaps.

### Current research progress and next plan (2026-07-15)

#### Current progress

The Range-side Guided Agent validation loop is now operational. The latest
`enterprise3-guided-pilot` run completed deployment, readiness checks, multi-hop
Agent execution, and business-objective verification successfully:

- `environment_verified=true`
- `attack_graph_valid=true`
- `guided_trial_success=true`
- `objective_achieved=true`
- all three target flags were captured

The Range objective contract is now separated into two views. The Agent receives
only the public objective (`id`, goal, target, actor, evidence field, and
verification mode); private `reference_command`, `success_pattern`, and Ground
Truth values remain verifier-side. The Agent must return structured
`objective_results`, which the verifier checks by objective ID and actor/target
binding. This prevents oracle leakage while keeping final business validation
deterministic.

Atom exploit Guides are being passed into the Range Agent and have demonstrated
practical value: they provide exploit order, foothold/pivot information,
protocol hints, required capabilities, and PoC locations. The current successful
trial is evidence that the Guide can reduce search, but it is not yet a causal
measurement. Guide quality still has shared-contract gaps: execution-context
requirements, transfer limits, fallback procedures, and command hints are not
uniformly represented. These must be addressed in the generic Guide schema and
Range preflight, not through CVE-specific fixes.

According to the current `data/atom_pool_status.json` snapshot, the managed pool
contains 109 verified entries. All 109 currently pass the recorded structure,
source-bundle, environment, native-exploit, validation-model, and template-ready
checks. The distribution remains highly skewed: 107 are `initial_access` and 2
are `execution`; all are categorized as `RCE`, with 73 `web_application`, 15
`middleware`, 13 `framework`, 4 `system_service`, and 4 `database` roles. This
is sufficient for layered RCE demonstrations, but not for balanced APT-style
multi-stage research.

#### Next implementation plan

Work is split by responsibility:

1. **Atom-pool expansion (opencode)**
   - Fill measured gaps in capability, MITRE phase, and service role rather than
     adding duplicate RCE atoms.
   - Every new or rebuilt Atom must pass structure/source-bundle/native
     verification and produce a reviewed exploit Guide.
   - Keep `structure-healthy`, `template-candidate`, and `template-anchor`
     classifications separate.

2. **Range-side coverage and matching (CVELab/Codex)**
   - Build a slot-to-Atom coverage matrix using `exploit_access`, verified
     `capability_grants`, assets, dependencies, and network reachability.
   - Identify which existing template slots can be varied safely and which need
     new Atom capabilities before adding templates.
   - Add generic Guide preflight checks for material availability, target/role
     consistency, foothold requirements, dependency order, and objective
     reachability.

3. **Range expansion**
   - First generate several controlled combinations within the existing
     `enterprise_3tier` template to separate Atom effects from template effects.
   - Then introduce additional templates only when the pool covers their required
     stages and roles.
   - Do not replace a failed combination with a hand-picked CVE; report the
     violated shared construction or orchestration contract.

4. **Evaluation and research evidence**
   - Keep the successful three-hop pilot as the baseline.
   - Run repeated no-Guide, full-Guide, and minimal-Guide trials after the pool
     has enough comparable alternatives.
   - Record environment validity, attack-graph validity, guided success,
     objective success, turns, tool calls, time, pivot success, and failure
     categories separately. Agent success is a capability/difficulty measure,
     not the sole definition of Range quality.

#### Acceptance gate for an expanded experiment pool

An Atom enters a Range experiment only after:

```text
structure check
→ source_bundle check
→ native verification
→ exploit Guide review
→ slot/capability/dependency preflight
→ reproducible Range trial
```

A Range experiment is considered interpretable only when environment and attack
graph checks pass, the public objective is supplied without oracle values, and
the result records guided-trial and objective outcomes independently.

Before implementing:

- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:

- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:

- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:

- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:

```json
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.
