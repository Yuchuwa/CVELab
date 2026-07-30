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

#### Current Atom lifecycle

Atom has exactly three build states:

1. **planned** — accepted into the build queue; `atom.yaml` does not exist.
2. **building** — construction or verification started, but at least one strict
   completion gate is missing or failed.
3. **completed** — every strict high-confidence gate in
   `docs/ATOM_BUILD_GUIDE.md` passes.

Structure, runtime, native verification, Guide and environment results are
evidence fields, not additional Atom types. Failed or deferred attempts remain
`building` with an explicit failure class. Matrix membership and template-slot
selection are owned by Range and must not be recorded as Atom lifecycle state.
Use the structured `verification.orchestrated_verification` record as
environment evidence; the legacy `environment_ready` mirror is not an
independent completion gate.

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
- `docs/WORK_PROGRESS_REPORT.md`

#### Progress recording requirement

Atom and Range progress must be recorded promptly in
`docs/WORK_PROGRESS_REPORT.md`. Record only established facts, with the date,
scope, Atom build status (`planned`, `building`, or `completed`) when
applicable, failed completion gates, verification/runtime result, known
limitations, and the next owner when work crosses the Atom/Range boundary.

**Mandatory recording rule:** Every work session must append a dated entry to
`docs/WORK_PROGRESS_REPORT.md` before the session ends, even if the work only
produced a negative result, a deferred TODO, or a read-only inspection. A
session that ran experiments, rebuilt Atoms, changed shared contracts, or
made a decision but did not write it to the report is an incomplete session.
Do not leave the report stale across a session boundary. If a finding needs a
later deep-dive, record it as a dated TODO entry now rather than relying on
memory or chat history.

**Auto-maintenance rule:** Do NOT ask the user whether to record progress in
`docs/WORK_PROGRESS_REPORT.md`. When a batch finishes, a shared contract is
changed, a model is tested, or a result is analyzed, append a dated entry
proactively and commit it. The report is a self-maintained ledger, not a
user-prompted task. Read it at session start to know prior state; write to it
whenever a fact is established.

- Record an Atom candidate when it is assessed, selected, rejected, built, or
  downgraded. Do not present a research candidate as a verified Atom.
- Record Atom-native, source-bundle, Guide, runtime-image, smoke, and service
  readiness outcomes independently from Range outcomes.
- Record each Range experiment's selected Atom combination and environment,
  attack-graph, Guided Agent, and objective results separately.
- Update the relevant candidate queue or status artifact alongside the progress
  report when a queue entry is added, promoted, rejected, or superseded.
- Do not rewrite historical results; append a dated correction or superseding
  entry when an older record is stale.

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
   - Keep the Atom lifecycle limited to `planned`, `building`, and `completed`;
     record individual gate results as evidence rather than additional types.

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

### Superseding near-term priority: scalable Atom and Range expansion

The immediate research priority is to expand the high-confidence Atom pool and
generate and validate Range combinations at scale as quickly as possible.

- Do **not** introduce proof that an Atom can carry business data, CRUD/data
  witnesses, real application-to-data-service credential binding, or Agent
  asset-use reporting as first-stage Atom admission gates.
- Keep the existing high-confidence Atom requirements: self-contained runtime,
  source bundle, native verification, orchestrated environment verification,
  and a reviewed Exploit Guide.
- Treat backend-specific asset setup as a Range/template compatibility concern,
  rather than a new burden on every Atom build.
- Prefer reusable slot-matching, template-composition, and batch-validation
  rules over per-CVE or per-Range fixes.
- Record environment validity, attack-graph validity, Guided Agent outcome,
  and objective outcome separately.  A richer business-data contract must not
  block batch composition in this first implementation stage.

The following are deferred to a later research phase unless a concrete template
requires them: structured data-operation evidence, real credential binding,
proof that an Agent used a specific asset, and service-family evidence beyond
what is needed for that template's executable setup.

### Current expansion baseline and execution plan (2026-07-18)

### This-week dataset-scale objective

The immediate delivery objective is a rapid first research dataset version:

```text
100+ usable high-confidence Atoms
→ 500–1000 Range experiments that complete Guided-Agent validation
```

For this objective, reasonable LLM API usage for native Atom reconstruction,
Guide generation/review, and Guided Range experiments is explicitly allowed.
Optimise for throughput through the shared pipeline and bounded batch execution,
not by weakening evidence requirements or hard-coding a CVE/Range-specific
workaround.

“Usable high-confidence Atom” continues to mean the existing first-stage
contract: self-contained runtime/source bundle, native verification,
orchestrated environment verification, and a reviewed Exploit Guide. Do not add
business-data/CRUD proof, real credential binding, or Agent asset-use evidence
as additional gates for this first dataset version.

“Guided-Agent validation completed” must retain separately recorded environment,
attack-graph, Guided-Agent, and objective outcomes. A failed Agent run is
research evidence and must not be rewritten as a passing Range merely to meet
the numerical target.

When throughput work reveals a failure, fix only a shared Atom construction or
Range composition/verification contract that applies to a class of cases. A
specific CVE or generated Range may serve as the reproducer, but never receives
a special branch solely to increase dataset counts.

### Dataset production plan

The work proceeds as one shared pipeline, with explicit gates:

```text
Phase 1: batch Atom reconstruction audit and supply preparation
→ Phase 2: repeated high-throughput Atom supply waves
→ Phase 3: coverage-first 500–1000 Range manifest generation
→ Phase 4: generate-only → environment-only → Guided-Agent batch validation
→ Phase 5: reproducible dataset aggregation and failure analysis
```

Phase 1 identifies reusable reconstruction classes (bundle completeness,
runtime/readiness contract, Guide/native evidence, and source availability)
without changing individual Atom data to force eligibility. Phase 2 produces
Atoms in bounded waves and records every acceptance, deferral, and failure
class. Phase 3 consumes only the recorded contracts to generate selected and
rejected combinations. Phase 4 does not send an Agent to a combination until
its deterministic preflight and environment validation pass. Phase 5 preserves
both successful and failed experiments with separate Atom, environment,
attack-graph, Guided-Agent, and objective outcomes.

The detailed Phase 1 ownership, tasks, and acceptance criteria are maintained
in `docs/STAGE1_ATOM_RECONSTRUCTION_PLAN.md`.

#### Established baseline

- The Range composition path now resolves backend-specific template asset
  variants from lightweight runtime `service_family` metadata. The first
  supported variants are PostgreSQL/5432 and Elasticsearch/HTTP 9200; this
  metadata identifies runtime compatibility only and is **not** proof of CRUD
  or business-data capability.
- The first five generated `enterprise_3tier` combinations passed
  `environment-only` validation. Both PostgreSQL and Elasticsearch variants
  completed deployment, asset setup/verify, attack-graph checks, and
  reachability checks.
- This is evidence that the shared composition path works for these two
  backends. It is not evidence that every existing Atom is runtime-ready or
  that Guided Agent validation has passed for every combination.

#### Short-term plan

1. **Atom supply expansion (OpenCode; parallel)**
   - Assess and build a batch of high-value candidates by capability,
     automation stability, diversity, and environment reliability.
   - Use the shared Atom pipeline only. Do not change Range templates,
     matching, verification, or generated scenarios to accommodate an
     individual candidate.
   - Record accepted, rejected, and downgraded candidates with their failure
     class in the candidate/status artifacts and progress report.

2. **Coverage-first batch composition (Codex)**
   - Make bounded matrix selection cover distinct DMZ, application, data-layer,
     and supported-backend alternatives rather than merely taking the first
     lexicographic combinations.
   - Keep matching and rejection explanations generic and reusable; no
     CVE-specific branches.

3. **Layered Range evaluation (Codex + operator)**
   - Run `generate-only` over the full matrix, then bounded concurrent
     `environment-only` validation, then serial Guided-Agent trials on a
     coverage-representative subset that passed environment validation.
   - Classify outcomes as Atom construction, runtime materialization, template
     compatibility, network/environment, Guide/execution-context, Agent
     planning, or objective verification. Modify shared contracts only when a
     failure class recurs; never tune one selected Range to make it pass.

#### Longer-term plan

- Add template service variants only after a corresponding runtime family has
  a stable setup/verify implementation and representative environment result.
- Expand templates only when the high-confidence pool covers their required
  roles, capabilities, and dependencies.
- Use the enlarged pool for controlled Guide/no-Guide and topology/Atom
  variation experiments, recording environment validity, attack-graph
  validity, Guided outcome, objective outcome, cost, time, and failure class
  separately.

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

## Session Handoff: No-Hint Range Evaluation (2026-07-20)

The current experiment compares three Agent contexts without changing Atom
data, templates, matcher rules, network topology, or target services:

```text
guided   = Guide + Guide-derived runtime hints + existing flag hints
no_guide = Guide removed, but existing flag hints retained
no_hint  = exploit hints removed; CVE and real Range topology remain visible
```

`no_hint` is not blind vulnerability discovery. The Agent still receives CVE
IDs, target IP/ports/zones, dependency and pivot order, execution host,
Atom-declared environment tools, verified capabilities, readiness probes, and
public business objectives. It derives exploitation and proof retrieval from
the live Range and known CVE, without fixed flag locations or flag-read
commands.

The shared Range implementation is complete:

- `src/clab_builder/orchestrator/composer/scenario_runner.py` supports all
  three contexts, uses a separate no-hint system prompt, omits fixed flag
  paths/commands, and audits serialized input and prompt before any LLM call.
- `src/clab_builder/orchestrator/composer/verifier.py` accepts
  `agent_context="no_hint"`, skips Guide preflight outside `guided`, removes
  Guide/flag fields from no-hint `input.json`, keeps Ground Truth verification
  outside Agent input, and records context/profile/hygiene results.
- `scripts/verify_enterprise3_guided_batch.py` adds
  `--agent-context guided|no-guide|no-hint` and includes the context in batch
  state, fingerprint, worker spec, and summary so `--resume` cannot mix modes.
- Tests: `tests/orchestrator/test_verifier.py` and
  `tests/orchestrator/test_guided_batch_runner.py`.

No Atom-side code or Atom data was changed for this no-hint task.

### Verified results so far

1. Targeted Range regression tests: **72 passed**.
2. Broader assembler/reconciliation/manifest/verifier regression: **121 passed**.
3. Full no-hint generate-only preflight:
   - input: `data/guide_ablation/manifest_reconciled.json`;
   - 71 combinations selected;
   - 70 generated successfully;
   - 1 rejected during generation and never entered an Agent denominator;
   - output: `data/guide_ablation/no_hint_preflight/summary.json`.
4. Four-case no-hint environment-only smoke:
   - output: `data/guide_ablation/no_hint_environment/summary.json`;
   - 3/4 completed successfully with environment, runtime, attack-graph, and
     attack-path checks passing;
   - all 3 completed cleanup successfully;
   - no Agent was called, so `prompt_hygiene=not_evaluated` is expected.

The rejected case is `b01-dmz-middleware`: CVE-2014-3120 exposes HTTP port
9200 but does not satisfy the current `dmz-web` service/role constraints. This
is a generic composition/matcher compatibility result, not a no-hint, Docker,
or parallelism failure. Do not add a CVE-specific exception.

### Immediate next steps for the new session

Run No-Hint Agent only on the three environment-validated cases first:

```bash
sudo -E env HOME="$HOME" PATH="$PATH" PYTHONPATH="$PWD/src" \
/home/hanlin/miniconda3/envs/playbook/bin/python \
scripts/verify_enterprise3_guided_batch.py \
  --cases matrix-2012-1823-2016-3088-2014-3120,matrix-2016-3088-2012-1823-2019-9193,b05-dual-variant \
  --agent-context no-hint \
  --parallel 3 \
  --max-turns 100 \
  --agent-timeout 1800 \
  --live-output \
  --output data/guide_ablation/no_hint_agent_smoke
```

Use a new output directory; do not resume the environment-only batch as an
Agent batch. Inspect its `summary.json` and each `verify_result.json`. Confirm
that every Agent result records `agent_context=no_hint`,
`hint_profile=exploit_hints_removed`, and a successful `prompt_hygiene` audit.

After the smoke, run environment-only on the remaining 70 generated cases in
bounded parallelism, then run no-hint Agent only on cases with:

```text
environment_verified=true
environment_success=true
attack_graph_valid=true
attack_path_reachable=true
execution_complete=true
```

Do not interpret no-hint Agent failure as Range invalidity when deterministic
environment and attack-path gates pass. Keep failure categories separate:
generation/preflight, runtime materialization, environment/readiness, network
reachability, Agent exploit/planning, Agent timeout/protocol, and objective
verification.

### Research interpretation boundary

The no-hint success rate measures autonomous exploitation and multi-hop planning
with known CVEs and topology. It does not measure CVE discovery. The expected
roughly 50% success rate is a research hypothesis, not a pass/fail gate. Do not
weaken the Range or alter an individual Atom to force that rate.

The prior 71-case No-Guide result remains historical evidence: 47/70 Agent
success and 44/70 objective success. It was not a strict paired Guided/No-Guide
experiment and does not need to be rerun before the first no-hint pilot.

### Required handoff bookkeeping

Append facts, not rewrites, to `docs/WORK_PROGRESS_REPORT.md`. Preserve these
artifacts when continuing:

- `data/guide_ablation/manifest_reconciled.json`
- `data/guide_ablation/no_hint_preflight/summary.json`
- `data/guide_ablation/no_hint_environment/summary.json`
- `docs/WORK_PROGRESS_REPORT.md`

When a recurring failure appears, fix the shared Atom construction or Range
composition/verification contract. A reproducing CVE or Range may be used for
tests, but must not receive a special-case branch.
