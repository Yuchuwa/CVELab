# Sysfield Bilingual Report Rewrite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite the Chinese and English sysfield reports as a defender-centric, problem-driven research report grounded in the current Stratified-50 evidence.

**Architecture:** The Chinese report defines the argument, chapter order, claims, tables, and evidence boundaries. The English report follows the same research structure and numbers, but uses natural research English rather than sentence-level translation. A final bilingual audit checks headings, metrics, source links, and claim strength.

**Tech Stack:** Markdown, CVELab experiment reports, shell-based consistency checks, Git.

## Global Constraints

- Follow the causal chain: field shift -> gap -> challenges -> techniques -> evidence -> implications -> limits.
- Write for defenders, benchmark designers, and platform operators; do not optimize or teach offensive tactics.
- Use direct, concrete language in the style of CyberGym and CyberGym-E2E; avoid invented method names and inflated claims.
- Treat attack completion, defensive visibility, and robustness under interference as separate outcomes.
- State that SysArmor is observe-only; signal hits do not prove prevention, and signal misses do not prove blindness.
- Report Kimi-K3 L2 as 50/50 complete and DeepSeek-V4-Pro L2 as 40/50 partial.
- Use the shared 40-case subset for the controlled model comparison: Kimi `18/40`, `16/40`, `15/40` for t1/t2/t3 and DeepSeek `19/40`, `10/40`, `6/40`.
- Describe the DeepSeek L1 none/high comparison as the operational effect of the current high configuration, not pure decoy causality.
- State that the harness-uplift experiment has not yet been run; do not report an uplift value.
- Preserve identical structures, quantities, source links, limitations, and claim strength across Chinese and English.

---

### Task 1: Freeze the Report Structure and Evidence Contract

**Files:**
- Read: `docs/superpowers/specs/2026-08-07-sysfield-problem-driven-report-design.md`
- Read: `reports/experiments/stratified50-experiment-summary.zh.md`
- Read: `reports/experiments/sysarmor-cvelab-stratified50-kimi-k3-watch.zh.md`
- Read: `reports/experiments/sysarmor-cvelab-stratified50-rerun300-case50.zh.md`
- Read: `reports/experiments/2026-08-07-deepseek-l1-none-high.md`

**Interfaces:**
- Consumes: Design requirements and source experiment reports.
- Produces: One shared chapter outline and one set of approved numbers for both reports.

- [x] **Step 1: Fix the shared chapter outline**

Use this exact top-level structure in both languages:

```text
Abstract
1. Introduction
2. Related Work
3. Research Challenges
4. Sysfield
5. Evaluation Methodology
6. Results
7. Discussion
8. Limitations
9. Conclusion
References
```

- [x] **Step 2: Fix the result table values**

Use these experiment-level values:

```text
Kimi L2 full: 50 cases; PASS 16; t1/t2/t3 22/18/16; objective 17;
  any new signal 42; expected hit 28; timeout 22; attack-window frames 23,252.
DeepSeek L2 partial: 40 cases; PASS 6; t1/t2/t3 19/10/6;
  any new signal 30; expected hit 14; attack-window frames 9,628.
Shared 40 cases: Kimi t1/t2/t3 18/16/15, PASS 15, any signal 34,
  expected hit 26; DeepSeek t1/t2/t3 19/10/6, PASS 6, any signal 30,
  expected hit 14.
Kimi shared-40 quadrants: pass/hit 12, pass/miss 3, fail/hit 14, fail/miss 11.
DeepSeek quadrants: pass/hit 3, pass/miss 3, fail/hit 11, fail/miss 23.
DeepSeek L1 none/high: PASS 2/0; t1 2/2; t2 2/0; t3 2/0;
  objective 1/0; timeout 6/19; mean elapsed 1417.6/2428.5 seconds;
  high interaction 50, direct contact 38, decoy hits 27,230.
Shared-40 missing rules, Kimi/DeepSeek: execution-tool network 12/23,
  workload network client 9/18, workload shell/interpreter 6/16.
```

- [x] **Step 3: Fix the evidence boundaries**

Use the following interpretations:

```text
The Kimi/DeepSeek comparison is a model comparison under the recorded matched L2 protocol,
but DeepSeek remains partial and does not establish a final model ranking.
The none/high comparison measures the current high configuration, which combines decoys
with a topology-hint difference and uses different worker parallelism.
The L1 decoy reports do not export comparable SysArmor signal accounting.
Missing expected signals may reflect absent behavior, telemetry limits, rule coverage,
or an expectation that is too strong for the realized trajectory.
```

### Task 2: Rewrite the Chinese Report

**Files:**
- Modify: `reports/report.zh.md`

**Interfaces:**
- Consumes: The design spec and Task 1 evidence contract.
- Produces: The canonical argument, tables, and conclusions used by the English report.

- [ ] **Step 1: Rewrite the abstract and introduction**

The abstract must state the problem, gap, four challenges, four techniques, principal evidence, implication, and limits in that order. The introduction must end with four research questions and three contributions; do not present time-ordered engineering work.

- [ ] **Step 2: Rewrite related work as an evaluation evolution**

Cover six routes: knowledge and interactive tasks; vulnerability discovery and reproduction; lifecycle and exploit formation; remote and multi-stage action; long-horizon vulnerability research; autonomous defense and defensive artifacts. Compare representative methods by task endpoint and evidence type, then identify defended-environment visibility as the remaining gap.

- [ ] **Step 3: Rewrite challenges and method as one-to-one pairs**

Map each challenge to one concrete technique:

```text
heterogeneous CVEs -> CVE atomization and multi-layer scenario composition
entangled model/system effects -> controlled comparisons on the same cases
completion versus visibility -> external outcome verification plus runtime observation
ambiguous signal misses -> expected-behavior coverage analysis
```

- [ ] **Step 4: Rewrite evaluation and results around RQ1-RQ4**

RQ1 reports multi-layer completion and the controlled model comparison. RQ2 separates the unrun harness experiment from the completed none/high interference comparison. RQ3 reports runtime visibility and the attack/visibility quadrants. RQ4 reports missing-rule distributions without calling every miss a blind spot.

- [ ] **Step 5: Rewrite discussion, limitations, conclusion, and references**

Discussion must address defenders, evaluators, and platform operators. Limitations must include partial DeepSeek results, observe-only SysArmor, behavioral-GT coverage, L1/L2 incomparability, and high-decoy confounds. The conclusion must return to the joint risk picture without repeating implementation details.

- [ ] **Step 6: Check the Chinese report**

Run:

```bash
rg -n '39/50|14/39|联合证据协议|析因实验设计|轨迹级评测|证明.*阻止|防御失明' reports/report.zh.md
```

Expected: no obsolete `39/50` or `14/39`; no rejected terminology; any use of “防御失明” appears only in a qualified statement.

### Task 3: Rewrite the English Report

**Files:**
- Modify: `reports/report.en.md`

**Interfaces:**
- Consumes: The completed Chinese report and Task 1 evidence contract.
- Produces: A structurally and numerically aligned English research report.

- [ ] **Step 1: Mirror the Chinese structure and argument**

Use the same heading hierarchy, RQs, tables, experiment arms, and limitations. Translate concepts into idiomatic research English; do not preserve Chinese sentence order when it reads unnaturally.

- [ ] **Step 2: Normalize terminology**

Use these terms consistently:

```text
attack completion
defensive visibility
robustness under interference
CVE atomization and multi-layer scenario composition
same-case controlled comparison
external outcome verification and runtime observation
expected-behavior coverage analysis
```

- [ ] **Step 3: Check the English report**

Run:

```bash
rg -n '39/50|14/39|joint evidence protocol|factorial experiment|trajectory-level evaluation|proves? prevention|defense is blind' reports/report.en.md
```

Expected: no obsolete values, rejected terminology, or unqualified prevention/blindness claims.

### Task 4: Audit Bilingual Consistency and Scope

**Files:**
- Verify: `reports/report.zh.md`
- Verify: `reports/report.en.md`

**Interfaces:**
- Consumes: Both rewritten reports.
- Produces: A final pair with matched structure, numbers, evidence links, and conclusion strength.

- [ ] **Step 1: Compare heading structures**

Run:

```bash
rg '^#{1,4} ' reports/report.zh.md
rg '^#{1,4} ' reports/report.en.md
```

Expected: the same number and order of headings.

- [ ] **Step 2: Compare all quantitative tokens**

Run:

```bash
rg -o '[0-9][0-9,]*(\.[0-9]+)?%?|[0-9]+/[0-9]+' reports/report.zh.md | sort | uniq -c
rg -o '[0-9][0-9,]*(\.[0-9]+)?%?|[0-9]+/[0-9]+' reports/report.en.md | sort | uniq -c
```

Expected: experiment quantities and their occurrence counts match; reference years may differ only where language-specific citation text requires it.

- [ ] **Step 3: Check Markdown and source links**

Run:

```bash
git diff --check -- reports/report.zh.md reports/report.en.md
rg -n 'reports/experiments|experiments/' reports/report.zh.md reports/report.en.md
```

Expected: no whitespace errors; both reports link to the same three source experiment reports and the consolidated summary.

- [ ] **Step 4: Review the final diff**

Run:

```bash
git diff -- reports/report.zh.md reports/report.en.md
```

Expected: both files are complete rewrites, all claims follow the design spec, and no unrelated file is changed.

- [ ] **Step 5: Commit the report rewrite**

```bash
git add reports/report.zh.md reports/report.en.md
git commit -m "docs: rewrite sysfield reports around defender evidence"
```
