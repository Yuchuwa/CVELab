# SysArmor Case11-50 GT Labels Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add tailored expected-signal GT labels for Stratified-50 case11-50 while preserving the already validated case1-10 labels.

**Architecture:** Introduce a new data-only JSON spec, `expected-signals-case1-50.json`, consumed by the existing signal exporter. The spec keeps `expected_rule_ids` compatible with existing tooling and adds explanatory metadata (`case_no`, `cves`, `label_rationale`) for reviewability.

**Tech Stack:** JSON label data, existing Python signal exporter, Markdown report.

## Global Constraints

- Labels must use generic behavior rule IDs only, not product names, CVE-specific labels, fixed paths, flag paths, lab-private directories, IPs, or ports.
- Case1-10 labels must be inherited unchanged from `expected-signals-case1-10.json`.
- Case11-50 labels must be tailored from each case's three CVE atoms and exploit-guide behavior.
- `download_by_lolbin` must be used only where already validated or where the target-side attack chain clearly requires LOLBin download behavior; do not add it broadly.
- Do not change runner behavior, rulepack contents, or signal exporter logic.

---

### Task 1: Define tailored CVE behavior profiles

**Files:**
- Reference: `data/stratified_50_ranges.json`
- Reference: `data/atoms/<CVE>/atom.yaml`
- Reference: `data/atoms/<CVE>/exploit_guide.yaml`

**Interfaces:**
- Consumes: CVE descriptions, attack methods, guide steps, required tools, and command-channel hints.
- Produces: A deterministic mapping from case CVE combinations to generic expected rule IDs.

- [ ] **Step 1: Use generic signal vocabulary**

Allowed GT rule IDs:

```json
[
  "workload_executes_shell_or_interpreter",
  "network_client_used_in_workload",
  "execution_tool_opens_network_connection",
  "download_by_lolbin"
]
```

- [ ] **Step 2: Apply tailored profile logic**

For every case11-50:

- Include `workload_executes_shell_or_interpreter` when the case contains a command execution / webshell / sandbox escape / script execution atom.
- Include `network_client_used_in_workload` when the chained range requires target-side lateral HTTP/socket/database access or post-RCE pivoting.
- Include `execution_tool_opens_network_connection` only when at least one CVE in the case has a command-channel or payload style that reasonably leads to a target-side shell/interpreter/tool making network connections during the attack chain.
- Include `download_by_lolbin` only if the case is already validated with that behavior or if the exploit guide clearly requires target-side download tooling.

### Task 2: Add case1-50 expected-signal JSON

**Files:**
- Create: `data/experiments/stratified-50/sysarmor-case0/expected-signals-case1-50.json`

**Interfaces:**
- Consumes: `expected-signals-case1-10.json`
- Produces: a 50-case JSON spec compatible with `scripts/export_sysarmor_signals.py --expected-signals`.

- [ ] **Step 1: Create JSON**

Create the file with top-level `description`, `label_policy`, `cve_profiles`, and `cases`.

- [ ] **Step 2: Validate**

Run:

```bash
jq '.cases | length' data/experiments/stratified-50/sysarmor-case0/expected-signals-case1-50.json
```

Expected: `50`.

### Task 3: Update report

**Files:**
- Modify: `docs/experiments_sysarmor_report.md`

**Interfaces:**
- Consumes: case1-50 GT label file.
- Produces: report notes that GT labels now cover case1-50.

- [ ] **Step 1: Update current口径 and constraints**

Mention `expected-signals-case1-50.json` as the active GT file for the full Stratified-50 experiment, while keeping historical first5/case1-10 files as evidence.

- [ ] **Step 2: Commit**

Run:

```bash
git add data/experiments/stratified-50/sysarmor-case0/expected-signals-case1-50.json docs/experiments_sysarmor_report.md docs/superpowers/plans/2026-07-31-sysarmor-case11-50-gt-labels.md
git commit -m "docs(cvelab): add sysarmor gt labels for case11-50"
```
