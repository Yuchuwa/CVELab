# SysArmor Case1-10 Expected Signals Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a unified case1-10 expected signal label file, re-evaluate case6-10 signals with it, and update the SysArmor experiment report with case numbering and expected-signal results.

**Architecture:** Keep expected-signal labels as data-only JSON consumed by the existing `scripts/export_sysarmor_signals.py --expected-signals` path. Preserve the existing first5 label file as historical evidence and introduce a case1-10 file for ongoing experiments.

**Tech Stack:** JSON label data, existing Python signal exporter, Markdown report.

## Global Constraints

- Expected signal labels must stay behavior-based and avoid product, CVE, fixed path, flag, or lab-private directory coupling.
- Attack flag status must use verifier / structured `verified_flags` as the formal source of truth.
- Case6-10 expected labels are derived from generic observed ruleIds in the formal run, not from product/CVE-specific semantics.
- Do not change SysArmor detection rules or runner behavior in this task.

---

### Task 1: Add unified case1-10 expected signal labels

**Files:**
- Create: `data/experiments/stratified-50/sysarmor-case0/expected-signals-case1-10.json`

**Interfaces:**
- Consumes: `scripts/export_sysarmor_signals.py --expected-signals`, which expects a top-level `cases` object mapping case IDs to `expected_rule_ids`.
- Produces: A reusable expected-signal JSON spec with `case_no` and `expected_rule_ids`.

- [ ] **Step 1: Create JSON spec**

Create `expected-signals-case1-10.json` with case1-5 copied from `expected-signals-first5.json` and case6-10 added from generic observed ruleIds.

- [ ] **Step 2: Validate JSON**

Run: `jq . data/experiments/stratified-50/sysarmor-case0/expected-signals-case1-10.json`

Expected: valid formatted JSON.

### Task 2: Re-export case6-10 signal evaluation

**Files:**
- Modify generated artifact: `data/experiments/stratified-50/runs/trial-sysarmor-rc5-general-case6-10-l2-20260731-a/signals/summary.json`

**Interfaces:**
- Consumes: `expected-signals-case1-10.json`
- Produces: `expected_signal_detection.evaluated=true` for case6-10.

- [ ] **Step 1: Re-run exporter with expected spec**

Run:

```bash
uv run python scripts/export_sysarmor_signals.py \
  data/experiments/stratified-50/runs/trial-sysarmor-rc5-general-case6-10-l2-20260731-a/batch \
  --output data/experiments/stratified-50/runs/trial-sysarmor-rc5-general-case6-10-l2-20260731-a/signals \
  --expected-signals data/experiments/stratified-50/sysarmor-case0/expected-signals-case1-10.json
```

Expected: summary shows `evaluated: true` for case6-10.

### Task 3: Update experiment report

**Files:**
- Modify: `docs/experiments_sysarmor_report.md`

**Interfaces:**
- Consumes: case1-10 expected spec and case6-10 re-exported summary.
- Produces: Report tables with case numbering and expected-signal results.

- [ ] **Step 1: Add case numbering**

Add a `case no` column to first5 and later-results tables and populate case1-case10.

- [ ] **Step 2: Update expected-signal references**

Mention `expected-signals-case1-10.json` as the unified spec and replace case6-10 “未评估” entries with evaluated ✅/❌ and missing ruleIds.

- [ ] **Step 3: Commit**

Run:

```bash
git add data/experiments/stratified-50/sysarmor-case0/expected-signals-case1-10.json docs/experiments_sysarmor_report.md docs/superpowers/plans/2026-07-31-sysarmor-case1-10-expected-signals.md
git commit -m "docs(cvelab): label sysarmor expected signals for case1-10"
```
