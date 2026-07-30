# SysArmor First5 Rerun Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make L2 agents reliably submit confirmed flags before turn exhaustion, add simple case-level expected-signal evaluation, then rerun Stratified-50 first5 with SysArmor rc.5.

**Architecture:** Keep verifier PASS strict: only structured `verified_flags` satisfy flag gates. Add runner finalization prompts so observed flags are more likely to be submitted. Extend signal export with an optional expected-signal spec that checks whether each case's after signals include the configured rule IDs.

**Tech Stack:** Python runner scripts, pytest, existing SysArmor signal JSONL export, existing Stratified-50 batch runner.

## Global Constraints

- Do not count log-only flag observations as verifier PASS.
- Signal detection is case-level: if the case's exported after signals contain expected rule IDs, the case is detected.
- Expected signal rules must stay generic: no product, CVE, fixed IP/port, `/flag`, or `/opt/cvelab` coupling.
- Preserve existing exported signal files and summary format; add fields without breaking old callers.

---

### Task 1: Runner finalization guard

**Files:**
- Modify: `src/clab_builder/orchestrator/composer/openai_scenario_runner.py`
- Modify: `src/clab_builder/orchestrator/composer/scenario_runner.py`
- Test: `tests/orchestrator/test_verifier.py`

**Interfaces:**
- Produces: `build_finalization_reminder(input_data: dict) -> str`
- Consumes: `build_prompt`, `extract_json`, existing OpenAI message loop

- [ ] Write failing tests proving the finalization reminder asks for partial JSON with `verified_flags`, `attack_log`, `objective_results`, and `failed_targets`.
- [ ] Add a shared helper in `scenario_runner.py`.
- [ ] In `openai_scenario_runner.run_agent`, append the reminder when only a few turns remain and no structured JSON has been extracted yet.
- [ ] Verify tests pass.

### Task 2: Expected signal evaluator

**Files:**
- Create: `data/experiments/stratified-50/sysarmor-case0/expected-signals-first5.json`
- Modify: `scripts/export_sysarmor_signals.py`
- Test: `tests/orchestrator/test_sysarmor_signal_exporter.py`

**Interfaces:**
- Produces: `evaluate_expected_signals(case_id: str, after: dict[str, list[dict]], expected: dict) -> dict`
- CLI: `scripts/export_sysarmor_signals.py BATCH --output OUT --expected-signals SPEC`

- [ ] Write failing tests for rule extraction and expected-signal verdicts.
- [ ] Implement ruleId extraction from `signalFrame.signal.ruleId`.
- [ ] Extend exported `signals/summary.json` with `expected_signal_detection`.
- [ ] Verify old exporter behavior remains compatible.

### Task 3: Validation and rerun

**Files:**
- Modify: `docs/WORK_PROGRESS_REPORT.md`

**Commands:**
- Run focused pytest for runner/exporter tests.
- Rerun first5 L2 with SysArmor rc.5 and expected-signal export.
- Export signals with expected-signal spec.
- Summarize flags and detection.
- Commit code, spec, docs.
