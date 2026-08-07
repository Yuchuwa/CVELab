# SysArmor Watch Window Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace snapshot-based SysArmor signal collection with continuous watcher collection across the attack window.

**Architecture:** Add watcher-session helpers in `sysarmor_runtime.py`, switch verifier detection branches to lifecycle-based collection, and expose explicit attack-window fields to downstream exporters.

**Tech Stack:** Python 3.12, pytest, subprocess-based orchestration

## Global Constraints

- Keep defended execution serial on a single host.
- Do not expand scope to exporter/report rewrites in this task.
- Do not preserve deprecated `signals_before` / `signals_after` keys.

---

### Task 1: Add watcher session runtime helpers

**Files:**
- Modify: `CVELab/src/clab_builder/orchestrator/composer/sysarmor_runtime.py`
- Test: `CVELab/tests/orchestrator/test_sysarmor_runtime.py`

**Interfaces:**
- Produces: watcher lifecycle helpers, frame time classification, attack-window detection summary

- [ ] Write failing tests for watcher launch, readiness failure, frame classification, and attack-window detection summary.
- [ ] Run the targeted runtime tests and verify they fail for missing watcher APIs.
- [ ] Implement watcher start/stop/load/classify helpers and the new detection summary function.
- [ ] Run the targeted runtime tests and verify they pass.

### Task 2: Switch verifier from snapshots to watcher windows

**Files:**
- Modify: `CVELab/src/clab_builder/orchestrator/composer/verifier.py`
- Test: existing orchestrator verifier/runtime tests as regression coverage

**Interfaces:**
- Consumes: watcher lifecycle helpers from `sysarmor_runtime.py`
- Produces: `signals_pre_attack`, `signals_attack_window`, `signals_grace_window`

- [ ] Replace both SysArmor detection branches with watcher lifecycle collection.
- [ ] Remove deprecated `signals_before` / `signals_after` keys and rely on explicit windowed fields.
- [ ] Run focused pytest targets for runtime/verifier/exporter regression.
