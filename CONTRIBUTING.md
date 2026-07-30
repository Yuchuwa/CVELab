# Contributing to CVELab

## Start with the Contract

Before editing code, read:

- `docs/ARCHITECTURE.md`
- `docs/INTERFACES.md`
- `docs/CURRENT_STATUS.md`
- the active contract linked for the subsystem

Use active implementation paths. Do not add new functionality to `atomic/` or
`core/` based only on an old document.

## Change Scope

- Make the smallest change that fixes the shared contract.
- Do not patch one CVE or generated Range as a workaround.
- Do not modify unrelated dirty-worktree files.
- Separate code, canonical data, generated results and documentation when they
  require different review.
- Preserve historical experiment results; add a correction or superseding run.

## Contract Changes

A persisted-field change must include:

1. Producer update.
2. Consumer update.
3. Contract or privacy regression test.
4. `docs/INTERFACES.md` update.
5. Migration decision when existing persisted data is affected.

Environment, Agent and objective outcomes are distinct. A change must not make
an Agent success text override deterministic or private verification.

## Testing

Run focused tests for the changed subsystem:

```bash
pytest -q --no-cov tests/shared
pytest -q --no-cov tests/atomizer
pytest -q --no-cov tests/orchestrator
pytest -q --no-cov tests/sft
```

Run broader tests when a shared model, template, Agent input or result contract
changes. Docker/ContainerLab tests should be reported separately from unit
tests; do not claim they ran when the host prerequisites were unavailable.

Before a commit:

```bash
git diff --check
git status --short
```

## Commit and Review Boundaries

Prefer one reviewable purpose per commit:

- schema and contract tests;
- Atom construction/runtime;
- Range planning/assembly;
- deterministic verification;
- Agent/experiment behavior;
- generated status or curated data;
- documentation.

Do not commit the entire shared working tree to capture one task. Stage only the
files intentionally reviewed for that commit.

## Data Safety

Follow `docs/DATA_POLICY.md`. In particular, do not commit `.env`, API keys, raw
Agent sessions, Ground Truth flags, generated scenarios, runtime state or large
source checkouts.

## Progress Records

- Update `docs/CURRENT_STATUS.md` only when current state changes.
- Append established facts to `docs/WORK_PROGRESS_REPORT.md`.
- Link to machine-readable evidence and name the denominator.
- Record failures and deferred work rather than silently dropping them.

## Pull Request Checklist

- The change has a clear subsystem and contract boundary.
- Focused tests pass.
- Persisted interfaces and docs agree.
- No CVE-specific workaround was added.
- No secrets, flags, private Ground Truth or generated runtime state are staged.
- Current status or roadmap was updated when the project state changed.
