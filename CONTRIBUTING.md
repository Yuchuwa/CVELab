# Contributing to CVELab

## Start with the Contract

Before editing code, read:

- `docs/ARCHITECTURE.md`
- `docs/COLLABORATION_PLAYBOOK.md`
- `docs/INTERFACES.md`
- `docs/CURRENT_STATUS.md`
- `docs/OPERATIONS.md`
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

Run the fast contract gate before a lane-specific test:

```bash
uv run python scripts/generate_atom_pool_status.py --check
uv run python scripts/tests/check_status_contracts.py
uv run python scripts/tests/check_docs_contracts.py
uv run pytest -q --no-cov \
  tests/shared/test_artifact_contracts.py \
  tests/shared/test_atom_pool_status.py \
  tests/orchestrator/test_guided_batch_runner.py
```

Run focused tests for the changed lane:

```bash
uv run pytest -q --no-cov tests/shared tests/atomizer -m "not docker and not slow"
uv run pytest -q --no-cov tests/orchestrator -m "not docker and not slow"
uv run pytest -q --no-cov tests/sft/test_convert_trajectories.py \
  -k "not test_qwen_template_renders_tool_arguments_as_object"
```

Run broader tests when a shared model, template, Agent input or result contract
changes. Docker/ContainerLab tests should be reported separately from unit
tests; do not claim they ran when the host prerequisites were unavailable.

Core CI does not require `data/guide_ablation/`, raw session files,
`data/sft/`, model adapters or an LLM endpoint. SFT contract tests use synthetic
fixtures; training/evaluation dependencies are an optional prepared-host
install (`uv sync --locked --group dev --extra sft`).

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

## Lane and Review Rules

The four ownership lanes are Atom, Range, Agent and SFT. The lane that produces
a contract owns its meaning; every consumer lane reviews a cross-boundary
change. A rotating release integrator reviews CI, documentation, generated
status, package policy and publication changes, and regenerates shared status
views only after upstream freshness checks pass. The producer author is never
the sole approval for a cross-lane contract change.

Every pull request names:

- primary lane and required reviewer;
- affected contracts and versions, producer and consumers;
- focused tests and exact status/freshness result;
- privacy/publication impact and known limitations;
- artifact handoff and next owner.

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
- The release integrator or delegated reviewer confirms generated views are
  fresh and CI does not depend on private raw Range/SFT data.
