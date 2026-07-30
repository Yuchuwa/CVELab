# Test Guide

Status: active

Python baseline: 3.12

## Test Layout

| Path | Scope |
|---|---|
| `tests/shared/` | Shared models, runtime and qualification contracts |
| `tests/atomizer/` | Atom ingestion, native verification and output |
| `tests/orchestrator/` | Range planning, assembly, verification and experiments |

SFT tests are currently part of an unreviewed in-flight worktree and are not
included in the clean default CI gate until that work is submitted separately.

The historical `tests/unit/`, `tests/integration/` and `tests/atomic/` paths are
not part of the active layout.

## Local Commands

Install development dependencies:

```bash
uv sync --group dev
```

Run the same non-Docker gate used by CI:

```bash
uv run pytest -q --no-cov \
  tests/shared tests/atomizer tests/orchestrator \
  -m "not docker and not slow"
```

Run a focused workstream:

```bash
uv run pytest -q --no-cov tests/shared tests/atomizer
uv run pytest -q --no-cov tests/orchestrator
```

Tests marked `docker`, `slow`, `network`, `connectivity` or `isolation` may
need Docker, ContainerLab, elevated network permissions or external services.
Run those explicitly on a prepared host and report them separately from the CI
gate.

## Marker Rules

Use an existing marker from `pyproject.toml` when a test needs an external
environment. A test that contacts Docker or a real network must not be left
unmarked.

Contract tests should use small temporary fixtures and must not contain real
flags, credentials, API keys or private Ground Truth copied from experiments.

## Before Review

Run:

```bash
git diff --check
git status --short
```

Report the exact test command and pass/skip/fail counts. Do not claim Docker or
ContainerLab validation unless it actually ran.
