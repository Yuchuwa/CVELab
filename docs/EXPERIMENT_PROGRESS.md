# Experiment Code and Progress

Status: active

Last reviewed: 2026-07-30

## Ownership

Person B, **Range and evaluation**, owns experiment design, execution and
interpretation:

- model and runner comparisons;
- Agent context levels and Guide ablations;
- topology/noise/decoy dimensions;
- batch manifests, execution parameters and denominators;
- Agent, objective, cost, timing and failure-category results.

Person A supplies completed Atom artifacts and investigates an Atom contract
failure when B identifies one. With a third person, engineering/research
support may maintain runners, CI, sanitization and SFT tooling, but B still owns
the scientific comparison and result interpretation.

## Main Code

| Responsibility | Implementation |
|---|---|
| Batch execution, resume and summary | `scripts/verify_enterprise3_guided_batch.py` |
| Range verification and result persistence | `orchestrator/composer/verifier.py` |
| Claude Agent execution | `orchestrator/composer/scenario_runner.py` |
| OpenAI-compatible Agent execution | `orchestrator/composer/openai_scenario_runner.py` |
| Guide/no-Guide manifest selection | `scripts/prepare_guide_ablation_manifest.py` |
| Reusable verified Range selection | `scripts/build_reusable_ranges_manifest.py` |
| Decoy experiment launch | `scripts/run_decoy_ablation.sh` |
| Sanitized progress generation | `scripts/generate_range_progress.py` |

## Required Experiment Identity

Every new batch summary records:

- model;
- Agent runner;
- Agent context;
- noise level;
- template;
- selected cases;
- maximum turns and timeout;
- run ID and input fingerprint.

Model is part of the resume fingerprint, so the same output directory cannot
silently mix models. API keys and base URLs are not persisted.

Historical summaries did not store model or runner consistently. The generated
progress view marks those fields `unknown_not_recorded`; directory names or
chat history are not treated as authoritative model metadata.

The current inventory contains 136 batch summaries and 3,787 sanitized result
records. Of those, 1,558 record an evaluated Agent, 488 record Agent success
and 483 record objective success. None of the historical summaries records a
machine-readable model identity, so a trustworthy automatic cross-model table
cannot yet be reconstructed from the artifacts alone. Detailed model names in
the historical work ledger remain descriptive evidence, not a normalized
experiment registry.

## Outcome Separation

Range construction and model performance use different denominators:

```text
generation
-> environment
-> Range build
-> attack graph
-> attack path
---------------- deterministic Range denominator
-> Agent evaluated
-> Agent success
-> objective success
---------------- experiment denominator
```

Agent or objective failure does not turn a successfully built Range into a
failed Range.

## Current Progress Files

- `data/experiment_status.json`: authoritative sanitized batch inventory.
- `data/experiment_status.csv`: one row per batch.
- `data/experiment_status.md`: human-readable batch list.
- `data/range_build_status.*`: per-Range and per-attempt deterministic build
  stages used to define each experiment denominator.
- `docs/WORK_PROGRESS_REPORT.md`: append-only decisions and detailed findings.

Regenerate the current views with:

```bash
python3 scripts/generate_range_progress.py
```

Raw scenario directories, prompts, flags, credentials and transcripts remain
local research artifacts and are not copied into these progress files.
