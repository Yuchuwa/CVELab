# CVELab

CVELab builds reproducible CVE environments and composes them into multi-node
ContainerLab ranges for security-agent research.

The active pipeline has two stages:

```text
Vulnerability source
-> Atom construction and native verification
-> data/atoms/<CVE>/
-> template matching and Range assembly
-> deterministic environment verification
-> optional Agent and objective evaluation
```

## Project Areas

| Area | Purpose | Main path |
|---|---|---|
| Shared contracts | Atom, Guide, Template and topology models | `src/clab_builder/shared/` |
| Atomizer | Build and verify a self-contained single-CVE Atom | `src/clab_builder/atomizer/` |
| Range composer | Match Atoms and generate multi-node scenarios | `src/clab_builder/orchestrator/composer/` |
| Templates | Define topology, slots, assets and objectives | `templates/` |
| Experiments | Generate matrices and run repeatable batches | `scripts/` |
| SFT | Convert trajectories and train/evaluate adapters | `sft/` |

The active implementation is `atomizer/` plus `orchestrator/composer/`.
`atomic/`, `core/`, and the older parser/generator/validator paths are legacy or
compatibility code and are not the starting point for new work.

## Documentation

- [Documentation index](docs/README.md)
- [Architecture and module boundaries](docs/ARCHITECTURE.md)
- [File and Python interfaces](docs/INTERFACES.md)
- [Current project status](docs/CURRENT_STATUS.md)
- [Roadmap](docs/ROADMAP.md)
- [Fresh-clone operations runbook](docs/OPERATIONS.md)
- [Contribution guide](CONTRIBUTING.md)
- [Data and publication policy](docs/DATA_POLICY.md)
- [Historical progress ledger](docs/WORK_PROGRESS_REPORT.md)

When prose and implementation disagree, use this precedence:

```text
Pydantic models and current code
-> contract tests
-> active interface documentation
-> generated status and experiment artifacts
-> historical progress records
```

## Requirements

- Python 3.12+
- Docker
- ContainerLab 0.74+
- `uv`

```bash
uv sync --locked --group dev
```

The Agent container is optional for core tests and is built only on a Docker host:

```bash
(cd docker && bash build.sh)
```

Create a local `.env` or export variables for Agent runs. Never commit it.

```bash
LLM_API_KEY=your-key
LLM_BASE_URL=https://your-compatible-endpoint
LLM_MODEL=your-model
```

## Quick Start

Build or inspect Atoms:

```bash
uv run cvelab atom run data/vulhub/bash/CVE-2014-6271
uv run cvelab atom list
```

Generate a scenario without deployment:

```bash
uv run cvelab generate enterprise_3tier \
  --cve CVE-2012-1823,CVE-2021-42013,CVE-2019-9193 \
  --name enterprise-demo
```

Run deterministic environment verification without an Agent:

```bash
uv run cvelab verify enterprise_3tier \
  --cve CVE-2012-1823,CVE-2021-42013,CVE-2019-9193 \
  --name enterprise-env \
  --environment-only
```

Run an independent empirical difficulty evaluation:

```bash
# Range: deploys an isolated copy once per model and writes only the report.
uv run cvelab difficulty range data/scenarios/enterprise3-demo \
  --output reports/difficulty-enterprise3-demo.json \
  --api-key "$LLM_API_KEY" --base-url "$LLM_BASE_URL"

# Atom: evaluate an already running target container. Add --reset-command
# when the target can be restored between model runs.
uv run cvelab difficulty atom data/atoms/CVE-2014-6271 \
  --container cve-target --target-ip 172.18.0.2 \
  --output reports/difficulty-CVE-2014-6271.json \
  --api-key "$LLM_API_KEY" --base-url "$LLM_BASE_URL"
```

The evaluator runs the fixed Qwen model set
(`qwen3.6-27b`, `qwen3.6-35b-a3b`, `qwen3.6-plus`, `qwen3.6-flash`) with a
30-turn / 1800-second default budget. It records solution rate, turns, wall
time, and tool calls in a separate JSON artifact. It never writes evaluation
results into an Atom or Range. Atom evaluation is marked
`state_isolated=false` unless `--reset-command` is supplied; a non-isolated
run should be treated as exploratory rather than a clean comparison.

Run focused tests before changing a subsystem:

```bash
uv run python scripts/generate_atom_pool_status.py --check
uv run python scripts/tests/check_status_contracts.py
uv run python scripts/tests/check_docs_contracts.py
uv run pytest -q --no-cov tests/shared tests/atomizer
uv run pytest -q --no-cov tests/orchestrator
```

The installed CLI exposes `atom`, `batch`, `generate`, `sysfield` and `verify`.
There is no `cvelab scenario` or `cvelab catalog` command. The batch experiment
runner has more controls than the installed CLI; invoke it as
`uv run python scripts/verify_enterprise3_guided_batch.py` and see
[`docs/INTERFACES.md`](docs/INTERFACES.md) first.

## Result Semantics

Range validity and Agent success are separate results:

- `environment_success`: deployment, services, assets and network are valid.
- `attack_graph_valid`: dependencies and capabilities form a valid graph.
- `attack_path_reachable`: the reference path is reachable under isolation.
- `agent_success`: the Agent completed the attack task in this trial.
- `objective_achieved`: private objective verification passed.

An Agent failure does not invalidate a Range whose deterministic gates passed.

## Repository Boundary

Canonical code, templates, reviewed Atom assets and documentation belong in
Git. Generated scenarios, raw trajectories, flags, credentials, model caches,
runtime state and local vulnerability-source checkouts do not. See
[`docs/DATA_POLICY.md`](docs/DATA_POLICY.md).

## License

See [`LICENSE`](LICENSE).
