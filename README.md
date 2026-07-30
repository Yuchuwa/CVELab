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
uv sync --group dev
cd docker && bash build.sh
```

Create a local `.env` for Agent runs. Never commit it.

```bash
LLM_API_KEY=your-key
LLM_BASE_URL=https://your-compatible-endpoint
LLM_MODEL=your-model
```

## Quick Start

Build or inspect Atoms:

```bash
cvelab atom run data/vulhub/bash/CVE-2014-6271
cvelab atom list
```

Generate a scenario without deployment:

```bash
cvelab generate enterprise_3tier \
  --cve CVE-2012-1823,CVE-2021-42013,CVE-2014-3120 \
  --name enterprise-demo
```

Run deterministic environment verification without an Agent:

```bash
cvelab verify enterprise_3tier \
  --cve CVE-2012-1823,CVE-2021-42013,CVE-2014-3120 \
  --name enterprise-env \
  --environment-only
```

Run focused tests before changing a subsystem:

```bash
pytest -q --no-cov tests/shared
pytest -q --no-cov tests/atomizer
pytest -q --no-cov tests/orchestrator
```

The batch experiment runner has more controls than the installed CLI. See
[`docs/INTERFACES.md`](docs/INTERFACES.md) before using
`scripts/verify_enterprise3_guided_batch.py`.

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
