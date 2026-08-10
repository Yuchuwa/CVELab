# Operations Runbook

Status: active

Last reviewed: 2026-08-09

This is the executable clean-clone path for the collaboration baseline. It
separates dependency-free contract checks from Docker, external vulnerability
sources and LLM-backed Agent work.

## Fresh Clone

Requirements for the core gate:

- Python 3.12 and `uv` with network access to the configured package index;
- the repository's `uv.lock` and tracked Atom/status artifacts;
- no Docker daemon, ContainerLab installation, LLM key, raw Range run or raw SFT
  corpus.

Run from a new checkout:

```bash
git clone git@github.com:Yuchuwa/CVELab.git CVELab
cd CVELab
uv sync --locked --group dev
uv run cvelab --help
uv run python scripts/generate_atom_pool_status.py --check
uv run python scripts/tests/check_status_contracts.py
uv run python scripts/tests/check_docs_contracts.py
uv run pytest -q --no-cov \
  tests/shared/test_artifact_contracts.py \
  tests/shared/test_atom_pool_status.py \
  tests/orchestrator/test_guided_batch_runner.py
```

The status command is read-only. It recomputes the live lifecycle index and
checks the tracked JSON, CSV and Markdown views without rewriting them. The
other script checks matrix provenance, documentation links, workflow YAML and
the required Phase 5 wording.

## Lane Tests

Run the smallest relevant gate first. All commands use the repository's `uv`
environment:

| Lane | Focused command | External requirements |
|---|---|---|
| Atom | `uv run pytest -q --no-cov tests/shared tests/atomizer -m "not docker and not slow"` | Docker/source checkout only for native or runtime tests |
| Range | `uv run pytest -q --no-cov tests/orchestrator -m "not docker and not slow"` | Docker/ContainerLab only for deployment tests |
| Agent | `uv run pytest -q --no-cov tests/shared/test_artifact_contracts.py tests/orchestrator/test_guided_batch_runner.py` | LLM endpoint only for real Agent trials |
| SFT | `uv run pytest -q --no-cov tests/sft/test_convert_trajectories.py -k "not test_qwen_template_renders_tool_arguments_as_object"` | Optional SFT dependencies; no raw corpus or model download for this subset |

For the broader active non-Docker gate:

```bash
uv run pytest -q --no-cov \
  tests/shared tests/atomizer tests/orchestrator \
  -m "not docker and not slow"
```

Tests that use Docker, ContainerLab, network privileges, external services or
model downloads are separate prepared-host checks. Report their exact command
and result; do not imply that the core CI gate ran them.

## External Dependencies

External vulnerability sources are intentionally not part of the repository.
Their revisions, licenses and acquisition URLs must be recorded in the Atom
handoff or experiment manifest.

### Vulhub

The Atom CLI expects a checkout at `data/vulhub` or an equivalent path passed as
the CVE directory. `data/vulhub/` is ignored by Git. On a prepared Atom host,
acquire a pinned revision and then run, for example:

```bash
git clone https://github.com/vulhub/vulhub.git data/vulhub
git -C data/vulhub checkout <pinned-vulhub-revision>
uv run cvelab atom run data/vulhub/<project>/<CVE>
```

Native verification may need Docker image pulls, source downloads and elevated
permissions. Those are Atom-lane evidence, not core CI assumptions.

### CVE-Factory

There is no single repository revision or checkout layout assumed by the core
pipeline. Keep the external CVE-Factory checkout outside tracked data (the
usual local location is `CVE-Factory/`), pass its source path to the relevant
preparation/scan script, and record the source revision in the Atom handoff.
Do not copy raw task writeups, solution files, flags or credentials into Git.

### Docker and ContainerLab

The Agent image is optional for the core gate. On a Docker host, the repository
build script creates `clab-agent:latest`:

```bash
(cd docker && bash build.sh)
```

Range deployment additionally requires a working Docker daemon and the
supported ContainerLab version. Check those prerequisites before running
`uv run cvelab verify ...` or a batch runner. A Docker image build may need
network access to the Kali package mirror, PyPI and image registries.

### Agent API

Only the runner should receive the API configuration. Use a local environment
or shell exports and never place credentials in manifests, prompts, session
files or pull requests:

```bash
export LLM_API_KEY='<local-secret>'
export LLM_BASE_URL='https://your-compatible-endpoint'
export LLM_MODEL='your-model'
```

The deterministic environment path does not require these variables:

```bash
uv run cvelab verify enterprise_3tier \
  --cve CVE-2012-1823,CVE-2021-42013,CVE-2019-9193 \
  --name enterprise-env \
  --environment-only
```

## Artifact Handoffs

An artifact is handed off only with its producer, consumer, contract/version,
source snapshot, exact verification command, privacy classification and known
limitations.

| From | Canonical handoff | Receiver | Required evidence |
|---|---|---|---|
| Atom | `data/atoms/<CVE>/atom.yaml`, `source_bundle/`, `exploit_guide.yaml` and `data/atom_pool_status.json` | Range | `completed` lifecycle, runtime/source hashes, native and orchestrated evidence, reviewed Guide |
| Range | Matrix manifest, `scenario.yaml`, `verify_result.json` and batch summary | Agent | Atom snapshot hash, template/binding identity, deterministic environment/graph/path results and private/public boundary |
| Agent | Exposure-pinned input/result/batch records and a sanitized trajectory export | SFT | Profile identity, runner/model/budget metadata, prompt-hygiene result and no private oracle values |
| SFT | Corpus manifest, exact JSONL hash, split manifest, training-run manifest and evaluation manifest | Release integrator | Schema IDs, source/skip accounting, group-aware split, portable paths and reproducible run identity |

Private Ground Truth, raw sessions, credentials, flags, generated scenario
directories, model adapters and unreviewed local logs stay outside normal CI
and release changes. A successful handoff does not claim exploit, Agent or model
success unless the corresponding independent result artifact says so.

## Regeneration Order

The release integrator runs and records this order:

```text
Atom lifecycle/status
  -> Range matrix and provenance
  -> Range build/experiment status
  -> Agent experiment status
  -> SFT corpus/split/run status
  -> generated CURRENT_STATUS.md
```

Stop on the first stale upstream snapshot. Do not regenerate a downstream view
from a stale Atom or Range input, and do not use a matrix accepted count as an
experiment success count.

## Cleanup and Reporting

Destroy temporary ContainerLab ranges and remove local runtime/session data
after prepared-host runs. Preserve sanitized summaries and immutable hashes;
keep raw evidence local under the data-policy rules. In the pull request or
work report, record the lane, exact command, pass/skip/fail result, artifact
paths, failure class and next owner.
