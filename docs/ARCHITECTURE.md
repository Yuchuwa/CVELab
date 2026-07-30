# Architecture and Module Boundaries

Status: active

Last reviewed: 2026-07-30

## System Flow

```text
Vulhub / CVE-Factory source
          |
          v
Atomizer: source capture + native verification + Guide + runtime
          |
          v
data/atoms/<CVE>/
          |
          v
Range planning: template matching + capability closure + asset variants
          |
          v
Range assembly: ContainerLab + Ansible + private Ground Truth
          |
          v
Deterministic verifier: deploy + readiness + network + attack graph
          |
          +---------------------> optional Agent trial
          |                              |
          v                              v
verify_result.json                session/output evidence
          |
          v
batch summaries, research analysis and optional SFT conversion
```

## Active Layers

### Shared contracts

Path: `src/clab_builder/shared/`

Owns data models and policy shared by Atom and Range code. Important models:

- `shared/models/atom.py`
- `shared/models/exploit_guide.py`
- `shared/models/template.py`
- `shared/models/topology.py`

New cross-subsystem fields must be defined here or recorded as an explicit
untyped-contract gap in `INTERFACES.md`.

### Atom construction

Path: `src/clab_builder/atomizer/`

Owns source ingestion, native environment lifecycle, native Agent execution,
source-bundle capture, Guide generation and derived runtime images. Its public
artifact is `data/atoms/<CVE>/`; Range code should consume the artifact instead
of importing Atomizer implementation details.

### Range planning and assembly

Path: `src/clab_builder/orchestrator/composer/`

Owns Atom loading, slot matching, capability closure, template resolution and
scenario materialization. Templates define topology, injection points, assets,
objectives and noise services; they must not contain CVE-specific workarounds.

### Deterministic verification

Primary path: `src/clab_builder/orchestrator/composer/verifier.py`

Owns runtime identity checks, deployment, service readiness, asset setup,
network reachability, isolation and attack-graph validation. These gates are
independent from Agent performance.

### Agent execution

Paths:

- `orchestrator/composer/scenario_runner.py`
- `orchestrator/composer/openai_scenario_runner.py`

Owns prompt construction, information-exposure profiles, tool execution,
structured output recovery and session records. The verifier owns transport and
private result verification; the Agent never receives private flags or private
objective assertions.

### Experiment control plane

Primary path: `scripts/verify_enterprise3_guided_batch.py`

Owns manifests, parallel workers, retry/quota behavior, resume fingerprints and
batch summaries. It is currently an operational public interface even though it
is not exposed by the installed CLI.

### Dataset and SFT

Paths: `src/clab_builder/orchestrator/composer/dataset_saver.py` and `sft/`

Owns trajectory conversion, leakage checks, training data and model evaluation.
It consumes experiment artifacts and must not change their historical meaning.

## Dependency Direction

Allowed dependency direction:

```text
shared <- atomizer
shared <- orchestrator/composer
Atom artifacts -> Range composer -> verifier -> experiments -> SFT
```

Avoid these dependencies:

- `shared` importing Atomizer or Range implementation code.
- Range verification rebuilding or mutating a specific Atom as a workaround.
- SFT conversion redefining online Agent context semantics.
- Templates branching on a CVE ID.

Known violations should be removed incrementally, not hidden with compatibility
branches. For example, `shared/service_resolver.py` currently imports Atomizer
helpers, and verifier runtime recovery imports Atomizer runtime code.

## Legacy Boundary

The active implementation is `atomizer/` plus `orchestrator/composer/`.

These paths are legacy or compatibility code until an explicit migration says
otherwise:

- `src/clab_builder/atomic/`
- `src/clab_builder/core/`
- `src/clab_builder/models/`
- older `orchestrator/parser/`, `generator/`, and `validator/` flows

Do not add new features to a legacy path merely because an old document points
to it. If compatibility is still required, document the caller and retirement
condition.

## Current Coupling Hotspots

The following files are functional but broad ownership hotspots:

- `atomizer/pipeline.py`
- `orchestrator/composer/scenario_assembler.py`
- `orchestrator/composer/verifier.py`

The collaboration baseline does not split them. Before structural refactoring,
stabilize the file contracts in `INTERFACES.md` and add contract tests so work
can be moved without changing behavior.

## Architectural Rules

1. Fix shared construction contracts, not one CVE or generated Range.
2. Keep native verification separate from orchestrated environment validation.
3. Keep deterministic Range validity separate from Agent and objective success.
4. Treat Guide content as advisory; actual Range topology and verified Atom
   capabilities are authoritative.
5. Keep Ground Truth and private objective assertions out of Agent input.
6. Preserve failed experiments as evidence; never rewrite them into passing
   results to improve aggregate counts.
