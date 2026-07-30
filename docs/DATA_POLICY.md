# Data and Publication Policy

Status: active

Last reviewed: 2026-07-30

## Data Classes

| Class | Examples | Git policy |
|---|---|---|
| Canonical code/config | `src/`, reviewed `templates/`, tests | Track |
| Canonical Atom asset | reviewed `data/atoms/<CVE>/` contract files | Track after provenance/licence review |
| Generated status | Atom-pool snapshot, curated manifest | Track only when reproducible and reviewed |
| Generated runtime | scenario directories, ContainerLab state, logs | Do not track |
| Raw research evidence | sessions, streams, Agent input/output, flags | Private by default |
| Model artifacts | adapters, checkpoints, caches | Do not track in Git |
| External source checkout | Vulhub, CVE-Factory, databases | Do not track as local directories |
| Secret | `.env`, API keys, tokens | Never track |

## Sensitive Research Content

Raw Range artifacts commonly contain:

- Ground Truth flags and canary values;
- internal and management IP addresses;
- credentials and Basic Authorization headers;
- absolute host paths;
- complete exploit commands and payloads;
- API transport errors containing endpoint/account details.

A file being useful for research does not make it publication-safe.

## Public Export

Public datasets should be produced into a dedicated export directory, not
committed from a raw batch directory. A public export should contain only:

- template and case metadata needed to understand the topology;
- versioned schemas;
- aggregate metrics with explicit denominators;
- sanitized trajectories selected for release;
- provenance that identifies code/Atom/template snapshots without secrets;
- a licence and responsible-use notice.

Required redaction includes:

- replacing flags and private objective markers;
- removing API keys, authorization headers and local credentials;
- normalizing private host paths and infrastructure endpoints;
- reviewing internal IPs according to the release purpose;
- removing verifier-private assertions from Agent-facing examples.

Run both automated secret/pattern scans and manual review before publication.

## Experiment Immutability

Raw experiment directories are immutable evidence. If verification logic is
corrected, write a derived result that references the original input and the
correction version. Do not overwrite a failed run into a passing run.

## Repository Ignore Boundary

The root `.gitignore` blocks common generated scenario, experiment, model and
external-source directories. A curated file that deserves publication should be
added through a reviewed, narrow exception or copied into a dedicated public
dataset tree with its own README and schema.
