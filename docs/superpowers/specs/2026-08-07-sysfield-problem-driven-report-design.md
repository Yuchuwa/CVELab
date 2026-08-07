# sysfield Problem-Driven Report Design

## Goal

Rewrite `reports/report.zh.md` and `reports/report.en.md` as a bilingual,
defender-centric research report. The report must explain what evidence
defenders, benchmark designers, and platform operators need in order to
characterize the risk boundary of frontier cyber agents in real defended
environments.

The report does not optimize offensive tactics. Controlled attack trajectories
are measurement instruments used to evaluate attack completion, defensive
visibility, and robustness under interference.

## First-Principles Narrative

Both language versions follow the same causal sequence:

1. **Field change:** cyber-agent evaluation is moving from static knowledge and
   isolated tasks toward executable, long-horizon action in realistic systems.
2. **Gap:** existing benchmarks measure PoCs, flags, patches, and objectives
   well, but rarely measure whether real defenses can observe or perturb the
   attack process.
3. **Challenges:** the benchmark must construct realistic but judgeable ranges,
   separate attack and defense outcomes, attribute signals to the attack
   window, define behavioral rather than benchmark-private detection ground
   truth, and measure interference without collapsing it into attack success.
4. **Key insight:** agent risk is not a single attack-success rate. Defenders
   need the joint profile of attack completion, defensive visibility, and
   robustness under interference.
5. **Approach:** sysfield combines CVELab multi-layer ranges, external attack
   verification, SysArmor runtime observation, attack-window attribution,
   behavioral expected signals, and decoy arms in one evidence protocol.
6. **Evidence:** separate experiments answer separate research questions about
   visibility, model-dependent behavior, and decoy-induced operational impact.
7. **Boundary:** conclusions remain limited by partial runs, observe-only
   detection, model/difficulty differences, behavioral-rule coverage, and the
   topology-hint confound in the current high-decoy arm.

The recurring thesis is:

> Attack success does not imply defensive blindness, and attack failure does
> not imply the absence of risk.

## Positioning

The report aligns with the responsible framing used by CyberGym,
CyberGym-E2E, and ExploitGym:

- realistic evaluation is necessary because synthetic or completion-only
  scores cannot reveal real risk and defensive requirements;
- offensive actions are included to support safe deployment, repair,
  evaluation, and defensive planning;
- dual-use capability is acknowledged, while the analytical endpoint remains
  the defender's need to model agents as a realistic source of attack pressure.

The report must not describe sysfield as a way to make agents more effective,
stealthy, or operationally capable. Detection misses are inputs to benchmark
and defensive-system improvement, not advice for evasion.

## Core Claims

### Core Problem

Do cyber agents remain effective in real defended environments?

Here, "effective" is multidimensional: completing attack objectives, remaining
visible or invisible to runtime defense, and maintaining progress under
deception or environmental interference.

### Defender-Centric Gap

Existing cyber-agent benchmarks primarily measure task completion, such as
PoCs, flags, patches, or final objectives, but rarely measure the visibility and
perturbability of attack processes in real defended environments. This leaves a
critical industry gap: whether baseline runtime defenses still observe key
attack behaviors when frontier agents enter realistic networks, and whether
deception and environmental noise still disrupt their trajectories.

### Key Insight

For defenders, benchmark designers, and platform operators, a single attack
success rate cannot characterize agent risk. A more useful evaluation target is
the joint profile of attack completion, defensive visibility, and robustness
under interference. Measuring all three is necessary to identify actual risk
and defensive exposure in realistic environments.

## Evidence Architecture

Experiments are organized by research dimension rather than execution order or
a primary/secondary hierarchy.

| Dimension | Evidence | Supported interpretation |
|---|---|---|
| Attack completion and defensive visibility | Kimi-K3 L2 SysArmor watch-window, 50/50 | Attack success, objectives, timeouts, new signals, and strict expected-signal hits are distinct outcomes. |
| Model-dependent behavior under defended observation | DeepSeek L2 SysArmor rerun, 40/50, compared cautiously with Kimi-K3 | The protocol can expose different attack and signal profiles across model-agent systems; the incomplete run does not support a final model ranking. |
| Robustness under interference | DeepSeek L1 paired none/high-decoy arms, 50/50 each | The current high configuration changes exploration cost, interaction, timeouts, and success outcomes while the range remains valid. |
| Evidence separation | Environment, graph/path, flags, objective, signals, timeout, and decoy interaction | Infrastructure validity, attack completion, business objective, visibility, and interference are not interchangeable labels. |

The report must preserve the configuration attached to every number. It must
not directly aggregate different models, L1/L2 contexts, detection arms, and
decoy arms into one success rate.

## Results Organization

The evaluation section answers questions rather than recounting experiment
batches:

1. Can agents reliably complete multi-layer attacks?
2. Can baseline runtime defense observe meaningful behavior during those
   trajectories?
3. Are attack completion and defensive visibility independent?
4. Does the protocol reveal different profiles across agent systems?
5. Do deception and environmental noise perturb agent trajectories?
6. What do misses and timeouts reveal about benchmark and defense boundaries?

Each subsection states the question, identifies the applicable experiment,
reports the evidence, and gives only the conclusion supported by that evidence.

## Required Boundaries

- SysArmor runs are detection/observe experiments, not blocking experiments;
  they do not show that attacks were prevented.
- A strict expected-signal miss does not prove defensive blindness. The agent
  may not have executed the expected behavior, telemetry may not cover it, or
  the case-level expectation may be too strong for the realized trajectory.
- A signal hit does not prove attack success, severity, or prevention.
- The DeepSeek L2 run is incomplete at 40/50 and supports only provisional
  cross-model interpretation.
- Kimi-K3 and DeepSeek L1 results differ in model context and experiment design;
  they answer different questions and must not be ranked directly.
- The current high-decoy arm includes a topology-hint difference caused by a
  serialization bug. Its result is the operational effect of the current high
  configuration, not an isolated causal estimate of container decoys.
- Transcript-derived decoy interaction is diagnostic evidence, not
  packet-level provenance.
- Current results are based on one manifest and limited model-agent systems;
  they do not establish universal model or defense rankings.

## Bilingual Consistency

The Chinese and English reports must have the same section structure, claims,
tables, experiment counts, caveats, and conclusion strength. English should be
written as natural research prose rather than a sentence-by-sentence literal
translation, but neither version may introduce evidence absent from the other.

The rewrite preserves useful technical detail from the current drafts, removes
stale `39/50` counts, incorporates the experiment summary dated August 7, 2026,
and keeps source experiment reports discoverable from the evaluation section.

## Acceptance Criteria

- The abstract follows problem, gap, challenge, approach, evidence,
  implication, and boundary in compact form.
- The introduction foregrounds the defender-centric gap and key insight.
- Related work positions sysfield as a complementary defensive-evidence
  dimension, not as an offensive leaderboard.
- Method sections explain how each component resolves a stated challenge.
- Results are grouped by research question and retain experiment-specific
  denominators and configurations.
- Detection, model comparison, and decoy evidence are all represented.
- Claims never exceed the limitations above.
- Chinese and English versions are structurally and numerically aligned.
