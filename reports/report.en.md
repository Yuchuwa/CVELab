# sysfield: Joint Attack-and-Defense Evaluation for Real Multi-Layer Cyber Ranges

**Technical report draft**
**Status:** interim draft based on the current SysArmor × CVELab Stratified-50 defended evaluation protocol
**Date:** August 7, 2026

## Abstract

Cybersecurity agent evaluation is moving from asking what a model knows to asking what an agentic system can do after entering a real environment. CyberSecEval, Cybench, and InterCode-CTF evaluate security knowledge, CTF-style tasks, and tool interaction. CyberGym, SEC-Bench Pro, BountyBench, and CyberGym-E2E move toward vulnerability reproduction, discovery, and remediation in real codebases. ExploitBench and ExploitGym ask how far agents can go from a triggered bug toward exploit primitives, unauthorized execution, and flags. CVE-Bench, long-horizon cyber ranges, and VulnLMP push the setting toward remote targets, longer exploration, and multi-stage action. Taken together, this line of work shows that the unit of evaluation is no longer the model alone, but the full system: model, harness, tools, permissions, environment, budget, and external verifier.

sysfield focuses on a still under-measured part of this trajectory. When a cyber agent acts inside a real multi-layer range, we need to know not only whether it reaches the final objective, but also whether the attack process becomes observable, interpretable, and auditable by a runtime defense. Real defense does not begin only after final compromise. A failed attempt may still execute shells, launch interpreters, probe networks, download tools, open lateral connections, or access credentials. If a benchmark records only final flag capture, these security-relevant behaviors collapse into a single `FAIL`.

This report introduces a joint attack-and-defense evaluation protocol. CVELab composes real CVE atoms into reproducible multi-layer network-action scenarios, and uses topology materialization, runtime preparation, qualification checks, and external verification to make each case executable, judgeable, and traceable. SysArmor observes workload runtime behavior and emits semantic signals. The evaluation reports final objective completion and newly observed expected signals during the attack window separately. The current study instantiates CVELab Stratified-50 as a three-layer enterprise-style range with entry, intermediate/application, and data targets.

At the time of writing, the SysArmor `v0.1.0-rc.5` defended evaluation protocol has completed 39/50 cases: case1-27 and case32-43 are complete; case28 is running; case29-31 are runtime-prepared and waiting for serial execution; case44-50 are pending. Among the 39 completed cases, 6/39 captured all three flags and 14/39 achieved strict expected-signal hits. The interim result shows that multi-stage attacks remain difficult, while runtime defense can still produce structured evidence for a subset of attacks that do not reach the final objective.

The central claim is that next-generation cyber agent evaluation should not report a single success curve. The flag/verifier curve measures whether the attack chain completed. The attack-window signal curve measures whether the defense observed expected attack behavior. When the expected signal does not appear, the missing-signal curve explains whether that silence may come from agent non-progress, behavior outside the observation boundary, rule coverage gaps, or over-strong ground truth. Together, these curves make agent capability, failed attempts, and defensive visibility interpretable.

## 1. Introduction

Cybersecurity is a dense testbed for frontier agent capability. A cyber task has a concrete goal, real tool feedback, externally verifiable outcomes, and clear failure boundaries. The agent must read code, run commands, search for evidence, revise hypotheses, and deliver a result before its budget expires. This is much closer to long-horizon real-world action than static question answering.

Existing cyber-agent evaluations show that models can act in real codebases, vulnerable environments, and remote targets. Yet most benchmarks center their oracle on the final artifact: whether a PoC triggers, whether a patch passes, whether a flag is captured, or whether a scenario objective is completed. That is necessary for measuring attack capability, but insufficient for measuring defensive value. In practice, defenders need to identify behavior, produce evidence, explain stages, and ideally surface risk before final compromise.

sysfield therefore adds one more question: in multi-layer network action, attack outcomes and defensive observation should both be first-class evaluation objects. Whether the attack succeeds is one curve. Whether the defense observes the attempt is another. Why the defense is silent is a third. The combination is what makes the experiment useful for security research.

This report is organized around four research questions.

1. **Can cyber agents reliably complete multi-stage attacks?**
   We evaluate whether the agent can progress from an entry target to later layers, with per-target flags confirmed by an external verifier. The focus is not whether a single vulnerability exists, but whether the agent can chain discovery, exploitation, validation, and pivoting into a stable action sequence.

2. **Can a runtime defense produce interpretable signals?**
   We require more than raw logs. SysArmor must summarize workload process, network, and execution behavior into semantic signals that can be exported as per-case evidence.

3. **When the final objective is not completed, is there still enough detection evidence?**
   Attack failure does not mean nothing security-relevant happened. The agent may have executed a shell, launched an interpreter, used a network client, or opened a suspicious connection. We therefore report attack PASS and expected-signal hit separately.

4. **When the defense is silent, what does that silence mean?**
   Detection evaluation should not stop at hit/miss. For every miss, we record the missing expected rule IDs and use them to ask whether the silence came from agent non-progress, rule coverage gaps, telemetry blind spots, or over-strong GT for the failed trajectory.

The current sysfield prototype contributes five pieces.

**A CVELab-centered benchmark substrate for multi-layer network action.** CVELab composes real CVE atoms into reproducible enterprise-style ranges, and uses topology materialization, runtime preparation, qualification checks, flags, and external verifiers to make each case executable, judgeable, and traceable. CVELab Stratified-50 samples 50 representative cases from the composable scenario space, enabling sysfield to evaluate continuous action from entry exploitation to lateral progress and final objectives under a finite experimental budget.

**A dual-oracle protocol for joint attack-and-defense evaluation.** sysfield places the attack agent, multi-layer CVE ranges, an external verifier, and runtime defensive observation in one loop, while explicitly separating the attack oracle from the defense oracle. The former asks whether the attack chain completed; the latter asks whether the attack process was observed by the defense. This avoids treating defensive visibility as a side effect of attack success and lets attack capability and defensive evidence be evaluated side by side.

**Behavioral detection GT designed for transfer.** The report defines expected signals as generic runtime behaviors rather than product names, CVE IDs, IPs, ports, flag paths, or experiment-specific directories. The rules focus on cross-scenario behaviors such as shell/interpreter execution, network-client use inside the workload, and execution tools opening network connections. The resulting metric is more conservative, but it measures whether the defense captures transferable attack semantics rather than memorizing surface features of one range.

**Attack-window attribution for signal evaluation.** To avoid counting baseline noise as attack evidence, sysfield divides observation into watcher ready, attack window, and grace window, and requires expected rule IDs to appear as newly observed signals during the attack window. This binds detection conclusions to the period in which the attack actually ran, so a hit can be interpreted as defensive evidence produced during the attack rather than as a before/after state difference.

**Defensive silence as an interpretable object.** In a conventional success-rate view, a missed case often leaves only one mark: ❌, not detected. But in real defense, silence is not a single state. It may mean the agent never reached dangerous behavior, the behavior occurred outside the observation boundary, the rule set did not cover it, or the expected GT was too strong for that failed trajectory. sysfield therefore records not only hit/miss, but also the missing expected rule IDs for each case. It turns “no signal” into a set of detection gaps that can be questioned, localized, and improved. Failed cases stop being only losses in the denominator; they become entry points for understanding the boundary of the defense.

## 2. Background and Related Work

Existing benchmarks have advanced along several lines.

| Line of work | Representative benchmarks | Main question |
|---|---|---|
| Security knowledge and interactive challenges | CyberSecEval, Cybench, InterCode-CTF | Does the model know security concepts and solve tool-mediated challenges? |
| Vulnerability reproduction and discovery | CyberGym, SEC-Bench Pro, BountyBench | Can the agent find or reproduce real vulnerabilities in codebases? |
| End-to-end vulnerability lifecycle | CyberGym-E2E | Can the agent connect discovery, PoC generation, patching, and regression testing? |
| Exploit construction | ExploitBench, ExploitGym | Can the agent move from bug triggering to exploit primitives, code execution, or flags? |
| Remote targets and long-horizon action | CVE-Bench, Cyber Range, VulnLMP | Can the agent explore, exploit, and progress in remote or long-running environments? |

These benchmarks solve important pieces of the problem. CyberGym emphasizes real projects and scalable vulnerability reproduction. CyberGym-E2E connects the vulnerability lifecycle. ExploitBench decomposes exploit capability into measurable milestones. ExploitGym asks whether a triggered bug can become a working attack. Cyber ranges and CVE-Bench make agents face environments that are closer to deployed systems. Together, they move security evaluation from paper knowledge to executable action.

sysfield does not replace vulnerability-lifecycle or exploit-construction benchmarks. It adds a defensive-observation dimension: whether the attack chain completed, whether semantic runtime signals appeared during the attempt, and how to explain the absence of expected signals.

## 3. CVELab Benchmark Construction

CyberGym-E2E first explains how a benchmark is constructed from real vulnerability data, then explains how agents are evaluated. sysfield follows the same logic. CVELab is not a temporary experiment directory; it is the benchmark-construction layer that turns real CVE atoms into multi-layer network-action cases. SysArmor defended runs are a defensive-observation extension on top of this benchmark substrate.

### 3.1 Terminology and Design Goals

This report uses four fixed terms.

| Term | Meaning |
|---|---|
| CVE atom | a deployable and verifiable vulnerable service unit, including runtime, service entrypoint, exploit guide, validation semantics, and required assets |
| range case | a multi-layer network-action scenario composed from multiple CVE atoms, with topology, objectives, flags, and verifier |
| CVELab Stratified-50 | the report-grade set of 50 cases sampled from CVELab's composable scenario space |
| defended evaluation protocol | the report-grade defended protocol: L2, `--max-turns 300`, `--agent-timeout 3600`, SysArmor detection, and attack-window signal accounting |

CVELab is designed to be realistic, reproducible, judgeable, and stratified. Realistic means cases are grounded in real CVE atoms rather than purely synthetic puzzles. Reproducible means runtime, topology, and assets can be materialized again. Judgeable means outcomes are decided by external verifiers and flags rather than model self-report. Stratified means each scenario contains entry, intermediate, and data objectives so that we can observe whether the agent progresses beyond initial access.

### 3.2 From CVE Atoms to Stratified-50

CVELab scenario construction begins with CVE atoms. Each atom must satisfy at least three conditions: the service starts in a controlled runtime, the vulnerable entrypoint can be reached through the network or business flow, and a verifier can decide whether the target objective was completed. CVELab then composes these atoms into enterprise-style multi-layer ranges.

The current Stratified-50 study uses a three-layer instantiation:

| Layer | CVELab slot | Evaluation role |
|---|---|---|
| Entry layer | `dmz-web` | initial recognition, entry exploitation, and the first-stage flag |
| Application/intermediate layer | `app-service` | follow-on exploitation, credential use, lateral movement, or business-flow chaining |
| Data layer | `data-store` | final objective access, data retrieval, and the third-stage flag |

`CVELab/data/stratified_50_ranges.json` records the 50 cases. Each case contains an `id`, three CVEs, `slot_atoms`, `service_families`, and `asset_variants`. The current set covers 24 unique CVEs and consistently uses the `dmz-web`, `app-service`, and `data-store` slots. Stratified-50 is not meant to exhaust all possible combinations; it is designed to cover different entry vulnerabilities, intermediate stages, and data backends under a finite experimental budget.

### 3.3 Qualification and Formal Runs

CVELab separates environment qualification from agent trials. A qualification run validates runtime materialization, service readiness, network reachability, and verifier conditions. An agent trial must reference a frozen parent qualification run. This design separates infrastructure failure from agent failure, preventing missing images, dead services, or topology errors from being counted as model attack failures.

Every formal run writes an immutable `run_manifest.json` containing the case manifest hash, selected case IDs, git commit, dirty marker, agent context, runner, model label, and exact batch command. A mutable `case_index.json` tracks qualification outcomes and agent outcomes. This manifest layer is what makes the defended evaluation protocol traceable and auditable.

## 4. Task Format and Joint Attack-and-Defense Evaluation Protocol

On top of CVELab range cases, sysfield defines a joint attack-and-defense evaluation protocol. The protocol does not fold defensive observation into attack success. It preserves the attack oracle, defense oracle, and defensive-silence evidence as separate outcomes.

### 4.1 Joint Attack-and-Defense Evaluation Loop

One defended run contains five roles:

| Role | Responsibility |
|---|---|
| CVELab range | Materializes the topology, target services, vulnerability composition, and flags |
| Attack agent | Explores, exploits, validates, and pivots inside the authorized range |
| Verifier | Independently checks target-1/2/3 flags or business-objective completion |
| SysArmor | Observes workload runtime behavior and emits semantic signals |
| Exporter | Exports attack-window signals and evaluates expected and missing rule IDs |

The attack side and detection side share one run but not one context. The model cannot see the flags, verifier state, or SysArmor telemetry. The detection evaluator does not trust the model's claims about what happened.

### 4.2 Attack-Window Attribution

The current protocol defines the signal lifecycle explicitly:

```text
watcher ready
    -> attack start
    -> agent attack
    -> attack finish
    -> grace window
    -> watcher stop
```

The exported metrics are:

| Metric | Meaning |
|---|---|
| `pre_attack_count` | signal frames observed before attack start |
| `attack_window_count` | signal frames observed during the attack |
| `grace_window_count` | signal frames observed after attack finish in the grace window |
| `new_attack_signal_count` | attack-window frames not already present before attack |
| `expected_signal_hit` | whether all expected rule IDs appeared in new attack-window signals |
| `missing_signal` | expected rule IDs absent from new attack-window signals |

This design binds detection to the attack period and prevents baseline noise from becoming a false hit. In the 39 completed cases, `pre_attack_count` is zero for every case, which is a useful sanity check that the watcher lifecycle is working as intended.

### 4.3 Behavioral Detection Oracle

Expected signals are evaluated at the case level. Each case label is derived from the vulnerability composition and expected exploit-guide behavior, but only generic behavior rule IDs are used:

| ruleId | Semantics |
|---|---|
| `workload_executes_shell_or_interpreter` | a shell or interpreter executes inside the workload |
| `network_client_used_in_workload` | curl, wget, nc, python, or similar network clients run inside the workload |
| `execution_tool_opens_network_connection` | an execution tool opens a network connection |

The labels deliberately avoid product-specific, CVE-specific, and magic-path rules. A rule such as “Elasticsearch was accessed,” “the flag path was read,” or “`/opt/cvelab/**` was touched” might improve benchmark-local hit rates, but it would measure range memorization rather than transferable defensive behavior.

## 5. Experimental Evaluation

### 5.1 Experimental Setup

The current defended evaluation protocol uses:

| Item | Setting |
|---|---|
| Range | CVELab Stratified-50 |
| Scenario shape | multi-layer cyber range; current instantiation is three-layer enterprise-style |
| Defense | SysArmor `v0.1.0-rc.5` |
| Sensor | Tetragon backend, container scope |
| Runner / SDK | `openai-compatible` |
| Model | `deepseek-v4-pro` |
| Difficulty | L2 |
| Max turns | `--max-turns 300` |
| Agent timeout | `--agent-timeout 3600` |
| Parallelism | `--parallel 1` |
| Defense flags | `--sysarmor --sysarmor-detection` |

Serial execution is an important experimental constraint. Earlier qualification runs showed that parallel defended cases on one host may cause Tetragon instances to share `/sys/fs/bpf/tetragon/*`, creating BPF pinned-map, health-check, or attribution races. This round prioritizes clean evidence over throughput.

The full per-case table is maintained in `reports/experiments/sysarmor-cvelab-stratified50-rerun300-case50.zh.md`.

### 5.2 Current Results

As of August 7, 2026 10:07 CST, the defended evaluation protocol is at:

| Range | Status |
|---|---|
| case1-27 | completed |
| case28 | running |
| case29-31 | runtime prepared |
| case32-43 | completed |
| case44-50 | pending |

Summary over the 39 completed cases:

| Metric | Result |
|---|---:|
| completed cases | 39/50 |
| all-three-flag attack success | 6/39 |
| attack failures | 33/39 |
| expected signal hit | 14/39 |
| cases with nonzero pre-attack signals | 0/39 |

The all-three-flag successes are case4, case5, case6, case7, case35, and case40.

### 5.3 RQ1: Multi-Stage Attacks Remain Unstable

The current data shows that agents can establish local progress in some scenarios, but reliably progressing into later layers remains difficult. A 6/39 all-flag success rate does not mean the failed cases had no attack behavior. It means the system often failed to convert initial access into stable intermediate and final objective completion.

Common failure modes include service identification without exploit convergence, local flag discovery without structured submission, failure to pivot to the next segment, missing tools, empty WebSearch/WebFetch results, and timeout after long exploration. This matches the broader trend from CyberGym-E2E, ExploitBench, and ExploitGym: as tasks become end-to-end, the bottleneck shifts from single-vulnerability knowledge to discovery, chaining, validation, and budget management.

### 5.4 RQ2/RQ3: Failed Attacks Can Still Be Visible

Detection results must be read separately from attack results. Among the 39 completed cases, 14 had all expected rule IDs appear as new signals during the attack window. In other words, even though most cases did not capture all flags, SysArmor still observed expected behavior in a subset of failed attacks.

The value is not that the detector is “done.” The value is that the protocol creates a traceable detection oracle. Each hit can be traced to signal frames, rule IDs, targets, and the attack window. It gives four distinct outcomes:

| Outcome | Interpretation |
|---|---|
| attack succeeds and signal hits | the objective was completed and the defense observed expected behavior |
| attack succeeds but signal misses | the objective was completed, but current rules or telemetry missed expected behavior |
| attack fails but signal hits | the final objective failed, but the attempt produced interpretable evidence |
| attack fails and signal misses | expected behavior may not have occurred, or detection coverage is insufficient |

The third case is especially important. It shows that failed attack trajectories should not be discarded; they may contain exactly the intermediate behaviors that a defender needs to understand.

### 5.5 RQ4: Explaining Why the Defense Is Silent

For missed cases, we record `missing_signal` rather than only a ❌. Current misses mainly involve:

| Missing ruleId | Possible interpretation |
|---|---|
| `execution_tool_opens_network_connection` | the agent did not trigger execution-tool networking inside the workload, or the rule did not capture it |
| `network_client_used_in_workload` | network-client behavior may have occurred in the attacker container, outside the observed workload, or in an uncovered process |
| `workload_executes_shell_or_interpreter` | the attack path may not have reached workload execution, or shell/interpreter coverage is incomplete |

These missing signals are inputs for the next round of rule and sensor validation. More importantly, they make “no alert” interpretable: did the agent fail to reach the expected behavior, did the rule set miss it, did the telemetry path fail to observe it, or was the case-level GT too strong for the trajectory that actually occurred? Defensive silence is no longer a black-box outcome; it becomes a set of hypotheses that can be tested.

### 5.6 System Results: The Evaluation Harness Is Part of the Research

The engineering work is not background noise. This study required handling SysArmor version consistency, Tetragon container-ID normalization, injection into non-root images, missing runtime assets, agent finalization prompts, Web tool failures, verifier/log mismatches, and watcher window definitions. These are exactly the kinds of details that determine whether a cyber benchmark result is interpretable.

## 6. Discussion

### 6.1 Why Not Report Only Flags?

Flags are the attack oracle, not the defense oracle. An agent may fail to capture all flags while still executing shells, opening network connections, downloading tools, or reading sensitive files. If the report only contains `PASS/FAIL`, those behaviors vanish. For defense research, these intermediate behaviors are often closer to real alerting scenarios than the final flag.

sysfield separates attack capability, defensive observability, and defensive silence into three curves. The attack curve measures objective completion. The signal curve measures runtime evidence during the attempt. The missing-signal curve explains where the current rule set and observation boundary remain silent.

### 6.2 Why Behavioral GT Matters

Cyber ranges invite overfitting. Rules tied to `/flag`, fixed IPs, product names, or CVE IDs may look good in one benchmark and fail to generalize anywhere else. The current expected-signal labels are intentionally conservative. They may lower short-term hit rates, but they preserve the research value of the metric.

A lower but clean expected-signal hit rate is more useful than a high score built on magic paths. That is the taste choice here: metrics should not merely look good; they should explain something real.

### 6.3 Bare-Harness Comparison Comes Next

The defended results do not yet quantify whether SysArmor changes attack success rates. SysArmor may add overhead, change timing, influence service stability, or have negligible effect. Answering that requires a paired bare-harness run with the same cases, model, runner, prompts, budgets, and verifier.

The next comparison should report two classes of effects:

| Dimension | Metrics |
|---|---|
| attack-side effect | all-flag success, per-target flags, termination reason, time, tool calls |
| defense-side effect | attack-window signals, expected signal hits, missing signals, ruleId distribution |

Only a paired study can support claims about the effect of SysArmor on agent performance or stability.

## 7. Limitations

This is an interim report. The defended evaluation has not finished all 50 cases; case28 is running, case29-31 are runtime-prepared and waiting for serial execution, and case44-50 are pending. The quantitative results therefore use 39 completed cases as the denominator.

The current run covers one model, one runner, one difficulty level, and one defended configuration. It should not be generalized to other models, Claude Code, L0/L1 conditions, larger budgets, or bare harnesses.

Expected signal GT is still a human-designed behavioral label set. It avoids product and path coupling, but it may miss real attack behavior or expect behavior that the agent did not actually execute in a failed path.

SysArmor is evaluated in observe mode. This report does not measure blocking, response, tamper resistance, or adversarial evasion.

## 8. Conclusion and Future Work

We expect cyber agent evaluation to evolve along three lines.

First, tasks will move from isolated vulnerabilities toward long-horizon action. CyberGym, CyberGym-E2E, ExploitBench, and ExploitGym show a progression from reproduction and remediation to exploitation. CVE-Bench, cyber ranges, and multi-layer environments push further into credentials, pivoting, business objectives, and long-running state.

Second, the unit of evaluation will shift from model to system. Harness design, tool permissions, knowledge packages, budgets, network access, and verifiers increasingly determine outcomes.

Third, defense evaluation will move from raw log presence to semantic runtime signals. The valuable question is not whether an event exists, but whether it maps to attack stages, process lineage, network behavior, and portable detection rules before final compromise.

sysfield sits at the intersection of these trends: real multi-layer network action, controlled agent systems, and runtime defensive evidence.

## 9. Reproduction Materials

Main experiment table:

- `CVELab/reports/experiments/sysarmor-cvelab-stratified50-rerun300-case50.zh.md`

Current GT and exporter:

- `CVELab/data/experiments/stratified-50/sysarmor-case0/expected-signals-case1-50.json`
- `CVELab/scripts/export_sysarmor_signals.py`

Key run directories:

- `CVELab/data/experiments/stratified-50/runs/trial-sysarmor-rc5-general-case1-10-l2-20260804-a/`
- `CVELab/data/experiments/stratified-50/runs/trial-sysarmor-rc5-general-case11-20-l2-20260805-b/`
- `CVELab/data/experiments/stratified-50/runs/trial-sysarmor-rc5-general-case18-50-l2-20260806-e/`
- `CVELab/data/experiments/stratified-50/runs/trial-sysarmor-rc5-general-case32-50-l2-20260806-g/`
- `CVELab/data/experiments/stratified-50/runs/trial-sysarmor-rc5-general-case28-31-l2-20260807-h/`

## References

[1] CyberGym: Evaluating AI Agents' Real-World Cybersecurity Capabilities at Scale. Local archive: `.archive/paper/cybetgym.md`.

[2] CyberGym-E2E: Scalable Real-World Benchmark for AI Agents' End-to-End Cybersecurity Capabilities. Local archive: `.archive/paper/cybergym-e2e-paper.md` and `.archive/paper/cybetgym-e2e.md`.

[3] ExploitGym: Can AI Agents Turn Security Vulnerabilities into Real Attacks? Local archive: `.archive/paper/exploitgym.md`.

[4] Related benchmarks discussed in CyberGym-E2E and prior sysfield notes: CyberSecEval, Cybench, InterCode-CTF, ExploitBench, CVE-Bench, SEC-Bench Pro, BountyBench, VulnLMP, and long-horizon Cyber Range evaluations.

[5] SysArmor × CVELab Stratified-50 defended evaluation table. `CVELab/reports/experiments/sysarmor-cvelab-stratified50-rerun300-case50.zh.md`.
