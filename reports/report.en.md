# sysfield: Evaluating Cyber Agents in Real Defended Environments

**Technical Report Draft**

**Status:** interim report based on the current CVELab x SysArmor experiments

**Date:** August 7, 2026

## Abstract

Cyber-agent evaluation is moving from static knowledge and isolated tasks to sustained action in real systems. Benchmarks such as CyberGym, CyberGym-E2E, and ExploitGym now measure vulnerability reproduction in real repositories, complete vulnerability lifecycles, and concrete exploit effects. Their primary outcomes, however, remain PoCs, patches, flags, or final objectives. They show what an agent completed, but say much less about what real defenses observed along the way or whether environmental interference changed the agent's behavior.

This leaves defenders with a central question: do cyber agents remain effective in real defended environments? Attack success alone cannot answer it. A successful attack does not imply that the defense was blind, and a failed attack does not imply that no risk existed. A failed trajectory may still leave high-value runtime evidence; a successful trajectory may have been visible from its earliest steps.

Evaluating this question poses four difficulties. Heterogeneous CVE environments are hard to compose into stable, judgeable multi-stage tasks. Model, harness, and environment effects are easily entangled. Final attack outcomes and defensive visibility are related but cannot substitute for one another. When an expected signal is absent, the absence does not by itself establish a defensive blind spot.

We present sysfield, which addresses these difficulties with four direct techniques. **CVE atomization and multi-layer scenario composition** create reproducible network tasks. **Same-case controlled comparisons** separate model, harness, and environmental effects. **External attack-outcome verification combined with runtime observation** measures completion and visibility independently. **Expected-behavior coverage analysis** makes missing signals explicit and interpretable. CVELab supplies three-layer ranges built from real CVEs, an external verifier judges stage flags and objectives, and SysArmor records attack-window runtime signals in observe-only mode.

We report three sets of interim results on Stratified-50. The Kimi-K3 and DeepSeek-V4-Pro L2 arms both completed all 50 cases. Kimi-K3 reached the three stages in 22/50, 18/50, and 16/50 cases, compared with 19/50, 10/50, and 6/50 for DeepSeek; the observed difference emerges mainly after initial access. The models produced new signals in 42/50 and 30/50 cases, with strict expected-signal hits in 28/50 and 14/50. In the DeepSeek L1 none/high comparison, the current high configuration increased timeouts from 6/50 to 19/50 and mean runtime from 1,417.6 to 2,428.5 seconds. Because that configuration also changes a topology hint, the result measures an overall interference effect, not a pure decoy effect.

The results show that frontier agents can complete some real multi-layer tasks, but their capability remains sensitive to the model and surrounding system. Baseline runtime defenses still produce structured evidence in many successful and failed trajectories. The most frequently missing behaviors concern execution tools opening network connections, network clients inside workloads, and shell or interpreter execution. These conclusions remain limited by a small set of agents, single runs, observe-only defense, current behavior-rule coverage, and incomplete per-rule missing-signal detail. sysfield is not intended to make agents more effective attackers. It provides defenders, evaluators, and platform operators with a more complete account of frontier-agent risk.

## 1. Introduction

### 1.1 Field shift: from model answers to system actions

Cybersecurity tasks are a natural test of agent capability. They have explicit goals, tools return real feedback, and environment state can verify the outcome. At the same time, they require a model to combine understanding, planning, tool use, state management, and error recovery over long interactions. As models have improved, cyber evaluation has moved from knowledge questions and CTFs to real repositories, remote targets, and long-horizon network action.

This shift changes the object being evaluated. The relevant unit is no longer an isolated model, but a complete agentic system defined by `model x harness x tools x environment x budget`. The same model can produce materially different results under different tools, context management, and execution frameworks. A benchmark that reports only a model name and final success rate can no longer explain where the capability came from.

### 1.2 Gap: task completion does not show what the defense observed

Prior work has substantially increased task realism. CyberGym verifies PoCs in real repositories. CyberGym-E2E connects discovery, PoC generation, patching, and regression testing. ExploitGym distinguishes vulnerability triggering from concrete attack effects. Cyber ranges connect multiple steps into sustained network action. Together, these benchmarks answer an important question: how realistic a security task can an agent complete?

Defenders need a second answer: are those actions visible to real defenses, and can deception or environmental noise perturb them? A final flag cannot answer this on its own. An agent may fail the final objective after already executing dangerous behavior. It may also complete the objective while leaving evidence throughout the trajectory. Compressing the entire run into PASS or FAIL discards both the attack process and the defensive exposure surface.

We therefore study the following core question:

> **Do cyber agents remain effective in real defended environments?**

Here, effectiveness has three dimensions: whether the agent completes the attack task, whether its actions are visible to runtime defenses, and whether it continues to make progress under deception or environmental interference. These dimensions must be measured separately and interpreted on the same case.

### 1.3 Research questions

The report addresses four questions in sequence:

- **RQ1:** Can agents complete multi-layer network tasks, and how does progression differ across models?
- **RQ2:** How much do the harness and environmental interference change that capability?
- **RQ3:** Do agent actions trigger baseline runtime-defense signals?
- **RQ4:** Which expected attack behaviors are most often not observed?

The first two questions measure attack completion and its system dependence. The latter two measure defensive visibility and its boundaries. Together, they form a defender-oriented risk profile rather than an offensive capability leaderboard.

### 1.4 Key insight and contributions

Our central insight is that **agent risk cannot be characterized by attack success alone; defenders need a joint view of attack completion, defensive visibility, and robustness under interference.**

This report makes three contributions:

1. **A multi-layer evaluation substrate built from real CVEs.** CVELab packages heterogeneous vulnerabilities as independently deployable and verifiable atoms, then composes them into network scenarios with stage-level objectives.
2. **An evaluation method that preserves both attack outcomes and defensive evidence.** An external verifier judges flags and objectives, while SysArmor records runtime signals independently. The two result types are aligned by case but remain separate measurements.
3. **Interim evidence on model differences, defensive visibility, and environmental interference.** The experiments show that model differences emerge primarily in sustained multi-layer progression, runtime signals occur in both successful and failed trajectories, and the current high-decoy configuration materially increases agent runtime cost.

## 2. Related Work

### 2.1 Six lines of cyber-agent evaluation

Cybersecurity benchmarks do not lie on one shared difficulty axis. Different works choose different starting points, endpoints, and judging semantics.

| Evaluation line | Representative work | Main technical advance | Primary endpoint |
|---|---|---|---|
| Security knowledge and interactive challenges | CyberSecEval, Cybench, InterCode-CTF [1-3] | Categorized task suites, containerized interaction, execution feedback, and subtask decomposition | Correct answer, subtask, or flag |
| Real vulnerability discovery and reproduction | CyberGym, SEC-Bench Pro, BountyBench, OSS-Fuzz-style evaluations [4-6] | Real repository reconstruction, withheld vulnerability artifacts, and executable pre-/post-patch or cross-version validation | Vulnerability, PoC, or patch |
| Vulnerability lifecycle and exploit formation | CyberGym-E2E, ExploitBench, ExploitGym [7-9] | End-to-end task chaining, capability ladders, two-stage validation, and mitigation ablation | Regression-tested patch, exploit primitive, or unauthorized execution |
| Remote targets and multi-stage action | AutoPen-Bench, CVE-Bench, WebExploitBench, OpenAI Cyber Range, UK AISI long-horizon evaluations [10-14] | Isolated remote targets, black-box interaction, external state verification, and stage-progress recording | Remote state, deepest step, or final objective |
| Long-horizon vulnerability research | VulnLMP [14] | Parallel research directions and reproducible evidence validation | Multi-day research artifact or controlled exploit primitive |
| Autonomous defense and defensive artifacts | AIxCC, CTI-REALM [15-16] | Executable vulnerability validation, functional patch testing, and validated CTI-to-rule pipelines | Repaired software or detection rule |

Raw success rates across these lines are not comparable. A CTF flag, a differentially validated PoC, unauthorized execution, a long-horizon objective, and a detection rule are different research objects. Longer runtime also does not imply broader coverage of network-attack stages.

### 2.2 How representative techniques advanced the field

CyberGym addresses scalable reproduction of real vulnerabilities. It reconstructs historical projects automatically and uses pre-/post-patch differential testing to determine whether a PoC corresponds to the target vulnerability [4]. SEC-Bench Pro withholds the original PoC, patch, and detailed report, then uses cross-version execution to validate open-ended vulnerability discovery [5]. These techniques improve realism and contamination resistance, but the tasks generally end at discovery or reproduction.

CyberGym-E2E connects discovery, PoC generation, patching, and regression testing, using reproducible environments and functional tests to constrain the patch [7]. ExploitBench uses staged checkpoints to separate triggering, exploit primitives, and code execution [8]. ExploitGym uses execution-based evaluation, two-stage validation, and mitigation ablation to determine whether an agent turns the specified vulnerability into a concrete attack effect [9]. Together, these works show that triggering, full exploitation, and repair are distinct capability levels.

AutoPen-Bench, CVE-Bench, WebExploitBench, and cyber ranges move evaluation toward remote targets or sustained network action [10-14]. They use isolated targets, external state, or stage progress to reduce uncertainty from agent self-reporting. VulnLMP extends the time available for research in another direction, although long-horizon vulnerability research does not automatically constitute a multi-host action chain [14].

AIxCC and CTI-REALM are closer to defensive work. The former evaluates autonomous vulnerability discovery and repair, while the latter evaluates the generation of detection rules from threat intelligence [15-16]. But an agent's ability to produce a defensive artifact is still different from an existing defense's ability to observe an attacking agent.

Public model system cards and systems such as Fugu-Cyber reveal a cross-cutting fact: cybersecurity results depend on harnesses, tools, and budgets, not on the bare model alone [14,16]. METR Time Horizon can characterize task duration, but it is not a substitute for coverage of security stages [17].

### 2.3 Where sysfield fits

sysfield does not replace these benchmarks, nor does it claim a stronger attack task. It adds a dimension that prior work rarely measures systematically: **preserving attack completion, runtime defensive visibility, and environmental-interference evidence within the same real network case.**

This position also determines the report's stance. Controlled attack trajectories are measurement instruments used to help defenders, evaluators, and platform operators understand risk boundaries. Missing signals are used to identify limitations in telemetry, rules, or ground truth, not to derive detection-evasion guidance.

## 3. Research Challenges

### 3.1 Heterogeneous CVEs are difficult to compose into stable multi-layer tasks

Real CVEs depend on different runtimes, ports, assets, and exploitation preconditions. Reproducing each vulnerability independently does not guarantee that several of them can be connected reliably in one topology. A multi-layer benchmark must also keep every stage reachable and judgeable while separating environment failures from agent failures.

### 3.2 Model and system effects are easily entangled

One run is shaped simultaneously by the model, harness, prompt information, tools, budget, noise, and environment state. If a comparison changes several of these conditions, the cause of the observed difference becomes unclear. Cross-benchmark leaderboards are especially prone to presenting system differences as model differences.

### 3.3 Attack completion and defensive visibility must both be measured

A final flag indicates how far the attack progressed, but not what the defense recorded. A signal hit indicates that expected behavior was observed, but not that the attack succeeded, was severe, or was blocked. The two outcomes must be aligned within the same run without being collapsed into one score.

### 3.4 A missing signal has no single interpretation

An expected signal may be absent for at least four reasons: the agent did not execute the behavior; the behavior occurred outside the current telemetry boundary; the rule did not cover the realized variant; or the case-level expectation was too strong for the failed trajectory. A miss therefore cannot be labeled a defensive blind spot by default.

## 4. sysfield

### 4.1 Method overview

sysfield addresses the four challenges with four corresponding techniques.

| Challenge | Technique | Implementation in sysfield |
|---|---|---|
| Heterogeneous vulnerabilities do not form stable tasks by default | CVE atomization and multi-layer scenario composition | Package each vulnerability as a deployable, verifiable, reusable atom, then compose ranges according to topology and capability dependencies |
| Multiple system factors change together | Same-case controlled comparisons | Hold cases, budgets, and protocols fixed while changing the model, harness, or interference condition |
| Final outcomes do not represent defensive visibility | External attack-outcome verification combined with runtime observation | Use a verifier for flags/objectives and SysArmor for signals; align both by case but report them separately |
| Signal misses are difficult to interpret | Expected-behavior coverage analysis | Define general expected behavior per case, record hits and missing rules, and interpret them against the realized trajectory |

### 4.2 CVE atomization and multi-layer scenario composition

A CVE atom is sysfield's smallest vulnerability unit. Each atom preserves a reconstructable runtime, service entry point, verification semantics, and the capability information required for composition. An atom must be independently deployable and verifiable before it can enter a multi-layer scenario.

CVELab composes atoms according to slot requirements and capability dependencies. The `enterprise_3tier` scenarios used in this report contain three stages:

| Stage | Scenario role | Evaluation semantics |
|---|---|---|
| Target 1 | DMZ entry service | Identify and use the entry point, then capture the first-stage flag |
| Target 2 | Application or intermediate service | Continue from existing access and capture the second-stage flag |
| Target 3 | Data service | Reach the final objective and capture the third-stage flag |

Before a formal run, every case passes environment validation, attack-graph validation, and path-reachability validation. The model cannot determine its own score. An external verifier checks each stage flag and the business objective. Environment qualification, attack completion, and objective completion therefore remain distinct records.

### 4.3 Same-case controlled comparisons

sysfield divides experimental variables into the model, harness, and interference condition. A valid comparison holds the case manifest, difficulty, budget, tool permissions, and verification protocol fixed, then changes one target variable.

This report contains two such comparisons. The Kimi-K3 and DeepSeek-V4-Pro L2 arms use the same recorded protocol and differ only in the model; they provide a model-capability comparison. The DeepSeek L1 none/high arms use the same 50-case manifest, model, runner, seed, and budget to measure the operational interference of the current high configuration.

Harness uplift is a predefined research question, but that experiment has not been run. We report no harness-uplift value and do not infer one from unmatched runs.

### 4.4 External outcome verification and runtime observation

sysfield preserves two independent result families for the same run:

- **Attack outcomes:** t1/t2/t3 flags, all-three completion, objective, timeout, and failure stage.
- **Defensive outcomes:** attack-window signals, whether any new signal appeared, expected-signal hits, and missing signals.

SysArmor is present as the runtime observation layer across the experiments. This report quantifies defensive metrics only for the L2 arms with complete signal accounting. The L1 none/high experiments also introduced SysArmor, but their current summaries do not export comparable attack-window signal fields; they are therefore excluded from quantitative detection comparisons.

SysArmor currently operates in observe-only mode. It records behavior but does not block the attack. This report evaluates visibility, not blocking or protection success.

### 4.5 Expected-behavior coverage analysis

Expected signals describe general runtime behavior rather than product names, CVE identifiers, fixed IP addresses, ports, or benchmark-private paths. The current Stratified-50 specification primarily uses the following rules:

| ruleId | Behavioral meaning |
|---|---|
| `workload_executes_shell_or_interpreter` | A shell or interpreter executes inside a workload |
| `network_client_used_in_workload` | A network client is used inside a workload |
| `execution_tool_opens_network_connection` | An execution-oriented tool opens a network connection |
| `download_by_lolbin` | A common system utility performs a download |

The watcher becomes ready before the attack and separates signals into pre-attack, attack-window, and grace-window observations. A strict expected-signal hit requires the expected rule to appear as a new signal during the attack window. This reduces the risk of counting baseline noise as attack evidence.

For each miss, sysfield retains the specific missing rule instead of only reporting a binary failure. This analysis measures expected-behavior coverage; it is not independent proof that the behavior occurred.

## 5. Evaluation Methodology

### 5.1 Stratified-50

Stratified-50 contains 50 `enterprise_3tier` cases and 24 unique CVEs. Sampling is stratified by historical entry-stage and intermediate-stage difficulty across six cells: easy/easy, easy/hard, mid/easy, mid/hard, hard/easy, and hard/hard. Historical outcomes are used only for sampling, not as model results in this report.

Each case contains three CVE slots and three stage flags. The data layer currently has only three CVE variants, so the set does not represent all enterprise software or attack paths. Cases also reuse CVEs and should not be treated as 50 statistically independent vulnerability samples.

### 5.2 Experimental arms

| Experimental arm | Primary variable | Completion | Question addressed |
|---|---|---:|---|
| Kimi-K3 L2 + SysArmor | model=`kimi-k3` | 50/50 | Complete multi-layer capability and defensive visibility |
| DeepSeek-V4-Pro L2 + SysArmor | model=`deepseek-v4-pro` | 50/50 | Model comparison under the Kimi protocol |
| DeepSeek-V4-Pro L1 none | interference=`none` | 50/50 | Current L1 baseline |
| DeepSeek-V4-Pro L1 high | interference=`high` | 50/50 | Operational interference of the current high configuration |
| Harness comparison | harness | not run | Uplift from the harness |

The two L2 model arms use the `openai-compatible` SDK, `openai` runner, L2 context, 300 turns, a 3,600-second agent timeout, serial execution, and the same SysArmor detection configuration. Both experiments completed all 50 cases and can be compared directly on the same set; a single run still cannot establish a general model ranking.

The L1 none/high arms use the same manifest, DeepSeek-V4-Pro, L1 context, 300 turns, a 3,600-second timeout, seed 1, and temperature 0. The none arm uses parallel=8 and high uses parallel=4; the arms run in a fixed none-then-high order. The high arm includes 43 decoys and also misses a data-router topology hint. This design measures the overall effect of the current high implementation.

### 5.3 Metrics

We measure attack completion with t1/t2/t3 flags, all-three completion, objective, timeout, and failure stage. We measure defensive visibility with the presence of any new signal, the number of attack-window signal frames, strict expected-signal hits, and attack/visibility quadrants. We measure interference with flags, objectives, timeouts, runtime, and decoy interaction.

Signal-frame counts measure observation volume. They are not counts of independent attack behaviors and do not directly indicate severity. We do not use total frame counts to rank model or detection capability.

### 5.4 Data sources

This report uses results persisted as of August 7, 2026. The consolidated values are in the [Stratified-50 experiment summary](experiments/stratified50-experiment-summary.zh.md). Case-level evidence is available in the [Kimi-K3 watch-window report](experiments/sysarmor-cvelab-stratified50-kimi-k3-watch.zh.md), [DeepSeek L2 report](experiments/sysarmor-cvelab-stratified50-rerun300-case50.zh.md), and [DeepSeek L1 none/high report](experiments/2026-08-07-deepseek-l1-none-high.md).

## 6. Results

### 6.1 RQ1: Can agents complete multi-layer tasks, and how do models differ?

Kimi-K3 completed all 50 L2 cases. It captured all three flags in 16/50 cases and reached t1, t2, and t3 in 22/50, 18/50, and 16/50 cases. It achieved the business objective in 17/50 cases, and 22/50 runs ended in a timeout. Frontier agents can therefore complete some real multi-layer tasks, but sustained progression remains unreliable.

DeepSeek-V4-Pro completed all 50 L2 cases. It captured all three flags in 6/50 cases and reached t1, t2, and t3 in 19/50, 10/50, and 6/50 cases. The two model arms use the same cases and protocol, so their results can be compared directly:

| Model | t1 | t2 | t3 / all-three completion |
|---|---:|---:|---:|
| Kimi-K3 L2 | 22/50 | 18/50 | 16/50 |
| DeepSeek-V4-Pro L2 | 19/50 | 10/50 | 6/50 |

The models differ by three cases at entry, and the gap widens at later stages. Kimi loses six cases from t1 to t3, whereas DeepSeek loses 13. This supports a bounded conclusion: **under the current protocol, the observed model difference lies mainly in sustained progression after initial access, not in initial entry.** Kimi records 22/50 timeouts and DeepSeek records 0/50. Their termination patterns differ, but without repeated trials this does not establish a general reliability ranking.

### 6.2 RQ2: How much do system conditions change capability?

The harness-uplift experiment has not been completed, so this report makes no quantitative claim about harness effects. The available evidence comes from the DeepSeek L1 none/high comparison.

| Metric | none | high |
|---|---:|---:|
| All-three completion | 2/50 | 0/50 |
| t1 / t2 / t3 | 2/50 / 2/50 / 2/50 | 2/50 / 0/50 / 0/50 |
| Objective | 1/50 | 0/50 |
| Timeout | 6/50 | 19/50 |
| Mean agent time | 1,417.6 s | 2,428.5 s |
| Median agent time | 1,091.7 s | 2,536.5 s |
| Decoy interaction | not applicable | 50/50 |
| Direct decoy contact | not applicable | 38/50 |
| Decoy hits | not applicable | 27,230 |

Both arms achieved 50/50 environment validation, attack-graph validity, path reachability, and cleanup, so the difference is not a range-deployment failure. The high configuration increased mean runtime by roughly 71% and timeouts from 6 to 19. The two cases that succeeded under none both failed under high, and there was no high-only success.

This is not a pure causal estimate of decoy effects. The high arm combines 43 decoys with different worker parallelism and a topology-hint serialization difference. The supported conclusion is narrower: **the current high configuration materially increases exploration and planning cost for the L1 agent.** Isolating the decoy effect requires fixing the topology hint, matching parallelism, and randomizing arm order.

### 6.3 RQ3: Do agent actions trigger defensive signals?

Yes, but signal coverage and attack completion are distinct.

Across all 50 Kimi cases, 42/50 produced at least one new attack-window signal and 28/50 covered every expected signal, with 23,252 attack-window signal frames in total. Across all 50 DeepSeek cases, 30/50 produced a new signal and 14/50 covered every expected signal, with 9,628 frames in total.

| Model | All-three completion | At least one new signal | Strict expected hit |
|---|---:|---:|---:|
| Kimi-K3 L2 | 16/50 | 42/50 | 28/50 |
| DeepSeek-V4-Pro L2 | 6/50 | 30/50 | 14/50 |

DeepSeek completed only six multi-layer tasks, yet 30 cases still produced runtime signals. Attack failure cannot be interpreted as an absence of security-relevant activity.

The four outcome quadrants make the separation explicit:

| Model | Attack success / signal hit | Attack success / signal miss | Attack failure / signal hit | Attack failure / signal miss |
|---|---:|---:|---:|---:|
| Kimi-K3, 50 cases | 12 | 4 | 16 | 18 |
| DeepSeek-V4-Pro, 50 cases | 3 | 3 | 11 | 33 |

Kimi has 16 cases and DeepSeek has 11 cases in which the attack failed but all expected signals were present. Both models also have cases in which the attack succeeded but expected-signal coverage was incomplete. The former shows that failed trajectories still expose behavior; the latter shows that success does not guarantee coverage by the current rules.

These results establish that SysArmor produced observational evidence. They do not show that an attack was prevented, nor does signal volume alone establish attack severity.

### 6.4 RQ4: Which expected behaviors are most often not observed?

The ten newly completed DeepSeek cases record expected-signal misses but do not include per-rule `missing_signal` detail. The table therefore compares the 40 cases for which both model arms have complete missing-rule fields:

| Missing rule | Kimi-K3 | DeepSeek-V4-Pro |
|---|---:|---:|
| `execution_tool_opens_network_connection` | 12 | 23 |
| `network_client_used_in_workload` | 9 | 18 |
| `workload_executes_shell_or_interpreter` | 6 | 16 |

For both models, execution tools opening network connections are missing most often, followed by network-client and shell/interpreter behavior inside workloads. This distribution provides priorities for rule and telemetry improvement, but it does not establish that DeepSeek is stealthier or that SysArmor is blind to those behaviors.

Expected rules describe behavior a case may require; they are not action-level labels of the realized trajectory. If DeepSeek stops earlier, some expected behaviors may never occur. Other misses may reflect rule coverage or telemetry boundaries. Distinguishing absent behavior from absent observation requires aligning each missing rule with tool calls and workload events.

### 6.5 Interim answer to the core question

Cyber agents retain meaningful attack capability in real defended environments, but that capability is not a stable constant. It varies across models and system conditions, decays quickly during multi-layer progression, and is materially perturbed by the current high configuration. At the same time, baseline runtime defenses have not broadly lost visibility: structured signals appear in many successful and failed trajectories.

Real risk therefore cannot be represented by either agent success or detection hit rate alone. Attack completion, defensive visibility, and robustness under interference must be reported together.

## 7. Discussion

### 7.1 For defenders: use process evidence before final compromise

A substantial fraction of failed attacks triggered all expected signals. Defenders should not treat failure to reach the final objective as an absence of risk, and they need not wait for the full attack chain before evaluating detection value. Process signals can support earlier investigation, correlation, and response design.

Observe-only evidence is not protection efficacy. A next step is to add blocking and response experiments under the same protocol and measure whether action taken after a signal reduces downstream flag capture. The current data cannot answer that question.

### 7.2 For benchmark designers: preserve outcomes and process

Stage-level flags are more informative than one PASS because they show where the agent stopped. Runtime signals add whether its actions were exposed. The two should be aligned at the case level but remain separate fields. Collapsing them into one score would hide important states such as successful-but-visible and failed-but-dangerous trajectories.

Benchmarks should also treat the model, harness, tools, budget, and environment as first-class experimental configuration. The full 50-case results show that model differences change by task stage. A final success rate alone cannot reveal whether a gap arose at entry or during sustained progression.

### 7.3 For platform operators: harnesses and environments are risk controls

Agent capability does not come from the model alone. The harness governs state management, tool execution, and recovery; the environment governs what the agent sees, what attracts it, and how it spends its budget. The current high configuration materially increases timeouts, showing that environmental design can change operating cost.

This does not establish a general protective effect for decoys. It does show that platform operators should include tool permissions, network views, environment feedback, budgets, and runtime observation in deployment evaluations rather than assigning risk from the model version alone.

### 7.4 Responsible evaluation boundary

sysfield uses known vulnerabilities inside authorized, isolated ranges and reports aggregate outcomes and defensive evidence. It does not provide tactical optimization for open-network attacks. The research stance is consistent with CyberGym, CyberGym-E2E, and ExploitGym: realistic tasks are necessary to measure capability and risk in support of safer deployment, defensive planning, and repair.

## 8. Limitations

1. **The model experiments have no repeated trials.** Both L2 arms completed all 50 cases, but one trajectory per case does not measure randomness or establish a general model ranking.
2. **SysArmor is observe-only.** The report cannot show that signals block attacks or improve response outcomes.
3. **Expected signals are not action-level ground truth.** A miss can reflect absent behavior, telemetry boundaries, rule coverage, or an expectation that is too strong. The ten newly completed DeepSeek cases also lack per-rule missing-signal detail.
4. **L1 and L2 answer different questions.** L2 supports model and visibility analysis; L1 none/high supports analysis of the current interference configuration. They cannot be ranked directly.
5. **The high comparison has confounds.** Parallelism differs, arm order is fixed, and high includes a topology-hint difference. The result is not a pure causal estimate of decoys.
6. **Decoy interaction comes from transcript diagnostics.** It is not packet-level provenance and does not prove that every text match represents a real network visit.
7. **The harness experiment is incomplete.** We can define the comparison but cannot report harness uplift.
8. **Task coverage is limited.** Stratified-50 reuses 24 CVEs, the data layer has only three CVE variants, and the suite does not represent all vulnerabilities, topologies, or MITRE ATT&CK stages.
9. **Signal frames are not independent behavior counts.** Volume depends on trajectory length and repeated behavior and cannot be read directly as attack count or severity.

## 9. Conclusion

Frontier cyber agents can complete some real multi-layer tasks, but successful entry does not guarantee sustained progression, and both model and environmental conditions change the resulting capability. At the same time, baseline runtime defenses still produce structured evidence across many successful and failed trajectories, while the current high configuration materially increases agent operating cost.

These results support a direct conclusion: the next generation of cyber-agent benchmarks cannot ask only whether the attack succeeded. They must also ask what the defense observed and when, how the environment changed the agent's behavior, and what a missing signal actually means.

> **Attack success does not imply defensive blindness, and attack failure does not imply the absence of risk.**

sysfield places attack completion, defensive visibility, and robustness under interference in one reproducible evaluation system. Its purpose is not to increase offensive capability, but to help defenders, evaluators, and platform operators understand the real risk boundaries of frontier agents.

## References

[1] Meta. [CyberSecEval / Purple Llama Cybersecurity Benchmarks](https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks).

[2] Zhang et al. [Cybench: A Framework for Evaluating Cybersecurity Capabilities and Risks of Language Models](https://arxiv.org/abs/2408.08926). 2024.

[3] Yang et al. [InterCode: Standardizing and Benchmarking Interactive Coding with Execution Feedback](https://arxiv.org/abs/2306.14898). 2023.

[4] Wang et al. [CyberGym: Evaluating AI Agents' Real-World Cybersecurity Capabilities at Scale](https://arxiv.org/abs/2506.02548). 2025.

[5] OpenAI. [SEC-Bench Pro](https://deploymentsafety.openai.com/gpt-5-6/sec-bench-pro). 2026.

[6] [BountyBench: Dollar Impact of AI Agent Attackers and Defenders on Real-World Cybersecurity Systems](https://arxiv.org/abs/2412.19127). 2024.

[7] [CyberGym-E2E: Benchmarking End-to-End Cybersecurity Agents](https://arxiv.org/abs/2606.04460). 2026.

[8] Lee and Brumley. [ExploitBench: A Capability Ladder Benchmark for LLM Cybersecurity Agents](https://arxiv.org/abs/2605.14153). 2026.

[9] Wang et al. [ExploitGym: Can AI Agents Turn Security Vulnerabilities into Real Attacks?](https://arxiv.org/abs/2605.11086). 2026.

[10] [AutoPenBench: Benchmarking Generative Agents for Penetration Testing](https://arxiv.org/abs/2410.03225). 2024.

[11] [CVE-Bench: A Benchmark for AI Agents' Ability to Exploit Real-World Web Application Vulnerabilities](https://arxiv.org/abs/2503.17332). 2025.

[12] AgentCyberRange. [WebExploitBench](https://huggingface.co/datasets/AgentCyberRange/WebExploitBench).

[13] OpenAI. [GPT-5 System Card](https://cdn.openai.com/gpt-5-system-card.pdf). 2025.

[14] OpenAI. [GPT-5.6 System Card](https://deploymentsafety.openai.com/gpt-5-6/). 2026.

[15] DARPA. [AI Cyber Challenge](https://aicyberchallenge.com/).

[16] Sakana AI. [Introducing Fugu-Cyber](https://sakana.ai/fugu-cyber-release/). 2026.

[17] METR. [Time Horizon](https://metr.org/time-horizons/).
