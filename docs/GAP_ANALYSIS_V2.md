# 阶段 1 缺口分析: atom 池按攻击链可达性语义(v2)的投影

> 状态: 阶段 1 分析报告（已基于修正后的 `pivot_capability` 和新的
> `enterprise_3tier` 依赖语义重跑）。
> 数据来源: `data/atoms/` 95 个 verified + single-service atom。
> 复现脚本: `PYTHONPATH=src python scripts/gap_analysis_v2.py`
> 结果文件: `data/gap_analysis_v2.json`

## 1. 结论先说

当前系统已经从“完全不能做真实攻击链”变成“可以做真实攻击链，但可用的上游跳板太少”。

具体说：

1. **`enterprise_3tier` 不再有硬空缺 slot**
   - 以前 `app-service` 是 0 候选，现在放宽后有 88 个候选。
   - `data-store` 一直有 7 个候选。
   - 所以三层网络的 3 个 slot 现在都能填上 atom。

2. **真正的硬缺口只剩一个：能当跳板的 atom 太少**
   - 95 个 single-service verified atom 里，只有 **7 个** 当前被标成
     `pivot_capability = shell`。
   - 其余 88 个仍是 `none`。
   - 这意味着链式模板虽然能生成，但上游 slot 必须抽到那少数几个能跳板的 atom。

3. **这 7 个不是“唯一真的能跳板”，只是“已经修正过字段”的那 7 个**
   - 之前我们确认过 9 个高置信 RCE atom 其实都能拿 shell。
   - 其中 2 个是多服务 atom，不在当前编排池（`single_service_only=True`）里。
   - 所以 single-service 里实际进入编排池的 7 个都已经修正成 `shell`，数字是合理的。

一句话：

**系统现在能做真实攻击链了，但“可选的上游跳板样本”还很少。**

## 2. 池子总量与基础分布

分析对象：95 个 `verified + single-service` atom。

### 2.1 pivot_capability 分布

| pivot_capability | 数量 | 含义 |
|---|---:|---|
| `none` | 88 | 攻陷后只能拿 flag，不能继续横移 |
| `shell` | 7 | 攻陷后能执行任意命令，可作为跳板 |

**能当跳板的 atom：7 / 95**

这 7 个是：

- `CVE-2012-1823`
- `CVE-2014-3120`
- `CVE-2017-10271`
- `CVE-2017-8386`
- `CVE-2018-10933`
- `CVE-2018-16509`
- `CVE-2019-9193`

它们全部都是 RCE，且 `flag_verify_command` 已经证明其本质是“能执行任意命令”；
现在把 `pivot_capability` 修正为 `shell` 后，编排器终于能把它们当成真实上游使用。

### 2.2 service_role / vuln_category / mitre_phase 分布

| 维度 | 分布 |
|---|---|
| `service_role` | `web_application=60`, `middleware=15`, `framework=13`, `system_service=4`, `database=3` |
| `vuln_category` | `RCE=95` |
| `primary_mitre_phase` | `initial_access=93`, `execution=2` |

这里能看出两个现实：

1. 池子依然**极度偏向 web RCE**。
2. `primary_mitre_phase` 依然几乎全是 `initial_access`，但在 v2 语义下，这已经不是系统可用性的硬瓶颈。

## 3. 现有模板各 slot 的候选情况

下面的数字是按**当前模板声明 + 当前编排池**统计出来的。

### 3.1 `dmz_simple`

| slot | matched | 其中可跳板 |
|---|---:|---:|
| `dmz-target-1` | 95 | 7 |

说明：单入口模板，没有依赖，几乎全池都能填。

### 3.2 `dmz_dual`

| slot | matched | 其中可跳板 |
|---|---:|---:|
| `dmz-target-1` | 88 | 4 |
| `dmz-target-2` | 82 | 7 |

说明：这还是两个并列入口，不是攻击链模板。`pivot_capability` 只影响未来要不要把它升级成链式模板。

### 3.3 `enterprise_3tier`

| slot | zone | matched | 其中可跳板 | 备注 |
|---|---|---:|---:|---|
| `dmz-web` | dmz | 88 | 4 | 入口层，且是上游，必须优先挑这 4 个里的一个 |
| `app-service` | app | 88 | 4 | 放宽后不再是硬空缺 |
| `data-store` | data | 7 | 3 | 候选少但不为空 |

这三个数字说明：

1. **`enterprise_3tier` 已经从“结构上跑不通”变成“结构上可以跑通”**
2. 但 `dmz-web` 作为链路起点，88 个候选里只有 4 个能当跳板，所以真正能走通的生成路径仍偏少

## 4. 当前真正的缺口是什么

### 缺口 A：跳板样本太少

这是现在唯一的**系统可用性硬瓶颈**。

不是说“没有可用 atom”，而是说：

- `enterprise_3tier` 的 `dmz-web` 有 88 个候选
- 但这 88 个里只有 4 个能作为真正上游
- 如果未来模板更多层、更长链，这个问题会被进一步放大

所以接下来最优先的工作不是再加更多模板，而是：

**继续修正高价值 RCE atom 的 `pivot_capability`**

### 缺口 B：深层服务角色仍偏少

`data-store` 只有 7 个候选，本质是因为当前池子：

- `system_service` 只有 4 个
- `database` 只有 3 个
- `file_service` 几乎没有进入 single-service 编排池

这不会立刻让系统不可用，但会限制你后面想做更多深层模板时的组合空间。

### 缺口 C：攻击动作多样性仍然差

虽然 v2 已经不再把这个当硬卡口，但如果你想让场景更像 APT，而不只是“多层 RCE 串联”，后面还是要补：

- credential_access
- persistence
- lateral_movement
- privilege_escalation

注意：

这已经是**真实性增强项**，不是现在“系统能不能用”的首要矛盾。

## 5. 对后续计划的影响

这次阶段 1 分析之后，优先级可以重新排：

### 第一优先级

继续修正更多高价值 RCE atom 的 `pivot_capability`。

理由：

- 这是最小改动
- 不需要从 CVE-Factory 新增 atom
- 直接提升链式模板的可用候选数

### 第二优先级

把正式编排流程切到依赖链模式（已开始落地）。

现在模板、matcher、ground_truth、prompt、verifier 已经接上了依赖语义，接下来要做的是用真实场景完整验证它。

### 第三优先级

再决定是否从 CVE-Factory 定向补：

1. `database/system_service/file_service` 角色
2. 能自然承担内网跳板的样本
3. 再往后才是更细的攻击动作多样性

## 6. 当前最实际的下一步

从工程价值看，下一步最值得做的是：

1. **继续修正更多高价值 RCE atom 的 `pivot_capability`**
2. **用新的依赖编排流程实际生成一个 `enterprise_3tier` 场景并验证**

这样我们就能回答最关键的问题：

**现在这套 v2 语义，不只是分析上成立，而是真的能在端到端场景里跑通。**
