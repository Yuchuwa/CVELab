# CVELab

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![ContainerLab](https://img.shields.io/badge/containerlab-0.74+-orange.svg)](https://containerlab.dev/)

CVE 漏洞环境自动化生成系统。从已知 CVE 信息出发，通过 AI Agent 自主验证漏洞可利用性，再按网络拓扑模板编排成多阶段多节点的攻防训练环境，并支持在 L0/L1/L2 三档难度下对 Agent 攻击能力做可重复评估。

## 当前状态 (2026-07)

### 已完成

- **Atom 池**：`data/atoms/` 下 60+ 个高置信度 atom（version 3 schema），每个含完整 `runtime_spec` / `source_bundle`（含 attacker 侧 PoC 材料）/ `flag_spec` / `validation_spec` / `exploit_guide`。覆盖 `initial_access` / `execution` 两个 MITRE 阶段，服务角色涵盖 web_application / middleware / framework / database。
- **Range 编排与验证**：`enterprise_3tier` 模板支持完整生命周期 deploy → setup → Agent → objective 验证 → destroy；端到端 Guided-Agent 验证链已跑通（环境验证 + 攻击图验证 + 攻击路径可达 + Guided-Agent 成功 + 业务目标达成）。
- **L0/L1/L2 三档难度**（见 `docs/AGENT_INPUT_LEVEL_INTERFACE.md`）：
  - `l0` — 仅入口 IP
  - `l1` — + 完整拓扑
  - `l2` — + CVE ID + 凭证型材料（`id_rsa`）；PoC payload 型材料（poc.py / poc.png / exploit.py）在任何级别都不挂载
  - `no-hint` 是 `l2` 的旧别名，保持兼容
- **Decoy（干扰节点）**：`--noise-level baseline` 在拓扑中注入轻量 alpine 干扰节点，`none` 关闭。干扰节点不出现在 Agent prompt 中（符合 AGENTCYBERRANGE §A.3）。
- **Guided-verified Range 清单**：`data/guide_ablation/all_guided_verified_v2.json` 收录 115 个通过 Guided 全门的 Range 组合（跨 batch 去重）。
- **批量实验基础设施**：
  - `scripts/generate_enterprise3_matrix.py` — 覆盖优先 + 入口 CVE 均衡的矩阵生成
  - `scripts/verify_enterprise3_guided_batch.py` — 并行批量验证（支持 `--agent-context {guided,no-guide,no-hint,l0,l1,l2}` + `--noise-level`）
  - `scripts/build_reusable_ranges_manifest.py` — 从历史 batch 抽取 Guided 全门通过的 Range
  - `scripts/reconcile_historical_range_results.py` — 历史 batch 结果对账
- **大规模实验结果**：已完成 100-case Guided batch（agent_success 45/72=62.5%）与 115-case L2+decoy batch，构成首批研究数据集。

### 已知限制

- **末层多样性受 atom 池限制**：`data-store` slot 的 `customer-records` asset 当前仅支持 postgresql / elasticsearch 变体，末层可用 CVE 为 3 个（CVE-2014-3120 / CVE-2015-1427 / CVE-2019-9193）。Redis 变体（解锁 CVE-2022-0543）在 TODO。
- **CVE-2017-12635（CouchDB）/ CVE-2019-10758（mongo-express）**：含 1 个 target + 1 个 auxiliary service，被 `single_service_only=True` 过滤，暂未进入矩阵。
- **CVE-2017-10271（WebLogic 7001）**：仅绑 localhost，data-plane 不可达，已标 `runtime_status: unsupported`。

## 系统架构

```
                          CVELab 端到端流水线

  Vulhub 漏洞源码                                                    拓扑模板
  (data/vulhub/)                                                    (templates/)
       │                                                                │
       ▼                                                                ▼
  ┌──────────┐     ┌──────────────┐                      ┌──────────────┐
  │ Parse    │────→│  AI Agent    │                      │ Template      │
  │ & Start  │     │ · 分析漏洞    │                      │ Loader        │
  │ Container│     │ · 设计攻击    │                      └──────┬───────┘
  └──────────┘     │ · 执行验证    │                             │
                   │ · 生成 Playbook│                             ▼
                   └──────┬───────┘                      ┌──────────────┐
                          │                              │ CVE Matcher   │
                          ▼                              │ 自动匹配 atom  │
                   ┌──────────────┐                      └──────┬───────┘
                   │  Atom        │                             │
                   │  data/atoms/ │◄────────────────────────────┘
                   │  ├── atom.yaml
                   │  ├── runtime/Dockerfile   ──┐
                   │  ├── source_bundle/         │
                   │  ├── exploit_guide.yaml      │
                   │  └── session.json            │
                   └──────────────┘                │
                                                    ▼
                                           ┌──────────────────────────────────┐
                                           │     Scenario Assembler            │
                                           │  · IP 自动分配 (/30 transit)       │
                                           │  · 路由计算 (BFS)                  │
                                           │  · FLAG 注入 + 管理网隔离          │
                                           │  · L0/L1/L2 PoC bind 条件化        │
                                           │  · Decoy 节点注入                  │
                                           └────────────┬───────────────────┘
                                                          │
                                                          ▼
                                           ┌──────────────────────────────────┐
                                           │  场景输出 (data/scenarios/<name>/) │
                                           │  ├── clab.yaml                    │
                                           │  ├── ansible/base.yaml            │
                                           │  ├── ansible/cve-setup.yaml       │
                                           │  ├── ansible/asset-setup.yaml     │
                                           │  ├── exploit_guides/ (Guided 用)  │
                                           │  ├── ground_truth.json (verifier) │
                                           │  └── flag-target-N.txt            │
                                           └────────────┬───────────────────┘
                                                          │
                                             deploy → ansible → 等待服务就绪
                                                          │
                                                          ▼
                                           ┌──────────────────────────────────┐
                                           │  Agent Verifier (attacker 容器内)  │
                                           │  · L0/L1/L2 按 level 裁剪输入       │
                                           │  · 按攻击路径逐目标渗透             │
                                           │  · 捕获 FLAG → 与 GT 比对          │
                                           │  · 业务目标达成验证                 │
                                           └────────────┬───────────────────┘
                                                          │
                                             destroy → 保存 verify_result.json
                                                          │
                                                          ▼
                                           ┌──────────────────────────────────┐
                                           │  Validation Round Provenance       │
                                           │  (run_id / case_id / agent_context  │
                                           │   / noise_level / validated_at)    │
                                           └──────────────────────────────────┘
```

**核心流程**：Vulhub 源码 → Agent 验证生成 atom → 模板 + atom 自动匹配 → 组装场景 → L0/L1/L2 按档裁剪 → Agent 渗透验证 → 分层记录结果

## 网络拓扑设计

每个场景基于 ContainerLab 构建真实网络拓扑：

```
                   管理网络 (eth0, 172.20.20.0/24)
                   ┌──────────────────────────────┐
                   │  仅 router 保留，其他节点 flush  │
                   └──────────────────────────────┘

数据面 (模拟企业网段):

   Attacker          Edge Router           Target (DMZ)
10.255.255.1/30 ←→ 10.255.255.2/30    192.168.100.2/24
                     192.168.100.1/24 ←→
                     
                     ┃ NAT (eth0 → 外网，供 Agent 调用 LLM API)
```

- **Transit 链路**: /30 点对点网段，模拟真实 router 间互联
- **Zone 网段**: 按类型分配 (DMZ: 192.168.x.x, 内网: 10.10.x.x)
- **管理网隔离**: attacker 和所有 target 的 eth0 被 flush，通信必须走数据面
- **NAT 出口**: 仅 attacker 直连的 router 开启 MASQUERADE，供 Agent 访问 LLM API

`enterprise_3tier` 拓扑：DMZ → App → Data 三层，attacker 从 DMZ 入口逐层横向移动至 Data 层读取 `customer-records` 业务目标。

## 安装

```bash
git clone <repository_url>
cd CVELab
uv sync

# 构建 Agent 容器镜像
cd docker && bash build.sh
```

依赖：Python 3.12+, Docker, [ContainerLab](https://containerlab.dev/), [uv](https://docs.astral.sh/uv/)

## 使用

### 配置 LLM API

```bash
# .env
LLM_API_KEY=your-key
LLM_BASE_URL=https://api.anthropic.com   # 或兼容 API
LLM_MODEL=claude-sonnet-4-6
```

### 单 CVE 原子化

部分 Vulhub 环境依赖宿主机内核参数。Elasticsearch/Kibana 相关 CVE 在启动前需要：

```bash
sudo sysctl -w vm.max_map_count=262144
```

如需持久化到重启后仍生效：

```bash
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-elasticsearch.conf
sudo sysctl --system
```

```bash
# Agent 驱动验证单个 CVE
cvelab atom run data/vulhub/bash/CVE-2014-6271

# XSS/Auth_Bypass/Info_Leak 等无 flag 成功样本会默认经过二级 LLM checker

# 跳过 Agent，仅生成配置
cvelab atom run data/vulhub/bash/CVE-2014-6271 --skip-agent

# 查看已生成的 atoms
cvelab atom list
```

### 多 CVE 场景

```bash
# 生成场景文件（不部署）
cvelab generate enterprise_3tier -c CVE-2017-12615 -c CVE-2017-15715 -c CVE-2014-3120 -n my-lab

# 一键全流程：生成 → 部署 → Agent 验证 → 销毁 → 保存结果
cvelab verify enterprise_3tier -c CVE-2017-12615 -c CVE-2017-15715 -c CVE-2014-3120 -n my-test
```

**`generate`** — 输出 clab.yaml + ansible + ground_truth 到 `data/scenarios/<name>/`

**`verify`** — 完整生命周期：deploy → ansible 配置 → Agent 渗透 → FLAG 验证 → destroy → 保存 `verify_result.json`

### 内置模板

| 模板 | 说明 | 难度 |
|------|------|------|
| `dmz_simple` | 单层 DMZ，1 个目标 | easy |
| `dmz_dual` | 单层 DMZ，2 个不同漏洞目标 | easy |
| `enterprise_3tier` | 三层企业网络 DMZ → App → Data | medium |

### 批量验证与 Guided-verified Range 复用

#### 生成组合矩阵

```bash
PYTHONPATH=src python scripts/generate_enterprise3_matrix.py \
  --output data/range_matrices/enterprise_3tier_hetero.json
```

矩阵生成器做覆盖优先 + 入口 CVE 均衡选择，避免单 CVE 主导。

#### 跑批量 Guided-Agent 验证

```bash
sudo -E env HOME="$HOME" PATH="$PATH" PYTHONPATH="$PWD/src" \
python scripts/verify_enterprise3_guided_batch.py \
  --case-manifest data/range_matrices/enterprise_3tier_hetero.json \
  --max-cases 100 \
  --agent-context guided \
  --noise-level none \
  --parallel 8 \
  --max-turns 150 \
  --agent-timeout 2400 \
  --live-output \
  --output data/guide_ablation/hetero_batch_guided
```

`--agent-context` 支持：`guided` / `no-guide` / `no-hint` / `l0` / `l1` / `l2`（`no-hint` 是 `l2` 的旧别名）。
`--noise-level` 支持：`none`（无干扰）/ `baseline`（轻量 decoy 节点）。

#### 从历史 batch 抽取 Guided-verified Range 清单

```bash
PYTHONPATH=src python scripts/build_reusable_ranges_manifest.py \
  data/guide_ablation/hetero100_guided \
  data/guide_ablation/hetero_batch2_guided \
  --output data/guide_ablation/all_guided_verified_v2.json
```

输出的 manifest 每条含 `id` / `cves` / `asset_variants` / `guided_gate`，按 `case_id` 跨 batch 去重，只保留通过全门（environment + attack_graph + attack_path + guided_trial + objective）的组合。

#### 复用 Guided-verified Range 跑其他档位

```bash
sudo -E env HOME="$HOME" PATH="$PATH" PYTHONPATH="$PWD/src" \
python scripts/verify_enterprise3_guided_batch.py \
  --case-manifest data/guide_ablation/all_guided_verified_v2.json \
  --max-cases 115 \
  --agent-context l2 \
  --noise-level baseline \
  --parallel 8 \
  --max-turns 150 \
  --agent-timeout 2400 \
  --live-output \
  --output data/guide_ablation/l2_decoy_merged
```

**重要**：batch 不复用旧 `scenario_dir`。系统按 manifest 的 `cves` 列表调 `pipeline.generate` 重新生成全新 Range（新 run_id → 新目录 → 新 flag → 新 PoC bind 按 level 条件化）。manifest 里的 `scenario_dir` 字段只是 provenance 记录，不被新 batch 读取。

### 给他人分享 Guided-verified Range

对方已有本仓库代码（含 `data/atoms/`）后，要复现这批 Guided-verified Range 只需：

1. **构建两个镜像**（一次性）：
   ```bash
   # Agent 镜像
   cd docker && bash build.sh

   # 各 CVE 的 runtime 镜像（manifest 涉及的 CVE）
   python scripts/migrate_runtime_tools.py   # 或用 runtime_builder 按 atom 的 runtime/Dockerfile 构建
   ```

2. **拿一份脱敏 manifest**（去掉你机器的绝对路径与 batch provenance）：
   每条留 `id` / `cves` / `asset_variants` / `guided_gate` 即可。

3. **按 manifest 重新生成 Range**：
   ```bash
   cvelab generate enterprise_3tier -c <cve1> -c <cve2> -c <cve3> -n <case_id>
   # 或直接跑批量
   python scripts/verify_enterprise3_guided_batch.py \
     --case-manifest <sanitized-manifest>.json --max-cases <N> \
     --agent-context guided --output <out>
   ```

manifest 就是"哪些 CVE 组合曾通过 Guided 全门"的清单 + 重生成所需的最小信息。Runtime 镜像从仓库里的 `atoms/<CVE>/runtime/Dockerfile` 可复现构建，无需额外分发。

## 项目结构

```
src/clab_builder/
├── cli.py                    # CLI 入口 (cvelab)
├── atomizer/                 # 单 CVE 原子化
│   ├── agent/                #   AI Agent (LLM + 工具调用)
│   ├── environment/          #   CVE 容器管理
│   ├── output/               #   Ansible + Playbook + exploit_guide 生成
│   ├── runtime_builder.py    #   runtime 镜像构建
│   └── pipeline.py           #   流程编排
├── orchestrator/             # 多 CVE 场景编排
│   └── composer/
│       ├── scenario_assembler.py  # IP 分配 + 路由 + YAML 生成 + L0/L1/L2 PoC bind + decoy
│       ├── scenario_runner.py    # Agent prompt 构建 + L0/L1/L2 裁剪 + audit
│       ├── verifier.py           # 全流程编排 + 攻击路径可达性 + validation_round provenance
│       ├── cve_matcher.py        # CVE 自动匹配 + effective_service_role
│       └── capability_closure.py # 能力闭包计算
├── shared/
│   ├── models/               # Pydantic 数据模型 (atom/template/exploit_guide)
│   ├── catalog/              # CVE 元数据
│   └── utils/                # 子网管理、日志、service_resolver
data/
├── atoms/                    # atom 生成产物 (含 runtime/Dockerfile + source_bundle)
├── guide_ablation/          # 批量实验输出 (summary/scenarios/manifest)
└── range_matrices/          # 组合矩阵
templates/                    # 拓扑模板 (enterprise_3tier 等)
docker/                       # Agent 容器 Dockerfile
scripts/                      # 矩阵生成 / 批量验证 / manifest 抽取等工具
docs/                         # 设计文档 (L0/L1/L2 接口、decoy、进度报告)
```

## 开发

```bash
uv sync --dev
uv run pytest tests/ -v --no-cov
```

## 技术栈

Python 3.12 · Click · Pydantic v2 · Claude Agent SDK · ContainerLab · Ansible · Docker · uv