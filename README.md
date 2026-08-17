# CVELab

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![ContainerLab](https://img.shields.io/badge/containerlab-0.74+-orange.svg)](https://containerlab.dev/)

CVE 漏洞环境自动化生成系统。从已知 CVE 信息出发，通过 AI Agent 自主验证漏洞可利用性，再按网络拓扑模板编排成多阶段多节点的攻防训练环境。

## 当前状态

- 已建立批量 atom 化流水线，覆盖 Vulhub 源和 raw_records 两类输入。
- `data/atom_scale/manifest.jsonl` 是全量运行账本：当前 338 条候选，其中 114 条已成功、128 条失败、4 条已存在跳过、92 条 raw_records 缺少本地验证镜像资产。
- `data/atom_scale/dataset.jsonl` / `dataset.parquet` 是干净数据集，只包含 114 条已成功 atom 化并带有 session 的样本。
- `data/atoms/` 下保留生成过程中的 atom 产物，当前有 235 个 `atom.yaml`；其中未进入 dataset 的目录可能是失败、半成品或待复核结果。
- 运行期已经处理了依赖容器校验、Agent 容器超时清理、Docker network 回收、LLM checker、非 RCE flag 注入收紧等批量运行问题。

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
                   │  ├── ansible/  ──────────┐
                   │  ├── playbook/            │
                   │  └── session.json         │
                   └──────────────┘             │
                                                ▼
                                         ┌──────────────────────────────────┐
                                         │     Scenario Assembler            │
                                         │  · IP 自动分配 (/30 transit)       │
                                         │  · 路由计算 (BFS)                  │
                                         │  · FLAG 注入 + 管理网隔离          │
                                         └──────────────┬───────────────────┘
                                                        │
                                                        ▼
                                         ┌──────────────────────────────────┐
                                         │  场景输出                          │
                                         │  ├── clab.yaml        (拓扑定义)   │
                                         │  ├── ansible/base.yaml (IP+路由)  │
                                         │  ├── ansible/cve-setup.yaml       │
                                         │  ├── ground_truth.json            │
                                         │  └── flag-target-N.txt            │
                                         └──────────────┬───────────────────┘
                                                        │
                                           deploy → ansible → 等待服务就绪
                                                        │
                                                        ▼
                                         ┌──────────────────────────────────┐
                                         │  Agent Verifier (attacker 容器内)  │
                                         │  · 按攻击路径逐目标渗透             │
                                         │  · 捕获 FLAG → 与 GT 比对          │
                                         └──────────────┬───────────────────┘
                                                        │
                                           destroy → 保存 verify_result.json
```

**核心流程**：Vulhub 源码 → Agent 验证生成 atom → 模板 + atom 自动匹配 → 组装场景 → Agent 渗透验证

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

## 安装

```bash
git clone <repository_url>
cd clab_builder
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
cvelab generate dmz_simple -c CVE-2014-6271 -n shellshock-lab

# 一键全流程：生成 → 部署 → Agent 验证 → 销毁 → 保存结果
cvelab verify dmz_simple -c CVE-2014-6271 -n shellshock-test

# 批量生成
cvelab batch dmz_simple --count 5
```

**`generate`** — 输出 clab.yaml + ansible + ground_truth 到 `data/scenarios/<name>/`

**`verify`** — 完整生命周期：deploy → ansible 配置 → Agent 渗透 → FLAG 验证 → destroy → 保存 `verify_result.json`

### 内置模板

| 模板 | 说明 | 难度 |
|------|------|------|
| `dmz_simple` | 单层 DMZ，1 个目标 | easy |
| `dmz_dual` | 单层 DMZ，2 个不同漏洞目标 | easy |
| `enterprise_3tier` | 三层企业网络 DMZ → App → Data | medium |
| `enterprise_4tier` | 四层企业网络 DMZ → App → Internal → Data | hard |
| `enterprise_5tier` | 五层企业网络 DMZ → App → Middleware → Internal → Data | hard |

### Atom 库与数据集

当前 clean dataset 包含 114 个成功 atom，涵盖 RCE、LFI、SSRF、反序列化、认证绕过、路径穿越、文件读写等漏洞类型。`data/atoms/` 保留更多生成产物，供复核、修复和二次筛选。

### 下一步规划

当前阶段的重点不是继续盲目扩量，而是把 114 个已成功 atom 转化为稳定可组合、可验证的数据资产：

1. **Atom 质量复核**
   - 对 `data/atom_scale/dataset.jsonl` 中的 114 个成功样本做结构校验、字段完整性校验和人工抽样复核。
   - 重点检查 `atom.yaml`、`playbook/sysfield.yaml`、`session.json` 三者是否一致，避免 checker 误判或 session 残留导致的假成功。
   - 将非 RCE 类样本的成功标准和 flag 注入策略固定下来，减少无意义 flag 验证。

2. **失败样本分类回流**
   - 保留 turns 耗尽类失败作为模型能力/提示词问题，不立即重跑。
   - 将 infra/code 类失败重新排队，例如 Docker network exhaustion、环境依赖未启动、Agent 容器清理超时、API 中断、checker 解析异常。
   - raw_records 的 92 条 `missing_build_asset` 需要恢复或重建对应 `cve-*:vuln` 本地镜像；`vuln_archive_path` 是源码包路径，不能直接 `docker load`。

3. **批量运行稳定化**
   - 默认以小批次并行运行，例如 `--workers 4`，每轮结束后检查 Docker 容器、网络、磁盘和 manifest 状态。
   - 对失败原因做稳定的状态枚举，避免把 infra 问题和漏洞不可利用混在同一个 `failed` 状态里。
   - 继续收敛环境启动前置条件，例如 Elasticsearch `vm.max_map_count`、数据库初始化、一次性 init/bootstrap 容器。

4. **场景组合验证**
   - 用 clean dataset 中的成功 atom 生成单目标和多目标 ContainerLab 场景。
   - 先验证 `dmz_simple`、`dmz_dual`、`enterprise_3tier` 三类模板，再扩展到 `enterprise_4tier`、`enterprise_5tier` 等更多网络路径和 MITRE 阶段组合。
   - 场景验证结果必须回写 ground truth 和 verifier 输出，作为 atom 是否可组合的第二层质量门槛。

5. **数据集发布准备**
   - 固化 `manifest.jsonl` 作为全量账本，`dataset.jsonl/parquet` 作为成功样本发布物。
   - 为每个成功 atom 生成摘要索引：CVE、漏洞类型、服务类型、端口、成功标准、是否需要宿主机前置条件。
   - 在达到稳定阈值后再扩量，目标是先形成一批可复现、可组合、可验证的高质量 atom，而不是只追求数量。

## 项目结构

```
src/clab_builder/
├── cli.py                    # CLI 入口 (cvelab)
├── atomizer/                 # 单 CVE 原子化
│   ├── agent/                #   AI Agent (LLM + 工具调用)
│   ├── environment/          #   CVE 容器管理
│   ├── output/               #   Ansible + Playbook 生成
│   └── pipeline.py           #   流程编排
├── orchestrator/             # 多 CVE 场景编排
│   └── composer/
│       ├── scenario_assembler.py  # IP 分配 + 路由 + YAML 生成
│       ├── scenario_runner.py     # Agent 验证 (attacker 容器内)
│       ├── verifier.py            # 全流程编排 (deploy → verify → destroy)
│       ├── cve_matcher.py         # CVE 自动匹配
│       └── template_loader.py     # 模板加载
├── shared/
│   └── models/               # Pydantic 数据模型
data/
├── atoms/                    # atom 生成产物
├── atom_scale/               # manifest + clean dataset
└── vulhub/                   # Vulhub 漏洞源码
templates/                    # 拓扑模板
docker/                       # Agent 容器 Dockerfile
```

## 开发

```bash
uv sync --dev
uv run pytest tests/ -v --no-cov
```

## 技术栈

Python 3.12 · Click · Pydantic v2 · Claude Agent SDK · ContainerLab · Ansible · Docker · uv
