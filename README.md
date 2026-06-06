# CVELab

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![ContainerLab](https://img.shields.io/badge/containerlab-0.74+-orange.svg)](https://containerlab.dev/)

CVE 漏洞环境自动化生成系统。从已知 CVE 信息出发，通过 AI Agent 自主验证漏洞可利用性，再按网络拓扑模板编排成多阶段多节点的攻防训练环境。

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

```bash
# Agent 驱动验证单个 CVE
cvelab atom run data/vulhub/bash/CVE-2014-6271

# 跳过 Agent，仅生成配置
cvelab atom run data/vulhub/bash/CVE-2014-6271 --skip-agent

# 查看已生成的 atoms
cvelab atom list
# Atoms (31): 21 verified, 8 unverified, 2 incomplete
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

### Atom 库

21 个已验证 CVE atom，涵盖 RCE、LFI、SSRF、反序列化、认证绕过等漏洞类型。

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
├── atoms/                    # 31 个 CVE atom
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
