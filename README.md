# CVE Scenario Lab Builder

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![ContainerLab](https://img.shields.io/badge/containerlab-0.74+-orange.svg)](https://containerlab.dev/)

从 CVE 漏洞信息到复杂网络攻防场景的全自动生成系统。利用 AI Agent 自主分析、验证漏洞，并通过原子化编排构建多阶段多节点的实战训练环境。

## 核心架构

项目包含两个解耦的子系统，通过 `data/atoms/` 目录对接：

```
项目一 (atomizer)                    项目二 (orchestrator)
CVE 信息 → Agent 自主验证 → atom → 模板编排 → 复杂攻防环境
                            │                        │
                   data/atoms/CVE-XXXX/        环境拓扑 YAML
                   ├── ansible/               + 完整攻击 playbook
                   └── playbook/
```

- **atomizer**: Agent 驱动的单 CVE 原子化。输入 CVE 信息和 writeup，Agent 自主分析、测试、验证，输出可部署的 Ansible 配置和攻击 playbook（ground truth）。
- **orchestrator**: 多 CVE 场景编排。从原子化 CVE 中选取并组合，基于模板生成多阶段多节点的网络攻防环境，attack playbook 由各 CVE 的 ground truth 组合而来。

## 快速开始

### 环境要求

- Python 3.12+
- Docker & ContainerLab
- [uv](https://docs.astral.sh/uv/) (Python 包管理器)

### 安装

```bash
git clone <repository_url>
cd clab_builder
uv sync
```

### CLI 使用

```bash
# 查看 CVE 原子库
clab-builder catalog list
clab-builder catalog show CVE-2021-44228

# 项目一：处理单个 CVE（Agent 驱动）
clab-builder atom run CVE-2021-44228 --image vulhub/log4j:2.14.1 --writeup ./writeup.md
clab-builder atom list
clab-builder atom show CVE-2021-44228

# 项目二：编排多 CVE 场景
clab-builder scenario generate templates/basic/log4j_full.yaml --atoms CVE-2021-44228
clab-builder scenario deploy output/clab.yaml
clab-builder scenario validate my-lab
clab-builder scenario attack output/scenario.yaml
```

## 项目结构

```
clab_builder/
├── src/clab_builder/
│   ├── cli.py                      # Click CLI 入口
│   ├── atomizer/                   # 项目一：单 CVE 原子化
│   │   ├── agent/                  #   Agent 系统（LLM 调用 + 自主决策）
│   │   ├── environment/            #   CVE 目标容器管理
│   │   ├── output/                 #   Ansible 配置 + Exploit Playbook 生成
│   │   └── pipeline.py             #   完整流程编排
│   ├── orchestrator/               # 项目二：多 CVE 编排
│   │   ├── parser/                 #   ContainerLab YAML 解析
│   │   ├── generator/              #   拓扑 → clab + ansible 配置生成
│   │   ├── validator/              #   环境验证（5 层网络测试 + 评分）
│   │   └── composer/               #   Ground Truth 组合（开发中）
│   └── shared/                     # 共用模块
│       ├── catalog/                #   CVE 原子库（32 个 verified catalog）
│       ├── models/                 #   Pydantic 数据模型
│       ├── config/                 #   配置管理
│       └── utils/                  #   子网管理、日志等
├── data/
│   ├── catalogs/verified/          # CVE 元数据（32 个 YAML）
│   └── atoms/                      # 项目一产出 → 项目二消费
│       └── CVE-2021-44228/
│           ├── atom.yaml
│           ├── ansible/deploy.yaml
│           └── playbook/exploit.yaml
├── templates/basic/                # 拓扑模板
├── scripts/                        # 辅助脚本
├── docker/                         # Agent 容器 Dockerfile
├── tests/                          # 测试套件
│   ├── atomizer/                   #   项目一测试
│   └── orchestrator/               #   项目二测试
└── docs/                           # 详细文档
```

## 工作流程

### 项目一：单 CVE 原子化

```
输入: CVE ID + vulhub 镜像 + writeup
  ↓
1. 启动 CVE 目标容器（Docker 隔离）
2. Agent 从 writeup 获取漏洞信息
3. Agent 自主分析并设计攻击路径
4. Agent 实际执行攻击并验证
5. 验证通过 → 生成 Ansible 配置 + Playbook
  ↓
输出: data/atoms/CVE-XXXX-XXXXXX/
```

Agent 拥有完全自主权：根据 CVE 类型自行决定使用 bash 命令还是编写 exploit 脚本，根据执行结果动态调整策略，直到验证通过。

### 项目二：多 CVE 场景编排

```
输入: 模板 YAML + 选取的 CVE atoms
  ↓
1. 从 catalog 筛选合适的 CVE（ATT&CK 阶段、复杂度）
2. 按模板编排多节点拓扑（attacker / router / victim）
3. 从各 atom 的 playbook 组合完整攻击路径
4. 生成 ContainerLab YAML + Ansible 配置
5. 部署 → 验证 → 执行攻击
  ↓
输出: 可部署的复杂攻防环境 + 完整 ground truth
```

## CVE Catalog 系统

内置 32 个经过验证的 CVE 原子库（2018+ 现代漏洞），包含：

- 基础信息（CVSS 评分、描述、CWE）
- 环境信息（Docker 镜像、端口、资源需求）
- 攻击信息（exploit 方法、复杂度、ATT&CK 映射）
- 拓扑适配（网络层级、角色、依赖关系）

```bash
# 按攻击阶段筛选
clab-builder catalog list --stage initial_access

# 按复杂度筛选
clab-builder catalog list --complexity low

# 验证 catalog 质量
clab-builder catalog validate
```

## 环境配置

复制 `.env` 文件并配置 LLM API（Agent 功能需要）：

```bash
# Agent 所需的 LLM 配置
LLM_API_KEY=your-api-key
LLM_MODEL=your-model-name
LLM_BASE_URL=https://api.anthropic.com   # 或兼容 API 地址

# 可选配置
MAX_RETRIES=3
TIMEOUT_SECONDS=600
LOG_LEVEL=INFO
```

非 Agent 功能（catalog 管理、拓扑生成、环境验证）不需要 LLM 配置。

## 开发

```bash
# 安装开发依赖
uv sync --dev

# 运行测试
uv run pytest tests/ -v

# 代码格式化
uv run black src/ tests/
uv run ruff check src/ tests/
```

## 技术栈

- **语言**: Python 3.12+
- **CLI**: Click
- **数据模型**: Pydantic v2
- **AI Agent**: Anthropic SDK / 兼容 LLM API
- **网络拓扑**: ContainerLab
- **配置管理**: Ansible
- **容器化**: Docker
- **包管理**: uv

## License

[MIT](LICENSE)
