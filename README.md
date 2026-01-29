# Containerlab Builder

> 一个基于 LLM 和 LangGraph 的智能网络拓扑自动化构建工具

## 项目背景

网络安全研究和渗透测试经常需要搭建复杂的网络实验环境。传统的手动配置方式存在以下问题：

- **配置繁琐**：需要手动编写 YAML 配置文件、分配 IP 地址、配置路由
- **易出错**：人工配置容易产生 IP 冲突、路由错误等问题
- **效率低下**：重复性的搭建工作浪费大量时间

本项目通过 LLM 智能化地解决这些问题，让用户只需用自然语言描述需求，即可自动生成可部署的网络实验环境。

## 核心功能

### 1. 自然语言生成拓扑
用户只需用自然语言描述需求（如"创建一个有 DMZ 和内网的渗透测试实验室"），系统即可自动：
- 分析需求复杂度（simple/medium/complex）
- 设计逻辑网络拓扑
- 选择合适的 Docker 镜像
- 自动注入虚拟交换机

### 2. 智能 IP 地址管理 (IPAM)
- 自动为每个子网分配 CIDR 地址段
- 为节点自动分配接口 IP 地址
- 路由器节点优先分配低地址（.1, .2），终端节点分配高地址（.10+）

### 3. 自动路由配置
- 集成 FRR 路由套件，自动生成 OSPF 配置
- 自动为路由器配置路由协议，实现跨子网通信

### 4. 多层验证机制
- **静态验证**：YAML 生成前检查 IP 冲突、接口重复、网关可达性等问题
- **动态验证**：部署失败时自动分析错误日志并修复

### 5. 自动错误修复 (Fixer)
当部署或配置出现错误时，Fixer 节点会：
- 分析错误日志
- 诊断问题根因（镜像拉取失败、接口冲突等）
- 最小化修改设计方案
- 自动重试部署（最多 3 次）

## 工作流程

```mermaid
flowchart LR
    Start([🎯 用户需求]) --> Generate["🤖 Generate<br/>LLM生成拓扑"]
    Generate --> Builder["🔨 Builder<br/>YAML+IPAM"]
    Builder --> Validate["✓ Validate<br/>静态验证"]
    Validate --> Deploy["🚀 Deploy<br/>部署"]
    Deploy --> Config["⚙️ Configure<br/>配置"]
    Config --> End([✅ 完成])

    Fixer["🔧 Fixer<br/>智能错误修复"]

    %% 设计错误路径 - 红色虚线
    Builder -.->|设计问题| Fixer
    Fixer ==>|建议+重生成| Generate

    %% 验证错误路径 - 橙色点线
    Validate -.-|验证失败| Fixer
    Fixer ==>|修复YAML| Validate

    %% 部署错误路径 - 紫色虚线
    Deploy -.->|部署问题| Fixer

    %% 系统错误路径 - 深红色，直接终止
    Deploy ==>|权限/系统错误| Failed([❌ 终止])

    %% Fixer 到其他路径
    Fixer -.->|不可恢复| Failed

    classDef main fill:#e7f3ff,stroke:#0066cc,stroke-width:2px
    classDef err fill:#fff4e6,stroke:#ff6b35,stroke-width:2px
    classDef term fill:#f8f9fa,stroke:#343a40,stroke-width:2px
    classDef ok fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px
    classDef bad fill:#ffebee,stroke:#c62828,stroke-width:2px

    class Generate,Builder,Validate,Deploy,Config main
    class Fixer err
    class Start,End term
    class End ok
    class Failed bad
```

### 流程说明

| 节点 | 功能 | 输出 |
|------|------|------|
| **Generate** | LLM 分析需求，生成逻辑拓扑 | `NetworkBlueprint` |
| **Builder** | IPAM 分配、YAML 生成、路由计算 | `.clab.yml` 文件 |
| **Validate** | 检查 IP 冲突、接口重复、网关可达性 | 验证结果 |
| **Deploy** | 调用 containerlab 部署 | 容器运行状态 |
| **Configure** | 配置服务、验证连通性 | 配置日志 |
| **Fixer** | 错误诊断 + 最小化修复 | 更新后的 Blueprint |

## 快速开始

### 环境要求
- Python 3.10+
- Containerlab
- Docker
- LLM API Key（支持 OpenAI、DeepSeek 等兼容接口）

### 安装

```bash
# 克隆项目
git clone <repository-url>
cd containerlab_builder

# 使用 uv 安装（推荐）
uv sync

# 或使用 pip
pip install -e .
```

### 配置

复制示例配置文件并填写你的配置：

```bash
cp .env.example .env
```

编辑 `.env` 文件，设置必要的环境变量：

```bash
# 必需配置
LLM_API_KEY="your_api_key_here"

# 可选配置
LLM_BASE_URL="https://api.deepseek.com/v1"  # 或其他 LLM API
LLM_MODEL="DeepSeek-V3.2"
MAX_RETRIES=3                              # 最大重试次数
TIMEOUT_SECONDS=600                         # 操作超时时间（秒）
LOG_LEVEL="INFO"

# 容器健康检查配置
CONTAINER_HEALTH_CHECK_INTERVAL=3           # 健康检查间隔（秒）
CONTAINER_HEALTH_CHECK_MAX_RETRIES=10       # 健康检查最大重试次数

# 日志配置
LOG_TO_FILE=true                            # 是否记录日志到文件
```

### 运行

```bash
python main.py
```

项目会自动为每次运行创建独立的会话目录，所有输出文件（YAML、日志等）都会保存在：
```
clab_out/<session_id>/
```

### 测试

项目提供了完整的集成测试套件，包含场景A和场景B的10个测试用例：

```bash
# 运行所有测试
python test/test_scenarios.py

# 只运行场景A测试
python test/test_scenarios.py --scenario A

# 只运行场景B测试
python test/test_scenarios.py --scenario B

# 运行特定测试用例（例如测试1和2）
python test/test_scenarios.py --tests 1 2
```

**测试用例覆盖**：
- **场景A测试（5个）**：清晰输入、模糊输入、最小化输入、多诱饵服务器、不同漏洞类型
- **场景B测试（5个）**：清晰输入、模糊输入、最小化输入、多漏洞目标、横向移动场景

## 使用示例

```
用户输入：
"创建一个渗透测试实验室，包含：
- 外部区域：Kali 攻击机和边界路由器
- 内部区域：核心路由器、Log4j 漏洞靶机、Redis 服务器
- 确保攻击机能访问内网"

系统自动生成完整的 Containerlab 配置并部署
```

## 支持的场景类型

系统支持三种渗透测试场景，根据学习目标和网络复杂度进行分类：

### 场景A：单层网络（基础测试）
- **学习目标**：基础扫描、服务枚举、单点利用、无复杂路由
- **网络结构**：扁平网络，所有节点在同一L2域
- **网络规模**：5-8个节点
- **组件**：
  - 1个漏洞目标
  - 1个攻击机（Kali Linux）
  - 2-3个诱饵服务器（模拟真实生产环境）
- **路由**：单路由器配置OSPF协议（统一路由逻辑）
- **适用场景**：基础渗透测试、真实环境模拟

### 场景B：三层企业网络（企业渗透测试）
- **学习目标**：路径选择、跨区域横向移动、基础路由理解
- **网络结构**：分层三层架构（边缘层 → 分发层 → 核心层/接入层）
- **网络规模**：8-15个节点
- **组件**：
  - N个漏洞目标（2-3个，部署在DMZ或内网）
  - 1个攻击机（Kali Linux）
  - 2-3个路由器
  - N个诱饵服务器分布在各区域（DMZ、内网）
- **路由**：通过FRR路由套件配置OSPF协议，实现跨区域通信
- **适用场景**：企业渗透测试、多层隔离网络、横向移动练习

### 场景C：防火墙保护网络（高级安全测试）
- **学习目标**：防火墙绕过、ACL配置错误利用、策略规避、高级横向移动
- **网络结构**：基于场景B的三层架构，增加防火墙/ACL控制
- **网络规模**：15-30个节点（最大场景）
- **组件**：
  - N个漏洞目标（2-3个，受防火墙保护）
  - 1个攻击机（Kali Linux）
  - 2-3个路由器 + 1-2个防火墙节点（或路由器ACL配置）
  - N个诱饵服务器分布在各区域
- **防火墙部署选项**：
  - 选项1：外部 → [专用防火墙] → DMZ → [路由器] → 内网
  - 选项2：外部 → [带ACL路由器] → DMZ → [带ACL路由器] → 内网
  - 选项3：混合 - 边缘专用防火墙 + 内部路由器ACL
- **适用场景**：高级安全测试、防火墙策略分析、ACL绕过技术
- **路由**：多路由器OSPF协议 + 防火墙规则控制跨区域访问
- **注意**：防火墙实现使用iptables/nftables

## 项目结构

```
containerlab_builder/
├── main.py              # LangGraph 工作流入口
├── state.py             # 全局状态定义
├── config.py            # 配置管理（基于 Pydantic）
├── logger.py            # 日志系统（支持会话隔离、彩色输出）
├── session_utils.py     # 会话管理工具
├── pyproject.toml       # 项目依赖配置
├── .env.example         # 环境变量配置示例
├── node/
│   ├── generate.py      # LLM 生成逻辑蓝图
│   ├── builder.py       # YAML 构建器 (IPAM + 路由)
│   ├── validate.py      # 静态验证（IP冲突、接口重复等）
│   ├── deploy.py        # Containerlab 部署
│   ├── deploy_agent.py  # 部署代理（异步部署、健康检查）
│   ├── configure.py     # 服务配置（路由注入、服务启动）
│   ├── fixer.py         # 错误修复（智能诊断与修复）
│   └── utils/           # 工具模块（模块化重构）
│       ├── __init__.py  # 模块初始化
│       ├── models.py    # Pydantic 数据模型定义
│       ├── builder.py   # 构建逻辑（JSON作为唯一真源）
│       └── applier.py   # 配置应用逻辑
├── tools/
│   ├── containerlab_tools.py  # Containerlab 工具函数
│   └── search_vuln_image.py   # 漏洞镜像搜索工具
├── test/
│   ├── test_configure.py      # 配置测试
│   └── test_scenarios.py      # 场景A/B集成测试（10个测试用例）
└── clab_out/            # 输出目录（自动生成）
    └── <session_id>/    # 每次运行的独立会话目录
        ├── *.clab.yml   # 生成的拓扑配置
        ├── *.json       # 拓扑数据（JSON作为唯一真源）
        └── *.log        # 会话日志
```

## 技术栈

- **LangChain**: LLM 集成与工作流编排
- **Containerlab**: 容器网络部署

## 许可证

MIT License
