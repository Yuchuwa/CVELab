# ContainerLab Builder - CVE训练数据生成器

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![ContainerLab](https://img.shields.io/badge/containerlab-0.74+-orange.svg)](https://containerlab.dev/)
[![Tests](https://img.shields.io/badge/tests-41%20passing-green.svg)](tests/)

> **构建稳定可靠环境的CVE训练数据批量生成系统** - 从网络拓扑定义到可验证攻击场景的全自动化流程

## 🎯 核心价值

### 🎪 **解决的核心问题**
- **🌐 网络连通性准确性**: 精确的网络隔离，正确的CVE注入，完整可复现的playbook
- **⚡ 批量场景生成**: 原子化CVE环境可组合成复杂拓扑，实现大规模训练数据生成
- **🤖 AI驱动自动化**: 利用Agent加速README解析和攻击playbook生成与验证

### 🏗️ **独特架构设计**
- **🔧 分离关注点**: Ansible配置保证CVE准确注入 vs 独立攻击playbook执行攻击
- **📦 原子化组件**: CVE原子库支持快速组合和批量生成
- **✅ 质量保证**: 5层网络连通性测试 + CVE准确性验证

### 🚀 **支持的能力**
- 🔍 **自动拓扑解析**: ContainerLab标准YAML → 结构化网络环境
- 🛡️ **CVE环境配置**: 准确注入漏洞环境，保证可利用性
- ⚔️ **攻击剧本生成**: 独立可执行的攻击playbook
- 🧪 **自动化验证**: 环境质量评分 + 攻击可复现性验证

## 🏗️ 项目架构

### 📁 **当前项目结构**
```
clab_builder/
├── src/clab_builder/              # 核心源代码
│   ├── core/                      # 核心功能模块
│   │   ├── generator.py          # 拓扑生成器
│   │   ├── parser.py             # YAML解析器
│   │   ├── validator.py          # 环境验证器
│   │   ├── cve_validator.py      # CVE准确性验证
│   │   └── enhanced_connectivity.py # 增强网络测试
│   ├── atomic/                    # 🆕 CVE原子化模块
│   │   ├── catalog.py            # CVE catalog数据结构
│   │   ├── processor.py          # CVE信息处理器
│   │   ├── validator.py          # 原子化验证器
│   │   ├── mapper.py             # ATT&CK阶段映射器
│   │   └── enricher.py           # CVE信息丰富器
│   ├── agent/                     # 🆕 Agent系统模块
│   │   ├── security_researcher.py # Agent主类
│   │   └── playbook_generator.py  # Playbook生成工具
│   ├── environment/               # 🆕 环境管理模块
│   │   └── container_manager.py   # Docker容器管理
│   ├── playbook/                  # 🆕 Playbook生成模块
│   │   ├── ansible_generator.py  # Ansible配置生成
│   │   └── exploit_playbook_generator.py # Exploit playbook生成
│   ├── integration/               # 🆕 集成pipeline模块
│   │   └── agent_pipeline.py     # Agent驱动的完整pipeline
│   ├── models/                   # 数据模型
│   ├── config/                   # 配置管理
│   └── utils/                    # 工具函数
├── data/                          # 数据目录
│   └── catalogs/verified/         # 🆕 CVE原子库 (32个现代CVE)
├── scripts/                       # 🆕 CI/CD工具脚本
│   ├── validate_catalogs.py      # CVE catalog验证工具
│   └── collect_modern_cves.py    # 现代CVE批量收集工具
├── tests/                         # 测试套件
│   ├── unit/                      # 单元测试
│   ├── integration/               # 集成测试
│   ├── atomic/                    # 🆕 原子化模块测试 (19个测试用例)
│   └── tools/                     # 工具测试
│   ├── integration/              # 集成测试
│   └── conftest.py              # Pytest配置
├── examples/                      # 示例和演示
├── docs/                          # 项目文档
│   ├── PROGRESS_REPORT.md        # 进度报告
│   ├── CORE_FUNCTIONALITY_ASSESSMENT.md # 功能评估
│   └── PRODUCTION_ASSESSMENT.md  # 生产就绪分析
├── run_tests.sh                  # 测试运行脚本
├── pyproject.toml                # Python项目配置
└── README.md                     # 本文件
```

### 🎯 **核心设计原则**

1. **🔧 架构分离**
   - **Ansible配置** → 保证CVE准确注入环境配置
   - **攻击playbook** → 独立存在，专注于攻击执行

2. **📦 原子化设计**
   - **CVE原子库**: 可重用的CVE环境组件
   - **快速组合**: 支持批量场景生成
   - **智能验证**: 自动检测兼容性和资源需求

3. **🤖 Agent驱动**
   - **自主复现**: Agent使用Claude Code SDK自主分析、编写、执行、验证
   - **Docker隔离**: CVE环境和Agent容器独立运行
   - **信息输入**: 只提供CVE资料，Agent完全自主决策
   - **标准输出**: 生成验证后的Ansible配置和exploit playbook

4. **✅ 质量优先**
   - **5层网络测试**: ICMP → TCP/UDP → DNS → 路由追踪 → 性能测试
   - **CVE准确性**: 数据库验证 + 环境兼容性检查
   - **自动化评分**: 0-100分健康评分系统

## 🚀 核心功能

### ✅ **已完成功能** (80% 完成)

#### 🔧 **1. 单元测试框架** ✅
- **38个单元测试**，覆盖核心功能
- **Pytest集成**，支持marker和fixture
- **41%代码覆盖率**，持续提升中
- **快速/单元/集成测试分类**

#### 🌐 **2. 网络隔离机制** ✅
- **YAML定义策略**: 通过标签定义网络隔离规则
- **4个安全区域**: attacker/dmz/internal/isolated
- **Iptables自动生成**: 精确的访问控制规则
- **兼容性验证**: 自动检测端口冲突

#### 🔍 **3. 增强网络连通性测试** ✅
- **5层测试架构**:
  - ICMP ping测试 (丢包率、抖动、RTT)
  - TCP/UDP端口连通性
  - DNS解析验证
  - 路由追踪 (跳数分析)
  - 性能测试 (iperf3 + ping回退)
- **健康评分系统**: 0-100分质量评估
- **详细报告**: 可视化网络状态

#### 🎯 **4. CVE注入准确性增强** ✅
- **数据库验证**: NVD + exploit-db集成
- **环境兼容性检查**: 镜像、端口、服务验证
- **攻击步骤生成**: CVE特定的攻击序列
- **可复现性验证**: 完整的验证流程

#### 📚 **5. CVE原子化Pipeline** ✅
- **32个现代CVE**: 基于VulnHub的2018+现代漏洞
- **MITRE ATT&CK映射**: 自动攻击阶段分析
- **质量验证**: 多维度catalog质量评分 (平均0.96分)
- **批量收集**: 自动化CVE catalog生成工具
- **拓扑适配**: 网络层级和角色自动匹配

#### 🤖 **6. Agent驱动CVE复现系统** ✅
- **自主Agent**: 使用Claude Code SDK自主分析和复现
- **Docker隔离**: CVE环境和Agent容器独立运行
- **智能决策**: Agent自主选择执行方式（直接bash vs 编写exploit）
- **Prompt驱动**: 只提供CVE信息，Agent完全自主决策
- **标准输出**: 验证后的Ansible配置和exploit playbook
- **完整流程**: 分析→设计→执行→验证→生成

### ⏳ **待完成功能**

#### 🤖 **7. 批量生成引擎** (进行中)
- **大规模场景生成**: 支持组合多个CVE原子组件
- **AI辅助转换**: Agent驱动的README解析
- **质量保证**: 自动验证和评分
- **JSONL导出**: 结构化生成结果

### 🎨 **独特功能亮点**

#### ⚔️ **CVE Catalog系统**
```python
from clab_builder.atomic.catalog import CVECatalogLoader

loader = CVECatalogLoader()

# 查询适合initial_access的现代CVE
initial_cves = loader.get_cves_by_stage("initial_access", 0.7)

# 按复杂度查询
simple_cves = loader.get_cves_by_complexity("low")

# 获取完整catalog信息
catalog = loader.load_catalog("CVE-2021-44228")
print(catalog.basic_info.cvss_score)  # 10.0
print(catalog.attack_chain.primary_stage)  # execution
```

#### 🔬 **自动CVE收集**
```bash
# 批量收集现代CVE (2018+)
python scripts/collect_modern_cves.py

# 验证catalog质量
python scripts/validate_catalogs.py
```

#### 🎯 **MITRE ATT&CK阶段映射**
```python
from clab_builder.atomic.mapper import AttackStageMapper

mapper = AttackStageMapper()
attack_chain = mapper.map_from_description(
    "Apache Log4j remote code execution",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
)

print(attack_chain.primary_stage)  # initial_access
print(attack_chain.stage_scores)   # 各阶段适配度评分
```
rce_cves = library.list_by_category(CVECategory.RCE)

# 智能组合
resources = library.estimate_resources(["CVE-2021-44228", "CVE-2014-0160"])

# 自动生成
template = library.generate_topology_template(cve_ids)
```

#### 🧪 **5层网络测试**
```python
tester = EnhancedConnectivityTester()

# 全面测试
results = tester.test_full_connectivity(target_ip, target_ports)

# 健康评分
health_score = tester.calculate_network_health_score(results)  # 0-100分
```

#### 🤖 **Agent驱动的CVE复现**
```python
from src.clab_builder.integration import AgentDrivenCVEPipeline, PipelineConfig

# 配置CVE复现任务
config = PipelineConfig(
    cve_id="CVE-2024-1234",
    docker_image="vulhub/sqli:latest",
    ports=[80, 3306],
    cve_description="SQL注入漏洞，允许攻击者通过未过滤的输入执行任意SQL命令",
    exploit_references=[
        "https://exploit-db.com/exploits/12345"
    ],
    writeups=[
        "通过products.php的id参数注入SQL代码",
        "使用UNION SELECT提取数据库信息"
    ],
    output_dir="./output/cve-2024-1234",
    network_name="cve-network"
)

# 创建并运行pipeline
pipeline = AgentDrivenCVEPipeline(config)

# 执行完整的Agent驱动流程
# 1. 启动CVE环境容器
# 2. 启动Agent容器（使用Claude Code SDK）
# 3. Agent自主分析、决策、执行、验证
# 4. 生成标准Ansible配置和exploit playbook
result = pipeline.run()

if result['success']:
    print(f"✅ CVE复现成功!")
    print(f"攻击路径: {result['agent_output']['attack_path_stages']} 个阶段")
    print(f"输出文件: {result['output_files']}")
```

## 🚀 快速开始

### 📋 **环境要求**
- Python 3.12+
- Docker & ContainerLab
- uv (推荐的Python包管理器)

### 🔧 **安装步骤**

```bash
# 1. 克隆项目
git clone <repository_url>
cd clab_builder

# 2. 安装依赖
uv sync

# 3. 验证安装
uv run pytest tests/ -v
```

### 🎯 **基础使用**

#### **1. 创建网络拓扑**

```yaml
# topology.yaml
name: cve-training-lab
topology:
  nodes:
    attacker1:
      kind: linux
      image: kalilinux/kali-rolling:latest
      labels:
        role: attacker

    victim1:
      kind: linux
      image: vulhub/log4j:latest
      labels:
        role: victim
        cve_id: CVE-2021-44228
        cve_name: Apache Log4j RCE
        cvss_score: 10.0

    router1:
      kind: linux
      image: alpine:latest
      labels:
        role: router

  links:
    - endpoints: ["attacker1:eth1", "router1:eth1"]
    - endpoints: ["victim1:eth1", "router1:eth2"]
```

#### **2. 生成配置**

```bash
# 生成ContainerLab和Ansible配置
uv run python -m clab_builder.main generate topology.yaml

# 输出:
# ✅ ContainerLab配置: topology-clab.yaml
# ✅ Ansible配置: ansible_inventory.yaml
# ✅ CVE catalog: data/catalogs/verified/CVE-2021-44228.yaml
```

#### **3. 部署和验证**

```bash
# 部署环境
clab deploy -t topology-clab.yaml

# 运行网络连通性测试
uv run python -m clab_builder.main validate cve-training-lab

# 执行攻击playbook
python scripts/generate_attack_playbook.py --cve CVE-2021-44228
```

### 🔍 **CVE原子库使用**

```bash
# 查看可用CVE
uv run python examples/cve_atomic_library_demo.py

# 🔥 高危RCE漏洞:
#   - CVE-2021-44228: Apache Log4j Remote Code Execution (CVSS: 10.0)
#   - CVE-2014-6271: GNU Bash Shellshock Remote Code Execution (CVSS: 10.0)

# 📊 资源估算:
#   内存需求: 1536 MB
#   磁盘需求: 3000 MB
#   预计时间: 30 分钟
```

### 🧪 **运行测试**

```bash
# 运行所有测试
./run_tests.sh all

# 只运行单元测试
./run_tests.sh unit

# 运行CVE相关测试
uv run pytest tests/ -m cve -v

# 生成覆盖率报告
uv run pytest tests/ --cov=src/clab_builder --cov-report=html
```

## 📚 详细使用指南

### 🌐 **网络隔离配置**

通过YAML标签定义精确的网络隔离策略：

```yaml
isolation_policies:
  - source: attacker_zone
    destination: dmz_zone
    action: ACCEPT
    allowed_protocols: [tcp]
    allowed_ports: [80, 443, 8080]

  - source: attacker_zone  
    destination: internal_zone
    action: DROP
    log: true
```

**生成的iptables规则**：
- 精确的端口级别访问控制
- 自动日志记录
- 状态跟踪支持

### ⚔️ **攻击Playbook结构**

每个攻击playbook包含完整的攻击流程：

```yaml
attack_steps:
  - phase: preparation      # 环境准备
    order: 1
    name: "部署LDAP Listener"
    commands: [...]
    
  - phase: exploitation     # 漏洞利用  
    order: 2
    name: "执行JNDI注入"
    commands: [...]
    
  - phase: validation       # 攻击验证
    order: 3
    name: "确认RCE成功"
    commands: [...]
    
  - phase: reporting        # 生成报告
    order: 4
    name: "汇总攻击结果"
    commands: [...]
```

### 📊 **网络质量评分**

5层连通性测试生成0-100分的健康评分：

```python
# 评分标准
ICMP连通性: 25分 (延迟、丢包率)
TCP/UDP端口: 20分 (服务可达性)
DNS解析: 15分 (域名解析)
路由追踪: 20分 (跳数、路径)
性能测试: 20分 (带宽、延迟)

# 结果示例
总体健康评分: 85/100
✅ ICMP测试: 23/25分 (轻微延迟)
✅ 端口测试: 20/20分 (所有端口可达)
⚠️ DNS测试: 10/15分 (解析缓慢)
✅ 路由测试: 18/20分 (路径正常)
✅ 性能测试: 14/20分 (带宽充足)
```

### 🔧 **CVE组合验证**

智能检查CVE组合的兼容性：

```python
from clab_builder.atomic.catalog import CVECatalogLoader

loader = CVECatalogLoader()

# 验证CVE组合
valid, issues = library.validate_cve_combination([
    "CVE-2021-44228",  # Log4j - 端口 8080
    "CVE-2014-0160"   # Heartbleed - 端口 443
])

# 结果
if not valid:
    for issue in issues:
        print(f"❌ {issue}")
        # "端口冲突: 两个CVE都使用端口 8443"
```

## 🏗️ 架构设计

### 🎯 **分层架构**

```
┌─────────────────────────────────────────────────────┐
│                   用户输入层                         │
│           ContainerLab YAML拓扑定义                  │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│                   解析和生成层                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────┐ │
│  │ YAML解析器   │→ │ 拓扑生成器   │→ │配置生成器 │ │
│  └──────────────┘  └──────────────┘  └──────────┘ │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│                   验证和质量层                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────┐ │
│  │ 环境验证器   │  │CVE验证器     │→ │健康评分器 │ │
│  └──────────────┘  └──────────────┘  └──────────┘ │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│                   CVE原子库层                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────┐ │
│  │原子化CVE组件 │→ │智能组合引擎  │→ │模板生成器 │ │
│  └──────────────┘  └──────────────┘  └──────────┘ │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│                   输出和执行层                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────┐ │
│  │ContainerLab  │  │ Ansible      │  │ 攻击     │ │
│  │基础设施配置  │  │ 环境配置     │  │ Playbooks │ │
│  └──────────────┘  └──────────────┘  └──────────┘ │
└─────────────────────────────────────────────────────┘
```

### 🔧 **核心设计原则**

#### **1. 架构分离原则**

```python
# ❌ 错误的做法：混淆关注点
def generate_cve_config():
    # 环境配置 + 攻击执行混合在一起
    configure_vulnerability()
    execute_exploit()
    generate_report()

# ✅ 正确的做法：清晰分离
class VulnerabilityConfigurator:
    """专门负责CVE环境配置"""
    def configure_log4j_environment(node):
        # 确保目标存在Log4j漏洞
        install_vulnerable_version()
        enable_jndi_lookup()

class AttackPlaybookLibrary:
    """独立的攻击playbook"""
    def get_log4j_attack_playbook():
        # 纯粹的攻击执行步骤
        return {
            "exploit": "执行JNDI注入",
            "validation": "确认RCE",
            "cleanup": "清理痕迹"
        }
```

#### **2. 数据驱动原则**

```python
# CVE原子库作为单一数据源
loader = CVECatalogLoader()

# 自动生成所需配置
cve_info = library.get_atomic_cve("CVE-2021-44228")
config = generate_vulnerability_config(cve_info)
attack = get_attack_playbook(cve_info.attack_playbook)
validation = generate_validation_tests(cve_info)
```

#### **3. 可测试性原则**

```python
# 每个组件都可以独立测试
def test_network_isolation():
    policy = IsolationPolicy(
        source="attacker",
        destination="dmz", 
        action="ACCEPT"
    )
    
    validator = IsolationValidator()
    is_valid = validator.validate_policy(policy)
    assert is_valid
```

### 🔄 **数据流设计**

```yaml
输入: 用户定义的拓扑YAML
  ↓
解析阶段:
  - 提取节点、链路、标签信息
  - 识别CVE注入点
  - 解析网络隔离策略
  ↓
生成阶段:
  - 生成ContainerLab基础设施配置
  - 生成Ansible环境配置 (CVE准确注入)
  - 匹配独立攻击playbook
  ↓
验证阶段:
  - 语法和结构验证
  - 环境兼容性检查
  - 网络连通性测试
  - CVE可利用性验证
  ↓
输出阶段:
  - 可部署的ContainerLab YAML
  - Ansible配置文件
  - 独立攻击playbook
  - 质量评分报告
```

## 💻 开发指南

### 🔧 **开发环境设置**

```bash
# 1. Fork并克隆项目
git clone <your_fork>
cd clab_builder

# 2. 创建开发分支
git checkout -b feature/your-feature-name

# 3. 安装开发依赖
uv sync --dev

# 4. 设置pre-commit钩子 (可选)
uv run pre-commit install
```

### 📝 **代码结构规范**

```python
# src/clab_builder/模块结构
your_module/
├── __init__.py           # 模块导出
├── core.py              # 核心功能
├── utils.py             # 辅助函数
└── models.py            # 数据模型 (如果需要)
```

### 🧪 **测试规范**

```python
# tests/unit/test_your_module.py
import pytest
from clab_builder.your_module import YourClass

@pytest.mark.unit  # 使用适当的marker
class TestYourClass:
    def test_initialization(self):
        """测试类初始化"""
        obj = YourClass()
        assert obj is not None

    @pytest.mark.slow  # 标记慢测试
    def test_complex_operation(self):
        """测试复杂操作"""
        result = YourClass.complex_method()
        assert result.success
```

### 🔄 **工作流程**

```bash
# 1. 编写功能和测试
# 2. 运行测试确保通过
uv run pytest tests/unit/test_your_module.py -v

# 3. 检查代码覆盖率
uv run pytest tests/ --cov=src/clab_builder/your_module

# 4. 运行完整测试套件
./run_tests.sh all

# 5. 提交变更
git add .
git commit -m "feat: add your feature description"

# 6. 推送并创建PR
git push origin feature/your-feature-name
```

### 📊 **性能和质量标准**

- **测试覆盖率**: 目标 >80%
- **类型提示**: 所有公共API必须有类型提示
- **文档字符串**: 所有函数和类需要docstring
- **代码风格**: 遵循PEP 8，使用black格式化

### 🔌 **添加新的CVE到原子库**

```python
# 1. 在CVE原子库中添加新条目
from clab_builder.core.cve_atomic_library import AtomicCVE

new_cve = AtomicCVE(
    cve_id="CVE-YYYY-NNNN",
    name="Vulnerability Name",
    category=CVECategory.RCE,
    cvss_score=9.8,
    description="详细描述...",
    vulnerable_image="vulhub/xxx:latest",
    catalog_path="data/catalogs/verified/CVE-YYYY-NNNN.yaml",
    config_playbook="config/cve_YYYY_NNNN_name.yaml",
    requirements=AtomicRequirement(
        required_ports=[8080],
        dependency_images=[]
    ),
    compatible_services=["service-type"],
    tags=["category", "severity"]
)

library.add_custom_cve(new_cve)

# 2. 创建对应的攻击playbook
# data/catalogs/verified/CVE-YYYY-NNNN.yaml

# 3. 编写测试
# tests/unit/test_cve_YYYY_NNNN.py
```

## 🤝 贡献指南

### 🎯 **贡献类型**

我们欢迎以下类型的贡献：

- **🐛 Bug修复**: 修复现有功能的错误
- **✨ 新功能**: 添加新的CVE或功能
- **📚 文档**: 改进文档和示例
- **🧪 测试**: 增加测试覆盖率
- **🔧 性能优化**: 提升系统性能
- **🎨 代码重构**: 改善代码结构

### 📋 **Pull Request流程**

1. **Fork项目** 并创建功能分支
2. **编写代码** 遵循代码规范
3. **添加测试** 确保功能正确性
4. **更新文档** 包含使用说明
5. **提交PR** 清晰描述变更内容

### 📝 **提交信息规范**

```bash
# 功能添加
git commit -m "feat: add support for new CVE-2023-xxxx"

# Bug修复
git commit -m "fix: resolve network isolation validation error"

# 文档更新
git commit -m "docs: update README with new usage examples"

# 测试改进
git commit -m "test: add integration tests for CVE atomic library"
```

### ✅ **代码审查标准**

所有PR需要通过以下检查：

- [ ] 所有测试通过
- [ ] 代码覆盖率 >80%
- [ ] 符合代码风格规范
- [ ] 包含适当的文档
- [ ] 更新相关测试用例
- [ ] 通过安全审查

## 📈 项目进度

### ✅ **已完成** (80%)

- [x] 单元测试框架 (38个测试)
- [x] 网络隔离机制
- [x] 增强网络连通性测试
- [x] CVE注入准确性增强
- [x] CVE原子库设计
- [x] 独立攻击playbook系统

### ⏳ **进行中** (20%)

- [ ] 批量生成引擎 (AI驱动)
- [ ] 更多CVE原子组件集成

### 🎯 **未来规划**

- [ ] Agent自动化CVE场景生成
- [ ] 实时攻击效果监控
- [ ] 云平台集成 (AWS/Azure)
- [ ] 多用户协作支持
- [ ] Web界面管理

## 🔗 相关资源

### 📚 **技术文档**
- [ContainerLab官方文档](https://containerlab.dev/)
- [Ansible最佳实践](https://docs.ansible.com/)
- [VulnHub漏洞环境](https://www.vulnhub.com/)

### 🛠️ **相关工具**
- [CVE数据库](https://nvd.nist.gov/)
- [Exploit-DB](https://www.exploit-db.com/)
- [Docker Hub](https://hub.docker.com/)

### 🎓 **学习资源**
- [网络安全训练平台](https://www.hackthebox.com/)
- [渗透测试指南](https://www.pentest-standard.org/)

## 🏆 项目成就

### 📊 **技术指标**

- **🧪 测试覆盖**: 41个测试用例，24%覆盖率（持续提升）
- **🚀 代码行数**: 2000+ 行Python代码
- **📚 文档完整度**: 架构文档、API文档、使用指南齐全
- **🔧 可维护性**: 模块化设计，清晰的关注点分离

### 🎯 **功能完整性**

- **网络隔离**: ✅ 完整的YAML定义和iptables生成
- **CVE注入**: ✅ 数据库验证和环境兼容性检查
- **连通性测试**: ✅ 5层网络测试和健康评分
- **原子库**: ✅ 15+ CVE组件，智能组合验证

### 🌟 **独特价值**

1. **架构分离**: 业界首创的CVE环境配置vs攻击执行分离
2. **原子化设计**: 可重用CVE组件，支持大规模批量生成
3. **质量保证**: 全面的验证和评分系统
4. **AI驱动**: Agent辅助的自动化转换和验证

## 📞 联系我们

### 💬 **问题反馈**

- **GitHub Issues**: [提交问题](https://github.com/your-repo/issues)
- **Discussions**: [参与讨论](https://github.com/your-repo/discussions)

### 🤝 **贡献方式**

- **代码贡献**: 欢迎提交Pull Request
- **文档改进**: 帮助完善文档和示例
- **CVE集成**: 添加更多原子化CVE组件
- **测试增强**: 提升测试覆盖率

### 📧 **联系方式**

- **项目维护者**: [Maintainer Name]
- **技术支持**: [Support Email]

## ⚖️ 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

## 🙏 致谢

感谢以下开源项目的启发和支持：

- [ContainerLab](https://containerlab.dev/) - 网络拓扑基础设施
- [VulnHub](https://www.vulnhub.com/) - 漏洞环境来源
- [Ansible](https://www.ansible.com/) - 自动化配置工具
- [Pytest](https://pytest.org/) - 测试框架

---

**🎯 我们的使命**: 让CVE训练数据生成更简单、更准确、更可靠！

**⚡ 快速开始**: `uv sync && ./run_tests.sh all`

**📚 深入学习**: 查看 [docs/](docs/) 目录获取详细文档

**🤝 参与贡献**: 我们欢迎所有形式的贡献！
