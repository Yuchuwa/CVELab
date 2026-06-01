# CVE原子化项目结构说明

## 🎯 **项目架构重组完成！**

### **新的目录结构**
```
clab_builder/
├── src/clab_builder/
│   ├── atomic/                    # 🆕 CVE原子化核心模块
│   │   ├── __init__.py            # 模块导出
│   │   ├── catalog.py             # CVE Catalog定义
│   │   ├── processor.py           # CVE处理器
│   │   ├── validator.py           # 原子化验证器
│   │   ├── mapper.py              # ATT&CK阶段映射器
│   │   └── enricher.py           # 信息丰富器
│   ├── core/                      # 核心功能模块
│   ├── models/                   # 数据模型
│   └── utils/                    # 工具函数
│
├── data/                          # 🆕 数据存储层
│   ├── raw/                      # 原始CVE数据
│   ├── processing/              # 处理中的数据
│   └── catalogs/               # 验证后的catalog
│       ├── verified/            # 已验证的catalog
│       └── failed/              # 验证失败的catalog
│
├── attacks/                       # 独立攻击playbook
├── tools/                        # 🆕 工具脚本
│   ├── atomic_pipeline_demo.py # Pipeline演示
│   └── catalog_loader_test.py  # Catalog加载测试
└── tests/                        # 测试套件
```

## 🔄 **清晰的Pipeline流程**

```
📥 收集 → ⚙️ 处理 → 🔧 丰富 → ✅ 验证 → 💾 存储 → 🎯 使用
```

## 🎯 **核心特性**

### **1. ATT&CK阶段映射** ⭐
- CVE自动映射到MITRE ATT&CK攻击阶段
- 支持按阶段查询和组合
- 基于描述、writeups、exploits自动推断

### **2. 分离的关注点**
- **Catalog**: 包含基础信息、环境、攻击、拓扑适配
- **Attack Playbook**: 独立存在，专注攻击执行
- **清晰的职责边界**

### **3. 质量保证**
- 语法验证、逻辑一致性检查
- 完整度、准确性、可利用性评分 (0-1分)
- 自动移动到verified/failed目录

## 🚀 **使用方式**

### **运行Pipeline演示**
```bash
# 查看Pipeline结构
python tools/atomic_pipeline_demo.py --structure

# 运行完整演示
python tools/atomic_pipeline_demo.py --demo
```

### **测试Catalog加载**
```bash
# 测试catalog加载器
python tools/catalog_loader_test.py
```

## 📊 **当前状态**

- ✅ **项目结构重组完成**
- ✅ **Pipeline架构清晰**
- ✅ **核心模块实现**
- ✅ **1个示例catalog可用** (CVE-2021-44228)
- ✅ **Pipeline演示可运行**
- ⏳ **需要扩展更多CVE catalog**

## 🎯 **下一步工作**

1. **扩展CVE catalog数量** - 从VulnHub收集15+热门CVE
2. **Agent驱动playbook生成** - 实际执行攻击生成playbook
3. **与现有系统集成** - 连接到TopologyGenerator

这个新架构为批量CVE生成提供了坚实的基础！