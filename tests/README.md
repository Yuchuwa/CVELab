# Pytest测试框架使用指南

## 测试结构

```
tests/
├── conftest.py                 # pytest配置和共享fixtures
├── unit/                       # 单元测试
│   ├── test_network_isolation.py
│   └── test_enhanced_connectivity.py
├── integration/                # 集成测试
│   └── test_workflow_integration.py
└── scenarios/                  # 场景测试
    └── (特定场景的测试)
```

## 运行测试

### 基础命令

```bash
# 运行所有测试
uv run pytest

# 运行单元测试
uv run pytest tests/unit/

# 运行集成测试
uv run pytest tests/integration/

# 运行特定测试文件
uv run pytest tests/unit/test_network_isolation.py

# 运行特定测试类
uv run pytest tests/unit/test_network_isolation.py::TestNetworkIsolationParsing

# 运行特定测试方法
uv run pytest tests/unit/test_network_isolation.py::TestNetworkIsolationParsing::test_parse_isolation_policies
```

### 按标记运行

```bash
# 运行所有单元测试
uv run pytest -m unit

# 运行所有隔离测试
uv run pytest -m isolation

# 运行所有连通性测试
uv run pytest -m connectivity

# 运行需要Docker的测试
uv run pytest -m docker

# 运行慢速测试
uv run pytest -m slow

# 组合标记
uv run pytest -m "unit and isolation"
uv run pytest -m "integration and not docker"
```

### 覆盖率报告

```bash
# 生成覆盖率报告
uv run pytest --cov=src/clab_builder --cov-report=html

# 查看HTML报告
open htmlcov/index.html

# 只显示覆盖率百分比
uv run pytest --cov=src/clab_builder --cov-report=term-missing
```

### 调试选项

```bash
# 显示详细输出
uv run pytest -v

# 显示print输出
uv run pytest -s

# 在第一个失败时停止
uv run pytest -x

# 进入pdb调试器
uv run pytest --pdb

# 显示本地变量
uv run pytest -l
```

## 测试标记说明

- `unit`: 单元测试，快速且隔离
- `integration`: 集成测试，测试组件间交互
- `network`: 网络相关测试
- `isolation`: 网络隔离测试
- `connectivity`: 连通性测试
- `cve`: CVE相关测试
- `slow`: 慢速测试（>1秒）
- `docker`: 需要Docker环境的测试

## Fixtures说明

### 主要Fixtures

- `sample_topology_data`: 示例拓扑数据
- `sample_topology_file`: 临时拓扑文件
- `sample_isolation_policies`: 示例隔离策略
- `mock_containers`: 模拟Docker容器
- `temp_workspace`: 临时工作空间
- `docker_available`: 检查Docker是否可用
- `examples_dir`: 示例YAML文件目录

### 使用Fixtures

```python
def test_example(sample_topology_file):
    # 直接使用fixture
    parser = ContainerLabParser(sample_topology_file)
    spec = parser.extract_topology_specification()
    assert spec is not None
```

## 编写测试指南

### 单元测试模板

```python
import pytest
from clab_builder.core.module import ClassToTest

@pytest.mark.unit
class TestClassName:
    """类描述"""

    def test_method_success_case(self):
        """测试成功情况"""
        # Arrange
        instance = ClassToTest()
        input_data = "test"

        # Act
        result = instance.method(input_data)

        # Assert
        assert result is not None
        assert result.status == "success"

    def test_method_failure_case(self):
        """测试失败情况"""
        instance = ClassToTest()

        with pytest.raises(ValueError):
            instance.method("invalid_input")
```

### 集成测试模板

```python
@pytest.mark.integration
class TestWorkflow:
    """工作流程测试"""

    def test_end_to_end_workflow(self, sample_topology_file):
        """测试端到端工作流程"""
        # 完整的集成测试
        parser = ContainerLabParser(sample_topology_file)
        spec = parser.extract_topology_specification()

        generator = TopologyGenerator(sample_topology_file)
        clab_config, ansible_config = generator.generate()

        assert clab_config is not None
        assert ansible_config is not None
```

## 最佳实践

1. **测试命名**: 使用描述性名称 `test_what_is_being_tested`
2. **AAA模式**: Arrange-Act-Assert结构
3. **独立性**: 每个测试应该独立运行
4. **速度**: 单元测试应该快速(<100ms)
5. **覆盖率**: 目标覆盖率>80%
6. **Mock**: 在单元测试中mock外部依赖

## 常见问题

### 测试失败

```bash
# 只运行失败的测试
uv run pytest --lf

# 先运行上次失败的测试
uv run pytest --ff

# 显示详细错误信息
uv run pytest -vv
```

### 并发测试

```bash
# 使用xdist并行运行测试
uv run pytest -n auto

# 按测试类分配
uv run pytest -n auto --dist loadscope
```

### 性能分析

```bash
# 显示最慢的10个测试
uv run pytest --durations=10

# 生成性能分析
uv run pytest --profile
```

## CI/CD集成

测试命令可以集成到CI/CD流水线：

```yaml
# .github/workflows/test.yml 示例
- name: Run tests
  run: uv run pytest --cov=src/clab_builder

- name: Upload coverage
  run: uv run pytest --cov=src/clab_builder --cov-report=xml
```

## 相关文档

- [pytest文档](https://docs.pytest.org/)
- [pytest-cov文档](https://pytest-cov.readthedocs.io/)
- [项目README](../README.md)