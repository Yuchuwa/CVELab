#!/bin/bash
# 测试运行脚本

set -e

echo "🧪 ContainerLab Builder 测试运行脚本"
echo "======================================"

# 检查是否安装了pytest
if ! command -v pytest &> /dev/null; then
    echo "❌ pytest未安装，请先安装: uv add --dev pytest pytest-cov"
    exit 1
fi

# 解析命令行参数
TEST_TYPE="${1:-all}"
COVERAGE="${2:-yes}"

case "$TEST_TYPE" in
    "unit")
        echo "🔬 运行单元测试..."
        EXTRA_ARGS="-m unit"
        ;;
    "integration")
        echo "🔗 运行集成测试..."
        EXTRA_ARGS="-m integration"
        ;;
    "isolation")
        echo "🔒 运行网络隔离测试..."
        EXTRA_ARGS="-m isolation"
        ;;
    "connectivity")
        echo "🌐 运行连通性测试..."
        EXTRA_ARGS="-m connectivity"
        ;;
    "fast")
        echo "⚡ 运行快速测试..."
        EXTRA_ARGS="-m 'not slow' -m 'not docker'"
        ;;
    "all")
        echo "🚀 运行所有测试..."
        EXTRA_ARGS=""
        ;;
    *)
        echo "❌ 未知测试类型: $TEST_TYPE"
        echo "使用方法: $0 [unit|integration|isolation|connectivity|fast|all] [coverage]"
        exit 1
        ;;
esac

# 构建pytest命令
PYTEST_CMD="uv run pytest"

# 添加覆盖率
if [ "$COVERAGE" = "yes" ]; then
    PYTEST_CMD="$PYTEST_CMD --cov=src/clab_builder --cov-report=term-missing --cov-report=html"
fi

# 添加详细输出
PYTEST_CMD="$PYTEST_CMD -v --tb=short"

# 添加测试类型参数
PYTEST_CMD="$PYTEST_CMD $EXTRA_ARGS"

echo ""
echo "执行命令: $PYTEST_CMD"
echo ""

# 运行测试
eval $PYTEST_CMD

# 检查结果
if [ $? -eq 0 ]; then
    echo ""
    echo "✅ 所有测试通过!"

    if [ "$COVERAGE" = "yes" ]; then
        echo ""
        echo "📊 覆盖率报告已生成:"
        echo "   - 终端: 见上方输出"
        echo "   - HTML: htmlcov/index.html"
    fi

    echo ""
    echo "💡 其他测试命令:"
    echo "   ./run_tests.sh unit           # 只运行单元测试"
    echo "   ./run_tests.sh integration    # 只运行集成测试"
    echo "   ./run_tests.sh fast           # 只运行快速测试"
    echo "   ./run_tests.sh all no         # 不生成覆盖率报告"
else
    echo ""
    echo "❌ 测试失败，请检查输出"
    exit 1
fi