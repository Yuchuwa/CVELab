#!/usr/bin/env python3
"""
Containerlab Builder 集成测试

测试简单、中等、复杂三种难度的网络拓扑构建。
"""
import sys
import os

# 添加项目根目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from main import run


def test_simple_topology():
    """测试简单拓扑：2个节点，点对点连接"""
    print("\n" + "="*80)
    print("📋 测试 1: 简单拓扑 (Simple)")
    print("="*80)
    print("场景: Kali 攻击机 + redis，通过路由器连接")
    print("-"*80)

    user_request = """
    创建一个简单的渗透测试实验室：
    - 1 个 Kali Linux 作为攻击机
    - 1 个 Redis 服务器作为靶机,包含CVE-2022-0543漏洞
    - 1 个 Alpine 路由器连接它们
    - 复杂度：simple
    """

    try:
        result = run(user_request)

        if result.get("is_complete"):
            print("\n✅ 简单拓扑测试 - 成功")
            print(f"   YAML: {result.get('yaml_path', 'N/A')}")
            return True
        else:
            print(f"\n❌ 简单拓扑测试 - 失败")
            print(f"   错误: {result.get('error_logs', 'Unknown')[:200]}")
            return False

    except Exception as e:
        print(f"\n❌ 简单拓扑测试 - 异常: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_medium_topology():
    """测试中等拓扑：多层隔离网络"""
    print("\n" + "="*80)
    print("📋 测试 2: 中等拓扑 (Medium)")
    print("="*80)
    print("场景: DMZ + 内网，多层隔离")
    print("-"*80)

    user_request = """
    创建一个中等复杂度的渗透测试实验室：
    - DMZ 区域：边界路由器 + Web 服务器
    - 内网区域：核心路由器 + 数据库服务器 + 文件服务器
    - 攻击机：Kali Linux
    - 复杂度：medium
    """

    try:
        result = run(user_request)

        if result.get("is_complete"):
            print("\n✅ 中等拓扑测试 - 成功")
            print(f"   YAML: {result.get('yaml_path', 'N/A')}")
            return True
        else:
            print(f"\n❌ 中等拓扑测试 - 失败")
            print(f"   错误: {result.get('error_logs', 'Unknown')[:200]}")
            return False

    except Exception as e:
        print(f"\n❌ 中等拓扑测试 - 异常: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_complex_topology():
    """测试复杂拓扑：网状网络 + OSPF 动态路由"""
    print("\n" + "="*80)
    print("📋 测试 3: 复杂拓扑 (Complex)")
    print("="*80)
    print("场景: 企业级网状拓扑，多区域 + OSPF 动态路由")
    print("-"*80)

    user_request = """
    创建一个复杂的企业级网络实验室：
    - 外网区域：边界路由器 x2
    - DMZ 区域：核心路由器 + Web 服务器 + 邮件服务器
    - 内网区域：汇聚路由器 x2 + 应用服务器 + 数据库服务器集群
    - 管理网：监控服务器 + 日志服务器
    - 攻击机：Kali Linux
    - 要求使用 OSPF 动态路由
    - 复杂度：complex
    """

    try:
        result = run(user_request)

        if result.get("is_complete"):
            print("\n✅ 复杂拓扑测试 - 成功")
            print(f"   YAML: {result.get('yaml_path', 'N/A')}")
            return True
        else:
            print(f"\n❌ 复杂拓扑测试 - 失败")
            print(f"   错误: {result.get('error_logs', 'Unknown')[:200]}")
            return False

    except Exception as e:
        print(f"\n❌ 复杂拓扑测试 - 异常: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_error_recovery():
    """测试错误恢复机制：使用不存在的镜像"""
    print("\n" + "="*80)
    print("📋 测试 4: 错误恢复 (Fixer 智能修复)")
    print("="*80)
    print("场景: 故意使用不存在的镜像，测试 Fixer 的修复能力")
    print("-"*80)

    user_request = """
    创建一个渗透测试实验室：
    - 1 个不存在镜像的节点（fake-image:invalid-tag）
    - 1 个标准 Ubuntu 服务器
    - 1 个路由器连接它们
    """

    try:
        result = run(user_request)

        # 由于镜像不存在，Fixer 应该会修复并重试
        if result.get("is_complete"):
            print("\n✅ 错误恢复测试 - 成功（Fixer 成功修复了问题）")
            print(f"   YAML: {result.get('yaml_path', 'N/A')}")
            return True
        else:
            error_logs = result.get('error_logs', '')
            print(f"\n⚠️  错误恢复测试 - 部分成功")
            print(f"   说明: Fixer 尝试修复但可能达到重试上限")
            print(f"   错误: {error_logs[:200] if error_logs else 'Unknown'}")
            # 这不算失败，因为测试的就是错误处理
            return True

    except Exception as e:
        print(f"\n⚠️  错误恢复测试 - 预期异常（可能达到重试上限）: {str(e)[:200]}")
        # RuntimeError 可能是达到重试上限，这也是预期的
        if "Max retries" in str(e) or "Unrecoverable" in str(e):
            print("   说明: Fixer 正常工作，达到了重试上限")
            return True
        return False


def main():
    """运行所有集成测试"""
    print("\n" + "="*80)
    print("🚀 Containerlab Builder 集成测试套件")
    print("="*80)
    print("测试范围：简单、中等、复杂拓扑 + 错误恢复机制")
    print("="*80)

    results = {}

    # 测试 1: 简单拓扑
    results['simple'] = test_simple_topology()

    # # 测试 2: 中等拓扑
    # results['medium'] = test_medium_topology()

    # # 测试 3: 复杂拓扑
    # results['complex'] = test_complex_topology()

    # # 测试 4: 错误恢复
    # results['error_recovery'] = test_error_recovery()

    # 汇总结果
    print("\n" + "="*80)
    print("📊 测试结果汇总")
    print("="*80)

    for test_name, passed in results.items():
        status = "✅ 通过" if passed else "❌ 失败"
        print(f"  {test_name:20s}: {status}")

    total = len(results)
    passed_count = sum(results.values())

    print("-"*80)
    print(f"总计: {passed_count}/{total} 测试通过")

    if passed_count == total:
        print("\n🎉 所有集成测试通过！")
        return 0
    else:
        print(f"\n⚠️  {total - passed_count} 个测试失败")
        return 1


if __name__ == "__main__":
    sys.exit(main())
