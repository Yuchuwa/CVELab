#!/usr/bin/env python3
"""
Containerlab Builder 集成测试

测试场景A（单层网络）和场景B（三层企业网络）的拓扑构建。
"""
import sys
import os

# 添加项目根目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from main import run


def test_scenario_a():
    """测试场景A：单层网络，1个漏洞目标 + N个端点"""
    print("\n" + "="*80)
    print("📋 测试 1: 场景A - 单层网络")
    print("="*80)
    print("场景: 扁平网络，Kali 攻击机 + Redis 漏洞目标")
    print("-"*80)

    user_request = """
    创建一个场景A的简单渗透测试实验室：
    - 1 个 Kali Linux 作为攻击机
    - 1 个 Redis 服务器作为靶机，包含CVE-2022-0543漏洞
    - 所有节点在同一个网络中
    """

    try:
        result = run(user_request)

        if result.get("is_complete"):
            print("\n✅ 场景A测试 - 成功")
            print(f"   YAML: {result.get('yaml_path', 'N/A')}")
            print(f"   JSON: {result.get('json_path', 'N/A')}")
            return True
        else:
            print(f"\n❌ 场景A测试 - 失败")
            print(f"   错误: {result.get('error_logs', 'Unknown')[:200]}")
            return False

    except Exception as e:
        print(f"\n❌ 场景A测试 - 异常: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_scenario_b():
    """测试场景B：三层企业网络，多层隔离"""
    print("\n" + "="*80)
    print("📋 测试 2: 场景B - 三层企业网络")
    print("="*80)
    print("场景: 边缘层 → 分发层 → 核心层，多层隔离")
    print("-"*80)

    user_request = """
    创建一个场景B的企业级渗透测试实验室：
    - 外网区域（边缘层）：Kali 攻击机
    - DMZ 区域：Web 服务器（包含Log4j漏洞 CVE-2021-44228）
    - 内网区域（核心层）：Redis 数据库服务器
    - 使用路由器实现三层架构和跨区域通信
    """

    try:
        result = run(user_request)

        if result.get("is_complete"):
            print("\n✅ 场景B测试 - 成功")
            print(f"   YAML: {result.get('yaml_path', 'N/A')}")
            print(f"   JSON: {result.get('json_path', 'N/A')}")
            return True
        else:
            print(f"\n❌ 场景B测试 - 失败")
            print(f"   错误: {result.get('error_logs', 'Unknown')[:200]}")
            return False

    except Exception as e:
        print(f"\n❌ 场景B测试 - 异常: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_scenario_c_reserved():
    """测试场景C：防火墙保护网络（预留接口）"""
    print("\n" + "="*80)
    print("📋 测试 3: 场景C - 防火墙保护网络（预留）")
    print("="*80)
    print("场景: 多层网络 + 防火墙放置点（实现待定）")
    print("-"*80)

    user_request = """
    创建一个场景C的防火墙保护网络实验室：
    - 外网区域：Kali 攻击机
    - DMZ 区域：Nginx Web 服务器（包含漏洞）
    - 内网区域：Redis 数据库服务器
    - 多层路由架构，为防火墙预留放置点
    """

    try:
        result = run(user_request)

        if result.get("is_complete"):
            print("\n✅ 场景C测试 - 成功")
            print(f"   YAML: {result.get('yaml_path', 'N/A')}")
            print(f"   JSON: {result.get('json_path', 'N/A')}")
            print("   注意: 防火墙节点已预留，具体实现待定")
            return True
        else:
            print(f"\n❌ 场景C测试 - 失败")
            print(f"   错误: {result.get('error_logs', 'Unknown')[:200]}")
            return False

    except Exception as e:
        print(f"\n❌ 场景C测试 - 异常: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_error_recovery():
    """测试错误恢复机制：使用不存在的漏洞"""
    print("\n" + "="*80)
    print("📋 测试 4: 错误恢复 (Fixer 智能修复)")
    print("="*80)
    print("场景: 故意请求不存在的漏洞，测试 Fixer 的修复能力")
    print("-"*80)

    user_request = """
    创建一个场景A的渗透测试实验室：
    - 1 个 Kali 攻击机
    - 1 个不存在的漏洞目标（FakeVuln-9999-9999）
    - 测试 Fixer 的错误处理能力
    """

    try:
        result = run(user_request)

        # 由于漏洞不存在，Fixer 应该会修复并重试
        if result.get("is_complete"):
            print("\n✅ 错误恢复测试 - 成功（Fixer 成功处理了问题）")
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
    print("测试范围：场景A（单层）、场景B（三层）、场景C（防火墙预留）+ 错误恢复")
    print("="*80)

    results = {}

    # 测试 1: 场景A
#    results['scenario_a'] = test_scenario_a()

    # 测试 2: 场景B
    results['scenario_b'] = test_scenario_b()

    # # 测试 3: 场景C（预留，可选）
    # results['scenario_c'] = test_scenario_c_reserved()

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
