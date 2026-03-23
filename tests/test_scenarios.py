#!/usr/bin/env python3
"""
Containerlab Builder 集成测试 - 场景A和B的综合测试

测试场景A（单层网络）和场景B（三层企业网络）的拓扑构建。
包含模糊输入和清晰输入的测试用例。
"""
import sys
import os
from typing import Dict, Any, List, Tuple
from dataclasses import dataclass

# 添加项目根目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from clab_builder.main import run


# ============================================
# 测试结果数据结构
# ============================================

@dataclass
class TestResult:
    """测试结果"""
    test_name: str
    passed: bool
    yaml_path: str = ""
    json_path: str = ""
    error_msg: str = ""
    notes: str = ""


# ============================================
# 场景A：单层网络测试（5个测试用例）
# ============================================

def test_scenario_a_01_clear_input() -> TestResult:
    """测试场景A - 清晰输入：明确指定所有细节"""
    print("\n" + "="*80)
    print("📋 测试 A-1: 场景A - 清晰输入（明确指定所有细节）")
    print("="*80)
    print("描述: 明确指定节点类型、漏洞、网络结构")
    print("-"*80)

    user_request = """
    创建一个场景A的渗透测试实验室，具体要求如下：
    - 实验室名称：redis-simple-pentest-lab
    - 场景类型：A（单层扁平网络）
    - 网络区域：dmz
    - 节点列表：
      1. 攻击机：名称为attacker，镜像为kali，角色为endpoint
      2. 漏洞目标：名称为redis-target，使用Vulhub的Redis CVE-2022-0543漏洞
      3. 诱饵服务器1：名称为nginx-web，镜像为nginx，角色为endpoint
      4. 诱饵服务器2：名称为ubuntu-app，镜像为ubuntu，角色为endpoint
    - 所有节点连接到dmz网络
    """

    try:
        result = run(user_request)

        if result.get("is_complete"):
            print("\n✅ 测试 A-1 - 成功")
            print(f"   YAML: {result.get('yaml_path', 'N/A')}")
            print(f"   JSON: {result.get('json_path', 'N/A')}")
            return TestResult(
                test_name="A-1_Clear_Input",
                passed=True,
                yaml_path=result.get('yaml_path', ''),
                json_path=result.get('json_path', ''),
                notes="清晰输入，系统正确生成拓扑"
            )
        else:
            print(f"\n❌ 测试 A-1 - 失败")
            print(f"   错误: {result.get('error_logs', 'Unknown')[:300]}")
            return TestResult(
                test_name="A-1_Clear_Input",
                passed=False,
                error_msg=result.get('error_logs', 'Unknown')[:300],
                notes="工作流未完成"
            )

    except Exception as e:
        print(f"\n❌ 测试 A-1 - 异常: {e}")
        import traceback
        traceback.print_exc()
        return TestResult(
            test_name="A-1_Clear_Input",
            passed=False,
            error_msg=str(e)[:300],
            notes="运行时异常"
        )


def test_scenario_a_02_vague_input() -> TestResult:
    """测试场景A - 模糊输入：自然语言描述，让系统推断细节"""
    print("\n" + "="*80)
    print("📋 测试 A-2: 场景A - 模糊输入（自然语言描述）")
    print("="*80)
    print("描述: 用自然语言简单描述需求，系统自动推断拓扑")
    print("-"*80)

    user_request = """
    我想做一个Redis漏洞测试，需要一个Kali攻击机和Redis靶机。
    再加几个正常的服务器模拟真实环境。
    都放在同一个网络里就行，不用太复杂。
    """

    try:
        result = run(user_request)

        if result.get("is_complete"):
            print("\n✅ 测试 A-2 - 成功")
            print(f"   YAML: {result.get('yaml_path', 'N/A')}")
            print(f"   JSON: {result.get('json_path', 'N/A')}")
            print("   说明: 系统成功推断出场景A拓扑")
            return TestResult(
                test_name="A-2_Vague_Input",
                passed=True,
                yaml_path=result.get('yaml_path', ''),
                json_path=result.get('json_path', ''),
                notes="模糊输入，系统正确推断拓扑"
            )
        else:
            print(f"\n❌ 测试 A-2 - 失败")
            print(f"   错误: {result.get('error_logs', 'Unknown')[:300]}")
            return TestResult(
                test_name="A-2_Vague_Input",
                passed=False,
                error_msg=result.get('error_logs', 'Unknown')[:300],
                notes="系统无法处理模糊输入"
            )

    except Exception as e:
        print(f"\n❌ 测试 A-2 - 异常: {e}")
        import traceback
        traceback.print_exc()
        return TestResult(
            test_name="A-2_Vague_Input",
            passed=False,
            error_msg=str(e)[:300],
            notes="运行时异常"
        )


def test_scenario_a_03_minimal_input() -> TestResult:
    """测试场景A - 最小化输入：仅提供核心信息"""
    print("\n" + "="*80)
    print("📋 测试 A-3: 场景A - 最小化输入（仅核心信息）")
    print("="*80)
    print("描述: 只说明漏洞类型，让系统自动补充其他组件")
    print("-"*80)

    user_request = """
    场景A，Redis CVE-2022-0543漏洞测试。
    """

    try:
        result = run(user_request)

        if result.get("is_complete"):
            print("\n✅ 测试 A-3 - 成功")
            print(f"   YAML: {result.get('yaml_path', 'N/A')}")
            print(f"   JSON: {result.get('json_path', 'N/A')}")
            print("   说明: 系统自动补充攻击机和诱饵服务器")
            return TestResult(
                test_name="A-3_Minimal_Input",
                passed=True,
                yaml_path=result.get('yaml_path', ''),
                json_path=result.get('json_path', ''),
                notes="最小输入，系统自动补充完整拓扑"
            )
        else:
            print(f"\n❌ 测试 A-3 - 失败")
            print(f"   错误: {result.get('error_logs', 'Unknown')[:300]}")
            return TestResult(
                test_name="A-3_Minimal_Input",
                passed=False,
                error_msg=result.get('error_logs', 'Unknown')[:300],
                notes="系统无法处理最小化输入"
            )

    except Exception as e:
        print(f"\n❌ 测试 A-3 - 异常: {e}")
        import traceback
        traceback.print_exc()
        return TestResult(
            test_name="A-3_Minimal_Input",
            passed=False,
            error_msg=str(e)[:300],
            notes="运行时异常"
        )


def test_scenario_a_04_multiple_decoys() -> TestResult:
    """测试场景A - 多诱饵服务器：测试诱饵服务器数量上限"""
    print("\n" + "="*80)
    print("📋 测试 A-4: 场景A - 多诱饵服务器（3个诱饵）")
    print("="*80)
    print("描述: 测试场景A的最大诱饵服务器配置")
    print("-"*80)

    user_request = """
    创建场景A实验室，Redis作为漏洞目标。
    需要添加3个诱饵服务器：Nginx、Ubuntu、Alpine，模拟真实环境。
    Kali作为攻击机。
    所有节点在同一网络。
    """

    try:
        result = run(user_request)

        if result.get("is_complete"):
            print("\n✅ 测试 A-4 - 成功")
            print(f"   YAML: {result.get('yaml_path', 'N/A')}")
            print(f"   JSON: {result.get('json_path', 'N/A')}")
            print("   说明: 成功创建3个诱饵服务器")
            return TestResult(
                test_name="A-4_Multiple_Decoys",
                passed=True,
                yaml_path=result.get('yaml_path', ''),
                json_path=result.get('json_path', ''),
                notes="3个诱饵服务器配置成功"
            )
        else:
            print(f"\n❌ 测试 A-4 - 失败")
            print(f"   错误: {result.get('error_logs', 'Unknown')[:300]}")
            return TestResult(
                test_name="A-4_Multiple_Decoys",
                passed=False,
                error_msg=result.get('error_logs', 'Unknown')[:300],
                notes="无法创建多诱饵配置"
            )

    except Exception as e:
        print(f"\n❌ 测试 A-4 - 异常: {e}")
        import traceback
        traceback.print_exc()
        return TestResult(
            test_name="A-4_Multiple_Decoys",
            passed=False,
            error_msg=str(e)[:300],
            notes="运行时异常"
        )


def test_scenario_a_05_different_vuln() -> TestResult:
    """测试场景A - 不同漏洞：测试非Redis漏洞"""
    print("\n" + "="*80)
    print("📋 测试 A-5: 场景A - 不同漏洞类型（Log4j）")
    print("="*80)
    print("描述: 测试场景A使用Log4j漏洞而非Redis")
    print("-"*80)

    user_request = """
    创建一个场景A的渗透测试实验室：
    - 1 个 Kali Linux 攻击机
    - 1 个 Log4j 漏洞目标（CVE-2021-44228）
    - 2 个诱饵服务器：Nginx和Ubuntu
    - 单层扁平网络结构
    """

    try:
        result = run(user_request)

        if result.get("is_complete"):
            print("\n✅ 测试 A-5 - 成功")
            print(f"   YAML: {result.get('yaml_path', 'N/A')}")
            print(f"   JSON: {result.get('json_path', 'N/A')}")
            print("   说明: 成功使用Log4j漏洞生成拓扑")
            return TestResult(
                test_name="A-5_Different_Vuln",
                passed=True,
                yaml_path=result.get('yaml_path', ''),
                json_path=result.get('json_path', ''),
                notes="Log4j漏洞配置成功"
            )
        else:
            print(f"\n❌ 测试 A-5 - 失败")
            print(f"   错误: {result.get('error_logs', 'Unknown')[:300]}")
            return TestResult(
                test_name="A-5_Different_Vuln",
                passed=False,
                error_msg=result.get('error_logs', 'Unknown')[:300],
                notes="无法使用Log4j漏洞"
            )

    except Exception as e:
        print(f"\n❌ 测试 A-5 - 异常: {e}")
        import traceback
        traceback.print_exc()
        return TestResult(
            test_name="A-5_Different_Vuln",
            passed=False,
            error_msg=str(e)[:300],
            notes="运行时异常"
        )


# ============================================
# 场景B：三层企业网络测试（5个测试用例）
# ============================================

def test_scenario_b_01_clear_input() -> TestResult:
    """测试场景B - 清晰输入：明确指定三层架构"""
    print("\n" + "="*80)
    print("📋 测试 B-1: 场景B - 清晰输入（明确三层架构）")
    print("="*80)
    print("描述: 明确指定边缘层、DMZ层、核心层的节点配置")
    print("-"*80)

    user_request = """
    创建一个场景B的企业渗透测试实验室，要求如下：
    - 实验室名称：enterprise-three-layer-pentest
    - 场景类型：B（三层企业网络）

    网络分层：
    1. 外网区域（external）：Kali攻击机
    2. DMZ区域：WebLogic漏洞目标 + Nginx诱饵服务器
    3. 内网区域（internal）：Redis漏洞目标 + PostgreSQL诱饵 + 文件服务器

    路由架构：
    - 边缘路由器（edge-router）：连接external和dmz
    - 核心路由器（core-router）：连接dmz和internal

    漏洞目标：
    - DMZ：WebLogic CVE-2020-14882（未授权访问RCE漏洞）
    - Internal：Redis CVE-2022-0543

    诱饵服务器：
    - DMZ：nginx-proxy（Nginx）
    - Internal：postgres-db（PostgreSQL）、file-server（Ubuntu）、app-server（Alpine）
    """

    try:
        result = run(user_request)

        if result.get("is_complete"):
            print("\n✅ 测试 B-1 - 成功")
            print(f"   YAML: {result.get('yaml_path', 'N/A')}")
            print(f"   JSON: {result.get('json_path', 'N/A')}")
            print("   说明: 成功创建三层企业网络")
            return TestResult(
                test_name="B-1_Clear_Input",
                passed=True,
                yaml_path=result.get('yaml_path', ''),
                json_path=result.get('json_path', ''),
                notes="清晰输入，三层架构配置成功"
            )
        else:
            print(f"\n❌ 测试 B-1 - 失败")
            print(f"   错误: {result.get('error_logs', 'Unknown')[:300]}")
            return TestResult(
                test_name="B-1_Clear_Input",
                passed=False,
                error_msg=result.get('error_logs', 'Unknown')[:300],
                notes="工作流未完成"
            )

    except Exception as e:
        print(f"\n❌ 测试 B-1 - 异常: {e}")
        import traceback
        traceback.print_exc()
        return TestResult(
            test_name="B-1_Clear_Input",
            passed=False,
            error_msg=str(e)[:300],
            notes="运行时异常"
        )


def test_scenario_b_02_vague_input() -> TestResult:
    """测试场景B - 模糊输入：企业网络自然语言描述"""
    print("\n" + "="*80)
    print("📋 测试 B-2: 场景B - 模糊输入（自然语言描述）")
    print("="*80)
    print("描述: 用自然语言描述企业网络需求，让系统推断架构")
    print("-"*80)

    user_request = """
    我需要一个企业渗透测试环境，模拟真实的公司网络。
    外面有攻击机，中间有DMZ放Web服务器，里面有数据库服务器。
    需要一些正常的业务服务器来模拟真实环境。
    用路由器把各个网络连起来。
    """

    try:
        result = run(user_request)

        if result.get("is_complete"):
            print("\n✅ 测试 B-2 - 成功")
            print(f"   YAML: {result.get('yaml_path', 'N/A')}")
            print(f"   JSON: {result.get('json_path', 'N/A')}")
            print("   说明: 系统自动推断出三层企业网络架构")
            return TestResult(
                test_name="B-2_Vague_Input",
                passed=True,
                yaml_path=result.get('yaml_path', ''),
                json_path=result.get('json_path', ''),
                notes="模糊输入，系统正确推断三层架构"
            )
        else:
            print(f"\n❌ 测试 B-2 - 失败")
            print(f"   错误: {result.get('error_logs', 'Unknown')[:300]}")
            return TestResult(
                test_name="B-2_Vague_Input",
                passed=False,
                error_msg=result.get('error_logs', 'Unknown')[:300],
                notes="系统无法处理模糊输入"
            )

    except Exception as e:
        print(f"\n❌ 测试 B-2 - 异常: {e}")
        import traceback
        traceback.print_exc()
        return TestResult(
            test_name="B-2_Vague_Input",
            passed=False,
            error_msg=str(e)[:300],
            notes="运行时异常"
        )


def test_scenario_b_03_minimal_input() -> TestResult:
    """测试场景B - 最小化输入：仅说明场景类型"""
    print("\n" + "="*80)
    print("📋 测试 B-3: 场景B - 最小化输入（仅场景类型）")
    print("="*80)
    print("描述: 只说明是场景B，系统自动补充三层架构")
    print("-"*80)

    user_request = """
    场景B，企业渗透测试实验室。
    """

    try:
        result = run(user_request)

        if result.get("is_complete"):
            print("\n✅ 测试 B-3 - 成功")
            print(f"   YAML: {result.get('yaml_path', 'N/A')}")
            print(f"   JSON: {result.get('json_path', 'N/A')}")
            print("   说明: 系统自动生成完整三层企业网络")
            return TestResult(
                test_name="B-3_Minimal_Input",
                passed=True,
                yaml_path=result.get('yaml_path', ''),
                json_path=result.get('json_path', ''),
                notes="最小输入，系统自动补充完整架构"
            )
        else:
            print(f"\n❌ 测试 B-3 - 失败")
            print(f"   错误: {result.get('error_logs', 'Unknown')[:300]}")
            return TestResult(
                test_name="B-3_Minimal_Input",
                passed=False,
                error_msg=result.get('error_logs', 'Unknown')[:300],
                notes="系统无法处理最小化输入"
            )

    except Exception as e:
        print(f"\n❌ 测试 B-3 - 异常: {e}")
        import traceback
        traceback.print_exc()
        return TestResult(
            test_name="B-3_Minimal_Input",
            passed=False,
            error_msg=str(e)[:300],
            notes="运行时异常"
        )


def test_scenario_b_04_multiple_vulns() -> TestResult:
    """测试场景B - 多漏洞目标：测试DMZ和内网各有漏洞"""
    print("\n" + "="*80)
    print("📋 测试 B-4: 场景B - 多漏洞目标（DMZ+内网）")
    print("="*80)
    print("描述: 测试场景B在DMZ和内网各部署一个漏洞目标")
    print("-"*80)

    user_request = """
    创建场景B实验室，多层企业网络：
    - 外部：Kali攻击机
    - DMZ：ActiveMQ漏洞（CVE-2023-46604）+ 2个诱饵服务器
    - 内网：Redis漏洞（CVE-2022-0543）+ 3个诱饵服务器
    - 用路由器实现三层隔离架构
    """

    try:
        result = run(user_request)

        if result.get("is_complete"):
            print("\n✅ 测试 B-4 - 成功")
            print(f"   YAML: {result.get('yaml_path', 'N/A')}")
            print(f"   JSON: {result.get('json_path', 'N/A')}")
            print("   说明: 成功在DMZ和内网各部署一个漏洞目标")
            return TestResult(
                test_name="B-4_Multiple_Vulns",
                passed=True,
                yaml_path=result.get('yaml_path', ''),
                json_path=result.get('json_path', ''),
                notes="多漏洞目标配置成功"
            )
        else:
            print(f"\n❌ 测试 B-4 - 失败")
            print(f"   错误: {result.get('error_logs', 'Unknown')[:300]}")
            return TestResult(
                test_name="B-4_Multiple_Vulns",
                passed=False,
                error_msg=result.get('error_logs', 'Unknown')[:300],
                notes="无法创建多漏洞配置"
            )

    except Exception as e:
        print(f"\n❌ 测试 B-4 - 异常: {e}")
        import traceback
        traceback.print_exc()
        return TestResult(
            test_name="B-4_Multiple_Vulns",
            passed=False,
            error_msg=str(e)[:300],
            notes="运行时异常"
        )


def test_scenario_b_05_lateral_movement() -> TestResult:
    """测试场景B - 横向移动：双层漏洞实战"""
    print("\n" + "="*80)
    print("📋 测试 B-5: 场景B - 横向移动实战（双层漏洞）")
    print("="*80)
    print("描述: DMZ和内网各部署一个漏洞目标，练习横向移动")
    print("-"*80)

    user_request = """
    创建一个场景B的渗透测试实验室，用于练习横向移动：

    网络分层：
    1. 外网区域：Kali Linux攻击机
    2. DMZ区域：一个漏洞目标 + 2个正常业务服务器
    3. 内网区域：一个漏洞目标 + 3个正常服务器（数据库、文件服务器、应用服务器）

    路由架构：
    - 边缘路由器连接外网和DMZ
    - 核心路由器连接DMZ和内网，配置ACL阻止外网直接访问内网

    测试目标：
    1. 从外网扫描并发现DMZ的漏洞
    2. 利用DMZ漏洞获取立足点
    3. 从DMZ横向移动到内网
    4. 发现并利用内网漏洞目标
    """

    try:
        result = run(user_request)

        if result.get("is_complete"):
            print("\n✅ 测试 B-5 - 成功")
            print(f"   YAML: {result.get('yaml_path', 'N/A')}")
            print(f"   JSON: {result.get('json_path', 'N/A')}")
            print("   说明: 成功创建双层漏洞横向移动环境")
            return TestResult(
                test_name="B-5_Lateral_Movement",
                passed=True,
                yaml_path=result.get('yaml_path', ''),
                json_path=result.get('json_path', ''),
                notes="双层漏洞横向移动场景配置成功"
            )
        else:
            print(f"\n❌ 测试 B-5 - 失败")
            print(f"   错误: {result.get('error_logs', 'Unknown')[:300]}")
            return TestResult(
                test_name="B-5_Lateral_Movement",
                passed=False,
                error_msg=result.get('error_logs', 'Unknown')[:300],
                notes="无法创建横向移动场景"
            )

    except Exception as e:
        print(f"\n❌ 测试 B-5 - 异常: {e}")
        import traceback
        traceback.print_exc()
        return TestResult(
            test_name="B-5_Lateral_Movement",
            passed=False,
            error_msg=str(e)[:300],
            notes="运行时异常"
        )


# ============================================
# 测试运行器
# ============================================

def run_scenario_a_tests(selected_tests: List[int] = None) -> List[TestResult]:
    """运行场景A的所有测试"""
    print("\n" + "="*80)
    print("🚀 开始运行场景A测试套件（单层网络）")
    print("="*80)

    tests = [
        test_scenario_a_01_clear_input,
        test_scenario_a_02_vague_input,
        test_scenario_a_03_minimal_input,
        test_scenario_a_04_multiple_decoys,
        test_scenario_a_05_different_vuln,
    ]

    if selected_tests:
        tests = [tests[i-1] for i in selected_tests if i <= len(tests)]

    results = []
    for test in tests:
        result = test()
        results.append(result)

    return results


def run_scenario_b_tests(selected_tests: List[int] = None) -> List[TestResult]:
    """运行场景B的所有测试"""
    print("\n" + "="*80)
    print("🚀 开始运行场景B测试套件（三层企业网络）")
    print("="*80)

    tests = [
        test_scenario_b_01_clear_input,
        test_scenario_b_02_vague_input,
        test_scenario_b_03_minimal_input,
        test_scenario_b_04_multiple_vulns,
        test_scenario_b_05_lateral_movement,
    ]

    if selected_tests:
        tests = [tests[i-1] for i in selected_tests if i <= len(tests)]

    results = []
    for test in tests:
        result = test()
        results.append(result)

    return results


def print_summary(scenario_a_results: List[TestResult], scenario_b_results: List[TestResult]):
    """打印测试结果汇总"""
    all_results = {
        "Scenario_A": scenario_a_results,
        "Scenario_B": scenario_b_results,
    }

    print("\n" + "="*80)
    print("📊 测试结果汇总")
    print("="*80)

    total_passed = 0
    total_count = 0

    for scenario, results in all_results.items():
        if not results:
            continue

        print(f"\n【{scenario}】")
        for r in results:
            status = "✅ 通过" if r.passed else "❌ 失败"
            print(f"  {r.test_name:30s} : {status}")
            if r.notes:
                print(f"    └─ {r.notes}")
            if r.error_msg:
                print(f"    └─ 错误: {r.error_msg[:100]}...")
            total_count += 1
            if r.passed:
                total_passed += 1

    print("\n" + "-"*80)
    print(f"总计: {total_passed}/{total_count} 测试通过 ({total_passed*100//total_count if total_count > 0 else 0}%)")

    if total_passed == total_count:
        print("\n🎉 所有集成测试通过！")
        return 0
    else:
        print(f"\n⚠️  {total_count - total_passed} 个测试失败")
        return 1


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(description="Containerlab Builder 集成测试")
    parser.add_argument("--scenario", choices=["A", "B", "ALL"], default="ALL",
                        help="选择测试场景（默认：全部）")
    parser.add_argument("--tests", nargs="+", type=int, metavar="N",
                        help="选择特定测试用例编号（例如：--tests 1 2 3）")

    args = parser.parse_args()

    scenario_a_results = []
    scenario_b_results = []

    if args.scenario in ["A", "ALL"]:
        scenario_a_results = run_scenario_a_tests(args.tests)

    if args.scenario in ["B", "ALL"]:
        scenario_b_results = run_scenario_b_tests(args.tests)

    return print_summary(scenario_a_results, scenario_b_results)


if __name__ == "__main__":
    sys.exit(main())
