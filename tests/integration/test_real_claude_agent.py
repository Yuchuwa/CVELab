"""
真正的LLM驱动CVE Pipeline测试

针对不同CVE测试pipeline是否正常工作，不使用模拟数据
"""

import pytest
import subprocess
import os
from pathlib import Path
import sys

# 添加项目路径
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root / "src"))

# 直接导入，避免config.py的导入问题
import sys
sys.path.insert(0, str(project_root / "src" / "clab_builder" / "agent"))
from real_claude_agent import RealClaudeAgent, CVEContext, AgentResult


@pytest.mark.integration
@pytest.mark.llm
class TestRealClaudeAgentPipeline:
    """测试真正的Claude Agent Pipeline"""

    @pytest.fixture(autouse=True)
    def check_env(self):
        """检查环境配置"""
        if not os.getenv("API_KEY"):
            pytest.skip("需要设置API_KEY环境变量")

    @pytest.fixture
    def agent(self):
        """初始化Claude Agent"""
        try:
            return RealClaudeAgent()
        except ValueError as e:
            pytest.skip(f"Claude Agent初始化失败: {e}")

    @pytest.fixture
    def activemq_context(self):
        """ActiveMQ CVE上下文"""
        return CVEContext(
            cve_id="CVE-2023-46604",
            description="Apache ActiveMQ远程代码执行漏洞，CVSS 10.0",
            exploit_references=[
                "https://github.com/vulhub/vulhub/tree/master/activemq"
            ],
            writeups=["通过反序列化执行任意代码"],
            docker_image="vulhub/activemq:5.11.1",
            ports=[8161, 61616],
            target_ip="172.18.0.2",
            environment_info={}
        )

    @pytest.fixture
    def sqli_context(self):
        """SQL注入CVE上下文"""
        return CVEContext(
            cve_id="CVE-2021-44228",
            description="Log4j远程代码执行漏洞",
            exploit_references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            writeups=["通过JNDI注入执行代码"],
            docker_image="vulhub/log4j:latest",
            ports=[8080],
            target_ip="172.18.0.3",
            environment_info={}
        )

    def test_activemq_analysis(self, agent, activemq_context):
        """测试ActiveMQ CVE分析"""
        print(f"\n🧪 测试ActiveMQ CVE分析")

        result = agent.analyze_and_exploit_cve(activemq_context)

        # 验证结果结构
        assert isinstance(result, AgentResult)
        assert hasattr(result, 'success')
        assert hasattr(result, 'attack_path')
        assert hasattr(result, 'mitre_mapping')
        assert hasattr(result, 'claude_response')

        # 验证Claude真实响应
        assert result.claude_response, "应该有Claude响应"
        assert len(result.claude_response) > 100, "Claude响应太短"

        # 验证分析结果
        assert isinstance(result.attack_path, dict)
        assert isinstance(result.mitre_mapping, dict)

        print(f"✅ ActiveMQ分析测试通过")
        print(f"   Claude响应长度: {len(result.claude_response)}")
        print(f"   攻击路径: {len(result.attack_path)} 阶段")
        print(f"   MITRE映射: {len(result.mitre_mapping)} 阶段")

    def test_sqli_analysis(self, agent, sqli_context):
        """测试SQL注入CVE分析"""
        print(f"\n🧪 测试SQL注入CVE分析")

        result = agent.analyze_and_exploit_cve(sqli_context)

        # 验证结果
        assert isinstance(result, AgentResult)
        assert result.claude_response

        # 验证不同CVE得到不同的分析
        assert "CVE-2021-44228" in result.claude_response or "log4j" in result.claude_response.lower()

        print(f"✅ SQL注入分析测试通过")
        print(f"   Claude响应: {len(result.claude_response)} 字符")

    def test_different_cve_different_analysis(self, agent):
        """测试不同CVE产生不同的分析结果"""
        print(f"\n🧪 测试不同CVE产生不同分析")

        context1 = CVEContext(
            cve_id="CVE-2023-46604",
            description="ActiveMQ RCE",
            exploit_references=["ref1"],
            writeups=["writeup1"],
            docker_image="image1",
            ports=[8161],
            target_ip="172.18.0.2",
            environment_info={}
        )

        context2 = CVEContext(
            cve_id="CVE-2021-44228",
            description="Log4j RCE",
            exploit_references=["ref2"],
            writeups=["writeup2"],
            docker_image="image2",
            ports=[8080],
            target_ip="172.18.0.3",
            environment_info={}
        )

        result1 = agent.analyze_and_exploit_cve(context1)
        result2 = agent.analyze_and_exploit_cve(context2)

        # 验证两个响应不同
        assert result1.claude_response != result2.claude_response, \
            "不同CVE应该产生不同的Claude响应"

        # 验证响应包含对应的CVE信息
        assert "CVE-2023-46604" in result1.claude_response or "activemq" in result1.claude_response.lower()
        assert "CVE-2021-44228" in result2.claude_response or "log4j" in result2.claude_response.lower()

        print(f"✅ 不同CVE分析测试通过")
        print(f"   响应1长度: {len(result1.claude_response)}")
        print(f"   响应2长度: {len(result2.claude_response)}")
        print(f"   响应不同: {'是' if result1.claude_response != result2.claude_response else '否'}")

    def test_attack_path_structure(self, agent, activemq_context):
        """测试攻击路径结构完整性"""
        print(f"\n🧪 测试攻击路径结构")

        result = agent.analyze_and_exploit_cve(activemq_context)

        # 验证攻击路径包含必要的阶段
        attack_path = result.attack_path

        # 应该至少有初始访问和执行阶段
        assert len(attack_path) >= 2, "攻击路径应该至少有2个阶段"

        # 验证每个阶段的结构
        for stage_name, stage_info in attack_path.items():
            assert "technique_id" in stage_info or "technique_name" in stage_info
            assert isinstance(stage_info, dict)

        print(f"✅ 攻击路径结构测试通过")
        print(f"   攻击阶段数: {len(attack_path)}")

    def test_mitre_mapping_completeness(self, agent, activemq_context):
        """测试MITRE映射完整性"""
        print(f"\n🧪 测试MITRE映射完整性")

        result = agent.analyze_and_exploit_cve(activemq_context)

        mitre_mapping = result.mitre_mapping

        # 验证MITRE映射结构
        assert isinstance(mitre_mapping, dict)
        assert len(mitre_mapping) >= 2, "应该至少有2个MITRE阶段"

        # 验证技术ID格式
        for stage, techniques in mitre_mapping.items():
            assert isinstance(techniques, list)
            for tech in techniques:
                assert tech.startswith("T"), f"技术ID应该以T开头: {tech}"

        print(f"✅ MITRE映射测试通过")
        print(f"   映射阶段数: {len(mitre_mapping)}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "-m", "llm"])
