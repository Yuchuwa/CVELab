#!/usr/bin/env python3
"""
Agent驱动的CVE复现Pipeline集成测试

测试完整的Agent驱动流程：从真实CVE到验证后的Ansible配置和playbook
"""

import pytest
import subprocess
from pathlib import Path
import sys
import time

# 添加项目路径
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root / "src"))

from clab_builder.integration import AgentDrivenCVEPipeline, PipelineConfig


@pytest.mark.integration
@pytest.mark.docker
class TestAgentDrivenPipeline:
    """Agent驱动Pipeline集成测试"""

    @pytest.fixture(autouse=True)
    def setup_containers(self):
        """设置测试容器"""
        # 确保Docker可用
        try:
            subprocess.run(["docker", "--version"], capture_output=True, check=True)
        except:
            pytest.skip("Docker不可用")

    @pytest.fixture
    def cve_config(self):
        """CVE测试配置"""
        return PipelineConfig(
            cve_id="CVE-2023-46604",
            docker_image="vulhub/activemq:5.11.1",
            ports=[8161, 61616],
            cve_description="""
CVE-2023-46604 - Apache ActiveMQ远程代码执行漏洞

CVSS评分: 10.0 (CRITICAL)
攻击向量: 网络访问
复杂度: 低
影响: 完全系统控制
            """,
            exploit_references=[
                "https://github.com/vulhub/vulhub/tree/master/activemq"
            ],
            writeups=["ActiveMQ反序列化RCE漏洞"],
            output_dir="/tmp/test_cve_output",
            network_name="cve-test-network",
            agent_container_image="security-researcher-agent:latest"
        )

    @pytest.fixture
    def agent_container(self):
        """启动Agent容器"""
        container_name = "test-security-researcher-agent"

        # 清理旧容器
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            capture_output=True
        )

        # 启动新容器
        result = subprocess.run([
            "docker", "run", "-d",
            f"--name={container_name}",
            "--network=cve-test-network",
            "-v", "/tmp/test_workspace:/workspace",
            "security-researcher-agent:latest",
            "tail", "-f", "/dev/null"
        ], capture_output=True, text=True)

        if result.returncode != 0:
            pytest.skip(f"Agent容器启动失败: {result.stderr}")

        container_id = result.stdout.strip()
        time.sleep(2)  # 等待容器完全启动

        yield container_id

        # 清理
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)

    def test_agent_container_tools(self, agent_container):
        """测试Agent容器中的工具"""
        required_tools = {
            "curl": "curl --version",
            "nc": "which nc",
            "python3": "python3 --version"
        }

        for tool, test_cmd in required_tools.items():
            result = subprocess.run(
                ["docker", "exec", "test-security-researcher-agent"] + test_cmd.split(),
                capture_output=True, timeout=10
            )
            assert result.returncode == 0, f"工具 {tool} 不可用"

    def test_agent_cve_reproduction(self, cve_config, agent_container):
        """测试完整的CVE复现流程"""
        # 创建pipeline
        pipeline = AgentDrivenCVEPipeline(cve_config)

        # 执行pipeline
        result = pipeline.run()

        # 验证结果
        assert result['success'], "Pipeline执行失败"
        assert 'cve_id' in result
        assert 'containers' in result
        assert 'agent_output' in result
        assert 'output_files' in result

        # 验证生成的文件
        for name, path in result['output_files'].items():
            file_path = Path(path)
            assert file_path.exists(), f"文件不存在: {name}"

            # 验证文件内容
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                assert len(content) > 0, f"文件为空: {name}"
                assert cve_config.cve_id in content, f"文件缺少CVE ID: {name}"

    def test_generated_ansible_config(self, cve_config):
        """测试生成的Ansible配置"""
        pipeline = AgentDrivenCVEPipeline(cve_config)
        result = pipeline.run()

        config_file = Path(result['output_files']['ansible_config'])
        with open(config_file, 'r') as f:
            config_content = f.read()

        # 验证配置结构
        assert "cve_environment:" in config_content
        assert "deployment:" in config_content
        assert cve_config.cve_id in config_content
        assert cve_config.docker_image in config_content

        for port in cve_config.ports:
            assert str(port) in config_content

    def test_generated_exploit_playbook(self, cve_config):
        """测试生成的Exploit Playbook"""
        pipeline = AgentDrivenCVEPipeline(cve_config)
        result = pipeline.run()

        playbook_file = Path(result['output_files']['exploit_playbook'])
        with open(playbook_file, 'r') as f:
            playbook_content = f.read()

        # 验证playbook结构
        assert "hosts:" in playbook_content
        assert "vars:" in playbook_content
        assert "tasks:" in playbook_content
        assert "mitre_technique_id" in playbook_content
        assert cve_config.cve_id in playbook_content


if __name__ == "__main__":
    # 可以直接运行此测试
    pytest.main([__file__, "-v", "-s", "-m", "integration"])
