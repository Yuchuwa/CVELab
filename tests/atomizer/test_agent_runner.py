"""Agent Runner 单元测试

测试 agent_runner.py 中的 JSON 提取和 prompt 构建。
"""

import pytest
import json

from clab_builder.atomizer.agent.agent_runner import extract_json, build_prompt


@pytest.mark.unit
class TestExtractJson:
    """JSON 结果提取测试"""

    def test_code_block_json(self):
        """从 ```json ... ``` 提取"""
        text = 'Here is the result:\n```json\n{"success": true, "evidence": ["ok"]}\n```'
        result = extract_json(text)
        assert result is not None
        assert result["success"] is True
        assert result["evidence"] == ["ok"]

    def test_bare_json(self):
        """裸 JSON 提取"""
        text = 'The result is {"success": false, "evidence": ["a"], "exploit_steps": ["b"], "mitre_mapping": {"x": ["y"]}}'
        result = extract_json(text)
        assert result is not None
        assert result["success"] is False

    def test_trailing_comma_fix(self):
        """修复尾随逗号"""
        text = '```json\n{"success": true, "evidence": ["a"], "exploit_steps": [], "mitre_mapping": {}}\n```'
        result = extract_json(text)
        assert result is not None
        assert result["success"] is True

    def test_no_json(self):
        """无 JSON 返回 None"""
        text = "I couldn't exploit this target."
        result = extract_json(text)
        assert result is None


@pytest.mark.unit
class TestBuildPrompt:
    """Prompt 构建测试"""

    def test_basic_prompt(self):
        """基本 prompt 包含目标信息"""
        prompt = build_prompt({
            "cve_id": "CVE-2021-44228",
            "target_ip": "172.18.0.2",
            "target_ports": [8983],
            "description": "Log4j RCE",
        })
        assert "CVE-2021-44228" in prompt
        assert "172.18.0.2" in prompt
        assert "8983" in prompt

    def test_prompt_with_writeup(self):
        """包含 writeup"""
        prompt = build_prompt({
            "cve_id": "CVE-2021-44228",
            "target_ip": "172.18.0.2",
            "target_ports": [8983],
            "writeup": "## Vulnerability Details\nJNDI injection...",
        })
        assert "Bug Report" in prompt
        assert "JNDI" in prompt

    def test_prompt_with_exploit_files(self):
        """包含 exploit 文件"""
        prompt = build_prompt({
            "cve_id": "CVE-2021-44228",
            "target_ip": "172.18.0.2",
            "target_ports": [8983],
            "exploit_files": {"poc.py": "print('pwned')"},
        })
        assert "poc.py" in prompt
        assert "print('pwned')" in prompt
