"""Agent Runner 单元测试

测试 agent_runner.py 中的 JSON 提取和 prompt 构建。
"""

import json

import pytest

from clab_builder.atomizer.agent.agent_runner import (
    SYSTEM_PROMPT,
    extract_json,
    build_prompt,
    extract_flag,
    redact_secrets,
    _extract_json_from_native_session,
)


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

    def test_over_escaped_quotes_in_command_repaired(self):
        """LLM 把多层转义的 Python payload 塞进 command 字段导致 json.loads 失败时，
        _repair_json_strings 应能把字符串内非法结束的引号转义回来。"""
        bad = (
            '```json\n'
            '{\n'
            '  "success": true,\n'
            '  "exploit_steps": [\n'
            '    {\n'
            '      "name": "upload",\n'
            '      "command": "python3 -c \\"name=\\\\\\\\\\"file_upload\\\\\\\\\\"; pass\\"",\n'
            '      "dynamic_values": {}\n'
            '    }\n'
            '  ],\n'
            '  "capability_grants": ["execute_command", "read_file"]\n'
            '}\n'
            '```'
        )
        result = extract_json(bad)
        assert result is not None
        assert result["success"] is True
        assert result["capability_grants"] == ["execute_command", "read_file"]
        assert "upload" in result["exploit_steps"][0]["name"]

    def test_repair_preserves_well_formed_json(self):
        """正常 JSON 不应被 _repair_json_strings 破坏。"""
        text = (
            '```json\n'
            '{"success": true, "exploit_principal": "root", '
            '"capability_grants": ["execute_command", "read_file", "write_file", "network_vantage"]}\n'
            '```'
        )
        result = extract_json(text)
        assert result is not None
        assert result["success"] is True
        assert result["exploit_principal"] == "root"
        assert result["capability_grants"] == [
            "execute_command", "read_file", "write_file", "network_vantage"
        ]

    def test_no_json(self):
        """无 JSON 返回 None"""
        text = "I couldn't exploit this target."
        result = extract_json(text)
        assert result is None

    def test_extract_flag_from_text(self):
        text = "The exploit printed flag{cve-2024-0001-deadbeef} in the response."
        assert extract_flag(text) == "flag{cve-2024-0001-deadbeef}"

    def test_native_session_extracts_final_assistant_json(self, tmp_path):
        """Recover final JSON from SDK session without taking earlier templates."""
        session = tmp_path / "session.json"
        events = [
            {
                "message": {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "text",
                            "text": 'Example only:\n```json\n{"success": false, "evidence": ["template"]}\n```',
                        }
                    ],
                }
            },
            {
                "message": {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "text",
                            "text": 'Final:\n```json\n{"success": true, "evidence": ["confirmed"]}\n```',
                        }
                    ],
                }
            },
        ]
        session.write_text("\n".join(json.dumps(event) for event in events))

        result = _extract_json_from_native_session(session)

        assert result is not None
        assert result["success"] is True
        assert result["evidence"] == ["confirmed"]

    def test_redact_secrets_before_persisting_session(self):
        text = (
            "ANTHROPIC_API_KEY=sk-real-secret-value-123456\n"
            'stdout={"llm_api_key": "sk-json-secret-value-123456"}\n'
            "Authorization: Bearer token-secret-value-1234567890\n"
            "raw sk-standalone-secret-value-123456"
        )

        redacted = redact_secrets(text)

        assert "sk-real-secret-value" not in redacted
        assert "sk-json-secret-value" not in redacted
        assert "token-secret-value" not in redacted
        assert "sk-standalone-secret" not in redacted
        assert "ANTHROPIC_API_KEY=<redacted>" in redacted


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

    def test_prompt_with_environment_context_and_guidance(self):
        """包含运行环境上下文和 exploit 指引"""
        prompt = build_prompt({
            "cve_id": "CVE-2019-7609",
            "target_ip": "172.18.0.2",
            "target_ports": [5601],
            "environment_context": {
                "docker_network": "cve-net",
                "services": [
                    {"service": "kibana", "running": True, "is_target": True},
                    {"service": "elasticsearch", "running": True, "is_target": False},
                ],
                "readiness_warnings": ["setup wizard pending"],
            },
            "exploit_guidance": "- Complete setup first.",
            "flag_hint": "flag lives in /flag",
        })
        assert "Running Environment Context" in prompt
        assert "elasticsearch" in prompt
        assert "Exploit Guidance" in prompt
        assert "Complete setup first" in prompt
        assert "Info_Leak" in prompt
        assert "do not waste turns trying unrelated flag paths" in prompt

    def test_prompt_without_flag_hint_uses_native_objective(self):
        """无 flag 任务应明确禁止偏到无关 RCE/flag hunting。"""
        prompt = build_prompt({
            "cve_id": "CVE-2017-12635",
            "target_ip": "172.24.0.2",
            "target_ports": [5984],
            "writeup": "Create a user with duplicate roles to gain admin privileges.",
        })
        assert "No flag has been planted" in prompt
        assert "do not pivot to unrelated" in prompt
        assert "Leave `captured_flag` empty" in prompt

    def test_system_prompt_forbids_external_research_with_shell_tools(self):
        """Bash is allowed for local target probing, not for Docker Hub/GitHub lookups."""
        assert "Do not use the Internet for research or source lookup" in SYSTEM_PROMPT
        assert "Do not fetch Docker Hub" in SYSTEM_PROMPT
        assert "Use curl/wget only against the" in SYSTEM_PROMPT
        assert "local target IP" in SYSTEM_PROMPT
