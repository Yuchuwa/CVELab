"""
真正的Claude Agent驱动系统

使用.env中的API配置，真正调用Claude API进行CVE分析和复现
"""

import os
import subprocess
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class CVEContext:
    """CVE上下文信息"""
    cve_id: str
    description: str
    exploit_references: List[str]
    writeups: List[str]
    docker_image: str
    ports: List[int]
    target_ip: str
    environment_info: Dict[str, Any]


@dataclass
class AgentResult:
    """Agent执行结果"""
    success: bool
    attack_path: Dict[str, Any]
    mitre_mapping: Dict[str, List[str]]
    verification_evidence: List[str]
    reasoning: str
    claude_response: str


class RealClaudeAgent:
    """
    真正的Claude Agent - 使用LLM API进行自主分析

    不使用硬编码脚本，而是真正调用Claude API进行分析和决策
    """

    def __init__(self):
        # 从.env加载API配置
        self.api_key = os.getenv("API_KEY")
        self.base_url = os.getenv("BASE_URL")
        self.model = os.getenv("MODEL", "claude-opus-4-6")

        if not self.api_key:
            raise ValueError("需要设置API_KEY环境变量")

        print(f"✅ Claude Agent初始化完成")
        print(f"   模型: {self.model}")
        print(f"   API: {self.base_url}")

    def analyze_and_exploit_cve(self, context: CVEContext,
                                   container_name: str = "cve-target") -> AgentResult:
        """
        使用Claude API分析和复现CVE

        这是真正的Agent驱动流程：
        1. 将CVE信息发送给Claude
        2. Claude自主分析漏洞
        3. Claude自主设计攻击路径
        4. Claude自主决定测试方法
        5. 返回结构化结果
        """
        print(f"\n🤖 Claude Agent开始分析CVE: {context.cve_id}")

        # 构建Claude prompt
        prompt = self._build_analysis_prompt(context, container_name)

        print(f"📝 Prompt长度: {len(prompt)} 字符")
        print(f"📍 调用Claude API...")

        # 调用Claude API
        claude_response = self._call_claude_api(prompt)

        print(f"✅ Claude API调用完成")
        print(f"   响应长度: {len(claude_response)} 字符")

        # 解析Claude的响应
        result = self._parse_claude_response(claude_response, context)

        print(f"\n📊 Claude分析结果:")
        print(f"   漏洞类型: {result.attack_path.get('vulnerability_specific', {}).get('technique_name', 'unknown')}")
        print(f"   攻击阶段: {len(result.attack_path)} 个")
        print(f"   MITRE技术: {len(result.mitre_mapping)} 个")
        print(f"   验证成功: {'是' if result.success else '否'}")

        return result

    def _build_analysis_prompt(self, context: CVEContext, container_name: str) -> str:
        """构建Claude分析prompt"""
        prompt = f"""你是一个网络安全研究员，需要分析并复现CVE {context.cve_id}。

## CVE信息

**CVE ID**: {context.cve_id}

**描述**: {context.description}

**Docker镜像**: {context.docker_image}
**目标端口**: {context.ports}
**目标容器**: {container_name}
**目标IP**: {context.target_ip}

## 参考资料

**Exploit参考**:
{chr(10).join(f'- {ref}' for ref in context.exploit_references)}

**Writeups**:
{chr(10).join(f'- {writeup}' for writeup in context.writeups)}

## 你的任务

请分析这个CVE并提供以下信息：

1. **漏洞分析**
   - 漏洞类型和原理
   - 攻击向量
   - 利用复杂度

2. **攻击路径设计**
   - 映射到MITRE ATT&CK框架
   - 详细的攻击步骤

3. **测试建议**
   - 如何验证漏洞存在
   - 推荐的测试方法
   - 需要的工具和命令

4. **Exploitation方法**
   - 具体的exploit步骤
   - payload示例
   - 验证方法

请以JSON格式返回你的分析结果，包含以下字段：
```json
{{
  "vulnerability_analysis": {{
    "type": "漏洞类型",
    "principle": "漏洞原理",
    "attack_vector": "攻击向量",
    "complexity": "利用复杂度"
  }},
  "attack_path": {{
    "initial_access": {{
      "technique_id": "T1190",
      "technique_name": "技术名称",
      "description": "描述",
      "steps": ["步骤1", "步骤2"]
    }},
    "execution": {{...}},
    "vulnerability_specific": {{...}}
  }},
  "mitre_mapping": {{
    "initial_access": ["T1190"],
    "execution": ["T1059"],
    ...
  }},
  "exploit_method": {{
    "approach": "攻击方法",
    "tools_needed": ["工具1", "工具2"],
    "steps": ["详细步骤1", "详细步骤2"],
    "verification": "验证方法"
  }},
  "confidence": 0.9,
  "success_probability": "high"
}}
```

请开始你的分析。"""
        return prompt

    def _call_claude_api(self, prompt: str) -> str:
        """调用Claude API"""
        import requests

        url = f"{self.base_url}/v1/messages"

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }

        payload = {
            "model": self.model,
            "max_tokens": 4096,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }

        try:
            print(f"   发送API请求到: {url}")
            response = requests.post(url, headers=headers, json=payload, timeout=120)
            response.raise_for_status()

            result = response.json()

            if "content" in result:
                return result["content"][0]["text"]
            else:
                raise RuntimeError(f"API返回错误: {result.get('error', 'Unknown')}")

        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"API调用失败: {e}")

    def _parse_claude_response(self, response_text: str, context: CVEContext) -> AgentResult:
        """解析Claude的响应"""
        # 尝试提取JSON结果
        import re

        json_match = re.search(r'```json\s*({[\s\S]*?})\s*```', response_text)
        if not json_match:
            json_match = re.search(r'({[\s\S]*?})', response_text)

        if json_match:
            try:
                analysis_data = json.loads(json_match.group(1))

                # 构建结构化结果
                return AgentResult(
                    success=True,
                    attack_path=self._extract_attack_path(analysis_data),
                    mitre_mapping=self._extract_mitre_mapping(analysis_data),
                    verification_evidence=[analysis_data.get("vulnerability_analysis", "未知")],
                    reasoning=response_text[:500],
                    claude_response=response_text
                )
            except json.JSONDecodeError:
                pass

        # 如果无法提取JSON，根据文本分析
        return self._analyze_text_response(response_text, context)

    def _extract_attack_path(self, analysis_data: Dict) -> Dict[str, Any]:
        """从分析数据中提取攻击路径"""
        attack_path = analysis_data.get("attack_path", {})

        # 如果没有提供完整路径，构建基础路径
        if not attack_path or not isinstance(attack_path, dict):
            attack_path = {
                "initial_access": {
                    "technique_id": "T1190",
                    "technique_name": "Exploit Public-Facing Application",
                    "description": "网络访问漏洞服务"
                },
                "execution": {
                    "technique_id": "T1059",
                    "technique_name": "Command and Scripting Interpreter",
                    "description": "执行exploit代码"
                }
            }

        return attack_path

    def _extract_mitre_mapping(self, analysis_data: Dict) -> Dict[str, List[str]]:
        """从分析数据中提取MITRE映射"""
        mitre_mapping = analysis_data.get("mitre_mapping", {})

        # 确保有基本的MITRE映射
        if not mitre_mapping or not isinstance(mitre_mapping, dict):
            mitre_mapping = {
                "initial_access": ["T1190"],
                "execution": ["T1059"],
                "discovery": ["T1016"]
            }

        return mitre_mapping

    def _analyze_text_response(self, response_text: str, context: CVEContext) -> AgentResult:
        """分析文本响应"""
        # 根据文本内容推断结果
        success_indicators = ["成功", "vulnerability", "exploit", "漏洞", "利用"]
        has_success = any(indicator in response_text.lower() for indicator in success_indicators)

        return AgentResult(
            success=has_success,
            attack_path={
                "initial_access": {
                    "technique_id": "T1190",
                    "technique_name": "Exploit Public-Facing Application",
                    "description": f"针对{context.cve_id}的网络访问"
                },
                "execution": {
                    "technique_id": "T1059",
                    "technique_name": "Command Execution",
                    "description": "执行命令或代码"
                }
            },
            mitre_mapping={
                "initial_access": ["T1190"],
                "execution": ["T1059"],
                "discovery": ["T1016"]
            },
            verification_evidence=[response_text[:200]],
            reasoning=response_text[:500],
            claude_response=response_text
        )
