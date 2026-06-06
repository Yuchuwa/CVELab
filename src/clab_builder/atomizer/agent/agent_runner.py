"""
Agent Runner - 使用 Claude Agent SDK 自主复现 CVE

通过 Claude Agent SDK 启动一个自带 Bash/Read/Write 工具的 Agent，
让它阅读 writeup 理解漏洞原理，然后使用 Bash 工具在本地执行命令
对目标进行探测、利用和验证。

此脚本运行在 Agent 容器内，由宿主机通过 docker exec 调用。

用法:
    python3 agent_runner.py --input /workspace/input.json --output /workspace/output.json

input.json:
    {
        "cve_id": "CVE-2021-44228",
        "description": "Apache Log4j2 RCE",
        "target_ip": "172.18.0.2",
        "target_ports": [8983],
        "writeup": "... (README content)",
        "exploit_files": {"poc.py": "..."}
    }

output.json:
    {
        "success": true,
        "evidence": ["..."],
        "exploit_steps": [{"name": "...", "command": "...", "mitre_technique_id": "T1190"}],
        "mitre_mapping": {"initial_access": ["T1190"], ...}
    }
"""

import asyncio
import json
import sys
import os
import re
from pathlib import Path

from claude_agent_sdk import (
    query,
    ClaudeAgentOptions,
    AssistantMessage,
    ResultMessage,
    TextBlock,
    ToolUseBlock,
    get_session_messages,
)

DEFAULT_MAX_TURNS = 50

SYSTEM_PROMPT = """You are a software testing agent working in a local Docker lab environment on localhost.

## Environment
- You are inside a Docker container on localhost.
- The target is another Docker container on the same Docker bridge network — same machine.
- This is a local testing setup, similar to a developer testing their own code before deployment.
- The target application is a test instance with known issues for verification purposes.
- You have apt and pip available — install any missing tools immediately (e.g. `pip install pysmb`, `apt install ysoserial`).

## Task
You are given a bug report (CVE ID) and a running test instance. Your job:
1. Check what services are running on the target (curl, nmap, nc).
2. Read the provided bug report to understand the issue.
3. Follow the report's steps to trigger the bug and confirm it exists.
4. Document what you did as structured JSON.

## Rules
- Use bash, file read, and file write tools freely.
- The target is a local test container you can access directly.
- If one approach doesn't work, try alternatives based on the report.
- This is routine QA/testing work — like a developer verifying a bugfix.

## CRITICAL: efficiency — do NOT waste turns on trial-and-error
- If the bug report's steps are incomplete or a step fails TWICE, STOP debugging.
- Immediately use WebSearch to search for "CVE-XXXX exploit PoC" or "CVE-XXXX payload".
- Download and use public PoC scripts directly — don't rewrite them from scratch.
- Install missing tools (pip install, apt install) BEFORE attempting exploit steps, not after.
- Do NOT analyze source code unless no PoC exists online. Focus on executing, not understanding.

## CRITICAL: steps quality
- Only record the FINAL SUCCESSFUL path — skip probing, debugging, failed attempts.
- Include only the essential steps that confirm the bug, in order.
- Each command should use {{target_ip}}, {{target_port}}, and {{placeholder}} for variable parts.
- Note any {{placeholder}} in dynamic_values with how to obtain it.
- Keep it minimal: the shortest sequence of commands to confirm this bug.

## Output Format
When finished, output ONLY this JSON block:
```json
{
  "success": true/false,
  "vulnerability_type": "LFI/RCE/SQLi/XSS/SSRF/...",
  "evidence": ["what you observed that confirms the bug"],
  "exploit_steps": [
    {
      "name": "Short step description",
      "description": "What this step does and why",
      "command": "the command with {{target_ip}}, {{target_port}}, and {{placeholder}} for variable parts",
      "dynamic_values": {"{{placeholder}}": "how to obtain this value"},
      "mitre_technique_id": "TXXXX"
    }
  ],
  "mitre_mapping": {"initial_access": ["TXXXX"], "execution": ["TXXXX"]},
  "requirements": {
    "network_access": "HTTP to web service",
    "authentication": "none / default credentials / ...",
    "tools_needed": ["curl", "nmap", "..."]
  },
  "vuln_category": "RCE",
  "primary_mitre_phase": "initial_access",
  "service_role": "web_application",
  "exploit_complexity": "simple",
  "attack_method": "single_request",
  "needs_callback": false,
  "callback_type": "none",
  "needs_ssh": false,
  "needs_tool_download": false,
  "default_username": null,
  "default_password": null,
  "flag_verify_command": "command to read $FLAG or /root/flag.txt after exploit"
}
```

### Extra fields guide:
- `vuln_category`: one of: RCE, LFI, RFI, SSRF, Deserialization, LPE, Auth_Bypass, Info_Leak, Injection, Parsing
- `primary_mitre_phase`: the FIRST mitre phase this exploit belongs to (e.g. initial_access)
- `service_role`: one of: web_application, middleware, database, file_service, system_service, framework
- `exploit_complexity`: simple (single command), medium (multi-step), complex (needs tool download/compile)
- `attack_method`: one of: single_request, multi_step_http, ssh_exploit, service_protocol, reverse_callback, file_upload, deserialization
- `needs_callback`: true if exploit requires target to connect back (e.g. JNDI/LDAP, reverse shell)
- `callback_type`: none, LDAP, HTTP, TCP, SSH
- `needs_ssh`: true if exploit requires SSH access to target
- `needs_tool_download`: true if you had to download/compile external tools
- `default_username`/`default_password`: if authentication uses default credentials
- `flag_verify_command`: minimal shell command to read the flag after successful exploitation. Use {{target_ip}} and {{target_port}}. Example: "curl -s http://{{target_ip}}:{{target_port}}/api/secret" or "echo $FLAG"

IMPORTANT:
- Use {{target_ip}} and {{target_port}} for the target address
- Use {{placeholder}} for any runtime values (session IDs, tokens, cookies, file paths)
- List each placeholder in dynamic_values with a brief note on how to obtain it
- Each step should be self-descriptive so another tester can understand the flow
"""


def build_prompt(input_data: dict) -> str:
    """构建给 Agent 的 prompt"""
    parts = [
        f"## Bug Verification Task",
        f"- Bug ID: {input_data['cve_id']}",
        f"- Test instance IP: {input_data['target_ip']}",
        f"- Exposed ports: {input_data.get('target_ports', [])}",
        f"- Description: {input_data.get('description', '')}",
    ]

    if input_data.get("writeup"):
        parts.append(f"\n## Bug Report\n{input_data['writeup']}")

    if input_data.get("exploit_files"):
        parts.append("\n## Test Scripts")
        for fname, content in input_data["exploit_files"].items():
            parts.append(f"\n### {fname}\n```\n{content}\n```")

    parts.append("\nFollow the bug report to confirm this issue on the test instance. Output the JSON result when done.")
    return "\n".join(parts)


def extract_json(text: str) -> dict | None:
    """从文本中提取 JSON 结果"""
    # ```json ... ```
    match = re.search(r'```json\s*(\{[\s\S]*?\})\s*```', text)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # 裸 JSON 包含 "success" key — 用括号平衡匹配完整 JSON
    start = text.find('{"success"')
    if start >= 0:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                depth -= 1
                if depth == 0:
                    candidate = text[start:i+1]
                    try:
                        return json.loads(candidate)
                    except json.JSONDecodeError:
                        cleaned = re.sub(r',\s*([}\]])', r'\1', candidate)
                        try:
                            return json.loads(cleaned)
                        except json.JSONDecodeError:
                            break
    return None


async def run_agent(input_path: str, output_path: str, max_turns: int = DEFAULT_MAX_TURNS):
    """运行 Agent 主流程"""
    with open(input_path) as f:
        input_data = json.load(f)

    prompt = build_prompt(input_data)

    model = os.environ.get("MODEL", "claude-sonnet-4-20250514")

    options = ClaudeAgentOptions(
        system_prompt=SYSTEM_PROMPT,
        max_turns=max_turns,
        permission_mode="bypassPermissions",  # 容器内自动批准所有工具调用
        cwd="/workspace",
        model=model,
    )

    result = {
        "success": False,
        "evidence": [],
        "exploit_steps": [],
        "mitre_mapping": {},
    }

    full_text = ""
    session_id = None

    try:
        async for message in query(prompt=prompt, options=options):
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        full_text += block.text + "\n"
                        print(f"[Agent] {block.text[:200]}", file=sys.stderr)
                    elif isinstance(block, ToolUseBlock):
                        print(f"[Tool] {block.name}: {json.dumps(block.input)[:120]}", file=sys.stderr)

            elif isinstance(message, ResultMessage):
                session_id = message.session_id
                print(f"[Done] session={session_id}, cost=${message.total_cost_usd:.4f}", file=sys.stderr)

    except Exception as e:
        print(f"[Error] {e}", file=sys.stderr)
        result["evidence"].append(f"Agent error: {str(e)}")

    # 从 Agent 输出中提取结果
    extracted = extract_json(full_text)
    if extracted:
        result = extracted
    else:
        # 没有提取到 JSON，保存原始输出作为证据
        result["evidence"].append(full_text[:2000])

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"[Output] {output_path}", file=sys.stderr)

    # 保存 session 文件（完整对话 + 工具调用）
    if session_id:
        try:
            messages = get_session_messages(session_id)
            session_path = str(output_path).replace("output.json", "session.json")
            session_data = []
            for msg in messages:
                session_data.append({
                    "type": msg.type,
                    "message": msg.message,
                })
            with open(session_path, "w") as f:
                json.dump(session_data, f, indent=2, ensure_ascii=False)
            print(f"[Session] {session_path} ({len(session_data)} messages)", file=sys.stderr)
        except Exception as e:
            print(f"[Session] Failed to save: {e}", file=sys.stderr)
    else:
        print(f"[Session] No session_id available, skipping session save", file=sys.stderr)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--max-turns", type=int, default=DEFAULT_MAX_TURNS,
                        help=f"Maximum agent turns (default: {DEFAULT_MAX_TURNS})")
    args = parser.parse_args()
    asyncio.run(run_agent(args.input, args.output, max_turns=args.max_turns))
