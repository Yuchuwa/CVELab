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
from typing import Any

from claude_agent_sdk import (
    query,
    ClaudeAgentOptions,
    AssistantMessage,
    ResultMessage,
    TextBlock,
    ToolUseBlock,
    UserMessage,
)

DEFAULT_MAX_TURNS = 80
DISALLOWED_TOOLS = [
    "WebSearch",
    "WebFetch",
    "Task",
    "TaskCreate",
    "TaskUpdate",
    "TaskOutput",
]

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
- Do not use the Internet for research or source lookup. Do not fetch Docker Hub,
  GitHub, search engines, CVE databases, package registries, blogs, or exploit
  sites with curl/wget/python/browser tools. Use curl/wget only against the
  local target IP, local service/container names from Running Environment
  Context, or loopback addresses needed for the lab.

## CRITICAL: local lab strategy
- You are running on Kali Linux with common tools available
  (curl, wget, nmap, nc, python3, openssl, sqlmap, gobuster, etc.).
- Treat the bug report (README), provided test scripts, and Running Environment
  Context as the authoritative source for this lab. They usually contain the
  intended PoC: HTTP requests, payloads, curl commands, parameters, and setup
  steps. Implement those steps directly with curl/python3 or local lab tools.
- If the report shows a raw HTTP request, reproduce it with `curl` using the exact
  same headers, URL path, query string, and POST body.
- Install missing system tools if a specific tool is genuinely needed and not
  already present on Kali.

## CRITICAL: efficiency — verify before assuming success
- If a step fails TWICE with the same approach, STOP and re-read the bug report
  carefully for a different angle (encoding, field names, element_parents, etc.).
- Verify command execution with OBJECTIVE tests before reporting success:
  - Timing attack: inject `sleep 5` as the command; if the request takes ~5s longer,
    code execution IS working (output may just be suppressed by error handling).
  - File write: inject `echo MARKER > /tmp/test.txt`, then read it back via a
    second exploit request or an accessible web path.
- If the exploit returns an error page but no command output, the command may NOT
  be executing — verify with a timing test BEFORE reporting success.
- If the environment requires setup (e.g., app installation wizard, database init),
  complete that setup FIRST using the bug report's instructions and the environment
  context before exploitation.
- For multi-container labs, check the environment context first. Use the listed
  service names, container IPs, and dependency services when the report requires
  database/search/backend connectivity.

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
  "flag_verify_command": "command to read $FLAG or /root/flag.txt after exploit",
  "captured_flag": "the exact flag value you retrieved from the target (empty string if not retrieved)"
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
- `captured_flag`: the EXACT flag value you read from the target via your exploit.
  For RCE/LFI/file-read/deserialization/etc. this is required for success. For
  Auth_Bypass/Info_Leak/SSRF/role-change bugs that do not provide file read or
  command execution, leave this empty and explain the objective evidence.

IMPORTANT:
- Use {{target_ip}} and {{target_port}} for the target address
- Use {{placeholder}} for any runtime values (session IDs, tokens, cookies, file paths)
- List each placeholder in dynamic_values with a brief note on how to obtain it
- Each step should be self-descriptive so another tester can understand the flow
"""


def _format_json_block(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)


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

    if input_data.get("environment_context"):
        parts.append(
            "\n## Running Environment Context\n"
            "The target lab has already been started. Use this context before probing:\n"
            f"```json\n{_format_json_block(input_data['environment_context'])}\n```"
        )

    if input_data.get("exploit_guidance"):
        parts.append(f"\n## Exploit Guidance\n{input_data['exploit_guidance']}")

    if input_data.get("exploit_files"):
        parts.append("\n## Test Scripts")
        for fname, content in input_data["exploit_files"].items():
            parts.append(f"\n### {fname}\n```\n{content}\n```")

    flag_hint = input_data.get("flag_hint", "")
    if flag_hint:
        parts.append(
            "\n## Flag Capture and Success Criteria\n"
            "A unique flag has been planted on the target. After confirming the exploit works, "
            f"retrieve it when the vulnerability gives command execution, arbitrary file read, "
            f"template evaluation, deserialization, upload-to-execution, or similar impact: {flag_hint}. "
            "Report the exact value in `captured_flag`.\n\n"
            "If the bug is strictly information disclosure (for example cache metadata/content leak, "
            "version disclosure, or header/body leak) and the bug does not provide a path to read "
            "arbitrary target files, do not waste turns trying unrelated flag paths. In that case, "
            "set `vuln_category` to `Info_Leak`, leave `captured_flag` empty, set `success` true only "
            "when the leak is objectively demonstrated, and put the concrete leaked bytes/headers and "
            "the reason the flag is unreachable in `evidence` and `flag_verify_command`."
        )
    else:
        parts.append(
            "\n## Success Criteria\n"
            "No flag has been planted for this task. Verify the exact vulnerability "
            "objective described in the bug report and do not pivot to unrelated "
            "RCE, file-read, os_daemon, query_server, shell, or flag-hunting chains. "
            "For Auth_Bypass or privilege/role escalation, success means proving the "
            "new privilege works with an authenticated request. Leave `captured_flag` "
            "empty and explain the objective evidence in `evidence`."
        )

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


def extract_flag(text: str) -> str:
    """Extract the first CTF-style flag value from text."""
    match = re.search(r"flag\{[^{}\s]{3,200}\}", text or "")
    return match.group(0) if match else ""


def _locate_native_session(session_id: str | None) -> Path | None:
    """Find the SDK's native session .jsonl (written by the claude CLI during query())."""
    if not session_id:
        return None
    config_dir = Path(os.environ.get("CLAUDE_CONFIG_DIR") or "~/.claude").expanduser()
    projects = config_dir / "projects"
    if not projects.is_dir():
        return None
    for found in projects.rglob(f"{session_id}.jsonl"):
        return found
    return None


def _content_block_text(block: Any) -> str:
    """Return text from SDK block objects or native session dict blocks."""
    if isinstance(block, TextBlock):
        return block.text
    if isinstance(block, dict) and block.get("type") == "text":
        return block.get("text") or ""
    text = getattr(block, "text", None)
    return text if isinstance(text, str) else ""


def _extract_json_from_native_session(session_path: Path | None) -> dict | None:
    """Recover the final JSON from the SDK native session if streaming missed it."""
    if not session_path or not session_path.exists():
        return None

    assistant_texts: list[str] = []
    for line in session_path.read_text(errors="replace").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        message = event.get("message")
        if not isinstance(message, dict) or message.get("role") != "assistant":
            continue
        content = message.get("content")
        if isinstance(content, str):
            assistant_texts.append(content)
        elif isinstance(content, list):
            text = "\n".join(
                _content_block_text(block)
                for block in content
                if _content_block_text(block)
            )
            if text.strip():
                assistant_texts.append(text)

    # Search from the end so the prompt's example schema or earlier drafts do
    # not beat the final report.
    for text in reversed(assistant_texts):
        extracted = extract_json(text)
        if extracted is not None:
            return extracted
    return None


SECRET_PATTERNS = [
    re.compile(r"(?i)\b((?:ANTHROPIC|OPENAI|LLM)_API_KEY=)([^\s\"'\\]+)"),
    re.compile(r'(?i)("(?:anthropic_|openai_|llm_)?api_key"\s*:\s*")([^"]+)(")'),
    re.compile(r"(?i)('(?:anthropic_|openai_|llm_)?api_key'\s*:\s*')([^']+)(')"),
    re.compile(r"(?i)\b(Bearer\s+)([A-Za-z0-9._\-]{16,})"),
]


def redact_secrets(text: str) -> str:
    """Remove API credentials before persisting agent sessions."""
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(
            lambda match: (
                f"{match.group(1)}<redacted>{match.group(3)}"
                if match.lastindex and match.lastindex >= 3
                else f"{match.group(1)}<redacted>"
            ),
            redacted,
        )
    redacted = re.sub(r"\bsk-[A-Za-z0-9_\-]{16,}\b", "sk-<redacted>", redacted)
    return redacted


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
        disallowed_tools=DISALLOWED_TOOLS,
    )

    result = {
        "success": False,
        "evidence": [],
        "exploit_steps": [],
        "mitre_mapping": {},
        "captured_flag": "",
    }

    full_text = ""
    session_id = None

    try:
        async for message in query(prompt=prompt, options=options):
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    block_text = _content_block_text(block)
                    if block_text:
                        full_text += block_text + "\n"
                        print(f"[Agent] {block_text[:200]}", file=sys.stderr)
                    elif isinstance(block, ToolUseBlock):
                        print(f"[Tool] {block.name}: {json.dumps(block.input)[:120]}", file=sys.stderr)

            elif isinstance(message, UserMessage):
                # tool results flow back as user messages — log them for a complete session
                print(f"[ToolResult] {str(message)[:160]}", file=sys.stderr)

            elif isinstance(message, ResultMessage):
                session_id = message.session_id
                print(f"[Done] session={session_id}, cost=${message.total_cost_usd:.4f}", file=sys.stderr)

    except Exception as e:
        print(f"[Error] {e}", file=sys.stderr)
        result["evidence"].append(f"Agent error: {str(e)}")

    native_jsonl = _locate_native_session(session_id)

    # 从 Agent 输出中提取结果。If the SDK stream misses the final text but the
    # native session was written, recover from the final assistant messages.
    extracted = extract_json(full_text)
    if extracted is None:
        extracted = _extract_json_from_native_session(native_jsonl)
    if extracted:
        result = extracted
    else:
        # 没有提取到 JSON，保存原始输出作为证据
        result["evidence"].append(full_text[:2000])
    result.setdefault("captured_flag", "")
    if not result.get("captured_flag"):
        result["captured_flag"] = extract_flag(full_text)

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"[Output] {output_path}", file=sys.stderr)

    # session: SDK 原生 .jsonl（query() 期间 CLI 子进程已写到 ~/.claude/projects/，
    # 容器挂载到宿主后落盘）。保存前脱敏，避免工具输出 env 时泄露 API key。
    session_path = str(output_path).replace("output.json", "session.json")
    if native_jsonl:
        Path(session_path).write_text(
            redact_secrets(native_jsonl.read_text(encoding="utf-8", errors="replace")),
            encoding="utf-8",
        )
        events = sum(1 for _ in open(session_path))
        print(f"[Session] native SDK jsonl -> {session_path} ({events} events)", file=sys.stderr)
    elif session_id:
        print(f"[Session] WARN: native .jsonl for {session_id} not found", file=sys.stderr)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--max-turns", type=int, default=DEFAULT_MAX_TURNS,
                        help=f"Maximum agent turns (default: {DEFAULT_MAX_TURNS})")
    args = parser.parse_args()
    asyncio.run(run_agent(args.input, args.output, max_turns=args.max_turns))
