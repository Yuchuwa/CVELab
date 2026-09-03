#!/usr/bin/env python3
"""用 claude_agent_sdk 实测，验证 URL/模型/环境变量是否跑通。

默认测试「ANTHROPIC_MODEL 环境变量」方案（绕过 CLI 的模型名校验）。
用 --mode arg 可对比旧方案（ClaudeAgentOptions(model=...)）。

用法:
    python3 scripts/check_sdk.py                        # ANTHROPIC_MODEL 方案
    python3 scripts/check_sdk.py --mode arg             # 旧方案(model 参数)
    python3 scripts/check_sdk.py --url http://api.pkuoslab.com:3000 --model deepseek-v4-pro --api-key sk-xxx
"""

import argparse
import asyncio
import os
import sys

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


async def run_once(args):
    from claude_agent_sdk import (
        query, ClaudeAgentOptions,
        AssistantMessage, ResultMessage, TextBlock, ToolUseBlock,
    )

    os.environ["ANTHROPIC_API_KEY"] = args.api_key
    os.environ["ANTHROPIC_BASE_URL"] = args.url
    os.environ["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"

    if args.mode == "arg":
        # 旧方案：把模型名直接传给 ClaudeAgentOptions.model（会被 CLI 校验）
        options = ClaudeAgentOptions(
            system_prompt="You are a minimal test agent. Answer concisely.",
            max_turns=5,
            permission_mode="bypassPermissions",
            cwd="/tmp",
            model=args.model,
        )
    else:
        # 新方案：不传 model，改用 ANTHROPIC_MODEL 环境变量（CLI 不解析别名，直接采用）
        os.environ["ANTHROPIC_MODEL"] = args.model
        options = ClaudeAgentOptions(
            system_prompt="You are a minimal test agent. Answer concisely.",
            max_turns=5,
            permission_mode="bypassPermissions",
            cwd="/tmp",
        )

    full_text = ""
    tool_calls = 0
    exit_error = None

    try:
        async for message in query(
            prompt="Run this shell command and report its exact output: `echo SDK_OK_$(date +%s)`",
            options=options,
        ):
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        full_text += block.text + "\n"
                        print(f"[Agent] {block.text[:200]}")
                    elif isinstance(block, ToolUseBlock):
                        tool_calls += 1
                        print(f"[Tool] {block.name}: {str(block.input)[:150]}")
            elif isinstance(message, ResultMessage):
                print(f"[Done] session={message.session_id} cost=${message.total_cost_usd:.4f}")
                if getattr(message, "is_error", False):
                    exit_error = str(message)
    except Exception as e:
        exit_error = str(e)
        print(f"[Error] {e}")

    return tool_calls, full_text, exit_error


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=os.environ.get("LLM_BASE_URL", "http://api.pkuoslab.com:3000"))
    ap.add_argument("--model", default=os.environ.get("LLM_MODEL", "deepseek-v4-pro"))
    ap.add_argument("--api-key", default=os.environ.get("LLM_API_KEY", ""))
    ap.add_argument("--mode", choices=["env", "arg"], default="env",
                    help="env=用 ANTHROPIC_MODEL 环境变量(新方案,默认); arg=用 ClaudeAgentOptions.model(旧方案)")
    args = ap.parse_args()

    print(f"ANTHROPIC_BASE_URL = {args.url}")
    print(f"MODEL             = {args.model}")
    print(f"MODE              = {args.mode} ({'ANTHROPIC_MODEL 环境变量' if args.mode == 'env' else 'ClaudeAgentOptions.model 参数'})")
    print()


    import claude_agent_sdk  # noqa: F401


    tool_calls, full_text, exit_error = await run_once(args)

    print()
    print("=" * 60)
    if exit_error:
        print("RESULT: FAIL (agent 报错)")
        print(f"  错误: {exit_error[:400]}")
    elif tool_calls > 0 and "SDK_OK" in full_text:
        print("RESULT: PASS (SDK 成功执行 Bash 并返回了 SDK_OK 输出)")
    elif tool_calls > 0:
        print("RESULT: PARTIAL (SDK 能跑，但未看到 SDK_OK 输出)")
    else:
        print("RESULT: FAIL (没有触发任何工具调用)")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
