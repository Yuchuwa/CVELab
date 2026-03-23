"""Fixer 节点：错误诊断和修复

分析部署错误日志，智能修复网络拓扑设计问题。
"""
from typing import Literal

from langchain.chat_models import init_chat_model
from langchain.agents import create_agent
from pydantic import BaseModel, Field
from langgraph.types import Command

from clab_builder.state import GraphState
from .utils import regenerate_yaml_from_json
from clab_builder.config import config
from tools.file_tools import read_file_tool, modify_file_tool
from clab_builder.logger import get_logger, set_log_context, log_error, log_step


# ============================================
# 错误类型标识符
# ============================================
ERROR_TYPE_BUILD = "[ERROR_TYPE:BUILD]"
ERROR_TYPE_VALIDATE = "[ERROR_TYPE:VALIDATE]"
ERROR_TYPE_DEPLOY = "[ERROR_TYPE:DEPLOY]"
ERROR_TYPE_CONFIGURE = "[ERROR_TYPE:CONFIGURE]"
ERROR_TYPE_SYSTEM = "[ERROR_TYPE:SYSTEM]"


# ============================================
# Agent 返回结构
# ============================================
class SuggestionResult(BaseModel):
    """建议生成 Agent 的返回结构（用于 builder 错误）"""
    suggestion: str = Field(..., description="针对蓝图错误的改进建议")


class JsonFixResult(BaseModel):
    """JSON 修复 Agent 的返回结构（用于 validator/deployer/configurator 错误）"""
    changes_summary: str = Field(..., description="修改内容摘要")
    files_modified: list[str] = Field(..., description="修改的文件路径列表")


def fixer(state: GraphState) -> Command[Literal["generator", "validator", "deployer"]]:
    """
    Fixer Node: 智能分析错误日志并修复配置文件

    新架构：JSON是唯一真源，YAML从JSON派生

    工作流程:
    1. 检查重试次数（熔断机制）
    2. 静态分析错误类型（无需 LLM）
    3. 根据错误类型调用对应的修复 Agent
    4. Agent 只修改 JSON 文件（不修改YAML）
    5. Fixer 调用 regenerate_yaml_from_json() 重新生成YAML
    6. 返回 Command 对象，包含 state 更新和路由目标

    路由策略:
    - BUILD 错误     → 生成建议 → generator
    - VALIDATE 错误   → 修改 JSON → 重新生成YAML → validator
    - DEPLOY 错误     → 修改 JSON → 重新生成YAML → validator → deployer
    - CONFIGURE 错误  → 修改 JSON → 重新生成YAML → validator → deployer
    - SYSTEM 错误     → 无法修复 → raise RuntimeError

    Args:
        state: 当前工作流状态

    Returns:
        Command 对象，包含 state 更新和 goto 路由目标

    Raises:
        RuntimeError: 当达到最大重试次数或遇到系统错误时
    """
    logger = get_logger("node.fixer")
    set_log_context(stage="fixer")

    # 1. 熔断机制：检查重试次数
    current_retries = state.get("retry_count", 0)
    max_retries = config.max_retries

    log_step(
        logger,
        f"Fixer activated (Attempt {current_retries + 1}/{max_retries})",
        status="start",
        retry_count=current_retries + 1
    )

    if current_retries >= max_retries:
        error_msg = (
            f"Max retries ({max_retries}) reached. "
            f"Unable to fix the topology. Last error: {state.get('error_logs', 'Unknown')}"
        )
        logger.error(f"❌ {error_msg}")
        raise RuntimeError(error_msg)

    error_logs = state.get("error_logs", "")

    # ============================================
    # 2. 静态错误类型判断（无需 LLM）
    # ============================================

    # 场景 4: 系统错误（不可恢复）
    if ERROR_TYPE_SYSTEM in error_logs:
        logger.error(f"❌ System error detected: {error_logs}")
        raise RuntimeError(f"Unrecoverable system error: {error_logs}")

    # 场景 1: builder 错误（蓝图设计问题）
    elif ERROR_TYPE_BUILD in error_logs:
        logger.info("🔧 Build error detected → invoking suggestion agent")
        try:
            fixer_result = _call_suggestion_agent(state, error_logs)

            # 附加建议到 user_request
            original_request = state.get("user_request", "")
            enhanced_request = f"{original_request}\n\n[修复建议]\n{fixer_result.suggestion}"

            log_step(
                logger,
                "Suggestion generated",
                status="success",
                routing_to="generator"
            )

            return Command(
                update={
                    "user_request": enhanced_request,
                    "blueprint": None,
                    "error_logs": "",
                    "retry_count": current_retries + 1
                },
                goto="generator"
            )

        except Exception as e:
            log_error(logger, e, "Suggestion agent failed")
            return Command(
                update={
                    "error_logs": f"Fixer Suggestion Error: {str(e)}",
                    "retry_count": current_retries + 1
                },
                goto="generator"
            )

    # 场景 2/3: validator 或 deployer 或 configurator 错误（配置问题）
    elif ERROR_TYPE_VALIDATE in error_logs or ERROR_TYPE_DEPLOY in error_logs or ERROR_TYPE_CONFIGURE in error_logs:
        if ERROR_TYPE_CONFIGURE in error_logs:
            error_type = "Configuration"
        elif ERROR_TYPE_VALIDATE in error_logs:
            error_type = "Validation"
        else:  # ERROR_TYPE_DEPLOY
            error_type = "Deployment"

        logger.info(f"🔧 {error_type} error detected → invoking JSON fix agent")

        try:
            # 1. Agent 修复 JSON
            fixer_result = _call_json_fix_agent(state, error_logs)

            # 2. 重新生成 YAML（从修复后的JSON）
            json_path = state.get("json_path")
            yaml_path = state.get("yaml_path")

            try:
                new_yaml_path = regenerate_yaml_from_json(json_path, yaml_path)
                logger.info(f"✓ YAML regenerated from JSON: {new_yaml_path}")

                log_step(
                    logger,
                    "Configuration fixed and YAML regenerated",
                    status="success",
                    changes=fixer_result.changes_summary,
                    files_modified=fixer_result.files_modified,
                    routing_to="validator"
                )

                # 3. 路由到 validator 重新验证
                return Command(
                    update={
                        "error_logs": "",
                        "yaml_path": new_yaml_path,  # 更新yaml路径
                        "retry_count": current_retries + 1
                    },
                    goto="validator"  # 统一到validator重新验证
                )

            except Exception as e:
                # YAML重新生成失败
                log_error(logger, e, "YAML regeneration failed")
                return Command(
                    update={
                        "error_logs": f"Fixer Error: Failed to regenerate YAML: {str(e)}",
                        "retry_count": current_retries + 1
                    },
                    goto="generator"  # 回到generator重新开始
                )

        except Exception as e:
            log_error(logger, e, "JSON fix agent failed")
            return Command(
                update={
                    "error_logs": f"Fixer JSON Error: {str(e)}",
                    "retry_count": current_retries + 1
                },
                goto="generator"
            )

    # 未知错误类型（降级处理)
    else:
        logger.warning(f"⚠️  Unknown error type, defaulting to generator route")
        logger.warning(f"   Error logs: {error_logs[:200]}")

        return Command(
            update={
                "error_logs": "",
                "retry_count": current_retries + 1
            },
            goto="generator"
        )


def _call_suggestion_agent(state: GraphState, error_logs: str) -> SuggestionResult:
    """
    调用建议生成 Agent（用于 builder 错误）。

    Args:
        state: 工作流状态
        error_logs: 错误日志

    Returns:
        SuggestionResult: 包含改进建议
    """
    user_request = state.get("user_request", "")

    model = init_chat_model(
        model_provider="openai",
        model=config.llm_model,
        temperature=0.7,  # 较高温度以获得创造性建议
        base_url=config.base_url,
        api_key=config.api_key
    )

    system_prompt = f"""你是网络拓扑设计专家。分析以下构建错误，给出简洁实用的改进建议。

### 用户的原始请求
{user_request}

### 错误日志
{error_logs}

### 你的任务
分析错误原因，给出 1-3 条具体的改进建议。每条建议用 • 开头。

### 常见错误和建议方向

**镜像不存在** (manifest not found / pull access denied)
• 建议使用标准镜像: alpine:latest, ubuntu:latest, kalilinux/kali-rolling:latest
• 避免使用带标签的漏洞镜像，或简化镜像名称

**拓扑结构冲突** (duplicate endpoint / interface conflict)
• 建议简化子网结构
• 检查节点角色定义，确保 router 不被定义为 endpoint
• 如果一个子网有超过2个节点，builder 会自动注入交换机

**蓝图解析错误** (validation error / schema error)
• 建议检查节点名称格式（只能小写、连字符）
• 确保所有必需字段都有值
• 简化网络复杂度，从 simple 开始

### 输出要求
- 给出具体的、可操作的建议
- 每条建议一行，用 • 开头
- 总字数控制在 200 字以内
"""

    agent = create_agent(
        model=model,
        system_prompt=system_prompt,
        tools=[],  # 不需要工具
        response_format=SuggestionResult
    )

    result = agent.invoke({
        "messages": [{
            "role": "user",
            "content": "请分析错误并给出改进建议。"
        }]
    })

    return result["structured_response"]


def _call_json_fix_agent(state: GraphState, error_logs: str) -> JsonFixResult:
    """
    调用 JSON 修复 Agent（用于 validator/deployer/configurator 错误）。

    Agent 只读取和修改 JSON 文件，不修改 YAML（YAML 会自动从 JSON 重新生成）。

    Args:
        state: 工作流状态
        error_logs: 错误日志

    Returns:
        JsonFixResult: 包含修改摘要和修改的文件列表
    """
    yaml_path = state.get("yaml_path")
    json_path = state.get("json_path")

    if not yaml_path:
        raise ValueError("yaml_path not found in state")
    if not json_path:
        raise ValueError("json_path not found in state")

    model = init_chat_model(
        model_provider="openai",
        model=config.llm_model,
        temperature=0.3,  # 较低温度，保持结构稳定
        base_url=config.base_url,
        api_key=config.api_key
    )

    system_prompt = """You are a ContainerLab and Docker infrastructure expert. Analyze deployment errors and fix configuration files.

## Important: JSON is the Single Source of Truth

**CRITICAL**: In this system architecture:
- **JSON is the single source of truth** - all configuration comes from JSON
- **YAML is auto-generated FROM JSON** - do NOT modify YAML directly
- After you fix JSON, the system will automatically regenerate YAML

## Your Task

1. Analyze the error logs to identify the root cause
2. Use `read_file_tool` to read the current JSON configuration
3. Determine what changes are needed in the JSON
4. Use `modify_file_tool` to write the corrected JSON
5. DO NOT modify the YAML file - it will be automatically regenerated from JSON

## Available Tools

### read_file_tool
Reads the content of a file.
- Use this to examine the current JSON configuration before making changes

### modify_file_tool
Writes new content to a file, overwriting the existing content.
- `file_path`: The JSON file path provided
- `new_content`: Complete new file content (NOT a diff, must be the entire file)

## SECURITY CONSTRAINTS
- You are ONLY authorized to modify the JSON file
- NEVER attempt to modify the YAML file - it's auto-generated from JSON
- Always return valid JSON that matches the schema

## Common Errors and Fixes in JSON

### 1. Container Startup Failures - Missing Environment Variables

**Problem**: Database containers fail to start without required environment variables.

**Fix**: Add required environment variables in `container_config.environment`:

```json
{
  "nodes": {
    "postgres-db": {
      "container_config": {
        "environment": {
          "POSTGRES_PASSWORD": "password123"
        }
      }
    }
  }
}
```

### 2. Image Pull Errors

**Fix**: Change to standard, verified images in `container_config.image`:
- `alpine:latest`
- `ubuntu:latest`
- `kalilinux/kali-rolling:latest`
- `nginx:latest`

### 3. Command Override Issues

**Fix**: Empty the `cmd` field:
```json
{
  "nodes": {
    "node-name": {
      "container_config": {
        "cmd": ""
      }
    }
  }
}
```

### 4. Network Configuration Errors

**Fix**: Modify `interfaces` and `default_route`:
```json
{
  "nodes": {
    "node-name": {
      "interfaces": [
        {
          "name": "eth1",
          "subnet": "dmz",
          "address": "10.0.0.10/24"
        }
      ],
      "default_route": {
        "destination": "0.0.0.0/0",
        "gateway": "10.0.0.254"
      }
    }
  }
}
```

## Output Format
After fixing the JSON, return a summary with:
- `changes_summary`: Brief description of what you changed
- `files_modified`: List with single item containing the JSON file path
"""

    agent = create_agent(
        model=model,
        system_prompt=system_prompt,
        tools=[read_file_tool, modify_file_tool],  # Agent 使用工具读取和修改文件
        response_format=JsonFixResult
    )

    result = agent.invoke({
        "messages": [{
            "role": "user",
            "content": f"""Please analyze the deployment errors and fix the JSON configuration.

JSON file path: {json_path}

IMPORTANT: Only modify the JSON file at {json_path}. Do NOT modify the YAML file.

Error logs:
{error_logs}"""
        }]
    })

    return result["structured_response"]
