"""Fixer 节点：错误诊断和修复

分析部署错误日志，智能修复网络拓扑设计问题。
"""
from typing import Dict, Any, Optional
import yaml

from langchain.chat_models import init_chat_model
from langchain.agents import create_agent
from pydantic import BaseModel, Field

from state import GraphState
from .utils import NetworkBlueprint
from config import config, MAX_RETRIES
from tools.containerlab_tools import clab_lifecycle_tool, node_config_tool
from logger import get_logger, set_log_context, log_error, log_step


# ============================================
# 错误类型标识符
# ============================================
ERROR_TYPE_BUILD = "[ERROR_TYPE:BUILD]"
ERROR_TYPE_VALIDATE = "[ERROR_TYPE:VALIDATE]"
ERROR_TYPE_DEPLOY = "[ERROR_TYPE:DEPLOY]"
ERROR_TYPE_SYSTEM = "[ERROR_TYPE:SYSTEM]"


# ============================================
# Agent 返回结构
# ============================================
class SuggestionResult(BaseModel):
    """建议生成 Agent 的返回结构（用于 builder 错误）"""
    suggestion: str = Field(..., description="针对蓝图错误的改进建议")


class YamlFixResult(BaseModel):
    """YAML 修复 Agent 的返回结构（用于 validator/deployer 错误）"""
    yaml_content: str = Field(..., description="修复后的完整 YAML 内容")
    changes_summary: str = Field(..., description="修改内容摘要")


def fixer(state: GraphState) -> Dict[str, Any]:
    """
    Fixer Node: 智能分析错误日志并路由到对应的修复 Agent。

    工作流程:
    1. 检查重试次数（熔断机制）
    2. 静态分析错误类型（无需 LLM）
    3. 根据错误类型路由到专门的修复 Agent
    4. 返回修复后的状态和路由目标

    路由策略:
    - BUILD 错误   → 生成建议 → generator
    - VALIDATE 错误 → 修改 YAML → validator
    - DEPLOY 错误   → 修改 YAML → validator
    - SYSTEM 错误   → 无法修复 → END

    Args:
        state: 当前工作流状态

    Returns:
        更新后的状态字典，包含 _fixer_target 路由标记

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

            # 返回标志：清空 blueprint 表示需要重新生成
            return {
                "user_request": enhanced_request,
                "blueprint": None,  # 清空旧蓝图，让 generator 重新生成
                "error_logs": "",
                "retry_count": current_retries + 1,
            }

        except Exception as e:
            log_error(logger, e, "Suggestion agent failed")
            return {
                "error_logs": f"Fixer Suggestion Error: {str(e)}",
                "retry_count": current_retries + 1,
            }

    # 场景 2/3: validator 或 deployer 错误（配置问题）
    elif ERROR_TYPE_VALIDATE in error_logs or ERROR_TYPE_DEPLOY in error_logs:
        error_type = "Validation" if ERROR_TYPE_VALIDATE in error_logs else "Deployment"
        logger.info(f"🔧 {error_type} error detected → invoking YAML fix agent")

        try:
            fixer_result = _call_yaml_fix_agent(state, error_logs)

            # 写入修复后的 YAML
            yaml_path = state.get("yaml_path")
            if not yaml_path:
                raise ValueError("yaml_path not found in state")

            with open(yaml_path, 'w', encoding='utf-8') as f:
                f.write(fixer_result.yaml_content)

            log_step(
                logger,
                "YAML fixed",
                status="success",
                changes=fixer_result.changes_summary,
                routing_to="validator"
            )

            # 返回标志：保留 blueprint，只清空 error_logs
            return {
                "error_logs": "",
                "retry_count": current_retries + 1,
            }

        except Exception as e:
            log_error(logger, e, "YAML fix agent failed")
            return {
                "error_logs": f"Fixer YAML Error: {str(e)}",
                "retry_count": current_retries + 1,
            }

    # 未知错误类型（降级处理）
    else:
        logger.warning(f"⚠️  Unknown error type, defaulting to generator route")
        logger.warning(f"   Error logs: {error_logs[:200]}")

        return {
            "error_logs": "",
            "retry_count": current_retries + 1,
        }


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


def _call_yaml_fix_agent(state: GraphState, error_logs: str) -> YamlFixResult:
    """
    调用 YAML 修复 Agent（用于 validator/deployer 错误）。

    Args:
        state: 工作流状态
        error_logs: 错误日志

    Returns:
        YamlFixResult: 包含修复后的 YAML 内容和修改摘要
    """
    yaml_path = state.get("yaml_path")
    if not yaml_path:
        raise ValueError("yaml_path not found in state")

    # 读取当前 YAML
    with open(yaml_path, 'r', encoding='utf-8') as f:
        current_yaml = f.read()

    model = init_chat_model(
        model_provider="openai",
        model=config.llm_model,
        temperature=0.3,  # 较低温度，保持结构稳定
        base_url=config.base_url,
        api_key=config.api_key
    )

    system_prompt = f"""你是 ContainerLab 配置修复专家。分析错误并修复 YAML 文件。

### 当前 YAML 配置
```yaml
{current_yaml}
```

### 错误日志
{error_logs}

### 你的任务
1. 分析错误原因
2. 修复 YAML 中的问题
3. 只修改必要部分，保持其他内容不变
4. 返回完整的修复后 YAML

### 常见错误修复方法

**IP 地址冲突**
• 修改冲突的 IP 地址，确保每个接口 IP 唯一
• 路由器使用 .1, 交换机使用 .2, 端点从 .64 开始
• 同一子网内不能有重复的 IP

**路由配置错误**
• 检查默认路由配置（via IP 必须是网关地址）
• 静态路由的目标网段不能与直连网段重叠
• 确保下一跳 IP 在直连网段内可达

**命令执行错误**
• 修正命令语法错误
• 调整 exec 命令的执行顺序（先安装工具，再配置 IP）
• 确保使用的命令在对应镜像中可用

**接口配置错误**
• 确保 IP 配置的接口名称与实际链路对应
• 检查接口编号（eth1, eth2 等）是否正确

### 输出要求
- 返回完整的、可直接使用的 YAML 文件
- 保持 YAML 格式正确，缩进使用 2 个空格
- 在 changes_summary 中简要说明修改了什么
"""

    agent = create_agent(
        model=model,
        system_prompt=system_prompt,
        tools=[clab_lifecycle_tool],  # 可能需要检查容器状态
        response_format=YamlFixResult
    )

    result = agent.invoke({
        "messages": [{
            "role": "user",
            "content": "请修复 YAML 配置文件。"
        }]
    })

    return result["structured_response"]
