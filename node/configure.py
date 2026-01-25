"""Configure 节点：容器内网络和服务验证

使用 ConfigApplier 收集诊断数据，然后使用 LLM 分析判断配置是否正确。
"""
import json
from typing import Dict, Any, List
from pydantic import BaseModel, Field
from langchain.chat_models import init_chat_model
from langchain.agents import create_agent

from state import GraphState
from config import config
from logger import get_logger, set_log_context, log_step
from .utils import ConfigApplier

# Configure 错误类型标识符
ERROR_TYPE_CONFIGURE = "[ERROR_TYPE:CONFIGURE]"


# ============================================
# 结构化输出模型
# ============================================
class NodeCheckResult(BaseModel):
    """单个节点的检查结果"""
    node_name: str = Field(..., description="Node name")
    overall_status: str = Field(..., description="PASS or FAIL")
    checks: List[str] = Field(..., description="List of check results (e.g., '✓ IP configured', '✗ Route not found')")
    issues: List[str] = Field(default=[], description="List of issues found (empty if none)")


class ConfigurationAnalysis(BaseModel):
    """配置分析结果（结构化输出）"""
    overall_status: str = Field(..., description="Overall status: PASS or FAIL")
    node_results: List[NodeCheckResult] = Field(..., description="Results for each node")
    summary: str = Field(..., description="Brief summary of the analysis")


configure_prompt = """
You are a Network and Service Configuration Analyzer.

Your task is to analyze the diagnostic data from containerlab containers and determine if the configuration is correct.

DIAGNOSTIC DATA includes:
- container: Container status (running/not_found)
- ip_config: "ip addr show" output + expected interfaces
- interfaces: "ip link show" output + expected interfaces
- routes: "ip route show" output + expected default route
- ports: "ss -tlnp" or "netstat -tlnp" output + expected ports
- processes: "ps aux" output + expected image

ANALYSIS CHECKLIST:
1. **Container Check**: Is the container running?
2. **Node Type**: Identify the node role (router, endpoint, vul-target, switch)
3. **IP Configuration**:
   - For routers/endpoints/vul-targets: Do the expected IP addresses appear in the output?
   - For switches (nodes with "sw-" prefix): NO IP configuration expected - they are Layer 2 switches
4. **Interface State**: Are all expected interfaces in UP state?
5. **Routing**: Is the default route configured (for endpoints/vul-targets only)?
6. **Port Listening**: For specified ports, are they listening?
7. **Process Running**: Does the expected service process appear in ps aux?

SPECIAL CASES:
- **Switch nodes** (names starting with "sw-"): These are Layer 2 switches and should NOT have IP addresses.
  - PASS if: Container running + Interfaces UP + NO IP addresses (except IPv6 link-local)
  - FAIL if: Container not running OR Interfaces DOWN OR Has IP addresses configured
- **Router nodes**: Should have IP addresses on all interfaces and run FRR (zebra, ospfd processes)
- **Endpoint/Vul-target nodes**: Should have IP addresses and default route configured

JUDGMENT:
- Return "PASS" if ALL critical checks succeed for each node
- Return "FAIL" if ANY critical check fails
- Skip non-critical checks (e.g., port checks if no ports specified)

OUTPUT FORMAT:
Fill in the structured output template with:
- overall_status: "PASS" or "FAIL"
- node_results: List of NodeCheckResult
  - node_name: Name of the node
  - overall_status: "PASS" or "FAIL" for this node
  - checks: List of check descriptions like "✓ IP address 10.0.0.64 configured", "✗ Default route not found"
  - issues: List of specific issues found
- summary: Brief summary (1-2 sentences)

Be specific about failures. Use ✓ for pass, ✗ for fail.
"""


def configure(state: GraphState) -> Dict[str, Any]:
    """
    Configure 节点：验证所有容器的网络和服务状态。

    工作流程:
    1. 使用 ConfigApplier.collect_diagnostics() 收集原始诊断数据
    2. 将诊断数据发送给 LLM 分析（使用结构化输出）
    3. LLM 填充 ConfigurationAnalysis 模板
    4. 根据分析结果设置 error_logs 和 is_complete

    Args:
        state: 当前工作流状态

    Returns:
        更新后的状态字典
    """
    logger = get_logger("node.configure")
    set_log_context(stage="configure")

    yaml_path = state.get("yaml_path")
    json_path = state.get("json_path")

    if not yaml_path or not json_path:
        logger.warning("Missing yaml_path or json_path, skipping verification")
        return {"is_complete": True}

    log_step(logger, "Collecting diagnostics from all nodes", status="start")

    try:
        import os
        lab_name = os.path.basename(yaml_path).replace('.clab.yml', '')
        config_dir = os.path.dirname(json_path)

        # 1. 收集诊断数据
        applier = ConfigApplier(lab_name, config_dir)
        diagnostics = applier.collect_diagnostics(yaml_path)

        logger.info(f"Collected diagnostics from {len(diagnostics['nodes'])} nodes")

        # 2. 准备 LLM 分析任务
        analysis_prompt = _build_analysis_prompt(diagnostics)

        # 3. 调用 LLM 分析（使用结构化输出）
        log_step(logger, "Analyzing diagnostics with LLM", status="start")

        model = init_chat_model(
            model_provider="openai",
            model=config.llm_model,
            temperature=0.1,
            base_url=config.base_url,
            api_key=config.api_key
        )

        agent = create_agent(
            model=model,
            system_prompt=configure_prompt,
            tools=[],
            response_format=ConfigurationAnalysis  # 结构化输出
        )

        result = agent.invoke({
            "messages": [{"role": "user", "content": analysis_prompt}]
        })

        # 4. 提取结构化响应
        analysis = _extract_structured_response(result)

        if analysis is None:
            logger.error("Failed to extract structured response from LLM")
            return {"is_complete": True}

        # 5. 记录分析结果
        logger.info(f"Overall Status: {analysis.overall_status}")
        logger.info(f"Summary: {analysis.summary}")

        for node_result in analysis.node_results:
            if node_result.overall_status == "PASS":
                logger.info(f"✓ {node_result.node_name}: All checks passed")
            else:
                logger.error(f"✗ {node_result.node_name}: Checks failed")

            for check in node_result.checks:
                logger.info(f"  {check}")

            for issue in node_result.issues:
                logger.error(f"  Issue: {issue}")

        # 6. 判断是否有问题
        if analysis.overall_status == "FAIL":
            log_step(logger, "Configuration issues detected", status="fail")

            # 构建详细错误信息
            error_lines = [f"Configuration verification failed: {analysis.summary}"]
            for node_result in analysis.node_results:
                if node_result.overall_status == "FAIL":
                    error_lines.append(f"\nNode: {node_result.node_name}")
                    for issue in node_result.issues:
                        error_lines.append(f"  - {issue}")

            error_msg = "\n".join(error_lines)
            return {
                "is_complete": False,
                "error_logs": f"{ERROR_TYPE_CONFIGURE} {error_msg}"
            }
        else:
            log_step(logger, "All configurations verified", status="success")
            return {"is_complete": True}

    except Exception as e:
        import traceback
        logger.error(f"Verification failed: {str(e)}")
        logger.debug(traceback.format_exc())

        # 验证失败不阻塞流程
        return {"is_complete": True}


def _build_analysis_prompt(diagnostics: Dict[str, Any]) -> str:
    """构建 LLM 分析提示。"""
    prompt = "Analyze the following diagnostic data from containerlab containers:\n\n"

    for node_name, node_data in diagnostics["nodes"].items():
        prompt += f"## Node: {node_name}\n"

        for check_name, check_data in node_data.get("checks", {}).items():
            prompt += f"\n{check_name.upper()}:\n"

            # 添加原始输出
            raw_output = check_data.get("raw_output", "")
            if raw_output:
                # IP 配置相关检查不截断（避免丢失关键信息）
                if check_name in ["ip_config", "interfaces", "routes"]:
                    prompt += f"Raw output:\n```\n{raw_output}\n```\n"
                # 其他检查限制输出长度（避免 token 过多）
                elif len(raw_output) > 500:
                    raw_output = raw_output[:500] + "\n... (truncated)"
                    prompt += f"Raw output:\n```\n{raw_output}\n```\n"
                else:
                    prompt += f"Raw output:\n```\n{raw_output}\n```\n"

            # 添加期望值
            expected = check_data.get("expected")
            if expected:
                prompt += f"Expected: {json.dumps(expected, indent=2)}\n"

            expected_image = check_data.get("expected_image")
            if expected_image:
                prompt += f"Expected image: {expected_image}\n"

            # 特殊状态
            status = check_data.get("status")
            if status:
                prompt += f"Status: {status}\n"

        prompt += "\n" + "-"*50 + "\n"

    prompt += "\nPlease analyze and fill in the structured output template."

    return prompt


def _extract_structured_response(result: Dict) -> ConfigurationAnalysis:
    """从 LLM 结果中提取结构化响应。"""
    logger = get_logger("node.configure")

    try:
        messages = result.get("messages", [])

        # 查找 structured_response
        if "structured_response" in result:
            return result["structured_response"]

        # 查找最后一个 AIMessage
        for msg in reversed(messages):
            if hasattr(msg, 'type') and msg.type == 'ai':
                if hasattr(msg, 'content') and isinstance(msg.content, dict):
                    # 某些版本可能返回字典
                    if "overall_status" in msg.content:
                        return ConfigurationAnalysis(**msg.content)
                elif hasattr(msg, 'content'):
                    # 尝试解析 JSON
                    import json
                    content_str = str(msg.content)
                    try:
                        content_dict = json.loads(content_str)
                        return ConfigurationAnalysis(**content_dict)
                    except:
                        pass

        logger.error("Could not extract structured response from LLM output")
        return None

    except Exception as e:
        logger.error(f"Error extracting structured response: {e}")
        return None

