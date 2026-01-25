"""Fixer 节点：错误诊断和修复

分析部署错误日志，智能修复网络拓扑设计问题。
"""
from typing import Dict, Any, Optional, Literal
import yaml

from langchain.chat_models import init_chat_model
from langchain.agents import create_agent
from pydantic import BaseModel, Field
from langgraph.types import Command

from state import GraphState
from .utils import NetworkBlueprint
from config import config, MAX_RETRIES
from tools.file_tools import read_file_tool, modify_file_tool
from logger import get_logger, set_log_context, log_error, log_step


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


class YamlFixResult(BaseModel):
    """YAML 修复 Agent 的返回结构（用于 validator/deployer/configurator 错误）"""
    changes_summary: str = Field(..., description="修改内容摘要")
    files_modified: list[str] = Field(..., description="修改的文件路径列表")


def fixer(state: GraphState) -> Command[Literal["generator", "validator", "deployer"]]:
    """
    Fixer Node: 智能分析错误日志并修复配置文件，同时决定下一步路由。

    工作流程:
    1. 检查重试次数（熔断机制）
    2. 静态分析错误类型（无需 LLM）
    3. 根据错误类型调用对应的修复 Agent
    4. Agent 使用工具修改文件
    5. 返回 Command 对象，包含 state 更新和路由目标

    路由策略:
    - BUILD 错误     → 生成建议 → generator
    - VALIDATE 错误   → 修改 YAML → validator
    - DEPLOY 错误     → 修改 YAML → validator
    - CONFIGURE 错误  → 修改 YAML → deployer
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
            next_node = "deployer"
        elif ERROR_TYPE_VALIDATE in error_logs:
            error_type = "Validation"
            next_node = "validator"
        else:  # ERROR_TYPE_DEPLOY
            error_type = "Deployment"
            next_node = "validator"

        logger.info(f"🔧 {error_type} error detected → invoking YAML fix agent")

        try:
            fixer_result = _call_yaml_fix_agent(state, error_logs)

            log_step(
                logger,
                "Files fixed by agent",
                status="success",
                changes=fixer_result.changes_summary,
                files_modified=fixer_result.files_modified,
                routing_to=next_node
            )

            return Command(
                update={
                    "error_logs": "",
                    "retry_count": current_retries + 1
                },
                goto=next_node
            )

        except Exception as e:
            log_error(logger, e, "YAML fix agent failed")
            return Command(
                update={
                    "error_logs": f"Fixer YAML Error: {str(e)}",
                    "retry_count": current_retries + 1
                },
                goto=next_node
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


def _call_yaml_fix_agent(state: GraphState, error_logs: str) -> YamlFixResult:
    """
    调用 YAML 修复 Agent（用于 validator/deployer/configurator 错误）。

    Agent 会自主读取 YAML 和 JSON 文件内容，分析错误，并使用 modify_file_tool 修复文件。

    Args:
        state: 工作流状态
        error_logs: 错误日志

    Returns:
        YamlFixResult: 包含修改摘要和修改的文件列表
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

## Background: ContainerLab Architecture

ContainerLab is a container-based network emulation tool that uses Docker containers to create network topologies.

### Key Concepts:
- **Nodes**: Docker containers representing network devices (routers, switches, endpoints, vulnerability targets)
- **Links**: Virtual ethernet connections between nodes (veth pairs)
- **Networks**: Docker bridge networks that connect nodes
- **Node Types**:
  - `kind: linux`: General Linux containers (endpoints, servers, attackers)
  - `kind: bridge`: Legacy bridge nodes (being replaced with linux switches)
- **Network Namespace**: Each container has its own network namespace for isolation
- **Interfaces**: Named eth1, eth2, eth3, etc. (eth0 is reserved for management)

### YAML Configuration Structure (.clab.yml):
```yaml
name: topology-name
topology:
  nodes:
    node-name:
      kind: linux
      image: image:tag
      environment:          # Environment variables for container startup
        ENV_VAR: value
      binds:                # Volume mounts (host-path:container-path)
        - /host/path:/container/path
      sysctls:              # System parameters (sysctl)
        net.ipv4.ip_forward: "1"
      cmd: ''               # Override container command
  links:
    - endpoints:
      - node1:eth1
      - node2:eth1
```

### JSON Configuration Structure (config.json):
```json
{
  "nodes": {
    "node-name": {
      "role": "endpoint|router|vul-target|switch",
      "image": "image:tag",
      "interfaces": [
        {
          "name": "eth1",
          "ip": "10.0.0.1/24",
          "gateway": "10.0.0.254"
        }
      ],
      "routes": [
        {
          "target": "0.0.0.0/0",
          "via": "10.0.0.254"
        }
      ],
      "exec": [
        "command to run in container"
      ]
    }
  }
}
```

## File Paths
You are authorized to work with ONLY these two files:
- YAML file: `{yaml_path}`
- JSON file: `{json_path}`

## Error Logs
```
{error_logs}
```

## Your Task
1. Analyze the error logs to identify the root cause
2. Use `read_file_tool` to read the current content of `{yaml_path}` and/or `{json_path}`
3. Determine what changes are needed to fix the issues
4. Use `modify_file_tool` to write the corrected content to the file(s)
5. Only modify the necessary parts, preserve everything else
6. Return a summary of changes and list of modified files

## Available Tools

### read_file_tool
Reads the content of a file.
- Use this to examine the current YAML or JSON configuration before making changes
- `file_path`: The path to read (must be `{yaml_path}` or `{json_path}`)

### modify_file_tool
Writes new content to a file, overwriting the existing content.
- `file_path`: The path to modify (must be `{yaml_path}` or `{json_path}`)
- `new_content`: Complete new file content (NOT a diff, must be the entire file)

## SECURITY CONSTRAINTS
- You are ONLY authorized to read/modify these two files: `{yaml_path}` and `{json_path}`
- NEVER attempt to read or modify any other files
- All file paths you provide to tools MUST match exactly these paths

## Common Errors and Fixes

### 1. Container Startup Failures

#### Missing Required Environment Variables
**Problem**: Database containers fail to start without required environment variables.

**Symptoms**:
- Container status: "Restarting (1)" or "Exited (1)"
- Error logs: "database is shut down", "password authentication failed"

**Fix**: Add required environment variables in YAML node configuration:

**PostgreSQL** (postgres:latest):
```yaml
postgres-db:
  kind: linux
  image: postgres:latest
  environment:
    POSTGRES_PASSWORD: password123
    # Alternative: POSTGRES_HOST_AUTH_METHOD: trust
```

**MySQL** (mysql:latest):
```yaml
mysql-db:
  kind: linux
  image: mysql:latest
  environment:
    MYSQL_ROOT_PASSWORD: password123
    # Alternative: MYSQL_ALLOW_EMPTY_PASSWORD: "yes"
```

**Redis** (redis:latest):
- No environment variables required

**Vulhub Images** (vulhub/*):
- Most require no environment variables
- Check specific vulhub documentation if needed

#### Image Pull Errors
**Problem**: Image not found or pull access denied.

**Symptoms**:
- Error: "manifest not found", "pull access denied"

**Fix**: Change to standard, verified images:
- `alpine:latest` - Minimal Linux distro
- `ubuntu:latest` - Standard Ubuntu
- `kalilinux/kali-rolling:latest` - Kali Linux
- `nginx:latest` - Web server
- `postgres:latest`, `mysql:latest`, `redis:latest` - Databases

### 2. IP Configuration Errors

#### IP Address Conflicts
**Problem**: Duplicate IP addresses on the same subnet.

**Symptoms**:
- Error: "RTNETLINK answers: File exists"
- Containers unable to communicate

**Fix in JSON**: Modify IP addresses to follow addressing scheme:
- Routers: `.1` in each subnet (e.g., `10.0.0.1/24`)
- Switches: `.2` in each subnet (e.g., `10.0.0.2/24`)
- Endpoints/Vul-targets: `.64` and higher (e.g., `10.0.0.64/24`)
- Ensure no duplicate IPs in the same subnet

#### Interface Naming Mismatch
**Problem**: JSON interface name doesn't match YAML link definition.

**Symptoms**:
- Error: "Cannot find device", "No such device"
- IP configuration fails

**Fix**: Ensure interface names match:
- YAML links define: `node1:eth1` <-> `node2:eth1`
- JSON must reference: `"name": "eth1"` (not eth2, eth0, etc.)
- Interface numbering starts at eth1 (eth0 is management)

### 3. Routing Configuration Errors

#### Default Route Issues
**Problem**: Default gateway not reachable or misconfigured.

**Symptoms**:
- Error: "RTNETLINK answers: Network is unreachable"
- Container cannot reach external networks

**Fix in JSON**: Ensure default route via IP matches router interface:
```json
{
  "routes": [
    {
      "target": "0.0.0.0/0",
      "via": "10.0.0.1"  // Must be router's IP in this subnet
    }
  ]
}
```

#### Static Route Overlap
**Problem**: Static route target overlaps with directly connected network.

**Symptoms**:
- Routing table conflicts
- Unreachable networks

**Fix**: Static routes should NOT overlap with interface subnets:
- If eth1 is `10.0.0.0/24`, don't add route for `10.0.0.0/24` or `10.0.0.0/16`
- Only add routes for remote networks (e.g., `192.168.1.0/24`)

### 4. FRR Routing Configuration

#### FRR Not Applying Configuration
**Problem**: Router ignores OSPF/BGP configuration.

**Cause**: FRR daemon (zebra/ospfd) needs restart to reload bind-mounted config.

**Current Implementation**:
- Config applied via bind mounts in YAML
- Restart handled by: `killall -HUP zebra ospfd` (executed during deployment)
- No JSON changes needed

**What to Check**:
- YAML binds: `/path/to/daemons:/etc/frr/daemons`
- YAML binds: `/path/to/frr.conf:/etc/frr/frr.conf`
- daemons file must enable: `zebra=yes`, `ospfd=yes`

### 5. Command Execution Errors

#### Command Not Found
**Problem**: Exec command fails because tool not available in image.

**Symptoms**:
- Error: "command not found", "exec: command not found"

**Fix**: Use commands available in the specific image:
- **Alpine**: Use `apk add` to install tools
- **Ubuntu/Debian**: Use `apt-get update && apt-get install`
- **Kali**: Has most tools pre-installed
- **CentOS/RHEL**: Use `yum install`

#### Command Order Dependencies
**Problem**: IP config fails because interface not ready yet.

**Symptoms**:
- Intermittent failures
- "Cannot find device" errors

**Fix**: Order commands properly in JSON exec array:
```json
{
  "exec": [
    "ip link set eth1 up",           // 1. Bring interface up
    "ip addr add 10.0.0.64/24 dev eth1",  // 2. Add IP
    "ip route add default via 10.0.0.1"   // 3. Add route
  ]
}
```

### 6. Link and Topology Errors

#### Duplicate Endpoint
**Problem**: Same endpoint appears in multiple links.

**Symptoms**:
- Validation error: "duplicate endpoint"
- Deployment fails

**Fix in YAML**: Each interface can only be used in one link:
```yaml
links:
  - endpoints:
    - router:eth1
    - switch:eth1
  - endpoints:
    - router:eth2    # OK: different interface
    - switch:eth2
  # NOT OK: router:eth1 used again in another link
```

#### Too Many Nodes Without Switch
**Problem**: More than 2 endpoints in same subnet without switch.

**Current Implementation**:
- Builder automatically injects `sw-` nodes when needed
- Switches are `kind: linux` with `image: alpine:latest`
- Switches have NO IP addresses (Layer 2 only)

**What to Check**:
- If subnet has 3+ nodes, ensure switch node exists
- Switch node name format: `sw-<zone>` (e.g., `sw-dmz`, `sw-internal`)
- All nodes in subnet connect to switch via links

### 7. Docker and Container Issues

#### Container Not Running
**Problem**: Container exits immediately after start.

**Symptoms**:
- `docker ps` shows container not in list
- `docker ps -a` shows "Exited (1)"

**Common Causes**:
1. Missing environment variables (see #1)
2. Invalid command in YAML `cmd` field
3. Image doesn't support default entrypoint

**Fix**: Remove or correct `cmd` field in YAML:
```yaml
node-name:
  kind: linux
  image: image:tag
  cmd: ''        # Empty string uses default entrypoint
  # OR remove cmd field entirely
```

#### Volume Mount Failures
**Problem**: Bind mount source file doesn't exist.

**Symptoms**:
- Error: "no such file or directory"
- Container fails to start

**Fix**: Ensure bind mount source paths exist:
```yaml
node:
  binds:
    - /existing/host/path:/container/path  # Source must exist
```

## Network Addressing Scheme Reference

When modifying IP addresses in JSON, follow this scheme:

### Subnet Design
- Use private IP ranges: `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`
- Each subnet should be `/24` (254 usable addresses) or smaller

### IP Assignment within Subnet
- `.1`: Router (gateway)
- `.2`: Switch (if present)
- `.64 - .254`: Endpoints and vulnerability targets
- `.254`: Network gateway (if different from router)

### Example Subnet: 10.0.0.0/24
```
10.0.0.1   - Router (gateway)
10.0.0.2   - Switch (if present)
10.0.0.64  - Endpoint 1
10.0.0.65  - Endpoint 2
10.0.0.66  - Vul-target
...
10.0.0.254 - Default gateway (if applicable)
```

## Docker Image-Specific Requirements

### Standard Images
- **alpine**: Minimal, use `apk add` to install tools
- **ubuntu**: Use `apt-get`, has many tools available
- **kalilinux/kali-rolling**: Pentest tools pre-installed

### Vulnerability Images (Vulhub)
- **vulhub/redis:5.0.7**: No special config needed
- **vulhub/solr:8.11.0**: No special config needed
- **vulhub/weblogic:******: May need specific ports exposed
- Check vulhub documentation for specific requirements

### Database Images
- **postgres**: Requires `POSTGRES_PASSWORD`
- **mysql**: Requires `MYSQL_ROOT_PASSWORD`
- **redis**: No environment variables needed
- **mongo**: Requires `MONGO_INITDB_ROOT_USERNAME` and `MONGO_INITDB_ROOT_PASSWORD`

### Routing Images
- **frrouting/frr:v8.4.1**: Use bind mounts for config, restart with HUP signal

## Workflow
1. Analyze error logs and identify error type
2. Examine current YAML and JSON configurations
3. Determine root cause (refer to common errors above)
4. Decide which file(s) to modify
5. Use `modify_file_tool` to write corrected file content
6. Return summary of changes and list of modified files

## Output Requirements
- `changes_summary`: Brief description of what was changed and why
- `files_modified`: List of file paths that were modified
- Be specific about environment variables added, IPs changed, routes fixed, etc.

## Important Notes
- Always provide COMPLETE file content to `modify_file_tool`, not just changes
- Maintain proper YAML indentation (2 spaces)
- Maintain proper JSON syntax (quotes, commas, brackets)
- When adding environment variables, use the exact variable names required
- When modifying IPs, ensure they follow the addressing scheme
- When fixing routes, verify the via IP is reachable
"""

    # 使用字符串替换填充路径占位符（避免转义花括号）
    system_prompt_filled = system_prompt.replace("{yaml_path}", yaml_path) \
                                          .replace("{json_path}", json_path) \
                                          .replace("{error_logs}", error_logs)

    agent = create_agent(
        model=model,
        system_prompt=system_prompt_filled,
        tools=[read_file_tool, modify_file_tool],  # Agent 使用工具读取和修改文件
        response_format=YamlFixResult
    )

    result = agent.invoke({
        "messages": [{
            "role": "user",
            "content": f"""Please analyze the deployment errors and fix the configuration files.

You are authorized to work with ONLY these two files:
- YAML: {yaml_path}
- JSON: {json_path}

Use the read_file_tool to examine the current content, then use modify_file_tool to fix any issues.

Error logs:
{error_logs}"""
        }]
    })

    return result["structured_response"]
