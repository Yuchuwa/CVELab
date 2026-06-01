# Agent SDK集成说明

## Claude Code SDK在Docker中的实际调用方式

### 方法1: 使用Python SDK（推荐）

创建一个Docker镜像，包含Claude Code SDK：

```dockerfile
# agent_container/Dockerfile
FROM python:3.11-slim

# 安装依赖
RUN pip install anthropic claude-code-sdk

# 安装安全研究工具
RUN apt-get update && apt-get install -y \
    nmap \
    netcat \
    curl \
    wget \
    python3-pip \
    git \
    vim \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /workspace

# 复制Agent脚本
COPY agent_runner.py /workspace/agent_runner.py

# 启动命令
CMD ["python3", "/workspace/agent_runner.py"]
```

### 方法2: Agent Runner脚本

```python
#!/usr/bin/env python3
"""
Agent Runner - 在Docker容器中运行Claude Code SDK
"""

import os
import sys
import json
from pathlib import Path
from anthropic import Anthropic
from claude_code_sdk import ClaudeCode  # 假设的SDK

class AgentRunner:
    def __init__(self):
        # 初始化Claude API
        self.api_key = os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("需要设置ANTHROPIC_API_KEY环境变量")

        self.client = Anthropic(api_key=self.api_key)
        self.claude_code = ClaudeCode(client=self.client)

    def run_task(self, prompt: str, work_dir: str):
        """
        执行Agent任务

        Args:
            prompt: 任务描述
            work_dir: 工作目录
        """
        # 设置工作目录
        os.chdir(work_dir)

        # 使用Claude Code SDK
        result = self.claude_code.run(
            prompt=prompt,
            tools=["bash", "read", "write"],
            timeout=600  # 10分钟
        )

        return result

    def main(self):
        """主函数"""
        # 读取prompt文件
        prompt_file = Path("/workspace/agent_prompt.txt")
        if not prompt_file.exists():
            print("❌ prompt文件不存在")
            sys.exit(1)

        with open(prompt_file, 'r', encoding='utf-8') as f:
            prompt = f.read()

        # 运行任务
        print("🤖 开始执行Agent任务...")
        result = self.run_task(prompt, "/workspace")

        # 保存结果
        output_file = Path("/workspace/agent_output.json")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

        print(f"✅ 任务完成，结果已保存到: {output_file}")

if __name__ == "__main__":
    runner = AgentRunner()
    runner.main()
```

### 方法3: 修改SecurityResearcherAgent调用

```python
def _run_claude_code_in_container(self, prompt: str, work_dir: str) -> Dict[str, Any]:
    """
    在Agent容器中运行Claude Code SDK
    """
    if not self.container_id:
        raise RuntimeError("Agent容器未启动")

    # 创建临时prompt文件
    prompt_file = Path(work_dir) / "agent_prompt.txt"
    with open(prompt_file, 'w', encoding='utf-8') as f:
        f.write(prompt)

    # 设置环境变量
    env = os.environ.copy()
    env['ANTHROPIC_API_KEY'] = os.getenv('ANTHROPIC_API_KEY', '')

    # 在容器中运行Agent Runner
    cmd = [
        "docker", "exec",
        "-e", f"ANTHROPIC_API_KEY={env['ANTHROPIC_API_KEY']}",
        self.container_id,
        "python3", "/workspace/agent_runner.py"
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=600,
        env=env
    )

    if result.returncode != 0:
        raise RuntimeError(f"Agent执行失败: {result.stderr}")

    # 读取输出文件
    output_file = Path(work_dir) / "agent_output.json"
    with open(output_file, 'r', encoding='utf-8') as f:
        return json.load(f)
```

### 构建和运行

```bash
# 构建Agent镜像
docker build -t security-researcher-agent:latest agent_container/

# 运行Pipeline
python -m src.clab_builder.main
```

## 实际SDK集成注意事项

1. **Claude Code SDK包**：需要确认实际的SDK包名和API
2. **认证**：需要设置ANTHROPIC_API_KEY环境变量
3. **工具调用**：SDK需要支持bash、read、write等工具
4. **超时设置**：CVE复现可能需要较长时间
5. **输出格式**：确保Agent输出结构化的JSON结果

## 简化版本（无需SDK）

如果Claude Code SDK不可用，可以简化为直接使用API：

```python
import anthropic

client = anthropic.Anthropic(api_key="your-api-key")

response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=4096,
    tools=[...],  # 定义工具
    messages=[
        {"role": "user", "content": prompt}
    ]
)
```

这样可以避免依赖专门的Claude Code SDK包。
