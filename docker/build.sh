#!/bin/bash
# 构建 Agent 容器镜像
# Agent 使用 Claude Agent SDK，自带 Bash/Read/Write 工具

IMAGE_NAME="clab-agent"
IMAGE_TAG="latest"

echo "Building Agent container image..."
echo "Image: ${IMAGE_NAME}:${IMAGE_TAG}"

docker build -t ${IMAGE_NAME}:${IMAGE_TAG} .

if [ $? -eq 0 ]; then
    echo "Build succeeded!"
    echo ""
    echo "Included tools:"
    echo "  - Claude Agent SDK (claude-agent-sdk>=0.2.87)"
    echo "  - nmap, netcat, curl, wget, sqlmap, nikto, hydra"
    echo "  - gobuster, ffuf, feroxbuster, dirsearch, dirb"
    echo "  - Python 3 + claude-agent-sdk"
    echo "  - jq, vim"
    echo ""
    echo "Usage:"
    echo "  agent_runner.py is mounted from src/ at runtime (not baked into image)"
    echo "  docker run -d --name agent \\"
    echo "    -e ANTHROPIC_API_KEY=your_key \\"
    echo "    -v /path/to/agent_runner.py:/opt/agent_runner.py:ro \\"
    echo "    -v /workspace:/workspace \\"
    echo "    ${IMAGE_NAME}:${IMAGE_TAG}"
else
    echo "Build failed"
    exit 1
fi
