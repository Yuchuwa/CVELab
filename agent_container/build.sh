#!/bin/bash
# 构建Agent容器镜像

IMAGE_NAME="security-researcher-agent"
IMAGE_TAG="latest"

echo "🔨 构建 Agent 容器镜像..."
echo "镜像名: ${IMAGE_NAME}:${IMAGE_TAG}"
echo "包含: Claude Code CLI + 安全研究工具"

# 构建镜像
docker build -t ${IMAGE_NAME}:${IMAGE_TAG} .

if [ $? -eq 0 ]; then
    echo "✅ 镜像构建成功!"
    echo ""
    echo "📋 镜像信息:"
    docker images ${IMAGE_NAME}:${IMAGE_TAG}
    echo ""
    echo "🔧 包含的工具:"
    echo "  - Claude Code CLI (@anthropic-ai/claude-code)"
    echo "  - nmap, netcat, curl, wget"
    echo "  - Python 3.12 + anthropic SDK"
    echo "  - jq, ripgrep, vim, tmux"
    echo ""
    echo "🚀 使用方法:"
    echo "  docker run -d --name agent \\"
    echo "    -e ANTHROPIC_API_KEY=your_key \\"
    echo "    -v /workspace:/workspace \\"
    echo "    ${IMAGE_NAME}:${IMAGE_TAG}"
else
    echo "❌ 镜像构建失败"
    exit 1
fi

