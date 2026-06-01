# Security Researcher Agent Container
# CVE reproduction and security research environment with Claude Code CLI

FROM ubuntu:22.04

LABEL description="Security Researcher Agent - CVE reproduction with Claude Code CLI"
LABEL version="1.0.0"

# Prevent interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Update and install system dependencies
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
    # Build essentials
    build-essential \
    software-properties-common \
    ca-certificates \
    gnupg \
    curl \
    wget \
    # Python
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    # Security research tools
    nmap \
    netcat-openbsd \
    git \
    sudo \
    # Network utilities
    net-tools \
    dnsutils \
    whois \
    tcpdump \
    iputils-ping \
    # Text processing
    jq \
    ripgrep \
    vim \
    tmux \
    # Web tools
    curl \
    wget \
    && apt-get autoremove -y \
    && apt-get autoclean \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js v20 (required for Claude Code CLI)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# Remove EXTERNALLY-MANAGED marker
RUN rm -f /usr/lib/python3.*/EXTERNALLY-MANAGED

# Install Claude Code CLI globally
RUN npm install -g @anthropic-ai/claude-code

# Install Python packages
RUN pip3 install --no-cache-dir \
    anthropic \
    requests \
    pyyaml

# Create non-root user for security
RUN useradd -m -s /bin/bash agent && \
    usermod -aG sudo agent && \
    echo "agent ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set up working directories
RUN mkdir -p /workspace /home/agent/.claude && \
    chown -R agent:agent /workspace /home/agent/.claude

# Switch to agent user
USER agent
WORKDIR /workspace

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV PATH="/home/agent/.local/bin:$PATH"

# Add Claude Code to PATH
ENV PATH="/usr/local/bin:$PATH"

# Default command - keep container running
CMD ["tail", "-f", "/dev/null"]
