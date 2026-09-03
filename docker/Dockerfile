# Security Researcher Agent Container
# CVE reproduction environment with Claude Agent SDK

FROM kalilinux/kali-rolling

LABEL description="clab-agent - CVE reproduction with Claude Agent SDK (Kali-based)"
LABEL version="3.1.0"

ENV DEBIAN_FRONTEND=noninteractive

# Use stable mirror (tsinghua, HTTP)
RUN sed -i 's|http://http.kali.org/kali|http://mirrors.tuna.tsinghua.edu.cn/kali|g' /etc/apt/sources.list.d/kali.sources

# System deps first
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential gcc \
    ca-certificates curl wget git unzip \
    python3 python3-pip python3-dev \
    nmap netcat-openbsd smbclient sshpass \
    sqlmap nikto hydra john gobuster ffuf feroxbuster dirsearch dirb \
    openssh-client \
    impacket-scripts \
    net-tools dnsutils tcpdump iputils-ping iproute2 \
    jq vim sudo xxd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Java runtime (for ysoserial and other Java tools)
RUN apt-get update && \
    apt-get install -y --no-install-recommends default-jre && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN rm -f /usr/lib/python3.*/EXTERNALLY-MANAGED

# Install Python packages - Claude Agent SDK provides built-in tools (Bash, Read, Write)
RUN pip3 install --no-cache-dir \
    claude-agent-sdk==0.2.87 \
    requests \
    pexpect \
    paramiko \
    pysmb \
    pycryptodome \
    pyyaml

# agent_runner.py is mounted from host via volume at runtime
# (src/clab_builder/atomizer/agent/agent_runner.py -> /opt/agent_runner.py:ro)

# Create work user
RUN useradd -m -s /bin/bash agent && \
    usermod -aG sudo agent && \
    echo "agent ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers && \
    mkdir -p /workspace && \
    chown -R agent:agent /workspace

USER agent
WORKDIR /workspace

ENV PYTHONUNBUFFERED=1
ENV LANG=C.UTF-8

CMD ["tail", "-f", "/dev/null"]
