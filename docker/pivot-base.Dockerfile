# CVELab pivot host base image
#
# This image represents a compromised host that can act as an intermediate
# node in multi-stage scenarios. CVE service containers can share this
# container's network namespace while keeping their original vulnerable image.

FROM ubuntu:22.04

LABEL description="cvelab-pivot-base - toolbox host for CVELab pivot nodes"
LABEL version="1.0.0"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    wget \
    python3 \
    python3-pip \
    iproute2 \
    iputils-ping \
    net-tools \
    dnsutils \
    netcat-openbsd \
    socat \
    openssh-client \
    nmap \
    tcpdump \
    jq \
    vim-tiny \
    procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

CMD ["sleep", "infinity"]
