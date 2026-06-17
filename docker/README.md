# Agent容器镜像

## 说明

这个Docker镜像用于运行安全研究员Agent，包含CVE复现所需的所有工具。

## 包含的工具

### 网络工具
- `curl` - HTTP客户端
- `wget` - 文件下载
- `netcat` (nc) - 网络连接工具
- `nmap` - 端口扫描
- `tcpdump` - 网络抓包
- `ping` - ICMP测试
- `nslookup`/`dig` - DNS查询

### 开发工具
- `git` - 版本控制
- `vim` - 文本编辑
- `python3` - Python 3.11
- `pip3` - Python包管理

## 构建镜像

```bash
cd agent_container
./build.sh
```

或手动构建：

```bash
docker build -t security-researcher-agent:latest .
```

### 构建 Pivot Host 镜像

多阶段场景中，如果 CVE 服务容器本身缺少 shell、Python、curl、socat 等基础能力，可以让 CVE 服务共享一个 pivot host 容器的网络命名空间。pivot host 镜像用下面的 Dockerfile 构建：

```bash
docker build -f pivot-base.Dockerfile -t cvelab-pivot-base:latest .
```

该镜像用于 `post_exploit.requires_pivot_host: true` 的 atom；原始 CVE 服务镜像保持不变，只共享 pivot host 的网络。

## 使用镜像

```bash
docker run -d \
  --name agent \
  --network cve-network \
  -v /path/to/workspace:/workspace \
  security-researcher-agent:latest
```

## 镜像大小

优化后的镜像大小约200MB，包含所有必要工具。

## 扩展

如需添加更多工具，修改Dockerfile中的RUN apt-get install部分。

### Claude Code SDK集成

如需集成Claude Code SDK，在Dockerfile中添加：

```dockerfile
# 安装Claude Code SDK
RUN pip3 install claude-code-sdk

# 设置API密钥环境变量
# ENV ANTHROPIC_API_KEY=your_api_key_here
```
