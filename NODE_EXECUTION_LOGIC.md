# ContainerLab Builder - 节点执行逻辑详解

## 目录

1. [工作流概览](#工作流概览)
2. [节点详解](#节点详解)
   - [Generate 节点](#1-generate-节点)
   - [Builder 节点](#2-builder-节点)
   - [Validate 节点](#3-validate-节点)
   - [Deploy 节点](#4-deploy-节点)
   - [Configure 节点](#5-configure-节点)
   - [Fixer 节点](#6-fixer-节点)
3. [条件路由逻辑](#条件路由逻辑)
4. [状态流转图](#状态流转图)

---

## 工作流概览

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ContainerLab Builder                         │
│                        LangGraph 工作流架构                           │
└─────────────────────────────────────────────────────────────────────┘

                            user_request
                                  ↓
                    ┌────────────────────────┐
                    │   1. GENERATE          │
                    │   生成网络拓扑蓝图      │
                    │   (LLM + Vulhub集成)   │
                    └──────────┬─────────────┘
                               │ blueprint
                               ↓
                    ┌────────────────────────┐
                    │   2. BUILDER           │
                    │   生成YAML配置文件      │
                    │   (IPAM + 拓扑构建)    │
                    └──────────┬─────────────┘
                               │ yaml_path
                               ↓
                    ┌────────────────────────┐        ┌──────────────┐
                    │   3. VALIDATE          │◄───────┤   FIXER      │
                    │   静态验证拓扑配置      │        │   智能修复    │
                    └──────────┬─────────────┘        └──────┬───────┘
                               │ pass                       │
                               ↓                            │ 失败
                    ┌────────────────────────┐              │
                    │   4. DEPLOY            │◄─────────────┘
                    │   部署容器实验室        │
                    │   (containerlab)       │
                    └──────────┬─────────────┘
                               │ is_deployed=true
                               ↓
                    ┌────────────────────────┐
                    │   5. CONFIGURE         │
                    │   配置网络接口和路由    │
                    │   (并行配置)            │
                    └──────────┬─────────────┘
                               ↓
                            is_complete=true
                               ↓
                              END
```

---

## 节点详解

---

### 1. GENERATE 节点

**文件**: `node/generate.py`

**职责**: 使用 LLM 解析自然语言请求，生成逻辑网络拓扑蓝图

#### 执行流程

```
┌──────────────────────────────────────────────────────────────┐
│ Generate 节点执行逻辑                                         │
└──────────────────────────────────────────────────────────────┘

输入: GraphState
  - user_request: "创建一个包含 Kali 攻击机和 Redis 靶机的实验室..."

步骤 1: 初始化 LLM 和 Agent
  ├─ 使用 init_chat_model() 创建模型实例
  │   ├─ model_provider: "openai"
  │   ├─ model: config.llm_model (如 "gpt-4o")
  │   ├─ temperature: 0.3 (中等创造性)
  │   ├─ base_url: config.base_url
  │   └─ api_key: config.api_key
  │
  └─ 使用 create_agent() 创建 Agent
      ├─ system_prompt: generate_prompt (网络架构师提示词)
      ├─ tools: [search_vulnerability_image]
      └─ response_format: NetworkBlueprint (结构化输出)

步骤 2: 调用 LLM 生成拓扑
  ├─ agent.invoke({"messages": [{"role": "user", "content": user_request}]})
  │
  ├─ LLM 分析用户请求，可能:
  │   ├─ 直接设计拓扑
  │   └─ 调用 search_vulnerability_image 查询漏洞镜像路径
  │
  └─ 返回结构化响应:
      {
        "structured_response": NetworkBlueprint {
          lab_name: "redis-cve-lab",
          complexity: "simple",
          subnets: ["dmz", "internal"],
          nodes: [
            { name: "attacker", role: "endpoint", ... },
            { name: "router", role: "router", ... },
            { name: "redis-target", role: "vul-target", ... }
          ]
        }
      }

步骤 3: 提取结构化数据
  ├─ 验证 "structured_response" 存在
  ├─ 提取 NetworkBlueprint 对象
  └─ 记录日志: 蓝图生成成功

输出: GraphState
  ├─ blueprint: NetworkBlueprint 对象
  └─ (错误情况) error_logs: "Generate failed: ..."

异常处理:
  ├─ ValueError: 无 structured_response
  └─ Exception: 记录错误日志，返回 error_logs
```

#### 关键组件

**`generate_prompt`** - 网络架构师系统提示词
- 定义复杂度等级 (simple < 5节点, medium 5-15节点, complex > 15节点)
- 定义设计规则（命名、子网逻辑、路由器定义）
- 提供 Few-Shot 示例
- 指导如何使用 `search_vulnerability_image` 工具

**`NetworkBlueprint`** - 结构化输出格式
```python
class NetworkBlueprint(BaseModel):
    lab_name: str           # 实验室名称 (kebab-case)
    complexity: Literal     # "simple" | "medium" | "complex"
    subnets: List[str]      # 子网名称列表
    nodes: List[LogicalNode] # 节点列表
```

---

### 2. BUILDER 节点

**文件**: `node/builder.py` + `node/utils.py`

**职责**: 从逻辑蓝图生成 ContainerLab YAML 配置文件和网络配置 JSON

#### 执行流程

```
┌──────────────────────────────────────────────────────────────┐
│ Builder 节点执行逻辑                                           │
└──────────────────────────────────────────────────────────────┘

输入: GraphState
  - blueprint: NetworkBlueprint 对象

步骤 1: 获取 Session 信息
  ├─ session_id = get_current_session_id()
  ├─ output_dir = "./clab_out/{session_id}"
  └─ 修改 lab_name: "{original_name}-{session_id}"

步骤 2: 初始化 NetworkBuilder
  ├─ NetworkBuilder(blueprint, output_dir)
  │
  ├─ 初始化输出结构:
  │   ├─ clab_nodes: {}        # 节点定义
  │   ├─ clab_links: []        # 链路定义
  │   └─ subnet_map: {}        # 子网 → CIDR 映射
  │
  ├─ 初始化 IPAM:
  │   ├─ supernet: 10.0.0.0/8
  │   ├─ subnet_iterator: /24 子网迭代器
  │   └─ node_ip_map: {}       # 节点 → 子网 → IP 映射
  │
  └─ 清理旧文件:
      ├─ 删除旧的 .clab.yml
      └─ 删除旧的 clab-{lab_name} 目录

步骤 3: NetworkBuilder.build() 主流程
  │
  ├─ 3.1 _allocate_subnets()
  │   └─ 为每个逻辑子网分配 /24 CIDR
  │       例: dmz → 10.0.0.0/24, internal → 10.0.1.0/24
  │
  ├─ 3.2 _process_topology()
  │   │
  │   ├─ 按子网分组节点: subnet_members[subnet] = [node1, node2, ...]
  │   │
  │   ├─ 对每个节点调用 _create_clab_node():
  │   │   │
  │   │   ├─ if node.role == "vul-target":
  │   │   │   ├─ 解析 docker-compose.yml
  │   │   │   ├─ 提取 image, ports, environment
  │   │   │   └─ 创建节点定义 (无 exec 命令)
  │   │   │
  │   │   └─ else (router/endpoint):
  │   │       ├─ 根据 image_flavor 确定 Docker 镜像
  │   │       │   └─ _determine_image(flavor, role)
  │   │       ├─ router: 添加 sysctls {net.ipv4.ip_forward: "1"}
  │   │       └─ 创建节点定义 (无 exec 命令)
  │   │
  │   └─ 对每个子网调用 _wire_subnet():
  │       │
  │       ├─ L2 拓扑构建:
  │       │   ├─ if len(members) > 2:
  │       │   │   └─ 注入 bridge 节点 + 连接所有成员
  │       │   └─ elif len(members) == 2:
  │       │       └─ 点对点直连
  │       │
  │       └─ L3 IP 分配:
  │           ├─ router_ip_offset = 1   (.1, .2, .3...)
  │           ├─ user_lan_offset = 64   (.64, .65, .66...)
  │           ├─ 为路由器分配 .1, .2, ...
  │           └─ 为端点分配 .64, .65, ...
  │
  ├─ 3.3 _generate_frr_configs()
  │   │
  │   └─ 为所有 router 节点生成 FRR 配置:
  │       ├─ 创建 {output_dir}/{router_name}/daemons
  │       │   └─ zebra=yes, ospfd=yes
  │       ├─ 创建 {output_dir}/{router_name}/frr.conf
  │       │   ├─ hostname {name}
  │       │   ├─ loopback: 10.10.{idx}.1/32
  │       │   ├─ interface ethX: ip address {ip}/24
  │       │   └─ router ospf: network {subnet} area 0
  │       └─ 添加 binds 挂载配置文件
  │
  └─ 3.4 生成输出文件
      ├─ _generate_yaml_structure():
      │   └─ {
      │       name: "lab-name-sessionid",
      │       topology: {
      │         nodes: {node1: {...}, node2: {...}},
      │         links: [{endpoints: ["node1:eth1", "node2:eth1"]}]
      │       }
      │     }
      │   → {lab_name}.clab.yml
      │
      └─ _generate_config_json():
          └─ {
              lab_name: "...",
              subnets: {dmz: "10.0.0.0/24"},
              nodes: {
                attacker: {
                  role: "endpoint",
                  image: "kalilinux/kali-rolling:latest",
                  interfaces: [{name: "eth1", address: "10.0.0.64/24"}],
                  default_route: {gateway: "10.0.0.1"}
                }
              }
            }
            → {lab_name}.config.json

输出: GraphState
  ├─ yaml_path: "./clab_out/{session_id}/{lab_name}.clab.yml"
  ├─ json_path: "./clab_out/{session_id}/{lab_name}.config.json"
  └─ error_logs: "" (成功时)
```

#### IP 分配策略

| 子网成员 | IP 范围 | 示例 |
|---------|--------|------|
| 路由器 | 10.X.X.1 - 10.X.X.63 | 10.0.0.1, 10.0.0.2 |
| 端点/靶机 | 10.X.X.64 - 10.X.X.254 | 10.0.0.64, 10.0.0.65 |

#### 镜像映射

| image_flavor | Docker 镜像 |
|-------------|------------|
| kali | kalilinux/kali-rolling:latest |
| alpine | alpine:latest |
| ubuntu | ubuntu:latest |
| redis | redis:latest |
| nginx | nginx:latest |
| (router) | frrouting/frr:v8.4.1 |

---

### 3. VALIDATE 节点

**文件**: `node/validate.py`

**职责**: 静态验证生成的 YAML 配置是否正确

#### 执行流程

```
┌──────────────────────────────────────────────────────────────┐
│ Validate 节点执行逻辑                                          │
└──────────────────────────────────────────────────────────────┘

输入: GraphState
  - yaml_path: "/path/to/file.clab.yml"

步骤 1: 读取 YAML 文件
  ├─ 使用 yaml.safe_load() 解析文件
  ├─ 提取: topology.nodes, topology.links
  └─ 失败则返回: "ERROR_TYPE:VALIDATE Invalid YAML syntax"

步骤 2: validate_topology() - 静态分析
  │
  ├─ 构建辅助数据结构:
  │   ├─ node_interfaces: {node: [eth1, eth2, ...]}  # 物理接口占用
  │   ├─ global_ips: {ip: node}                      # IP 全局映射
  │   ├─ node_ip_objs: {node: [IPv4Interface, ...]}  # 节点 IP 对象
  │   └─ adjacency: {node: [neighbor1, neighbor2]}   # 邻居关系图
  │
  ├─ Check 1: L1 物理接口排他性
  │   └─ 遍历所有 links:
  │       ├─ 验证 endpoints.length == 2
  │       ├─ 验证节点存在性
  │       ├─ 检测接口重复使用
  │       └─ 记录: used_endpoints, node_interfaces, adjacency
  │
  ├─ Check 2: 路由器接口隔离 (同网段检查)
  │   └─ 防止 ARP Flux: 同一节点不能有多个接口在同一子网
  │
  ├─ Check 3: 管理网段冲突检测
  │   └─ 检测 IP 是否与 172.20.20.0/24 (containerlab 管理网) 冲突
  │
  ├─ Check 4: 网关可达性 (下一跳检查)
  │   └─ 对于每个静态路由:
  │       ├─ 检查网关 IP 是否存在于网络中
  │       └─ 检查网关 IP 是否在本地接口的子网内
  │
  ├─ Check 5: 操作系统能力 (工具缺失)
  │   └─ 检查:
  │       ├─ 非 Alpine 镜像使用 ip 命令前是否安装 iproute2
  │       └─ 安装命令必须在配置命令之前
  │
  ├─ Check 6: 命令执行顺序
  │   └─ install_cmd_index < first_ip_cmd_index
  │
  ├─ Check 7: 全局 IP 唯一性
  │   └─ 检测重复 IP 地址
  │
  └─ Check 8: 链路状态依赖
      └─ 检查配置 IP 的接口是否有对应的物理链路

步骤 3: 生成验证结果
  ├─ result.valid: True/False
  ├─ result.errors: ["[L1 Error] ...", "[L3 Error] ..."]
  └─ result.warnings: ["[Routing Warning] ..."]

输出: GraphState
  ├─ error_logs: "" (验证通过)
  └─ error_logs: "ERROR_TYPE:VALIDATE Validation failed:\n..." (失败)
```

#### 错误类型

| 错误前缀 | 含义 | 示例 |
|---------|------|------|
| `[L1 Error]` | 物理层错误 | 接口重复使用 |
| `[L3 Error]` | 网络层错误 | IP 冲突、同网段多接口 |
| `[Routing Error]` | 路由错误 | 网关不可达 |
| `[Sys Error]` | 系统错误 | 缺少必要工具 |
| `[Config Error]` | 配置错误 | 配置不存在的接口 |

---

### 4. DEPLOY 节点

**文件**: `node/deploy.py`

**职责**: 使用 ContainerLab 部署容器实验室

#### 执行流程

```
┌──────────────────────────────────────────────────────────────┐
│ Deploy 节点执行逻辑                                            │
└──────────────────────────────────────────────────────────────┘

输入: GraphState
  - yaml_path: "/path/to/file.clab.yml"
  - blueprint: NetworkBlueprint

步骤 1: 环境检测
  ├─ check_containerlab_needs_sudo()
  │   ├─ 尝试: "containerlab version"
  │   ├─ 成功 → 不需要 sudo
  │   └─ 失败 → 需要 sudo
  │
  └─ get_sudo_prefix() → "sudo " 或 ""

步骤 2: 启动外部容器 (ext-container/vul-target)
  │
  └─ start_external_containers(blueprint):
      ├─ [BUG] 查找 role == "ext-container" (实际是 "vul-target")
      │   └─ 当前会跳过此步骤！
      │
      ├─ 对每个 ext-container:
      │   ├─ 定位 docker-compose.yml
      │   ├─ 修改配置:
      │   │   ├─ 设置 container_name
      │   │   └─ 清空 ports: []
      │   ├─ 生成临时 override 文件
      │   ├─ 执行: docker compose up -d
      │   └─ 删除临时文件
      │
      └─ 返回 True/False

步骤 3: 预清理 (Pre-Clean)
  └─ containerlab destroy -t {yaml_path} --cleanup
      └─ 清理之前的部署

步骤 4: 流式部署
  │
  └─ run_command_streaming():
      ├─ 执行: containerlab deploy -t {yaml_path} --reconfigure
      ├─ 实时打印输出到日志
      ├─ 超时检测: config.timeout_seconds
      └─ 返回: (return_code, full_output)

步骤 5: 错误类型判断
  │
  └─ if return_code != 0:
      ├─ 检查错误日志关键词:
      │   ├─ "permission denied" → ERROR_TYPE_SYSTEM
      │   ├─ "docker not running" → ERROR_TYPE_SYSTEM
      │   ├─ "out of memory" → ERROR_TYPE_SYSTEM
      │   └─ 其他 → ERROR_TYPE_DEPLOY
      │
      ├─ 截断日志 (避免 token 过多)
      └─ 返回 error_logs

步骤 6: 修复文件权限
  │
  └─ fix_permissions(output_dir):
      ├─ 检测 $SUDO_USER
      ├─ 执行: chown -R $SUDO_USER:$SUDO_USER {path}
      └─ 使 VSCode 等工具能读取状态文件

步骤 7: 健康检查
  │
  └─ wait_for_lab_healthy():
      ├─ 轮询: containerlab inspect -t {yaml_path} --format json
      ├─ 解析容器状态
      ├─ 检查所有容器是否 "running"
      ├─ 重试: max_retries 次，间隔 interval 秒
      └─ 返回: (is_healthy, inspect_data)

步骤 8: 应用网络配置
  │
  └─ 调用 node/apply_config.py:
      ├─ 提取 lab_name
      ├─ 读取 {lab_name}.config.json
      ├─ 对每个节点:
      │   ├─ 获取容器 PID
      │   ├─ 使用 nsenter 执行:
      │   │   ├─ ip addr add {address} dev {interface}
      │   │   ├─ ip link set dev {interface} up
      │   │   └─ ip route replace default via {gateway}
      │   └─ router: 重启 FRR
      └─ 返回成功/失败

输出: GraphState
  ├─ error_logs: "" (成功)
  ├─ is_deployed: True
  ├─ inspect_data: {lab_name: [{name, state, ...}]}
  └─ (失败) error_logs: "ERROR_TYPE:DEPLOY ..." 或 "ERROR_TYPE:SYSTEM ..."
```

#### 关键函数

| 函数 | 职责 |
|-----|------|
| `check_containerlab_needs_sudo()` | 检测是否需要 sudo |
| `run_command_streaming()` | 实时执行命令并打印输出 |
| `start_external_containers()` | 启动 Vulhub 外部容器 |
| `wait_for_lab_healthy()` | 等待所有容器 Running |
| `fix_permissions()` | 修复文件所有权 |

---

### 5. CONFIGURE 节点

**文件**: `node/configure.py`

**职责**: 使用 Agent 并行配置所有容器的网络接口

#### 执行流程

```
┌──────────────────────────────────────────────────────────────┐
│ Configure 节点执行逻辑                                         │
└──────────────────────────────────────────────────────────────┘

输入: GraphState
  - inspect_data: {lab_name: [{name, state, ...}]}
  - yaml_path: "/path/to/file.clab.yml"

步骤 1: 解析容器列表
  ├─ 从 inspect_data 提取容器列表
  ├─ 提取 lab_name
  └─ 检查容器数量

步骤 2: 读取 YAML 配置
  ├─ yaml.safe_load(yaml_path)
  ├─ 提取 topology.nodes
  └─ 获取每个节点的 exec 命令

步骤 3: 准备配置任务
  │
  └─ _prepare_config_tasks():
      └─ 对每个容器:
          ├─ 提取短名称: "clab-{lab}-{node}" → "node"
          ├─ 获取预期配置: nodes_config[node_short_name]
          ├─ 提取 exec 命令列表
          └─ 返回: tasks = [{container, container_name, ...}]

步骤 4: 并行配置所有节点
  │
  └─ _configure_nodes_parallel(tasks):
      │
      ├─ 获取 session_id (传递给子线程)
      ├─ max_workers = min(len(tasks), config.max_configure_workers)
      │
      └─ ThreadPoolExecutor:
          ├─ 提交所有任务: executor.submit(_configure_single_node, task, session_id)
          │
          └─ 对每个任务:
              │
              └─ _configure_single_node():
                  │
                  ├─ [子线程] 设置 session_id
                  ├─ 初始化 LLM 和 Agent:
                  │   ├─ model = init_chat_model(...)
                  │   ├─ agent = create_agent(
                  │   │       model=model,
                  │   │       system_prompt=configure_prompt,
                  │   │       tools=[node_config_tool])
                  │   │
                  │   └─ agent.invoke({
                  │       "messages": [{
                  │         "role": "user",
                  │         "content": config_task
                  │       }]
                  │     })
                  │
                  ├─ 提取 Agent 响应
                  ├─ 检查配置是否成功 (_check_config_success)
                  │   ├─ 检测成功指示词: "✅", "pass", "configured successfully"
                  │   └─ 检测失败指示词: "failed", "error:", "not found"
                  │
                  └─ 返回: {node, success, message, logs}

步骤 5: 聚合结果
  ├─ success_count = sum(result["success"])
  ├─ fail_count = len(results) - success_count
  └─ 记录失败的节点

输出: GraphState
  └─ is_complete: True
```

#### Configure Prompt

Agent 会执行以下诊断和修复：

```
1. DIAGNOSE (诊断)
   - ip addr show       # 查看接口和 IP
   - ip route show      # 查看路由表
   - which ip           # 检查工具是否安装

2. VERIFY (验证)
   - 检查接口是否配置了 IP
   - 检查默认路由是否存在
   - 检查接口是否 UP

3. FIX (修复)
   - 安装工具: apk add iproute2 / apt-get install iproute2
   - 配置 IP: ip addr add {ip}/{mask} dev {iface}
   - 启动接口: ip link set {iface} up
   - 添加路由: ip route replace default via {gateway}

4. VERIFY (验证修复)
   - 再次运行 ip addr show 确认
```

---

### 6. FIXER 节点

**文件**: `node/fixer.py`

**职责**: 智能分析错误并路由到对应的修复策略

#### 执行流程

```
┌──────────────────────────────────────────────────────────────┐
│ Fixer 节点执行逻辑                                             │
└──────────────────────────────────────────────────────────────┘

输入: GraphState
  - error_logs: "ERROR_TYPE:XXX ..."
  - retry_count: 当前重试次数
  - user_request: 原始用户请求
  - blueprint / yaml_path

步骤 1: 熔断机制检查
  │
  ├─ if retry_count >= max_retries:
  │   └─ raise RuntimeError("Max retries reached")
  │
  └─ retry_count++

步骤 2: 静态错误类型判断
  │
  ├─ 场景 1: ERROR_TYPE_BUILD (蓝图设计问题)
  │   │
  │   ├─ 调用 _call_suggestion_agent():
  │   │   ├─ 初始化 LLM (temperature=0.7, 高创造性)
  │   │   ├─ 分析错误日志
  │   │   ├─ 生成改进建议 (SuggestionResult)
  │   │   └─ 返回: "• 使用标准镜像 alpine:latest\n• 简化子网结构"
  │   │
  │   ├─ 附加建议到 user_request
  │   │   └─ enhanced_request = original + "\n[修复建议]\n" + suggestion
  │   │
  │   └─ 返回状态:
  │       ├─ user_request: enhanced_request
  │       ├─ blueprint: None  # 清空，触发重新生成
  │       └─ retry_count: +1
  │
  ├─ 场景 2/3: ERROR_TYPE_VALIDATE / ERROR_TYPE_DEPLOY (配置问题)
  │   │
  │   ├─ 调用 _call_yaml_fix_agent():
  │   │   ├─ 读取当前 YAML
  │   │   ├─ 初始化 LLM (temperature=0.3, 低创造性)
  │   │   ├─ 分析错误 + 修复 YAML (YamlFixResult)
  │   │   │   ├─ 修改 IP 地址冲突
  │   │   │   ├─ 修正路由配置
  │   │   │   ├─ 调整命令执行顺序
  │   │   │   └─ 保持其他内容不变
  │   │   └─ 返回: {yaml_content, changes_summary}
  │   │
  │   ├─ 覆盖写入 YAML 文件
  │   │   └─ with open(yaml_path, 'w') as f: f.write(yaml_content)
  │   │
  │   └─ 返回状态:
  │       ├─ error_logs: ""
  │       └─ retry_count: +1
  │
  ├─ 场景 4: ERROR_TYPE_SYSTEM (系统错误)
  │   │
  │   └─ raise RuntimeError("Unrecoverable system error")
  │       └─ 终止工作流
  │
  └─ 场景 5: 未知错误类型
      └─ 默认降级处理，清空 error_logs，继续执行

输出: GraphState
  ├─ 场景 1: {user_request, blueprint=None, retry_count+1}
  ├─ 场景 2/3: {error_logs="", retry_count+1}
  └─ 场景 4: RuntimeError 异常
```

#### 错误类型标识符

| 错误类型 | 标识符 | 触发节点 | 修复策略 | 路由目标 |
|---------|--------|---------|---------|---------|
| 蓝图错误 | `ERROR_TYPE_BUILD` | Builder | 生成建议，重新生成蓝图 | Generator |
| 验证错误 | `ERROR_TYPE_VALIDATE` | Validator | 直接修改 YAML | Validator |
| 部署错误 | `ERROR_TYPE_DEPLOY` | Deployer | 直接修改 YAML | Validator |
| 系统错误 | `ERROR_TYPE_SYSTEM` | Deployer | 无法修复 | END |

---

## 条件路由逻辑

### main.py 中的路由函数

```python
def check_build_errors(state) -> str:
    """Builder 后的路由"""
    if not state.get("error_logs"):
        return "validator"   # 成功 → 验证
    return "fixer"            # 失败 → 修复

def check_validation_errors(state) -> str:
    """Validator 后的路由"""
    if not state.get("error_logs"):
        return "deployer"    # 成功 → 部署
    return "fixer"            # 失败 → 修复

def check_deploy_errors(state) -> str:
    """Deployer 后的路由"""
    if not state.get("error_logs") and state.get("is_deployed"):
        return "configurator"  # 成功 → 配置
    return "fixer"             # 失败 → 修复

def route_after_fixer(state) -> str:
    """Fixer 后的智能路由"""
    if state.get("blueprint") is None:
        return "generator"    # 蓝图被清空 → 重新生成
    return "validator"        # YAML 被修复 → 重新验证
```

---

## 状态流转图

```
GraphState 结构:

{
  "user_request": str,          # 用户输入 (不变或被 Fixer 增强)
  "blueprint": NetworkBlueprint, # 逻辑蓝图 (Builder 生成, Fixer 可能清空)
  "yaml_path": str,             # YAML 文件路径 (Builder 生成)
  "json_path": str,             # 配置 JSON 路径 (Builder 生成)
  "error_logs": str,            # 错误日志 (清空表示成功)
  "is_deployed": bool,          # 部署状态 (Deployer 设置)
  "inspect_data": Dict,         # 容器状态数据 (Deployer 生成)
  "retry_count": int,           # 重试计数 (Fixer 递增)
  "is_complete": bool           # 完成状态 (Configurator 设置)
}

状态流转:

START → {
  user_request: "...",
  blueprint: None,
  yaml_path: "",
  error_logs: "",
  is_deployed: False,
  inspect_data: {},
  retry_count: 0,
  is_complete: False
}

↓ (Generate)

{
  blueprint: NetworkBlueprint(...),
  ...
}

↓ (Builder)

{
  blueprint: NetworkBlueprint(...),
  yaml_path: "./clab_out/{session}/{lab}.clab.yml",
  json_path: "./clab_out/{session}/{lab}.config.json",
  ...
}

↓ (Validate) - 如果有错误

{
  error_logs: "ERROR_TYPE:VALIDATE ...",
  retry_count: 1
}

↓ (Fixer) - YAML 修复

{
  error_logs: "",
  yaml_path: "./clab_out/{session}/{lab}.clab.yml" (已修改),
  retry_count: 2
}

↓ (Validate) - 第二次验证通过

{
  error_logs: "",
  ...
}

↓ (Deploy)

{
  is_deployed: True,
  inspect_data: {...},
  ...
}

↓ (Configure)

{
  is_complete: True,
  ...
}

END
```

---

## 附录

### 已知问题

1. **角色名称不匹配** (`deploy.py:273`)
   - 代码查找 `role == "ext-container"`
   - 实际定义是 `role == "vul-target"`
   - 导致外部容器启动逻辑失效

2. **命令注入风险** (`deploy.py` 多处)
   - 使用 `shell=True` 执行命令
   - 路径参数未经过滤

3. **IP 分配硬编码** (`utils.py:238-254`)
   - 路由器: .1 - .63
   - 端点: .64 - .254
   - 大规模网络可能溢出

### 文件结构

```
containerlab_builder/
├── main.py                    # 工作流入口
├── state.py                   # 状态定义
├── config.py                  # 配置管理
├── logger.py                  # 日志系统
├── session_utils.py           # 会话管理
├── node/
│   ├── generate.py            # 生成节点
│   ├── builder.py             # 构建节点
│   ├── validate.py            # 验证节点
│   ├── deploy.py              # 部署节点
│   ├── configure.py           # 配置节点
│   ├── fixer.py               # 修复节点
│   ├── utils.py               # 工具类
│   └── apply_config.py        # 配置应用器
├── tools/
│   ├── search_vuln_image.py   # 漏洞镜像搜索
│   └── containerlab_tools.py  # ContainerLab 工具
└── test/
    └── integration_test.py    # 集成测试
```

---

**文档生成时间**: 2026-01-20
**项目版本**: master
**作者**: Claude Code
