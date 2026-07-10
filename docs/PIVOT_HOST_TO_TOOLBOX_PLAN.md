# 删除 pivot host、统一 bind-mount 静态 toolbox 方案

> 状态:已实施
> 日期:2026-07-03
> 涉及模块:`orchestrator/composer/scenario_assembler.py`

## 背景

项目二在组装场景时,为"弱漏洞节点攻陷后缺少工具"的问题引入了 pivot host 机制:给 target 套一层 `cvelab-pivot-base` 容器,漏洞服务容器通过 `network-mode: container` 共享其网络命名空间。经实测与代码审查,该机制存在根本性设计错位与多个部署隐患,需重构为统一 bind-mount 静态工具箱方案。

## 一、问题诊断

### 1.1 pivot host 机制现状

`scenario_assembler.py` 中 `_needs_runtime_pivot_host(atom, is_intermediate)` 判定是否生成 pivot host:

- `atom.post_exploit.requires_pivot_host == True`,或
- 该 atom 是中间节点且 `pivot_capability == NONE`

触发后(`scenario_assembler.py:133-143`):
- `target-N` → pivot host(`cvelab-pivot-base:latest`,`sleep infinity`),持有 eth1 链路与 netns
- `target-N-service` → 漏洞服务容器(`atom.docker_image`),`network-mode: container:clab-{scenario}-target-N`

### 1.2 三个核心问题

**问题 1:工具箱攻击者用不到(设计错位)**

`network-mode: container:` 只共享**网络命名空间**,不共享文件系统/pid。攻击者通过 RCE 拿到的 shell 落在漏洞服务容器(`target-N-service`),而工具箱在 pivot host(`target-N`)里——两者 mnt/pid 隔离,工具不可见。

**问题 2:`cvelab-pivot-base:latest` 无构建定义**

被 20 个 atom 引用,但全仓库无 Dockerfile/构建脚本。本地未手动 build 则部署失败。

**问题 3:启动顺序竞态**

`network-mode: container:clab-{scenario}-{node}` 要求 pivot host 先于 service 容器启动。ContainerLab 不保证顺序,间歇性部署失败。

### 1.3 弱环境实测数据

对 31 个本地 vulhub 镜像探测工具存量:

| 工具 | 覆盖 |
|---|---|
| bash | 30/31 |
| perl | 22/31(9 个无) |
| curl | ~22/31 |
| nc | 6/31 |
| python3 | 8/31 |

- 9 个无 perl 的镜像中,6 个有 nc;4 个(apisix×2、kibana×2)极弱,仅 bash+curl
- vulhub 的 `/bin/sh` 多为 dash,不支持 `/dev/tcp`;但 `/bin/bash` 是真 bash,`/dev/tcp` 可用
- 结论:确有弱环境,但 pivot host 并未解决

### 1.4 动态链接工具跨镜像不可用(验证)

将 `cvelab-pivot-base`(Ubuntu 22.04, glibc 2.35)的 curl 挂入异构镜像:

| 目标镜像 | libc | 失败原因 |
|---|---|---|
| `vulhub/nginx:1.4.2` | glibc 2.19 (Debian8) | `libcurl.so.4: cannot open shared object file` |
| `vulhub/httpd:2.4.43` | glibc 2.28 (Debian10) | `GLIBC_2.33 not found` |
| `vulhub/apisix:2.9` | musl (Alpine) | `no version information available` |

根因:pivot-base 工具全部动态链接 glibc,bind-mount 单二进制到异构镜像无法运行。**工具箱必须用静态编译二进制。**

## 二、目标对照

| 维度 | 现状(pivot host) | 改后(toolbox bind-mount) |
|---|---|---|
| 弱节点补工具 | sidecar 容器 + `network-mode: container` | 每个 target bind-mount 静态工具目录到 `/opt/toolbox:ro` |
| 工具可用性 | ❌ RCE shell 在 service 容器,工具在 pivot host,文件系统隔离 | ✅ 工具在 target 容器内,RCE shell 直接可用 |
| 镜像依赖 | 依赖 `cvelab-pivot-base:latest`(无 Dockerfile) | 无新镜像,仅静态二进制文件 |
| 启动竞态 | `network-mode: container` 要求 pivot host 先起 | 无,单容器 |
| 跨镜像兼容 | 动态链接 glibc,Debian8/Alpine 跑不起来 | 静态二进制,glibc/musl 通吃 |
| 代码路径 | `_needs_runtime_pivot_host` 分支 + 两容器 | 单一:每个 target 加一条 bind |

## 三、toolbox 内容与构建

### 3.1 目录与内容

仓库根 `assets/toolbox/`(与 `data/atoms/` 平级):

```
assets/toolbox/
├── build.sh     可复现获取脚本(提交)
├── busybox      官方 busybox 镜像提取,静态 — 含 nc/wget/telnet/httpd/sh/awk/sed/dd(gitignore)
└── socat        静态编译 — 端口转发/横向 pivot(gitignore)
```

二进制文件本身 gitignore,仅提交 `build.sh`。

### 3.2 build.sh

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# busybox: 官方镜像本身就是静态,单文件含 nc/wget/telnet/httpd/sh 等
docker run --rm busybox:latest cat /bin/busybox > busybox
chmod +x busybox

# socat: 先取 Alpine 的 socat,验证跨镜像可用性;若 musl 动态版不通则改现场静态编译
docker run --rm alpine:latest sh -c '
  apk add --no-cache socat >/dev/null 2>&1
  cat $(command -v socat)' > socat 2>/dev/null || echo "socat 需手动放(见方案 3.3)"
chmod +x socat 2>/dev/null || true
```

### 3.3 socat 静态化说明

Alpine 的 socat 动态链接 musl。musl 单一 libc 跨镜像兼容性优于 glibc,但仍可能在非 musl 镜像失败。若验证不通,补现场编译:

```bash
docker run --rm alpine:latest sh -c '
  apk add --no-cache build-base openssl-dev openssl-libs-static
  wget -qO- https://www.dest-unreach.org/socat/download/socat-1.8.0.0.tar.gz | tar xz
  cd socat-1.8.0.0 && ./configure --enable-static && make -j
  cat socat' > socat
```

兜底:即使 socat 不可用,busybox 已覆盖 nc/wget/反弹,满足基本需求。

## 四、代码改动

全部集中在 `src/clab_builder/orchestrator/composer/scenario_assembler.py`。

### 4.1 assemble() 签名加 toolbox_dir 参数

与 `atoms_dir` 模式对齐,新增 `toolbox_dir: str = "assets/toolbox"`。

### 4.2 删除 pivot 分支,每个 target 加 toolbox bind

**当前**(`scenario_assembler.py:109-143`):

```python
is_intermediate = i < min(len(template.injection_points), len(atoms)) - 1
requires_pivot_host = _needs_runtime_pivot_host(atom, is_intermediate)
...
binds.append(f"{flag_file_name}:/flag.txt")
node_def["binds"] = binds
if requires_pivot_host:
    service_node_name = f"{node_name}-service"
    clab["topology"]["nodes"][node_name] = {
        "kind": "linux",
        "image": atom.post_exploit.pivot_host_image,
        "cmd": "sleep infinity",
    }
    node_def["network-mode"] = f"container:clab-{scenario_name}-{node_name}"
    clab["topology"]["nodes"][service_node_name] = node_def
else:
    clab["topology"]["nodes"][node_name] = node_def
```

**改后**:

```python
# CLab binds: init files (absolute) + FLAG file (relative) + toolbox (absolute, ro)
binds = []
atoms_path = Path(atoms_dir).resolve()
for init_file in atom.service_startup.init_files:
    abs_path = atoms_path / atom.cve_id / "init" / init_file.filename
    binds.append(f"{abs_path}:{init_file.container_path}")
binds.append(f"{flag_file_name}:/flag.txt")
toolbox_abs = Path(toolbox_dir).resolve()
binds.append(f"{toolbox_abs}:/opt/toolbox:ro")
node_def["binds"] = binds
clab["topology"]["nodes"][node_name] = node_def
```

删除:`is_intermediate`、`requires_pivot_host`、`service_node_name`、`_needs_runtime_pivot_host` 调用、整个 `if requires_pivot_host` 分支。

### 4.3 删除 _needs_runtime_pivot_host 函数

`scenario_assembler.py:54-62` 整个函数移除,连带 line 16 的 `PivotCapability` import。

### 4.4 injections / ground_truth 去掉 pivot 字段

**当前** `:172-181` 和 `:199-211` 含 `service_node`、`requires_pivot_host`。改后移除。下游 `verifier.py`、`sysfield_exporter.py`、`scenario_runner.py` 均未读取这两个字段(已确认),`injections` 里 `node_name` 即最终容器名。

### 4.5 _generate_base_yaml 不动

target IP/路由/flush eth0 用 `node_name`(`:439-452`),单容器仍叫 `target-N`,无需改动。toolbox bind 不影响 netns。

## 五、模型与 atom.yaml 处理

`AtomConfig.post_exploit`(`PivotCapability`/`requires_pivot_host`/`pivot_host_image`)和 20 个 `atom.yaml` 里的 `post_exploit` 块:**保留不动**。

- 保留可避免改 20 个 atom.yaml + 模型迁移,符合 CLAUDE.md「Surgical Changes」
- 它们降级为纯元数据(记录 CVE 原本是否需要 pivot),不再驱动运行时
- 可在后续清理时移除,本次不碰

## 六、测试改动

### 6.1 删除/重写 4 个 pivot 测试

- `tests/orchestrator/test_scenario_assembler.py:175-187` `test_pivot_host_atom_generates_host_and_service_nodes` → 删除
- `:189-202` `test_pivot_host_link_and_ip_allocation_use_host_node` → 删除
- `:204-225` `test_intermediate_weak_atom_auto_generates_pivot_host` → 删除
- `tests/orchestrator/test_scenario_pipeline.py:269-301` `test_dmz_simple_pivot_atom_writes_sysfield_playbook` → 删 pivot 断言,保留 SysField playbook 断言

### 6.2 新增 toolbox 测试

`tests/orchestrator/test_scenario_assembler.py`:

```python
def test_target_gets_toolbox_bind(self, assembler):
    atom = _make_atom()
    result = assembler.assemble("dmz_simple", [atom], atoms_dir=...,
                                toolbox_dir="assets/toolbox")
    binds = result["clab"]["topology"]["nodes"]["target-1"]["binds"]
    assert any(b.endswith(":/opt/toolbox:ro") for b in binds)
    # 单容器,无 -service 节点
    assert "target-1-service" not in result["clab"]["topology"]["nodes"]
```

helper `_make_atom` 的 `requires_pivot_host` 参数可保留(不影响)或简化移除。

## 七、CLI 透传

`generate`/`verify`/`batch` 命令调用链 `ScenarioPipeline.generate()` → `ScenarioAssembler.assemble()` 上,`toolbox_dir` 用默认值 `"assets/toolbox"` 即可,**无需加 CLI 选项**(与 `atoms_dir` 当前是否透传保持一致)。运行时 cwd 为仓库根,`assets/toolbox` 解析正确。

## 八、agent prompt 告知

`scenario_runner.py` `build_prompt()`(`:130-141`)在 target 描述里加一行:

```python
desc += f"- Toolbox: /opt/toolbox (busybox nc/wget, socat) — use if shell lacks tools\n"
```

让 agent 知道弱 shell 里能直接调用 `/opt/toolbox/busybox nc ...`。

## 九、验证清单

1. `bash assets/toolbox/build.sh` → 确认 busybox/socat 生成且 `file` 显示 statically linked
2. 静态兼容实测:把 busybox 挂进 `vulhub/nginx:1.4.2`(Debian8)、`vulhub/apisix:2.9`(Alpine)、`vulhub/httpd:2.4.43`(Debian10)三个异构镜像,`/tmp/busybox --help` 全部能跑
3. `pytest tests/orchestrator/test_scenario_assembler.py tests/orchestrator/test_scenario_pipeline.py -q` 全绿
4. `clab-builder generate dmz_simple -c CVE-2014-0160` → 检查生成 `clab.yaml` 里 target-1 有 `:/opt/toolbox:ro` bind,无 `target-1-service` 节点
5. (可选,需部署)`clab-builder verify dmz_simple -c <cve>` 部署后 `docker exec` 进 target,`ls /opt/toolbox` 存在且 `./busybox nc -h` 可用

## 十、改动文件清单

| 文件 | 改动 |
|---|---|
| `src/clab_builder/orchestrator/composer/scenario_assembler.py` | 删 pivot 分支/函数/字段,加 toolbox bind + `toolbox_dir` 参数 |
| `src/clab_builder/orchestrator/composer/scenario_runner.py` | prompt 加 toolbox 提示 |
| `tests/orchestrator/test_scenario_assembler.py` | 删 3 pivot 测试,加 1 toolbox 测试 |
| `tests/orchestrator/test_scenario_pipeline.py` | 删 pivot 断言 |
| `assets/toolbox/build.sh` | 新增 |
| `assets/toolbox/busybox`、`socat` | build.sh 生成(gitignore 二进制) |
| `.gitignore` | 加 `assets/toolbox/busybox`、`assets/toolbox/socat` |
| `shared/models/atom.py` | **不动**(保留 PostExploit 字段) |
| 20 个 `atom.yaml` | **不动** |

## 十一、风险与回退

- **风险**:socat 静态化可能需现场编译;若 musl 动态版跨镜像不通,build.sh 兜底只交付 busybox(busybox 已覆盖 nc/wget/反弹,够用)
- **回退**:改动集中在 `scenario_assembler.py` 单文件 + 测试,git revert 即可;atom.yaml/模型未动,无数据迁移

## 十二、待确认

1. **toolbox 内容**:`busybox + socat` 够,还是要加 static curl(部分 CVE 需 HTTPS)?
2. **atom.yaml/模型**:保留 `PostExploit` 字段不动(推荐),还是一并清理?
