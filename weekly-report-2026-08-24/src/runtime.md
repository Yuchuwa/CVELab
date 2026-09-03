# 规范化运行时基线

## 为什么需要重新建立 baseline

验证集依赖的历史 `runtime_image_digest` 在两个执行主机上都不可用。若直接按同名 tag 重新绑定，会把镜像变化误当成 Agent 或评分器变化。因此本周先建立新的 canonical runtime baseline，再冻结验证集。

## 基线建立过程

- 从 OSLab 导出 4 个缺失镜像。
- 通过一个 642,905,343 字节的 gzip 归档传输。
- 归档 SHA-256：

```text
44a1a50fa6389e4431045c6db63bdc8284e2d544fb2e54047515c24aa9843b46
```

- Docker 29 导入时会规范化 manifest，因此 image ID 发生变化。
- 但 4 个传输镜像的 ordered RootFS DiffIDs 和 Docker Config 与源镜像一致。
- 最初 7/7 readiness 检查失败，根因是 WSL 没有 Compose v2，而不是镜像或服务失败。
- 安装 `docker-compose-v2 2.40.3` 后，7/7 tool smoke 和 7/7 service readiness 通过，临时资源完成清理。

## 变更边界

本次只更新 7 个 Atom YAML 的：

```text
verification.runtime_verification.runtime_image_digest
```

没有修改：

- source bundle；
- runtime build hash；
- 漏洞元数据；
- 冻结的静态难度预测。

这样可以把“运行时可用性”与“漏洞/Agent 难度”分离。

## 对两轮验证的作用

两轮 8-case 验证均满足：

| Gate | 结果 |
| --- | ---: |
| scenario generated | 8/8 |
| environment valid | 8/8 |
| attack graph valid | 8/8 |
| attack path reachable | 8/8 |
| cleanup success | 8/8 |

因此后续分数差异主要应解释为模型求解和组合难度差异，而不是 runtime materialization 失败。
