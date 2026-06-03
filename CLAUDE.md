# CLAUDE.md

## Project Overview

**CVE Scenario Lab Builder** - 一个从 CVE 原子化到复杂网络攻防环境编排的全自动生成系统。

包含两个子项目：
- **atomizer** (项目一): Agent 驱动的单 CVE 原子化 - 从 CVE 信息生成 Ansible 配置 + 攻击 playbook
- **orchestrator** (项目二): 多 CVE 编排 - 从原子化 CVE 组合多阶段多节点的攻防环境

两个项目通过 `data/atoms/` 目录解耦：项目一写入，项目二消费。

## Project Structure

```
src/clab_builder/
├── cli.py              # Click CLI 入口 (clab-builder)
├── atomizer/           # 项目一: 单 CVE 原子化
│   ├── agent/          #   Agent 系统 (LLM + 工具调用)
│   ├── environment/    #   CVE 容器管理
│   ├── output/         #   Ansible 配置 + Playbook 生成
│   └── pipeline.py     #   流程编排
├── orchestrator/       # 项目二: 多 CVE 编排
│   ├── parser/         #   ContainerLab YAML 解析
│   ├── generator/      #   拓扑配置生成
│   ├── validator/      #   环境验证 (5 层网络测试)
│   └── composer/       #   Ground Truth 组合 (待实现)
├── shared/             # 共用模块
│   ├── catalog/        #   CVE 原子库 (32 个 verified catalog)
│   ├── models/         #   Pydantic 数据模型
│   ├── config/         #   配置管理
│   └── utils/          #   子网管理、日志等
data/
├── catalogs/verified/  # CVE 元数据 YAML (32 个)
└── atoms/              # 项目一产出 / 项目二消费
templates/basic/        # 拓扑模板
```

## CLI

```bash
clab-builder atom run <cve-id>      # Agent 驱动 CVE 原子化
clab-builder atom list              # 列出已生成的 atom
clab-builder scenario generate ...  # 编排多 CVE 场景
clab-builder scenario validate ...  # 验证部署的环境
clab-builder catalog list           # 列出 CVE catalog
```

## Key Technical Details

- Python 3.12+, uv 包管理, Click CLI, Pydantic 数据模型
- Agent 使用 LLM API (Anthropic 或兼容 API)
- Docker 隔离: CVE 环境容器 + Agent 容器独立运行
- ContainerLab 管理网络拓扑
- config.py 使用延迟加载，不再导入时 sys.exit

## Behavioral Guidelines

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:

- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:

- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:

- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:

- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:

```json
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.