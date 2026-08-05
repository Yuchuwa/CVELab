# SysArmor Watch Window Design

## 目标

把 CVELab 中 SysArmor signal 采集从 `before/after` 双快照改成持续 watcher 覆盖攻击窗口，支持：

- watcher ready
- attack start
- attack finish
- grace window
- watcher stop

同时保持 defended case 串行，不引入同 host 多个 Tetragon defended case 并发。

## 设计

### 1. 持续 watcher 会话

在每个 target 容器中启动一个长生命周期：

- `sysarmorctl --json signal watch --include-events`

其 stdout 写入每个 target 的 JSONL 文件，stderr 写入日志文件。会话元数据保存在 verifier 结果中。

### 2. 攻击窗口分类

采集结束后按每个 frame 的 `signalFrame.observedAt/observed_at` 分类为：

- `pre_attack`
- `attack_window`
- `grace_window`

### 3. 输出字段

结果显式保存为：

- `signals_stream_all`
- `signals_pre_attack`
- `signals_attack_window`
- `signals_grace_window`

### 4. 检测口径

当前 detection 结果改为基于 `attack_window`：

- `signal_detected = attack_executed and attack_window_count > 0`

grace window 单独记录，不默认计入正式命中。

## 范围

本次只改：

- `sysarmor_runtime.py`
- `verifier.py`
- 对应测试

`export_sysarmor_signals.py` 直接切到新显式字段，不再保留旧 `signals_before` / `signals_after`。
