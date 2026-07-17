"""扫描 CVE-Factory 任务包，按是否"真实网络服务型"分类，产出候选清单。

用于 CVELab 接入：CVELab atomizer 需要服务直接 up 起来、暴露端口、能从外部
网络攻击。CVE-Factory 是 Terminal Bench client 模式（client 容器 sleep infinity
或跑 entrypoint.sh，test_vuln.py 在容器内测 localhost）。本脚本按 compose 的
command + test_vuln.py 的网络/mock 特征，把任务分成 candidate / weak / source / other。

用法:
    python scripts/scan_cve_factory_tasks.py \\
        --input-dir CVE-Factory/cve_tasks/trainset \\
        --output data/cve_factory_scan.csv
"""
import argparse
import csv
import re
import sys
from pathlib import Path

import yaml

# test_vuln.py 网络请求信号
NET_RE = re.compile(
    r"requests\.(get|post|put|delete|patch|head)|httpx|urllib|urlopen|"
    r"http\.client|aiohttp|websocket|socket\.|curl|http://|https://",
    re.IGNORECASE,
)
# test_vuln.py 源码 mock / 动态加载信号
MOCK_RE = re.compile(
    r"unittest\.mock|from unittest|import mock|patch\(|MagicMock|Mock\(|"
    r"importlib|spec_from_file|load_module|exec\(open|source_file_loader",
    re.IGNORECASE,
)
SLEEP_CMD_RE = re.compile(r"sleep\s+infinity|sleep\s+8640000", re.IGNORECASE)
CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def first_service_command(compose_path: Path) -> str:
    """提取 docker-compose.yaml 第一个 service 的 command 字段（去引号）。"""
    try:
        data = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    except Exception:
        return ""
    services = (data or {}).get("services") or {}
    if not services:
        return ""
    first = next(iter(services.values()))
    cmd = (first or {}).get("command", "")
    if isinstance(cmd, list):
        return " ".join(str(x) for x in cmd)
    return str(cmd or "")


def count_services(compose_path: Path) -> int:
    try:
        data = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    except Exception:
        return 0
    return len(((data or {}).get("services") or {}))


def expose_ports(dockerfile_path: Path) -> list[str]:
    ports = []
    for line in dockerfile_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.startswith("EXPOSE"):
            ports.extend(re.findall(r"\d+(?:/\w+)?", line))
    return ports


def dockerfile_from(dockerfile_path: Path) -> str:
    for line in dockerfile_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.startswith("FROM"):
            return line.split()[1] if len(line.split()) > 1 else ""
    return ""


def dockerfile_cmd(dockerfile_path: Path) -> str:
    for line in dockerfile_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.startswith(("CMD", "ENTRYPOINT")):
            return line.strip()
    return ""


def classify_service(compose_cmd: str) -> str:
    """按 compose command 判断服务启动方式。"""
    if not compose_cmd:
        return "none"
    if SLEEP_CMD_RE.search(compose_cmd):
        return "sleep_infinity"
    if "entrypoint.sh" in compose_cmd:
        return "entrypoint"
    # 直接起服务的命令
    if re.search(r"apache2-foreground|nginx|httpd|catalina|redis-server|mysqld|"
                 r"node |python.*runserver|python.*http\.server|gunicorn|uvicorn|"
                 r"server\.js|\.sh|server\b|memcached|postgres|mongo|etcd",
                 compose_cmd, re.IGNORECASE):
        return "direct_service"
    return "other"


def classify_test(test_vuln_path: Path) -> tuple[str, int, int]:
    if not test_vuln_path.exists():
        return "missing", 0, 0
    text = test_vuln_path.read_text(encoding="utf-8", errors="ignore")
    net = len(NET_RE.findall(text))
    mock = len(MOCK_RE.findall(text))
    if net and mock:
        return "mixed", net, mock
    if net:
        return "network", net, mock
    if mock:
        return "mock", net, mock
    return "other", net, mock


def classify_task(row: dict) -> str:
    """综合分类标签。

    主信号是 test_vuln.py 是否发网络请求（证明漏洞通过网络触发、服务真在跑）+
    是否有可暴露端口。service_type 仅作辅助：sleep_infinity + network 说明服务在
    测试里临时起，改造暴露端口要额外工作。
    """
    tst = row["test_type"]
    has_port = bool(row["expose_ports"])
    if tst == "mock":
        return "source_analysis"
    if tst == "network":
        if has_port:
            # sleep_infinity 型改造更重，单列
            return "weak_candidate" if row["service_type"] == "sleep_infinity" else "candidate"
        return "candidate_no_expose"
    if tst == "mixed":
        return "weak_candidate"
    return "other"


def scan_task(task_dir: Path, source_set: str = "") -> dict | None:
    cve_id = task_dir.name
    if not CVE_RE.match(cve_id):
        return None
    compose = task_dir / "docker-compose.yaml"
    dockerfile = task_dir / "Dockerfile"
    test_vuln = task_dir / "tests" / "test_vuln.py"
    task_yaml = task_dir / "task.yaml"

    compose_cmd = first_service_command(compose) if compose.exists() else ""
    service_type = classify_service(compose_cmd)
    test_type, net_n, mock_n = classify_test(test_vuln)

    # task.yaml 元数据
    difficulty = category = ""
    tags = ""
    if task_yaml.exists():
        try:
            ty = yaml.safe_load(task_yaml.read_text(encoding="utf-8")) or {}
            difficulty = str(ty.get("difficulty", "") or "")
            category = str(ty.get("category", "") or "")
            t = ty.get("tags") or []
            tags = ";".join(str(x) for x in t) if isinstance(t, list) else str(t)
        except Exception:
            pass

    row = {
        "cve_id": cve_id.upper(),
        "source_set": source_set,
        "service_type": service_type,
        "compose_command": compose_cmd[:80],
        "num_services": count_services(compose) if compose.exists() else 0,
        "expose_ports": " ".join(expose_ports(dockerfile)) if dockerfile.exists() else "",
        "dockerfile_from": dockerfile_from(dockerfile) if dockerfile.exists() else "",
        "dockerfile_cmd": dockerfile_cmd(dockerfile)[:60] if dockerfile.exists() else "",
        "has_task_deps_entrypoint": (task_dir / "task-deps" / "entrypoint.sh").exists(),
        "test_type": test_type,
        "test_net_signals": net_n,
        "test_mock_signals": mock_n,
        "difficulty": difficulty,
        "category": category,
        "tags": tags,
        "has_solution": (task_dir / "solution.sh").exists(),
    }
    row["label"] = classify_task(row)
    return row


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input-dir", required=True, nargs="+",
                    help="一个或多个 CVE-Factory 任务集目录（如 trainset trainset_0313_part1）")
    ap.add_argument("--output", default="data/cve_factory_scan.csv", help="输出 CSV 路径")
    args = ap.parse_args()

    rows = []
    for in_dir in args.input_dir:
        input_dir = Path(in_dir)
        if not input_dir.is_dir():
            print(f"input-dir not found: {input_dir}", file=sys.stderr)
            return 1
        source_set = input_dir.name
        for task_dir in sorted(input_dir.iterdir()):
            if not task_dir.is_dir():
                continue
            row = scan_task(task_dir, source_set=source_set)
            if row:
                rows.append(row)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0].keys()) if rows else ["cve_id"]
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    # 终端汇总
    from collections import Counter
    by_label = Counter(r["label"] for r in rows)
    by_service = Counter(r["service_type"] for r in rows)
    by_test = Counter(r["test_type"] for r in rows)
    print(f"扫描完成: {len(rows)} 个任务 → {out}")
    print("\n=== 综合分类 (label) ===")
    for k, v in by_label.most_common():
        print(f"  {k:24s} {v}")
    print("\n=== 服务启动方式 (service_type) ===")
    for k, v in by_service.most_common():
        print(f"  {k:20s} {v}")
    print("\n=== test_vuln 类型 (test_type) ===")
    for k, v in by_test.most_common():
        print(f"  {k:20s} {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())