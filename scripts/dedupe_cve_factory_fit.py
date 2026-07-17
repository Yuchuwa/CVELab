"""对 CVE-Factory 严格 fit 清单做按-CVE 去重，并产出/更新一组清单文件。

输入:
  - data/cve_factory_scan.csv          (scan_cve_factory_tasks.py 产出)
  - data/cve_factory_fit_tasks.txt     (严格 fit 清单, 含跨子集重复)

去重规则(保守, effort 最小导向):
  - 同一 CVE 跨子集出现多份时, 比较各版本信号, 选"更好"的
  - 信号优先级: has_solution > service_type(entrypoint>direct>other>none)
                > 单端口 > difficulty(easy>medium>hard) > test_net_signals
  - 0313 版本必须严格优于 trainset 才胜出; 持平则 trainset 优先(主集更稳定)

输出(覆盖):
  - data/cve_factory_fit_tasks.txt             (去重后, 每CVE一条路径)
  - data/cve_factory_direct_fit_ids.txt        (纯CVE ID, 大写)
  - data/cve_factory_direct_fit_task_paths.txt (去重后任务路径)
  - data/cve_factory_direct_fit_summary.json   (摘要+items)
  - data/cve_factory_direct_fit_duplicate_ids.json (重复明细+chosen)
"""
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

DATA = Path("data")
SVC_RANK = {"entrypoint": 3, "direct_service": 2, "other": 1, "none": 0}
DIFF_RANK = {"easy": 2, "medium": 1, "hard": 0}
SET_PRIORITY = {"trainset": 0, "trainset-2": 1, "trainset_0313_part1": 2,
                "trainset_0313_part2": 3}  # 持平时主集优先


def load_fit_and_rows():
    fit_paths = [l.strip() for l in (DATA / "cve_factory_fit_tasks.txt").read_text().splitlines() if l.strip()]
    rows_by_key = {}
    for r in csv.DictReader(open(DATA / "cve_factory_scan.csv")):
        rows_by_key[(r["source_set"], r["cve_id"])] = r
    # fit_paths 形如 "trainset/cve-2015-10023"
    keys = []
    for p in fit_paths:
        s, _, cve = p.partition("/")
        keys.append((s, cve.upper()))
    return fit_paths, rows_by_key, keys


def score(row):
    """返回 (sol, svc_rank, single_port, diff_rank, net) 元组, 越大越好。"""
    sol = 1 if row["has_solution"] == "True" else 0
    svc = SVC_RANK.get(row["service_type"], 0)
    ports = [p for p in row["expose_ports"].split() if p]
    single = 1 if len(ports) == 1 else 0
    diff = DIFF_RANK.get(row["difficulty"], 1)
    net = int(row["test_net_signals"]) if row["test_net_signals"].isdigit() else 0
    return (sol, svc, single, diff), net


def pick_winner(versions):
    """versions: [(key, row), ...] where key=(source_set, cve_id)。返回 (chosen_key, reason)。"""
    if len(versions) == 1:
        return versions[0][0], "unique"
    # 主信号元组 + 网络信号(仅作 tiebreaker, 需明显更高才翻转)
    scored = []
    for key, row in versions:
        main, net = score(row)
        scored.append((key, row, main, net))
    by_main = sorted(scored, key=lambda x: x[2], reverse=True)
    top_main = by_main[0][2]
    tied = [x for x in by_main if x[2] == top_main]
    if len(tied) == 1:
        w = tied[0]
        return w[0], f"strictly_better_main {w[2]}"
    # 主信号持平: 网络信号明显更高(>=3)才翻转
    tied.sort(key=lambda x: x[3], reverse=True)
    max_net = tied[0][3]
    clear = [x for x in tied if all(x[3] >= y[3] + 3 for y in tied if y[0] != x[0])]
    if clear:
        w = clear[0]
        return w[0], f"clearly_more_network_signals({w[3]})"
    # 持平 → trainset 优先
    tied.sort(key=lambda x: SET_PRIORITY.get(x[0][0], 9))
    w = tied[0]
    return w[0], f"tie_trainset_priority {w[2]}/{w[3]}"


def main():
    fit_paths, rows_by_key, keys = load_fit_and_rows()

    # 按 CVE 分组
    by_cve = defaultdict(list)
    for k in keys:
        if k not in rows_by_key:
            print(f"WARN: {k} 不在 scan.csv, 跳过", file=sys.stderr)
            continue
        by_cve[k[1]].append(k)

    chosen = {}          # cve_id -> (source_set, cve_id)
    dup_detail = {}      # cve_id -> {"paths":[...], "chosen":..., "reason":...}
    for cve, versions in sorted(by_cve.items()):
        vers = [(k, rows_by_key[k]) for k in versions]
        win, reason = pick_winner(vers)
        chosen[cve] = win
        if len(versions) > 1:
            dup_detail[cve] = {
                "paths": [f"{k[0]}/{k[1].lower()}" for k in versions],
                "chosen": f"{win[0]}/{win[1].lower()}",
                "reason": reason,
            }

    # 排序: 按 source_set 优先级 + cve_id
    ordered = sorted(chosen.items(), key=lambda kv: (SET_PRIORITY.get(kv[1][0], 9), kv[0]))
    paths = [f"{s}/{c.lower()}" for c, (s, _) in ordered]

    # 写 fit_tasks.txt (覆盖)
    (DATA / "cve_factory_fit_tasks.txt").write_text("\n".join(paths) + "\n", encoding="utf-8")
    # 写 ids.txt (大写)
    (DATA / "cve_factory_direct_fit_ids.txt").write_text("\n".join(c for c, _ in ordered) + "\n", encoding="utf-8")
    # 写 task_paths.txt (小写路径, 与另一session格式一致)
    (DATA / "cve_factory_direct_fit_task_paths.txt").write_text("\n".join(paths) + "\n", encoding="utf-8")
    # 写 summary.json
    summary = {
        "count": len(ordered),
        "unique_cve_ids": len(ordered),
        "source_root": "/home/hanlin/CVELab/CVE-Factory/cve_tasks",
        "selection_rule": "single-service + compose starts service (entrypoint/direct) + test_vuln network requests + TCP EXPOSE port; dedup by CVE (trainset priority unless 0313 strictly better)",
        "items": [{"cve_id": c, "task_path": f"{s}/{c.lower()}"} for c, (s, _) in ordered],
    }
    (DATA / "cve_factory_direct_fit_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    # 写 duplicate_ids.json
    dup_json = {
        "task_count_before_dedup": len(keys),
        "unique_cve_ids": len(ordered),
        "duplicate_id_count": len(dup_detail),
        "duplicates": dup_detail,
    }
    (DATA / "cve_factory_direct_fit_duplicate_ids.json").write_text(
        json.dumps(dup_json, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # 终端汇报
    print(f"去重前(含重复): {len(keys)} 条路径")
    print(f"去重后唯一 CVE: {len(ordered)}")
    print(f"重复 CVE: {len(dup_detail)}")
    # 选 0313 的有多少
    flip = sum(1 for d in dup_detail.values() if "trainset_priority" not in d["reason"] and "unique" not in d["reason"])
    flip_0313 = sum(1 for d in dup_detail.values() if d["chosen"].startswith("trainset_0313"))
    print(f"其中选 0313 版的: {flip_0313}")
    print(f"  - 因主信号严格更优: {sum(1 for d in dup_detail.values() if 'strictly_better' in d['reason'])}")
    print(f"  - 因网络信号明显更高: {sum(1 for d in dup_detail.values() if 'more_network' in d['reason'])}")
    print(f"  - 持平→trainset优先: {sum(1 for d in dup_detail.values() if 'tie_trainset' in d['reason'])}")
    print("\n输出文件:")
    for f in ["cve_factory_fit_tasks.txt", "cve_factory_direct_fit_ids.txt",
              "cve_factory_direct_fit_task_paths.txt", "cve_factory_direct_fit_summary.json",
              "cve_factory_direct_fit_duplicate_ids.json"]:
        print(f"  data/{f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
