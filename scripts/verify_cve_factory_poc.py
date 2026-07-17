#!/usr/bin/env python3
"""Verify a CVE-Factory task by running its test_vuln.py inside a host-built
container (no DinD). Confirms CVE-Factory CVEs can be deployed as atom assets.

CVE-Factory test convention: test_vuln.py FAILS in the vulnerable state
(vulnerability exploitable) and PASSES in the fixed state. So a non-zero
pytest exit code means the vulnerability IS exploitable -> verified=True.

Flow per CVE:
  1. docker build --network host (git clone via host network)
  2. docker run -d with entrypoint wrapped to keep running; mount tests/ dir
  3. wait for service ready (probe port inside container)
  4. run pytest test_vuln.py INSIDE the container (localhost reaches service)
  5. non-zero exit = vulnerability detected = verified=True
  6. cleanup container
"""
import os, re, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _run(cmd, timeout=60, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)


def _extract_port(task_dir: Path) -> str | None:
    df = task_dir / "Dockerfile"
    if df.exists():
        for line in df.read_text(errors="replace").splitlines():
            m = re.match(r"\s*EXPOSE\s+(\d+)", line)
            if m:
                return m.group(1)
    tv = task_dir / "tests" / "test_vuln.py"
    if tv.exists():
        m = re.search(r"localhost:(\d+)", tv.read_text(errors="replace")[:800])
        if m:
            return m.group(1)
    return None


def _entrypoint_arg(task_dir: Path) -> str:
    df = task_dir / "Dockerfile"
    if df.exists():
        text = df.read_text(errors="replace")
        for line in text.splitlines():
            m = re.match(r"\s*COPY\s+(\S*entrypoint\.sh)\s+(\S+)", line)
            if m:
                return f"bash {m.group(2).rstrip('/')}"
        for line in text.splitlines():
            m = re.search(r'["\']?(\S*entrypoint\.sh)["\']?', line)
            if line.strip().startswith("CMD") and m:
                return f"bash {m.group(1)}"
    return "bash /entrypoint.sh"


def verify_one(task_dir: Path, cve_id: str, keep_on_fail: bool = False) -> dict:
    result = {"cve_id": cve_id, "verified": False}
    image = f"cve-{cve_id.lower()}:vuln"
    container = f"poc-verify-{cve_id.lower()}"

    # 1. build
    build = _run(["docker", "build", "-t", image, "-f", str(task_dir/"Dockerfile"),
                  "--network", "host", str(task_dir)], timeout=900)
    if build.returncode != 0:
        result["error"] = f"build failed: {build.stderr[-400:]}"
        return result
    result["build"] = "ok"

    # 2. run (mount tests dir so test_vuln.py is available inside the container)
    _run(["docker", "rm", "-f", container], timeout=15)
    ep_arg = _entrypoint_arg(task_dir)
    tests_dir = task_dir / "tests"
    run_args = ["docker", "run", "-d", "--name", container, "--entrypoint", "sh"]
    if tests_dir.exists():
        run_args += ["-v", f"{tests_dir}:/tests:ro"]
    run_args += [image, "-c", ep_arg]
    run = _run(run_args, timeout=30)
    if run.returncode != 0:
        result["error"] = f"run failed: {run.stderr[-200:]}"
        return result

    # 3. wait for service ready (probe port inside container)
    port = _extract_port(task_dir)
    if not port:
        _run(["docker", "rm", "-f", container])
        result["error"] = "no service port found"
        return result
    ready = False
    for _ in range(40):
        # /dev/tcp is unreliable across base images; use python socket which
        # every CVE-Factory container ships (the app itself is python/node/go
        # but the base image has python3 for pip).
        probe = _run(["docker", "exec", container, "python3", "-c",
                     f"import socket;s=socket.create_connection(('127.0.0.1',{port}),2);s.close()"], timeout=10)
        if probe.returncode == 0:
            ready = True
            break
        time.sleep(3)
    if not ready:
        logs = _run(["docker", "logs", "--tail", "20", container], timeout=10).stdout
        if not keep_on_fail:
            _run(["docker", "rm", "-f", container])
        result["error"] = f"service not ready on {port}\n{logs[-400:]}"
        return result
    result["ready"] = True

    # 4. run test_vuln.py. The exploit effects (marker files, env reads) live in
    # the CVE container, so pytest MUST run inside it to observe them. Try
    # installing pytest in the CVE container first; if the image has no
    # python/pip (Node/Go), fall back to a separate python:3.12-slim container
    # that joins the CVE container's network (this can't see marker files, so
    # it only verifies HTTP-response-based tests, not file-based ones).
    pytest_rc, out = None, ""
    # 4a. try inside the CVE container
    inst = _run(["docker", "exec", container, "sh", "-c",
                 "python3 -m pip install -q pytest --break-system-packages 2>/dev/null; "
                 "python3 -m pytest --version 2>/dev/null"], timeout=120)
    if inst.returncode == 0:
        pytest = _run(["docker", "exec", "-w", "/tests", container,
                       "python3", "-m", "pytest", "test_vuln.py", "-v", "--tb=line",
                       "--no-header", "-o", "addopts=", "-p", "no:cacheprovider"], timeout=180)
        pytest_rc, out = pytest.returncode, (pytest.stdout or "") + (pytest.stderr or "")
        result["pytest_location"] = "cve_container"
    else:
        # 4b. fall back to a python:3.12-slim container joining CVE net namespace
        pytest_args = ["docker", "run", "--rm", "--network", f"container:{container}",
                       "-v", f"{tests_dir}:/tests:ro", "python:3.12-slim", "sh", "-c",
                       "pip install -q --break-system-packages pytest requests 2>/dev/null; "
                       "cd /tests && python -m pytest test_vuln.py -v --tb=line "
                       "--no-header -o addopts= -p no:cacheprovider"]
        pytest = _run(pytest_args, timeout=180)
        pytest_rc, out = pytest.returncode, (pytest.stdout or "") + (pytest.stderr or "")
        result["pytest_location"] = "sidecar_python"

    result["pytest_returncode"] = pytest_rc
    if pytest_rc in (126, 127):
        result["verified"] = False
        result["error"] = f"pytest not runnable (rc={pytest_rc}): {out[-300:]}"
    elif "no tests ran" in out or "collected 0 items" in out:
        result["verified"] = False
        result["error"] = "test_vuln.py collected 0 tests"
    else:
        # CVE-Factory convention: tests FAIL in vulnerable state -> non-zero = vuln exists
        result["verified"] = pytest_rc != 0
    result["pytest_tail"] = out[-700:]

    # 5. cleanup
    if not (keep_on_fail and not result["verified"]):
        _run(["docker", "rm", "-f", container], timeout=15)
    return result


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--cve", action="append", required=True)
    p.add_argument("--generated-dir", default="data/generated/cve_factory_wave1")
    p.add_argument("--keep-on-fail", action="store_true",
                   help="Keep container running on failure for debugging")
    args = p.parse_args()
    for cve in args.cve:
        td = ROOT / args.generated_dir / cve
        if not td.exists():
            print(f"{cve}: source not prepared"); continue
        print(f"=== {cve} ===")
        r = verify_one(td, cve, keep_on_fail=args.keep_on_fail)
        print(f"  verified={r['verified']} build={r.get('build','?')} ready={r.get('ready','?')} pytest_rc={r.get('pytest_returncode','?')}")
        if r.get("error"):
            print(f"  error: {r['error'][:200]}")
        if r.get("pytest_tail"):
            print(f"  pytest: {r['pytest_tail'][-400:]}")
        print()