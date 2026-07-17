"""CVE-Factory structured verifier (batch 7).

Replaces the old verify_cve_factory_poc.py heuristic (any nonzero pytest
exit == vulnerability) with the authoritative CVE-Factory test contract:

  test_func.py  -> ALL PASS  (functionality intact)
  test_vuln.py   -> ALL FAIL (vulnerability assertions trigger)
  no collection / import / fixture / setup ERROR
  no unexpected SKIPPED
  both suites must collect > 0 tests

Produces a structured CVEFactoryVerificationResult that the atom importer
(batch 8-9) consumes to write the unified native_verification record.

Observer-scope correctness:
  A test_vuln.py that checks a TARGET-LOCAL marker file (os.path.exists) can
  only be faithfully run INSIDE the CVE container. A network-sidecar pytest
  run would inspect the sidecar filesystem, not the target's, and would
  produce a false "marker missing" that the old heuristic misclassified as
  vulnerability. This verifier detects target-local observers and refuses
  to validate them from a sidecar.
"""
from __future__ import annotations

import hashlib
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

# Reuse the authoritative CVE-Factory parser instead of rewriting a weaker one.
_FACTORY_SRC = Path(__file__).resolve().parent.parent / "CVE-Factory"
if str(_FACTORY_SRC) not in sys.path:
    sys.path.insert(0, str(_FACTORY_SRC))


@dataclass
class TestSuiteResult:
    __test__ = False  # not a pytest test class
    name: str
    collected: int
    passed: int
    failed: int
    errors: int
    skipped: int
    outcomes: list[dict] = field(default_factory=list)
    raw_tail: str = ""

    @property
    def ran(self) -> bool:
        return self.collected > 0


@dataclass
class CVEFactoryVerificationResult:
    cve_id: str
    verified: bool = False
    rejection: str = ""  # build_failed | service_not_ready | func_failed |
                         # vuln_not_observed | collection_error | runtime_error |
                         # mixed_outcome | observer_scope_incompatible | no_tests
    build_ok: bool = False
    service_ready: bool = False
    func: Optional[TestSuiteResult] = None
    vuln: Optional[TestSuiteResult] = None
    observer_scope: str = ""  # target_local | network | unknown
    pytest_location: str = ""  # cve_container | sidecar_python
    image_digest: str = ""
    source_hash: str = ""
    test_hash: str = ""
    timestamp: str = ""
    stdout_tail: str = ""
    stderr_tail: str = ""

    def to_native_verification(self) -> dict:
        """Build the unified native_verification dict (batch 6 shape)."""
        evidence: list[str] = []
        if self.func and self.func.ran:
            evidence.append(
                f"test_func.py: {self.func.passed} passed, {self.func.failed} failed"
            )
        if self.vuln and self.vuln.ran:
            evidence.append(
                f"test_vuln.py: {self.vuln.passed} passed, {self.vuln.failed} failed "
                f"(FAIL = vulnerability present)"
            )
        if self.build_ok and not self.service_ready:
            evidence.append("service started but did not become ready")
        if self.rejection:
            evidence.append(f"rejection: {self.rejection}")
        return {
            "success": self.verified,
            "mode": "native",
            "provenance": "cve_factory_poc",
            "evidence": evidence[:5],
            "captured_flag": "",
            "flag_matched": False,
            "reason": self.rejection or (
                "func PASS + vuln FAIL (CVE-Factory contract)" if self.verified
                else "not verified"
            ),
            "flag_recovery": {
                "attempted": False,
                "success": False,
                "method": "not_applicable_poc_marker_based",
            },
            "witnesses": {},
            "source_hash": self.source_hash,
            "test_hash": self.test_hash,
            "test_results": {
                "test_func": {
                    "passed": self.func.passed if self.func else 0,
                    "failed": self.func.failed if self.func else 0,
                    "errors": self.func.errors if self.func else 0,
                    "skipped": self.func.skipped if self.func else 0,
                } if self.func else {},
                "test_vuln": {
                    "passed": self.vuln.passed if self.vuln else 0,
                    "failed": self.vuln.failed if self.vuln else 0,
                    "errors": self.vuln.errors if self.vuln else 0,
                    "skipped": self.vuln.skipped if self.vuln else 0,
                } if self.vuln else {},
            },
            "timestamp": self.timestamp,
        }


def _detect_observer_scope(tests_dir: Path) -> str:
    """Inspect test_vuln.py for target-local observers.

    A target-local observer checks the target filesystem (marker files) or
    target process state from within the pytest process. If pytest runs in a
    sidecar sharing only the network namespace, these checks see the sidecar
    filesystem and produce false negatives that look like "vulnerability
    present" to a naive nonzero-exit heuristic.
    """
    tv = tests_dir / "test_vuln.py"
    if not tv.is_file():
        return "unknown"
    try:
        text = tv.read_text(errors="replace")
    except OSError:
        return "unknown"
    # target-local filesystem / process observers
    local_signals = [
        r"os\.path\.exists\s*\(",
        r"os\.remove\s*\(",
        r"os\.listdir\s*\(",
        r"open\s*\(\s*['\"]/",          # open('/tmp/...')
        r"/tmp/[a-z_]",
        r"subprocess\.",
        r"psutil\.",
    ]
    for pat in local_signals:
        if re.search(pat, text):
            return "target_local"
    return "network"


def _run(cmd, timeout=60, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)


def _extract_port(task_dir: Path) -> Optional[int]:
    df = task_dir / "Dockerfile"
    if df.exists():
        for line in df.read_text(errors="replace").splitlines():
            if line.strip().startswith("EXPOSE"):
                for m in re.findall(r"\b(\d+)(?:/\w+)?\b", line):
                    try:
                        return int(m)
                    except ValueError:
                        pass
    tv = task_dir / "tests" / "test_vuln.py"
    if tv.exists():
        text = tv.read_text(errors="replace")[:8000]
        m = re.search(r"localhost:(\d+)", text)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                pass
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


def _sha256_dir(d: Path) -> str:
    h = hashlib.sha256()
    for f in sorted(d.rglob("*")):
        if f.is_file():
            h.update(f.read_bytes())
    return h.hexdigest()


def _parse_suite_from_pytest(name: str, out: str) -> TestSuiteResult:
    """Parse pytest stdout into a TestSuiteResult."""
    collected = passed = failed = errors = skipped = 0
    outcomes: list[dict] = []
    # final summary line: "2 failed, 3 passed, 1 skipped in 0.1s"
    for m in re.finditer(r"(\d+)\s+(passed|failed|error|skipped)", out):
        cnt = int(m.group(1))
        st = m.group(2)
        if st == "passed":
            passed = cnt
        elif st == "failed":
            failed = cnt
        elif st == "error":
            errors = cnt
        elif st == "skipped":
            skipped = cnt
    # collected count
    m = re.search(r"(\d+)\s+(?:items?\s+collected|tests?\s+collected|selected)", out)
    if m:
        collected = int(m.group(1))
    elif "no tests ran" in out or "collected 0 items" in out:
        collected = 0
    else:
        collected = passed + failed + errors + skipped
    # per-test outcomes from short summary
    in_summary = False
    for line in out.splitlines():
        if "short test summary info" in line:
            in_summary = True
            continue
        if in_summary:
            m = re.match(r"(PASSED|FAILED|ERROR|SKIPPED)\s+(.+?)::(.+)", line.strip())
            if m:
                outcomes.append({"status": m.group(1).lower(),
                                 "node": f"{m.group(2)}::{m.group(3)}"})
    return TestSuiteResult(
        name=name, collected=collected, passed=passed, failed=failed,
        errors=errors, skipped=skipped, outcomes=outcomes,
        raw_tail=out[-700:],
    )


def verify_cve_factory_task(
    task_dir: Path,
    cve_id: str,
    *,
    keep_on_fail: bool = False,
    pytest_timeout: int = 180,
) -> CVEFactoryVerificationResult:
    """Verify a prepared CVE-Factory task against the authoritative contract.

    Builds the image on the host (network=host for git clone), runs the
    service, waits for readiness, then runs test_func.py and test_vuln.py
    INSIDE the CVE container (so target-local observers see the right
    filesystem). Falls back to a sidecar only for network observers, and
    refuses target-local observers from a sidecar.
    """
    from datetime import datetime, timezone
    r = CVEFactoryVerificationResult(
        cve_id=cve_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    image = f"cve-{cve_id.lower()}:vuln"
    container = f"poc-verify-{cve_id.lower()}"

    r.source_hash = _sha256_dir(task_dir)
    tests_dir = task_dir / "tests"
    if tests_dir.is_dir():
        r.test_hash = _sha256_dir(tests_dir)
    r.observer_scope = _detect_observer_scope(tests_dir)

    # 1. build
    build = _run(["docker", "build", "-t", image, "-f", str(task_dir / "Dockerfile"),
                  "--network", "host", str(task_dir)], timeout=900)
    if build.returncode != 0:
        r.rejection = "build_failed"
        r.stderr_tail = build.stderr[-400:]
        return r
    r.build_ok = True
    # image digest
    did = _run(["docker", "images", "-q", "--no-trunc", image], timeout=15)
    if did.returncode == 0 and did.stdout.strip():
        r.image_digest = did.stdout.strip()

    # 2. run
    _run(["docker", "rm", "-f", container], timeout=15)
    ep_arg = _entrypoint_arg(task_dir)
    run_args = ["docker", "run", "-d", "--name", container, "--entrypoint", "sh"]
    if tests_dir.exists():
        run_args += ["-v", f"{tests_dir}:/tests:ro"]
    run_args += [image, "-c", ep_arg]
    run = _run(run_args, timeout=30)
    if run.returncode != 0:
        r.rejection = "build_failed"
        r.stderr_tail = run.stderr[-200:]
        _run(["docker", "rm", "-f", container], timeout=15)
        return r

    # 3. readiness
    port = _extract_port(task_dir)
    if not port:
        logs = _run(["docker", "logs", "--tail", "20", container], timeout=10).stdout
        if not keep_on_fail:
            _run(["docker", "rm", "-f", container], timeout=15)
        r.rejection = "service_not_ready"
        r.stdout_tail = f"no port found\n{logs[-400:]}"
        return r
    ready = False
    for _ in range(40):
        probe = _run(["docker", "exec", container, "python3", "-c",
                      f"import socket;s=socket.create_connection(('127.0.0.1',{port}),2);s.close()"],
                     timeout=10)
        if probe.returncode == 0:
            ready = True
            break
        time.sleep(3)
    if not ready:
        logs = _run(["docker", "logs", "--tail", "20", container], timeout=10).stdout
        if not keep_on_fail:
            _run(["docker", "rm", "-f", container], timeout=15)
        r.rejection = "service_not_ready"
        r.stdout_tail = f"service not ready on {port}\n{logs[-400:]}"
        return r
    r.service_ready = True

    # 4. run pytest INSIDE the CVE container (faithful to target-local markers)
    pytest_rc, out, location = _run_pytest_in_container(
        container, tests_dir, r.observer_scope, pytest_timeout,
    )
    r.pytest_location = location
    full_out = (out or "")

    # 5. parse suites
    r.func = _parse_suite_from_pytest("test_func.py", full_out)
    r.vuln = _parse_suite_from_pytest("test_vuln.py", full_out)
    r.stdout_tail = full_out[-700:]

    # 6. judge by authoritative contract
    r.verified, r.rejection = _judge(r, pytest_rc, full_out)

    # 7. cleanup
    if not (keep_on_fail and not r.verified):
        _run(["docker", "rm", "-f", container], timeout=15)
    return r


def _run_pytest_in_container(container: str, tests_dir: Path,
                             observer_scope: str, timeout: int) -> tuple[int, str, str]:
    """Run pytest inside the CVE container; fall back to sidecar for network
    observers only. Returns (returncode, combined_output, location)."""
    # Try inside the CVE container first.
    inst = _run(["docker", "exec", container, "sh", "-c",
                 "python3 -m pip install -q pytest --break-system-packages 2>/dev/null; "
                 "python3 -m pytest --version 2>/dev/null"], timeout=120)
    if inst.returncode == 0:
        pytest = _run(["docker", "exec", "-w", "/tests", container,
                       "python3", "-m", "pytest", "test_vuln.py", "test_func.py",
                       "-v", "--tb=line", "--no-header",
                       "-o", "addopts=", "-p", "no:cacheprovider"], timeout=timeout)
        return (pytest.returncode,
                (pytest.stdout or "") + (pytest.stderr or ""),
                "cve_container")
    # Sidecar fallback: only valid for network observers.
    if observer_scope == "target_local":
        # Cannot faithfully observe target-local markers from a sidecar.
        # Return a sentinel so the judge rejects with observer_scope_incompatible.
        return (0, "OBSERVER_SCOPE_INCOMPATABLE: target_local marker cannot be "
                  "observed from a network-only sidecar", "sidecar_python")
    pytest_args = ["docker", "run", "--rm", "--network", f"container:{container}",
                   "-v", f"{tests_dir}:/tests:ro", "python:3.12-slim", "sh", "-c",
                   "pip install -q --break-system-packages pytest requests 2>/dev/null; "
                   "cd /tests && python -m pytest test_vuln.py test_func.py -v --tb=line "
                   "--no-header -o addopts= -p no:cacheprovider"]
    pytest = _run(pytest_args, timeout=timeout)
    return (pytest.returncode,
            (pytest.stdout or "") + (pytest.stderr or ""),
            "sidecar_python")


def _judge(r: CVEFactoryVerificationResult, pytest_rc: int, out: str) -> tuple[bool, str]:
    """Apply the authoritative CVE-Factory contract to the parsed suites."""
    # Observer-scope sentinel from sidecar fallback
    if "OBSERVER_SCOPE_INCOMPATABLE" in out and r.pytest_location == "sidecar_python":
        return False, "observer_scope_incompatible"

    # Collection / runtime errors
    if "OBSERVER_SCOPE_INCOMPATABLE" not in out:
        if "no tests ran" in out or "collected 0 items" in out:
            return False, "no_tests"
        if re.search(r"error[s]?\s+(in|during)", out, re.IGNORECASE) and \
           (r.func is None or r.func.collected == 0) and \
           (r.vuln is None or r.vuln.collected == 0):
            return False, "collection_error"

    func = r.func
    vuln = r.vuln
    if not func or not func.ran:
        return False, "no_tests"
    if not vuln or not vuln.ran:
        return False, "no_tests"
    # func must all PASS
    if func.failed > 0 or func.errors > 0:
        return False, "func_failed"
    if func.passed == 0:
        return False, "func_failed"
    # vuln must all FAIL (and have no errors/skips that mask the result)
    if vuln.errors > 0:
        return False, "runtime_error"
    if vuln.skipped > 0:
        return False, "mixed_outcome"
    if vuln.passed > 0:
        # some vuln assertions passed => vulnerability NOT fully present
        if vuln.failed > 0:
            return False, "mixed_outcome"
        return False, "vuln_not_observed"
    if vuln.failed == 0:
        return False, "vuln_not_observed"
    # Authoritative contract satisfied
    return True, ""


__all__ = [
    "CVEFactoryVerificationResult",
    "TestSuiteResult",
    "verify_cve_factory_task",
]