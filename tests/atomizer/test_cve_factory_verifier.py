"""Tests for the CVE-Factory structured verifier (batch 7).

Covers the authoritative test contract and observer-scope correctness.
These are pure-judgement tests: they exercise _judge and _detect_observer_scope
directly without docker, so they run anywhere.
"""
from pathlib import Path

from clab_builder.atomizer.cve_factory_verifier import (
    CVEFactoryVerificationResult,
    TestSuiteResult,
    _judge,
    _detect_observer_scope,
)


def _result(func=None, vuln=None, out="", location="cve_container"):
    return CVEFactoryVerificationResult(
        cve_id="CVE-X", build_ok=True, service_ready=True,
        func=func, vuln=vuln, pytest_location=location,
        stdout_tail=out, timestamp="t",
    )


def test_func_pass_vuln_fail_is_verified():
    func = TestSuiteResult("test_func.py", collected=2, passed=2, failed=0,
                            errors=0, skipped=0)
    vuln = TestSuiteResult("test_vuln.py", collected=3, passed=0, failed=3,
                           errors=0, skipped=0)
    ok, rej = _judge(_result(func, vuln), pytest_rc=1, out="")
    assert ok is True
    assert rej == ""


def test_func_failed_rejects():
    func = TestSuiteResult("test_func.py", collected=2, passed=1, failed=1,
                           errors=0, skipped=0)
    vuln = TestSuiteResult("test_vuln.py", collected=3, passed=0, failed=3,
                           errors=0, skipped=0)
    ok, rej = _judge(_result(func, vuln), pytest_rc=1, out="")
    assert ok is False
    assert rej == "func_failed"


def test_vuln_passed_rejects_as_not_observed():
    """If all vuln assertions PASS, the vulnerability is NOT present."""
    func = TestSuiteResult("test_func.py", collected=2, passed=2, failed=0,
                           errors=0, skipped=0)
    vuln = TestSuiteResult("test_vuln.py", collected=3, passed=3, failed=0,
                           errors=0, skipped=0)
    ok, rej = _judge(_result(func, vuln), pytest_rc=0, out="")
    assert ok is False
    assert rej == "vuln_not_observed"


def test_vuln_mixed_outcome_rejects():
    func = TestSuiteResult("test_func.py", collected=2, passed=2, failed=0,
                           errors=0, skipped=0)
    vuln = TestSuiteResult("test_vuln.py", collected=3, passed=1, failed=2,
                           errors=0, skipped=0)
    ok, rej = _judge(_result(func, vuln), pytest_rc=1, out="")
    assert ok is False
    assert rej == "mixed_outcome"


def test_vuln_errors_rejects_as_runtime_error():
    func = TestSuiteResult("test_func.py", collected=2, passed=2, failed=0,
                           errors=0, skipped=0)
    vuln = TestSuiteResult("test_vuln.py", collected=3, passed=0, failed=2,
                           errors=1, skipped=0)
    ok, rej = _judge(_result(func, vuln), pytest_rc=1, out="")
    assert ok is False
    assert rej == "runtime_error"


def test_vuln_skipped_rejects_as_mixed():
    func = TestSuiteResult("test_func.py", collected=2, passed=2, failed=0,
                           errors=0, skipped=0)
    vuln = TestSuiteResult("test_vuln.py", collected=3, passed=0, failed=2,
                           errors=0, skipped=1)
    ok, rej = _judge(_result(func, vuln), pytest_rc=1, out="")
    assert ok is False
    assert rej == "mixed_outcome"


def test_no_tests_collected_rejects():
    ok, rej = _judge(_result(out="collected 0 items"), pytest_rc=0,
                     out="collected 0 items")
    assert ok is False
    assert rej == "no_tests"


def test_no_func_suite_rejects():
    vuln = TestSuiteResult("test_vuln.py", collected=3, passed=0, failed=3,
                           errors=0, skipped=0)
    ok, rej = _judge(_result(func=None, vuln=vuln), pytest_rc=1, out="")
    assert ok is False
    assert rej == "no_tests"


def test_target_local_observer_detected(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_vuln.py").write_text(
        "def test_x():\n"
        "    assert not os.path.exists('/tmp/marker')\n"
    )
    assert _detect_observer_scope(tests) == "target_local"


def test_network_observer_detected(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_vuln.py").write_text(
        "import requests\n"
        "def test_x():\n"
        "    r = requests.get('http://localhost:80/')\n"
        "    assert 'root' not in r.text\n"
    )
    assert _detect_observer_scope(tests) == "network"


def test_sidecar_target_local_rejects_as_observer_incompatible():
    """A target-local marker cannot be observed from a network-only sidecar."""
    ok, rej = _judge(
        _result(out="OBSERVER_SCOPE_INCOMPATABLE", location="sidecar_python"),
        pytest_rc=0, out="OBSERVER_SCOPE_INCOMPATABLE: target_local marker",
    )
    assert ok is False
    assert rej == "observer_scope_incompatible"


def test_to_native_verification_shape():
    func = TestSuiteResult("test_func.py", collected=2, passed=2, failed=0,
                           errors=0, skipped=0)
    vuln = TestSuiteResult("test_vuln.py", collected=3, passed=0, failed=3,
                           errors=0, skipped=0)
    r = _result(func, vuln)
    r.verified = True
    r.source_hash = "sha:abc"
    r.test_hash = "sha:def"
    nv = r.to_native_verification()
    assert nv["provenance"] == "cve_factory_poc"
    assert nv["success"] is True
    assert nv["flag_recovery"]["success"] is False
    assert nv["flag_recovery"]["method"] == "not_applicable_poc_marker_based"
    assert nv["test_results"]["test_func"]["passed"] == 2
    assert nv["test_results"]["test_vuln"]["failed"] == 3
    assert nv["source_hash"] == "sha:abc"
    assert any("func PASS + vuln FAIL" in e for e in nv["evidence"]) or \
           any("func" in e for e in nv["evidence"])