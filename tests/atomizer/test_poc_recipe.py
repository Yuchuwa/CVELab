"""Tests for PoC recipe extraction and three-state verification (batch 8)."""
from pathlib import Path
from textwrap import dedent

from clab_builder.atomizer.cve_factory_verifier import (
    CVEFactoryVerificationResult, TestSuiteResult,
)
from clab_builder.atomizer.poc_recipe import (
    extract_recipe,
    judge_three_state,
    is_range_adaptable,
)


def _result(verified=True, observer="target_local"):
    func = TestSuiteResult("test_func.py", collected=2, passed=2, failed=0,
                            errors=0, skipped=0)
    vuln = TestSuiteResult("test_vuln.py", collected=3, passed=0, failed=3,
                           errors=0, skipped=0)
    return CVEFactoryVerificationResult(
        cve_id="CVE-X", verified=verified, build_ok=True, service_ready=True,
        func=func, vuln=vuln, observer_scope=observer, timestamp="t",
    )


def _write_test_vuln(tmp_path, body):
    d = tmp_path / "CVE-X" / "tests"
    d.mkdir(parents=True)
    (d / "test_vuln.py").write_text(dedent(body))
    return d.parent / "tests" / "test_vuln.py"


def test_extract_recipe_marker_based(tmp_path):
    p = _write_test_vuln(tmp_path, """
        import os, requests
        BASE_URL = 'http://localhost:8080'
        def test_rce():
            requests.get(BASE_URL + '/run', params={'cmd': 'touch /tmp/marker_x'})
            assert not os.path.exists('/tmp/marker_x'), 'Vulnerability: command execution'
    """)
    recipe = extract_recipe(p)
    assert recipe.observer_scope == "target_local"
    assert recipe.uses_target_marker is True
    assert recipe.http_response_evidence is False
    assert recipe.endpoint.startswith("BASE_URL")
    assert recipe.method == "get"
    assert "execute_command" in recipe.inferred_capabilities


def test_extract_recipe_http_response(tmp_path):
    p = _write_test_vuln(tmp_path, """
        import requests
        BASE_URL = 'http://localhost:80'
        def test_lfi():
            r = requests.get(BASE_URL + '/?file=../../etc/passwd')
            assert 'root:' not in r.text, 'Vulnerability: /etc/passwd leaked'
    """)
    recipe = extract_recipe(p)
    assert recipe.observer_scope == "network"
    assert recipe.uses_target_marker is False
    assert recipe.http_response_evidence is True
    assert "read_file" in recipe.inferred_capabilities


def test_marker_based_test_is_not_range_adaptable(tmp_path):
    p = _write_test_vuln(tmp_path, """
        import os, requests
        def test_rce():
            requests.get('http://localhost:80/x', params={'c': 'touch /tmp/m'})
            assert not os.path.exists('/tmp/m'), 'command execution'
    """)
    recipe = extract_recipe(p)
    ts = judge_three_state(_result(), recipe)
    assert ts.vulnerability_observed is True
    assert ts.capability_verified is False
    assert ts.range_flag_recovery_verified is False
    assert is_range_adaptable(ts) is False
    assert "target-local marker" in ts.reason


def test_http_response_test_is_vulnerability_observed_not_recovery_verified(tmp_path):
    p = _write_test_vuln(tmp_path, """
        import requests
        def test_lfi():
            r = requests.get('http://localhost:80/?f=../../etc/passwd')
            assert 'root:' not in r.text, 'leaked'
    """)
    recipe = extract_recipe(p)
    ts = judge_three_state(_result(observer="network"), recipe)
    assert ts.vulnerability_observed is True
    # Still not recovery-verified until runtime injection is wired.
    assert ts.range_flag_recovery_verified is False
    assert is_range_adaptable(ts) is False
    assert ts.flag_recovery_method == "http_response_channel_candidate"


def test_unobserved_vulnerability_all_false():
    ts = judge_three_state(_result(verified=False, observer="network"))
    assert ts.vulnerability_observed is False
    assert ts.capability_verified is False
    assert ts.range_flag_recovery_verified is False
    assert is_range_adaptable(ts) is False


def test_inferred_capabilities_are_not_verified_grants(tmp_path):
    """A marker test whose assertion text mentions /etc/passwd still does not
    grant read_file as a verified capability — it only ran one fixed command."""
    p = _write_test_vuln(tmp_path, """
        import os, requests
        def test_x():
            requests.get('http://localhost:80/', params={'c': 'cat /etc/passwd > /tmp/m'})
            assert not os.path.exists('/tmp/m'), 'leaked /etc/passwd via command execution'
    """)
    recipe = extract_recipe(p)
    ts = judge_three_state(_result(), recipe)
    assert "read_file" in ts.inferred_capabilities
    assert "execute_command" in ts.inferred_capabilities
    # inferred != verified
    assert ts.verified_capabilities == []
    assert ts.capability_verified is False


def test_native_verification_overlay_shape(tmp_path):
    p = _write_test_vuln(tmp_path, """
        import requests
        def test_lfi():
            r = requests.get('http://localhost:80/?f=../../etc/passwd')
            assert 'root:' not in r.text, 'leaked'
    """)
    recipe = extract_recipe(p)
    ts = judge_three_state(_result(observer="network"), recipe)
    overlay = ts.to_native_verification_overlay()
    assert overlay["flag_recovery"]["attempted"] is False
    assert overlay["three_state"]["vulnerability_observed"] is True
    assert overlay["three_state"]["range_flag_recovery_verified"] is False