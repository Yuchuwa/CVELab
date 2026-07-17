"""PoC recipe extraction and the three-state verification model (batch 8).

A CVE-Factory test_vuln.py proves the vulnerability is OBSERVED, but that is
not the same as proving a capability or that a Range flag can be recovered.
This module separates three states that the old pipeline conflated:

  vulnerability_observed   — test_func PASS + test_vuln FAIL (batch 7)
  capability_verified      — a specific capability (execute_command/read_file/...)
                             has independent witness evidence
  range_flag_recovery_verified — a randomized flag injected into the target can
                             be recovered through the SAME vulnerability channel

Only range_flag_recovery_verified lets a PoC atom enter Guided Range as a
template_candidate. vulnerability_observed alone keeps native verified=True
but the atom stays review_required (no verified capability grants, no
flag-recovery contract).

This batch implements the static recipe extraction and the three-state
judgement from a CVEFactoryVerificationResult. Runtime randomized-witness
execution (batch 7's verifier + injection) feeds these judgements; this
module turns the evidence into the contract decision.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Optional

from clab_builder.atomizer.cve_factory_verifier import CVEFactoryVerificationResult


@dataclass
class PoCRecipe:
    """Static extraction of the exploit elements from test_vuln.py.

    Used by batch 9 to generate the advisory Guide. The recipe describes the
    NATIVE exploit (localhost, marker-based); the Guide rewrites it with
    Range placeholders and a flag-recovery procedure.
    """
    cve_id: str
    endpoint: str = ""
    method: str = ""
    auth: str = ""           # none | default_credentials | session
    payload_construction: str = ""
    observer_scope: str = ""  # target_local | network
    expected_outcome: str = ""
    # Which capabilities the test_vuln.py assertions imply, structurally.
    # These are INFERRED from the assertion text, not independently witnessed.
    inferred_capabilities: list[str] = field(default_factory=list)
    # Whether the test reads a target-local marker (no external recovery).
    uses_target_marker: bool = False
    # Whether the test issues an HTTP request whose response body proves the
    # effect (a candidate for external flag recovery).
    http_response_evidence: bool = False
    source_ref: str = ""


@dataclass
class ThreeStateVerification:
    vulnerability_observed: bool = False
    capability_verified: bool = False
    range_flag_recovery_verified: bool = False
    verified_capabilities: list[str] = field(default_factory=list)
    inferred_capabilities: list[str] = field(default_factory=list)
    flag_recovery_method: str = ""
    recipe: Optional[PoCRecipe] = None
    reason: str = ""

    def to_native_verification_overlay(self) -> dict:
        """Fields to merge into native_verification (batch 6 shape)."""
        return {
            "flag_recovery": {
                "attempted": self.range_flag_recovery_verified,
                "success": self.range_flag_recovery_verified,
                "method": self.flag_recovery_method,
            },
            "witnesses": {},
            "three_state": {
                "vulnerability_observed": self.vulnerability_observed,
                "capability_verified": self.capability_verified,
                "range_flag_recovery_verified": self.range_flag_recovery_verified,
            },
        }


# Assertion-text -> inferred capability. Conservative: only capabilities the
# test's assertion text explicitly demonstrates. A marker file proves only
# command execution of ONE fixed command; read_file requires the assertion to
# reference arbitrary file content; network_vantage requires an outbound
# connection assertion.
_ASSERTION_CAPABILITY = [
    (r"/etc/passwd|root:|arbitrary file", "read_file"),
    (r"os\.system|subprocess|Popen|exec\(|command execution", "execute_command"),
    (r"write|upload.*file|created.*file", "write_file"),
    (r"ssrf|outbound|connect.*to|initiate.*request", "network_vantage"),
    (r"credential|password|secret|api.?key", "read_credential"),
    (r"authenticat|login|session|cookie", "authenticate"),
]


def _infer_capabilities_from_assertions(test_text: str) -> list[str]:
    caps: list[str] = []
    low = test_text.lower()
    for pat, cap in _ASSERTION_CAPABILITY:
        if re.search(pat, low) and cap not in caps:
            caps.append(cap)
    return caps


def _extract_http_requests(tree: ast.AST) -> list[dict]:
    """Extract requests.get/post calls: method, url, data/files presence."""
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            attr = ""
            if isinstance(func, ast.Attribute):
                attr = func.attr
            if attr in ("get", "post", "put", "delete", "request"):
                url = ""
                if node.args:
                    try:
                        url = ast.unparse(node.args[0])
                    except Exception:
                        pass
                has_data = any(
                    kw.arg in ("data", "json") for kw in node.keywords
                )
                has_files = any(kw.arg == "files" for kw in node.keywords)
                calls.append({"method": attr, "url": url,
                               "has_data": has_data, "has_files": has_files})
    return calls


def _extract_assertion_texts(tree: ast.AST) -> list[str]:
    """Extract assert statement messages (the .msg of an assert)."""
    texts: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assert) and node.msg is not None:
            try:
                texts.append(ast.unparse(node.msg))
            except Exception:
                pass
    return texts


def extract_recipe(test_vuln_path) -> Optional[PoCRecipe]:
    """Statically analyze test_vuln.py into a PoCRecipe.

    Returns None if the file cannot be parsed.
    """
    try:
        text = test_vuln_path.read_text(errors="replace")
        tree = ast.parse(text)
    except (OSError, SyntaxError):
        return None
    cve_id = test_vuln_path.parent.parent.name
    recipe = PoCRecipe(cve_id=cve_id, source_ref=str(test_vuln_path))

    requests = _extract_http_requests(tree)
    if requests:
        req = requests[0]
        recipe.method = req["method"] or "get"
        recipe.endpoint = req["url"] or ""
        if req["has_files"]:
            recipe.payload_construction = "multipart file upload"
        elif req["has_data"]:
            recipe.payload_construction = "form data"
    asserts = _extract_assertion_texts(tree)
    if asserts:
        recipe.expected_outcome = asserts[0][:200]

    # observer scope
    if re.search(r"os\.path\.exists|os\.remove|/tmp/[a-z_]", text):
        recipe.observer_scope = "target_local"
        recipe.uses_target_marker = True
    else:
        recipe.observer_scope = "network"
    # http response evidence: assertion references response body
    if re.search(r"response\.text|response\.content|r\.text|r\.content", text):
        recipe.http_response_evidence = True

    recipe.inferred_capabilities = _infer_capabilities_from_assertions(text)
    return recipe


def judge_three_state(
    result: CVEFactoryVerificationResult,
    recipe: Optional[PoCRecipe] = None,
) -> ThreeStateVerification:
    """Decide the three verification states from a verifier result + recipe.

    vulnerability_observed:   batch-7 contract (func PASS + vuln FAIL)
    capability_verified:      NOT granted by a marker-based test alone.
                              Requires independent witness evidence, which the
                              static recipe cannot produce. So this is False
                              unless a future runtime witness layer sets it.
    range_flag_recovery_verified: only if the vulnerability channel is an HTTP
                              request whose response body carries the effect
                              (so a randomized flag placed at a reachable path
                              can be read through the same channel). Marker-
                              based tests cannot recover an external flag, so
                              they stay False here.
    """
    ts = ThreeStateVerification()
    ts.vulnerability_observed = result.verified
    ts.recipe = recipe

    if not result.verified:
        ts.reason = result.rejection or "vulnerability not observed"
        return ts

    if recipe is not None:
        ts.inferred_capabilities = list(recipe.inferred_capabilities)

    # capability_verified: the static recipe only INFERRES capabilities from
    # assertion text. A marker file proves one fixed command ran, not that
    # ARBITRARY commands can be run. So inferred capabilities do NOT become
    # verified grants. A runtime witness layer (future) would run two
    # randomized commands through the channel to prove execute_command, etc.
    ts.capability_verified = False
    ts.verified_capabilities = []
    ts.reason = "vulnerability observed; capability requires runtime witness"

    # range_flag_recovery: only an HTTP-response-evidence channel can carry
    # an externally-recoverable flag. A target-local marker cannot be read
    # from the attacker.
    if recipe is not None and recipe.http_response_evidence:
        # Candidate: the same HTTP channel that leaked the marker/contents
        # could leak a randomized flag placed at a reachable path. This is a
        # NECESSARY condition, not a sufficient one — actual recovery must be
        # verified at runtime by injecting a random flag and reading it.
        # Mark as a recovery METHOD, but not as verified, until runtime proof.
        ts.flag_recovery_method = "http_response_channel_candidate"
        ts.reason = "vulnerability observed; http channel may carry flag (runtime recovery needed)"
    elif recipe is not None and recipe.uses_target_marker:
        ts.flag_recovery_method = "not_applicable_target_marker"
        ts.reason = "vulnerability observed; target-local marker cannot recover external flag"

    ts.range_flag_recovery_verified = False
    return ts


def is_range_adaptable(ts: ThreeStateVerification) -> bool:
    """A PoC atom is Range-adaptable only if its vulnerability channel can
    potentially carry an externally-recoverable flag (necessary condition)
    AND a runtime recovery has been demonstrated.

    Until runtime recovery is wired (future batch), this returns False for
    marker-only tests, which is the conservative correct answer: a
    marker-based PoC must NOT enter Guided Range as a verified-capability atom.
    """
    return ts.range_flag_recovery_verified


__all__ = [
    "PoCRecipe",
    "ThreeStateVerification",
    "extract_recipe",
    "judge_three_state",
    "is_range_adaptable",
]