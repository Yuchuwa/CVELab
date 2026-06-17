"""Compatibility wrapper for legacy enhanced connectivity imports."""

from clab_builder.orchestrator.validator.connectivity import (
    ConnectivityTestResult,
    EnhancedConnectivityTester,
    ICMPTestResult,
    TCPTestResult,
)

__all__ = [
    "ConnectivityTestResult",
    "EnhancedConnectivityTester",
    "ICMPTestResult",
    "TCPTestResult",
]

