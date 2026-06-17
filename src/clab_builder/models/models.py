"""Compatibility wrapper for the legacy clab_builder.models.models module."""

from clab_builder.shared.models.topology import (
    ContainerLabTopology,
    IsolationPolicy,
    NetworkLink,
    NetworkNode,
    SecurityZone,
    TopologySpecification,
)

__all__ = [
    "ContainerLabTopology",
    "IsolationPolicy",
    "NetworkLink",
    "NetworkNode",
    "SecurityZone",
    "TopologySpecification",
]

