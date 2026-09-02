"""Reusable benign-service planning primitives for Range scenarios.

The package deliberately contains no Atom- or CVE-specific branches.  It is
an adapter boundary between Atom runtime metadata and template topology
slots; scenario generation may keep importing the legacy helper names while
callers migrate to this package.
"""

from .profiles import (
    NOISE_PROFILE_VERSION,
    NOISE_PROFILE_REGISTRY,
    NoiseProfile,
    matched_noise_services,
    profile_admission,
    profile_coverage,
    resolve_noise_profile,
    surface_spec,
    http_surface_command,
)
from .workloads import NOISE_ACTIVITY_VERSION, workload_command

__all__ = [
    "NOISE_PROFILE_VERSION",
    "NOISE_PROFILE_REGISTRY",
    "NoiseProfile",
    "matched_noise_services",
    "profile_admission",
    "profile_coverage",
    "resolve_noise_profile",
    "surface_spec",
    "http_surface_command",
    "NOISE_ACTIVITY_VERSION",
    "workload_command",
]
