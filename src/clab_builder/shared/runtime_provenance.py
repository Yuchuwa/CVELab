"""Portable provenance contract for locally built Atom runtime images.

Docker's local image ID includes build-time configuration metadata and is not a
portable identity for a derived image.  Runtime images therefore carry the
stable recipe facts that Range needs to verify after a legitimate local
rebuild: the generated recipe hash, the resolved base image digest and the
declared source image.
"""
from __future__ import annotations

from typing import Mapping


RUNTIME_PROVENANCE_VERSION = "1"
RUNTIME_PROVENANCE_SCHEMA_LABEL = "org.cvelab.runtime.provenance-version"
RUNTIME_GENERATED_HASH_LABEL = "org.cvelab.runtime.generated-hash"
RUNTIME_BASE_IMAGE_DIGEST_LABEL = "org.cvelab.runtime.base-image-digest"
RUNTIME_SOURCE_IMAGE_LABEL = "org.cvelab.runtime.source-image"


def runtime_provenance_labels(
    generated_hash: str,
    base_image_digest: str,
    source_image: str,
) -> dict[str, str]:
    """Return the exact Docker labels for one derived runtime recipe."""
    return {
        RUNTIME_PROVENANCE_SCHEMA_LABEL: RUNTIME_PROVENANCE_VERSION,
        RUNTIME_GENERATED_HASH_LABEL: str(generated_hash),
        RUNTIME_BASE_IMAGE_DIGEST_LABEL: str(base_image_digest),
        RUNTIME_SOURCE_IMAGE_LABEL: str(source_image),
    }


def runtime_provenance_matches(
    labels: Mapping[str, object] | None,
    generated_hash: str,
    base_image_digest: str,
    source_image: str,
) -> bool:
    """Whether image labels prove the requested derived-runtime recipe.

    Empty recipe facts are never sufficient: accepting them would turn a
    missing provenance record into a successful verification.
    """
    if not labels or not generated_hash or not base_image_digest or not source_image:
        return False
    expected = runtime_provenance_labels(
        generated_hash, base_image_digest, source_image,
    )
    return all(str(labels.get(key) or "") == value for key, value in expected.items())


def pinned_runtime_base_reference(source_image: str, base_image_digest: str) -> str:
    """Prefer a registry digest in ``FROM`` while retaining local fallbacks.

    A repo digest is portable and immutable (``repo@sha256:...``).  A local
    Docker image ID is not a valid portable ``FROM`` reference, so custom
    Dockerfile/intermediate-image paths continue using their local tag.
    """
    base = str(base_image_digest or "").strip()
    return base if "@sha256:" in base else source_image


__all__ = [
    "RUNTIME_PROVENANCE_VERSION",
    "RUNTIME_PROVENANCE_SCHEMA_LABEL",
    "RUNTIME_GENERATED_HASH_LABEL",
    "RUNTIME_BASE_IMAGE_DIGEST_LABEL",
    "RUNTIME_SOURCE_IMAGE_LABEL",
    "runtime_provenance_labels",
    "runtime_provenance_matches",
    "pinned_runtime_base_reference",
]
