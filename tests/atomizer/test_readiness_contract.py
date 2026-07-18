"""Shared readiness selection for Atom reconstruction."""

from clab_builder.atomizer.pipeline import AtomizerPipeline
from clab_builder.shared.models.atom import ExploitAccess


def test_pipeline_readiness_prefers_exploit_entry_port():
    access = ExploitAccess(required_service={"protocol": "http", "port": 8161})

    assert AtomizerPipeline._readiness_port_for_access(access, [61616, 8161]) == 8161


def test_pipeline_readiness_falls_back_to_first_declared_port():
    assert AtomizerPipeline._readiness_port_for_access(
        ExploitAccess(required_service={}), [61616, 8161]
    ) == 61616
