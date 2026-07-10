"""Benchmark execution utilities for CVELab scenarios."""

from clab_builder.orchestrator.benchmark.agent_spec import AgentSpec
from clab_builder.orchestrator.benchmark.runner import BenchmarkRunner
from clab_builder.orchestrator.benchmark.scoring import score_agent_result

__all__ = ["AgentSpec", "BenchmarkRunner", "score_agent_result"]
