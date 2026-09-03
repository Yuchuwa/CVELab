"""Independent empirical difficulty evaluation for Atom and Range artifacts."""

from .constants import DEFAULT_MODELS
from .difficulty import (
    EvaluationRun,
    aggregate_runs,
    classify_difficulty,
    sha256_file,
    trial_specs,
    verifier_backed_success,
    wilson_interval,
    write_report,
)
from .credibility import (
    analyze_against_baselines,
    analyze_probability_predictions,
    fit_baseline_models,
    kendall_tau_b,
)
from .study import (
    assess_manifest_qualification,
    build_frozen_run_plan,
    collect_trial_outcomes,
    manifest_integrity,
)

__all__ = [
    "DEFAULT_MODELS",
    "EvaluationRun",
    "aggregate_runs",
    "classify_difficulty",
    "sha256_file",
    "trial_specs",
    "verifier_backed_success",
    "wilson_interval",
    "write_report",
    "analyze_against_baselines",
    "analyze_probability_predictions",
    "fit_baseline_models",
    "kendall_tau_b",
    "assess_manifest_qualification",
    "build_frozen_run_plan",
    "collect_trial_outcomes",
    "manifest_integrity",
]
