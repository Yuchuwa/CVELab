import math

import pytest

from clab_builder.evaluation.credibility import (
    analyze_against_baselines,
    analyze_probability_predictions,
    brier_score,
    fit_baseline_models,
    kendall_tau_b,
    log_loss,
    spearman_correlation,
)


def test_spearman_uses_average_ranks_for_ties():
    assert spearman_correlation([1, 1, 3], [1, 2, 3]) == pytest.approx(0.866025)
    assert kendall_tau_b([1, 1, 3], [1, 2, 3]) == pytest.approx(0.816497)


def test_probability_scores_reward_calibrated_predictions():
    assert brier_score([0.8, 0.2], [1, 0]) == 0.04
    assert log_loss([0.8, 0.2], [1, 0]) == pytest.approx(
        -math.log(0.8), abs=1e-6
    )


def test_analyze_probability_predictions_reports_case_intervals():
    result = analyze_probability_predictions([
        {
            "id": "easy",
            "predicted_success_probability": 0.8,
            "outcomes": [True, True, False],
        },
        {
            "id": "hard",
            "predicted_success_probability": 0.2,
            "outcomes": [False, False, True],
        },
    ])

    assert result["case_count"] == 2
    assert result["run_count"] == 6
    assert result["spearman_case_difficulty"] == 1.0
    assert result["cases"][0]["observed_success_interval"]["total"] == 3


def test_probability_analysis_reports_model_families_separately():
    result = analyze_probability_predictions([
        {
            "id": "case-a",
            "predicted_success_probability": 0.5,
            "outcomes": [
                {"model_family": "family-a", "success": True},
                {"model_family": "family-a", "success": False},
                {"model_family": "family-b", "success": False},
            ],
        }
    ])

    assert result["per_model_family"]["family-a"]["run_count"] == 2
    assert result["per_model_family"]["family-b"]["run_count"] == 1


def test_calibration_fit_compares_simple_baselines_on_held_out_cases():
    calibration = [
        {
            "id": "cal-easy",
            "baselines": {"cve_count": 1},
            "outcomes": [True, True, True],
        },
        {
            "id": "cal-hard",
            "baselines": {"cve_count": 3},
            "outcomes": [False, False, False],
        },
    ]
    fitted = fit_baseline_models(calibration)
    held_out = [
        {
            "id": "test-easy",
            "predicted_success_probability": 0.9,
            "baselines": {"cve_count": 1},
            "outcomes": [True, True],
        },
        {
            "id": "test-hard",
            "predicted_success_probability": 0.1,
            "baselines": {"cve_count": 3},
            "outcomes": [False, False],
        },
    ]

    result = analyze_against_baselines(held_out, fitted)

    assert fitted["fit_split"] == "calibration"
    assert fitted["models"]["cve_count"]["coefficient"] < 0
    assert result["architecture"]["brier_score"] == 0.01
    assert "constant_success_probability" in result["baselines"]
    assert (
        result["baselines"]["constant_success_probability"][
            "brier_improvement_of_architecture"
        ]
        > 0
    )


@pytest.mark.parametrize(
    ("probabilities", "outcomes"),
    [([], []), ([1.2], [True]), ([0.5], [True, False])],
)
def test_probability_metrics_reject_invalid_inputs(probabilities, outcomes):
    with pytest.raises(ValueError):
        brier_score(probabilities, outcomes)
