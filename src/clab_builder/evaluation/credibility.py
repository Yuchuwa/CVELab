"""Statistical primitives for difficulty reliability and validity studies."""

from __future__ import annotations

import math
import statistics
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from .difficulty import wilson_interval


def _average_ranks(values: Sequence[float]) -> list[float]:
    order = sorted(range(len(values)), key=lambda index: values[index])
    ranks = [0.0] * len(values)
    start = 0
    while start < len(order):
        end = start + 1
        while end < len(order) and values[order[end]] == values[order[start]]:
            end += 1
        average = (start + 1 + end) / 2.0
        for position in range(start, end):
            ranks[order[position]] = average
        start = end
    return ranks


def _pearson(left: Sequence[float], right: Sequence[float]) -> float | None:
    if len(left) != len(right):
        raise ValueError("metric inputs must have equal length")
    if len(left) < 2:
        return None
    left_mean = statistics.fmean(left)
    right_mean = statistics.fmean(right)
    left_delta = [value - left_mean for value in left]
    right_delta = [value - right_mean for value in right]
    denominator = math.sqrt(
        sum(value * value for value in left_delta)
        * sum(value * value for value in right_delta)
    )
    if denominator == 0:
        return None
    return sum(
        left_value * right_value
        for left_value, right_value in zip(left_delta, right_delta, strict=True)
    ) / denominator


def spearman_correlation(
    predicted: Sequence[float], observed: Sequence[float]
) -> float | None:
    """Return tie-aware Spearman correlation."""
    value = _pearson(_average_ranks(predicted), _average_ranks(observed))
    return round(value, 6) if value is not None else None


def kendall_tau_b(
    predicted: Sequence[float], observed: Sequence[float]
) -> float | None:
    """Return Kendall's tau-b, retaining ties in either ranking."""
    if len(predicted) != len(observed):
        raise ValueError("metric inputs must have equal length")
    if len(predicted) < 2:
        return None
    concordant = discordant = predicted_ties = observed_ties = 0
    for left in range(len(predicted) - 1):
        for right in range(left + 1, len(predicted)):
            predicted_delta = predicted[left] - predicted[right]
            observed_delta = observed[left] - observed[right]
            if predicted_delta == 0 and observed_delta == 0:
                continue
            if predicted_delta == 0:
                predicted_ties += 1
            elif observed_delta == 0:
                observed_ties += 1
            elif predicted_delta * observed_delta > 0:
                concordant += 1
            else:
                discordant += 1
    denominator = math.sqrt(
        (concordant + discordant + predicted_ties)
        * (concordant + discordant + observed_ties)
    )
    if denominator == 0:
        return None
    return round((concordant - discordant) / denominator, 6)


def brier_score(
    predicted_probabilities: Sequence[float], outcomes: Sequence[bool | int]
) -> float:
    if len(predicted_probabilities) != len(outcomes) or not outcomes:
        raise ValueError("Brier score requires equal, non-empty inputs")
    if any(probability < 0.0 or probability > 1.0 for probability in predicted_probabilities):
        raise ValueError("predicted probabilities must be within [0, 1]")
    return round(
        statistics.fmean(
            (probability - int(bool(outcome))) ** 2
            for probability, outcome in zip(
                predicted_probabilities, outcomes, strict=True
            )
        ),
        6,
    )


def log_loss(
    predicted_probabilities: Sequence[float],
    outcomes: Sequence[bool | int],
    *,
    epsilon: float = 1e-15,
) -> float:
    if len(predicted_probabilities) != len(outcomes) or not outcomes:
        raise ValueError("log loss requires equal, non-empty inputs")
    if any(probability < 0.0 or probability > 1.0 for probability in predicted_probabilities):
        raise ValueError("predicted probabilities must be within [0, 1]")
    losses = []
    for probability, outcome in zip(
        predicted_probabilities, outcomes, strict=True
    ):
        probability = min(1.0 - epsilon, max(epsilon, probability))
        observed = int(bool(outcome))
        losses.append(
            -(observed * math.log(probability) + (1 - observed) * math.log(1 - probability))
        )
    return round(statistics.fmean(losses), 6)


def analyze_probability_predictions(cases: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Analyze case probabilities against run-level binary outcomes."""
    rows = list(cases)
    if not rows:
        raise ValueError("at least one case is required")
    predicted_runs: list[float] = []
    outcomes: list[bool] = []
    predicted_difficulty: list[float] = []
    observed_difficulty: list[float] = []
    family_cases: dict[str, list[dict[str, Any]]] = {}
    case_rows = []
    for row in rows:
        case_id = str(row.get("id") or row.get("case_id") or "")
        probability = float(row["predicted_success_probability"])
        outcome_records = [
            value if isinstance(value, dict) else {"success": bool(value)}
            for value in row["outcomes"]
        ]
        case_outcomes = [bool(value.get("success")) for value in outcome_records]
        if not case_id or not case_outcomes:
            raise ValueError("each case requires an id and at least one outcome")
        if probability < 0.0 or probability > 1.0:
            raise ValueError("predicted probabilities must be within [0, 1]")
        successes = sum(case_outcomes)
        observed_rate = successes / len(case_outcomes)
        predicted_runs.extend([probability] * len(case_outcomes))
        outcomes.extend(case_outcomes)
        predicted_difficulty.append(1.0 - probability)
        observed_difficulty.append(1.0 - observed_rate)
        case_rows.append({
            "case_id": case_id,
            "predicted_success_probability": probability,
            "successes": successes,
            "runs": len(case_outcomes),
            "observed_success_rate": round(observed_rate, 6),
            "observed_success_interval": wilson_interval(
                successes, len(case_outcomes)
            ),
        })
        for family in sorted(
            {
                str(record.get("model_family") or "")
                for record in outcome_records
                if record.get("model_family")
            }
        ):
            family_outcomes = [
                bool(record.get("success"))
                for record in outcome_records
                if str(record.get("model_family") or "") == family
            ]
            family_cases.setdefault(family, []).append({
                "id": case_id,
                "predicted_success_probability": probability,
                "outcomes": family_outcomes,
            })
    per_model_family = {}
    for family, family_rows in sorted(family_cases.items()):
        family_predicted = []
        family_outcomes = []
        family_predicted_difficulty = []
        family_observed_difficulty = []
        for row in family_rows:
            family_predicted.extend(
                [row["predicted_success_probability"]] * len(row["outcomes"])
            )
            family_outcomes.extend(row["outcomes"])
            family_predicted_difficulty.append(
                1.0 - row["predicted_success_probability"]
            )
            family_observed_difficulty.append(
                1.0 - sum(row["outcomes"]) / len(row["outcomes"])
            )
        per_model_family[family] = {
            "case_count": len(family_rows),
            "run_count": len(family_outcomes),
            "brier_score": brier_score(family_predicted, family_outcomes),
            "log_loss": log_loss(family_predicted, family_outcomes),
            "spearman_case_difficulty": spearman_correlation(
                family_predicted_difficulty, family_observed_difficulty
            ),
            "kendall_tau_b_case_difficulty": kendall_tau_b(
                family_predicted_difficulty, family_observed_difficulty
            ),
        }
    return {
        "case_count": len(rows),
        "run_count": len(outcomes),
        "brier_score": brier_score(predicted_runs, outcomes),
        "log_loss": log_loss(predicted_runs, outcomes),
        "spearman_case_difficulty": spearman_correlation(
            predicted_difficulty, observed_difficulty
        ),
        "kendall_tau_b_case_difficulty": kendall_tau_b(
            predicted_difficulty, observed_difficulty
        ),
        "per_model_family": per_model_family,
        "cases": case_rows,
    }


def _case_outcomes(row: dict[str, Any]) -> list[bool]:
    return [
        bool(value.get("success")) if isinstance(value, dict) else bool(value)
        for value in row.get("outcomes") or []
    ]


def fit_baseline_models(cases: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Fit univariate logistic baseline mappings on calibration cases only."""
    rows = list(cases)
    if not rows or any(not _case_outcomes(row) for row in rows):
        raise ValueError("baseline fitting requires outcomes for every case")
    outcome_counts = [
        (sum(_case_outcomes(row)), len(_case_outcomes(row)))
        for row in rows
    ]
    successes = sum(success for success, _ in outcome_counts)
    total = sum(count for _, count in outcome_counts)
    constant = min(1.0 - 1e-6, max(1e-6, successes / total))
    feature_names = sorted(
        {
            name
            for row in rows
            for name, value in (row.get("baselines") or {}).items()
            if name != "constant_success_probability"
            and isinstance(value, (int, float))
            and not isinstance(value, bool)
        }
    )
    models: dict[str, Any] = {
        "constant_success_probability": {
            "kind": "constant",
            "probability": round(constant, 12),
        }
    }
    for name in feature_names:
        if any(not isinstance((row.get("baselines") or {}).get(name), (int, float)) for row in rows):
            continue
        values = [float(row["baselines"][name]) for row in rows]
        mean = statistics.fmean(values)
        scale = statistics.pstdev(values) or 1.0
        standardized = [(value - mean) / scale for value in values]
        intercept = math.log(constant / (1.0 - constant))
        coefficient = 0.0
        for iteration in range(4000):
            gradient_intercept = 0.0
            gradient_coefficient = 0.0
            for (success_count, outcome_count), feature in zip(
                outcome_counts, standardized, strict=True
            ):
                prediction = 1.0 / (
                    1.0 + math.exp(-max(-30.0, min(30.0, intercept + coefficient * feature)))
                )
                residual = prediction * outcome_count - success_count
                gradient_intercept += residual
                gradient_coefficient += residual * feature
            learning_rate = 0.1 / math.sqrt(iteration + 1)
            intercept -= learning_rate * gradient_intercept / total
            coefficient -= learning_rate * gradient_coefficient / total
        models[name] = {
            "kind": "univariate_logistic",
            "feature_mean": round(mean, 12),
            "feature_scale": round(scale, 12),
            "intercept": round(intercept, 12),
            "coefficient": round(coefficient, 12),
        }
    return {
        "schema_version": 1,
        "fit_split": "calibration",
        "case_count": len(rows),
        "run_count": total,
        "models": models,
    }


def _baseline_probability(model: Mapping[str, Any], value: Any) -> float:
    if model.get("kind") == "constant":
        return float(model["probability"])
    standardized = (
        float(value) - float(model["feature_mean"])
    ) / float(model["feature_scale"])
    linear = float(model["intercept"]) + float(model["coefficient"]) * standardized
    return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, linear))))


def analyze_against_baselines(
    cases: Iterable[dict[str, Any]],
    baseline_fit: Mapping[str, Any],
) -> dict[str, Any]:
    """Compare frozen architecture probabilities with calibration-fit baselines."""
    rows = list(cases)
    architecture = analyze_probability_predictions(rows)
    baselines = {}
    for name, model in sorted((baseline_fit.get("models") or {}).items()):
        baseline_rows = []
        for row in rows:
            value = (row.get("baselines") or {}).get(name)
            if model.get("kind") != "constant" and not isinstance(value, (int, float)):
                raise ValueError(f"missing numeric baseline feature: {name}")
            baseline_rows.append({
                **row,
                "predicted_success_probability": _baseline_probability(model, value),
            })
        analysis = analyze_probability_predictions(baseline_rows)
        baselines[name] = {
            **analysis,
            "brier_improvement_of_architecture": round(
                analysis["brier_score"] - architecture["brier_score"], 6
            ),
            "log_loss_improvement_of_architecture": round(
                analysis["log_loss"] - architecture["log_loss"], 6
            ),
        }
    return {
        "architecture": architecture,
        "baselines": baselines,
    }
