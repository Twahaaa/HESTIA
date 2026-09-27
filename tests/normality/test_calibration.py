"""Visibly synthetic mechanics tests for deterministic normal calibration."""

from __future__ import annotations

import pytest

from hestia.normality.calibration import ValidationScore, calibrate_alert_budget


def test_alert_budget_is_reproducible_and_ties_use_evidence_reference_order() -> None:
    synthetic_validation = [
        ValidationScore("synthetic:c", 0.8, True),
        ValidationScore("synthetic:a", 0.8, True),
        ValidationScore("synthetic:b", 0.8, True),
        ValidationScore("synthetic:d", 0.2, True),
    ]

    first = calibrate_alert_budget(synthetic_validation, max_alerts_per_batch=2)
    second = calibrate_alert_budget(list(reversed(synthetic_validation)), max_alerts_per_batch=2)

    assert first == second
    assert first.minimum_score == 0.8
    assert first.unit == "sessions_per_evaluation_batch"
    assert first.tie_handling == "score_desc_then_evidence_ref_asc"
    assert first.select(synthetic_validation) == ("synthetic:a", "synthetic:b")


def test_calibration_rejects_non_normal_or_non_finite_validation_inputs() -> None:
    with pytest.raises(ValueError, match="explicit normal validation"):
        calibrate_alert_budget(
            [ValidationScore("synthetic:unknown", 1.0, False)],
            max_alerts_per_batch=1,
        )
    with pytest.raises(ValueError, match="finite"):
        calibrate_alert_budget(
            [ValidationScore("synthetic:nan", float("nan"), True)],
            max_alerts_per_batch=1,
        )
