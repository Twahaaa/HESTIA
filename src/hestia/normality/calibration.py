"""Held-out-normal alert-budget calibration with deterministic ties."""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class ValidationScore:
    evidence_ref: str
    raw_score: float
    normal_validation: bool


@dataclass(frozen=True)
class AlertBudgetPolicy:
    """Frozen maximum alert budget for one evaluation batch."""

    max_alerts_per_batch: int
    minimum_score: float
    calibration_observation_count: int
    unit: str = "sessions_per_evaluation_batch"
    tie_handling: str = "score_desc_then_evidence_ref_asc"

    def select(
        self, scores: tuple[ValidationScore, ...] | list[ValidationScore]
    ) -> tuple[str, ...]:
        """Apply the frozen threshold and budget without changing the policy."""
        eligible = (item for item in scores if item.raw_score >= self.minimum_score)
        ordered = sorted(eligible, key=lambda item: (-item.raw_score, item.evidence_ref))
        return tuple(item.evidence_ref for item in ordered[: self.max_alerts_per_batch])


def calibrate_alert_budget(
    validation_scores: tuple[ValidationScore, ...] | list[ValidationScore],
    *,
    max_alerts_per_batch: int,
) -> AlertBudgetPolicy:
    """Choose and freeze a score floor from held-out explicitly normal validation."""
    if max_alerts_per_batch < 1:
        raise ValueError("max_alerts_per_batch must be positive")
    if not validation_scores:
        raise ValueError("Calibration requires held-out normal validation scores")
    refs: set[str] = set()
    for item in validation_scores:
        if not item.normal_validation:
            raise ValueError("Calibration accepts only explicit normal validation scores")
        if not item.evidence_ref or item.evidence_ref in refs:
            raise ValueError("Calibration evidence references must be non-empty and unique")
        if not math.isfinite(item.raw_score):
            raise ValueError("Calibration scores must be finite")
        refs.add(item.evidence_ref)
    ordered = sorted(validation_scores, key=lambda item: (-item.raw_score, item.evidence_ref))
    boundary = min(max_alerts_per_batch, len(ordered)) - 1
    return AlertBudgetPolicy(
        max_alerts_per_batch=max_alerts_per_batch,
        minimum_score=ordered[boundary].raw_score,
        calibration_observation_count=len(ordered),
    )


__all__ = ["AlertBudgetPolicy", "ValidationScore", "calibrate_alert_budget"]
