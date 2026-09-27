"""Descriptive evaluation metrics; undefined denominators remain null."""

from __future__ import annotations

import math
from collections.abc import Iterable
from statistics import median

from hestia.evaluation.contracts import Truth


def wilson(successes: int, total: int) -> tuple[float, float] | None:
    """95% Wilson binomial interval, undefined when no observations exist."""
    if total <= 0:
        return None
    z = 1.959963984540054
    proportion = successes / total
    denominator = 1 + z * z / total
    centre = (proportion + z * z / (2 * total)) / denominator
    margin = (
        z
        * math.sqrt(proportion * (1 - proportion) / total + z * z / (4 * total * total))
        / denominator
    )
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def confusion(rows: Iterable[tuple[Truth, str | None]]) -> dict[str, object]:
    """Binary attack detection; abstentions are *not* counted as true negatives.

    Benign is negative, suspicious/malicious positive. Unknown truth is excluded
    from the labelled denominator but counted. Missing/insufficient/incomplete
    predictions abstain, with a separate coverage measure.
    """
    tp = fp = tn = fn = abstained = unknown = 0
    for truth, prediction in rows:
        if truth is Truth.unknown:
            unknown += 1
        elif prediction not in {"benign", "suspicious", "malicious"}:
            abstained += 1
        elif truth is Truth.attack:
            if prediction == "benign":
                fn += 1
            else:
                tp += 1
        elif prediction == "benign":
            tn += 1
        else:
            fp += 1
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None
    labelled = tp + fp + tn + fn + abstained
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "abstained": abstained,
        "unknown_truth": unknown,
        "labelled": labelled,
        "decided": labelled - abstained,
        "precision": precision,
        "precision_ci95": wilson(tp, tp + fp),
        "recall": recall,
        "recall_ci95": wilson(tp, tp + fn),
        "f1": f1,
        "abstention_rate": abstained / labelled if labelled else None,
        "decision_coverage": (labelled - abstained) / labelled if labelled else None,
    }


def latency(seconds: Iterable[float]) -> dict[str, float | None]:
    values = sorted(seconds)
    if not values:
        return {"p50_seconds": None, "p95_seconds": None}
    return {
        "p50_seconds": median(values),
        "p95_seconds": values[math.ceil(0.95 * len(values)) - 1],
    }


def false_alert_rate(false_alerts: int, normal_hours: float) -> float | None:
    """Requires measured normal exposure; never infer it from session count."""
    return false_alerts / normal_hours if normal_hours > 0 else None
