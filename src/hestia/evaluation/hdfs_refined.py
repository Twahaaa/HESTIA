"""Validation-only model selection for an HDFS normal-sequence baseline.

The previously reported HDFS evaluation aggregate has already been viewed, so
this is exploratory. Candidates and the validation selection policy are frozen
in a public config before the evaluation split is scored. Only explicitly normal
training traces update estimators; anomaly annotations are used for validation
model selection and final measurement, never as a predictor feature.
"""

from __future__ import annotations

import hashlib
import json
import math
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from pydantic import Field

from hestia.evaluation.hdfs import (
    SOURCE_URL,
    HDFSConfig,
    TransitionBaseline,
    _confusion,
    _intervals,
    _split,
    load_labels,
    source_order,
    traces,
)

LENGTH_BINS = (2, 5, 10, 20, 50, 100)
CANDIDATES = ("mean", "mean_length", "mean_peak", "mean_length_peak")
QUANTILES = (0.95, 0.97, 0.99)


class RefinedConfig(HDFSConfig):
    min_validation_recall: float = Field(default=0.95, gt=0, le=1)


def length_bin(length: int) -> str:
    """Predeclared length bins, including short and long trace tails."""
    if length < 1:
        raise ValueError("trace length must be positive")
    return next((str(edge) for edge in LENGTH_BINS if length <= edge), ">100")


@dataclass(frozen=True)
class ScoredTrace:
    block_id: str
    first_line: int
    length: int
    scores: dict[str, float]


def candidate_scores(
    model: TransitionBaseline, normal_lengths: Counter[str], events: tuple[str, ...]
) -> dict[str, float]:
    """Four fixed candidates; length rarity fitted only from training normals."""
    mean, peak = model.score_components(events)
    bucket = length_bin(len(events))
    total = normal_lengths.total()
    rarity = -math.log((normal_lengths[bucket] + 1) / (total + len(LENGTH_BINS) + 1))
    return {
        "mean": mean,
        "mean_length": mean + 0.25 * rarity,
        "mean_peak": 0.75 * mean + 0.25 * peak,
        "mean_length_peak": 0.5 * mean + 0.25 * peak + 0.25 * rarity,
    }


def normal_threshold(scores: list[float], quantile: float) -> float:
    if not scores or not 0 < quantile < 1:
        raise ValueError("normal validation scores and a valid quantile are required")
    ordered = sorted(scores)
    return ordered[math.ceil(quantile * len(ordered)) - 1]


def choose_validation(
    records: list[ScoredTrace], labels: dict[str, bool], *, min_recall: float
) -> tuple[dict[str, object], list[dict[str, object]]]:
    """Select maximum precision at >= target recall, with fixed tie-breaking.

    A baseline candidate remains the control even if no candidate meets the
    target. No selection can inspect an evaluation-split prediction or label.
    """
    if not records or {labels[row.block_id] for row in records} != {False, True}:
        raise ValueError("selection needs both normal and anomalous validation cases")
    grid: list[dict[str, object]] = []
    for candidate in CANDIDATES:
        normal = [row.scores[candidate] for row in records if not labels[row.block_id]]
        for quantile in QUANTILES:
            threshold = normal_threshold(normal, quantile)
            matrix = _confusion(
                [(labels[row.block_id], row.scores[candidate] > threshold) for row in records]
            )
            grid.append(
                {
                    "candidate": candidate,
                    "quantile": quantile,
                    "threshold": threshold,
                    "confusion": matrix,
                }
            )
    eligible = [item for item in grid if (item["confusion"]["recall"] or 0) >= min_recall]
    if not eligible:
        # The fallback is measured, not asserted to meet the target.
        return grid[0] | {"met_recall_target": False}, grid
    chosen = max(
        eligible,
        key=lambda item: (
            item["confusion"]["precision"] or 0,
            item["confusion"]["recall"] or 0,
            -CANDIDATES.index(item["candidate"]),
            -QUANTILES.index(item["quantile"]),
        ),
    )
    return chosen | {"met_recall_target": True}, grid


def validation_error_analysis(
    records: list[ScoredTrace], labels: dict[str, bool], threshold: float
) -> dict[str, object]:
    """Full error-length counts and varied examples from validation, not test."""
    bins: dict[str, Counter[str]] = {
        category: Counter()
        for category in ("true_positive", "false_positive", "true_negative", "false_negative")
    }
    members: dict[str, list[ScoredTrace]] = {category: [] for category in bins}
    for row in records:
        actual, predicted = labels[row.block_id], row.scores["mean"] > threshold
        category = (
            "true_positive"
            if actual and predicted
            else "false_negative"
            if actual
            else "false_positive"
            if predicted
            else "true_negative"
        )
        bins[category][length_bin(row.length)] += 1
        members[category].append(row)
    examples: dict[str, list[dict[str, object]]] = {}
    for category in ("false_positive", "false_negative"):
        ordered = sorted(members[category], key=lambda item: (item.first_line, item.block_id))
        if not ordered:
            examples[category] = []
            continue
        # Early, middle, late plus shortest/longest: varied, not a random sample.
        selected = [
            ordered[0],
            ordered[len(ordered) // 2],
            ordered[-1],
            min(ordered, key=lambda item: (item.length, item.block_id)),
            max(ordered, key=lambda item: (item.length, item.block_id)),
        ]
        unique = {item.block_id: item for item in selected}
        examples[category] = [
            {
                "block_id": item.block_id,
                "first_line": item.first_line,
                "event_count": item.length,
                "mean_surprise": item.scores["mean"],
            }
            for item in unique.values()
        ]
    return {
        "length_bin_counts": {
            name: {bucket: count for bucket, count in sorted(values.items())}
            for name, values in bins.items()
        },
        "varied_error_examples": examples,
        "note": "Selected from validation by source order and trace length; not statistically representative.",
    }


def evaluate_refined_hdfs(
    archive_path: Path, config_path: Path, output_root: Path
) -> dict[str, object]:
    config = RefinedConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
    if config.schema_version != 1 or config.normal_alert_quantile not in QUANTILES:
        raise ValueError("unsupported HDFS config version or control quantile")
    content = archive_path.read_bytes()
    if hashlib.md5(content).hexdigest() != config.archive_md5:  # noqa: S324 - upstream identity
        raise ValueError("HDFS archive differs from configured checksum")
    archive_sha = hashlib.sha256(content).hexdigest()
    with zipfile.ZipFile(archive_path) as archive:
        bounds, raw_lines = source_order(archive)
        labels = load_labels(archive)
        if set(bounds) != set(labels):
            raise ValueError("raw HDFS blocks and annotations do not match")
        train_end, validation_end = _intervals(
            [first for first, _ in bounds.values()],
            config.train_fraction,
            config.validation_fraction,
        )
        baseline = TransitionBaseline()
        normal_lengths: Counter[str] = Counter()
        split_counts: Counter[str] = Counter()
        seen: set[str] = set()
        for trace in traces(archive):
            if trace.block_id not in labels or trace.block_id in seen:
                raise ValueError("duplicate or unlabelled HDFS trace")
            seen.add(trace.block_id)
            split = _split(*bounds[trace.block_id], train_end, validation_end)
            split_counts[split] += 1
            if split == "training" and not labels[trace.block_id]:
                baseline.learn(trace.event_ids)
                normal_lengths[length_bin(len(trace.event_ids))] += 1
        if seen != set(labels) or not normal_lengths:
            raise ValueError("missing traces or no normal training cases")
        validation = [
            ScoredTrace(
                trace.block_id,
                bounds[trace.block_id][0],
                len(trace.event_ids),
                candidate_scores(baseline, normal_lengths, trace.event_ids),
            )
            for trace in traces(archive)
            if _split(*bounds[trace.block_id], train_end, validation_end) == "validation"
        ]
        selected, grid = choose_validation(
            validation, labels, min_recall=config.min_validation_recall
        )
        control = next(
            item
            for item in grid
            if item["candidate"] == "mean" and item["quantile"] == config.normal_alert_quantile
        )
        analysis = validation_error_analysis(validation, labels, control["threshold"])
        # Freeze both policies, then score the held-out cases once. The label
        # lookup here is strictly for final metrics, never for selecting a rule.
        control_rows: list[tuple[bool, bool]] = []
        selected_rows: list[tuple[bool, bool]] = []
        for trace in traces(archive):
            if _split(*bounds[trace.block_id], train_end, validation_end) != "evaluation":
                continue
            scores = candidate_scores(baseline, normal_lengths, trace.event_ids)
            control_rows.append((labels[trace.block_id], scores["mean"] > control["threshold"]))
            selected_rows.append(
                (labels[trace.block_id], scores[selected["candidate"]] > selected["threshold"])
            )
    result: dict[str, object] = {
        "schema_version": 1,
        "benchmark": "Loghub HDFS v1 completed block traces",
        "source": SOURCE_URL,
        "archive_sha256": archive_sha,
        "config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        "unit": "completed block trace",
        "raw_log_lines": raw_lines,
        "blocks": len(bounds),
        "split_counts": {
            split: split_counts[split]
            for split in ("training", "validation", "evaluation", "cross_boundary")
        },
        "training_normal": normal_lengths.total(),
        "validation_cases": len(validation),
        "selection_policy": "max validation precision at >= configured recall; ties favor recall then simpler rule",
        "validation_grid": grid,
        "selected": selected,
        "validation_error_analysis": analysis,
        "evaluation_control": _confusion(control_rows),
        "evaluation_selected": _confusion(selected_rows),
        "limitations": [
            "Exploratory: the original full HDFS evaluation aggregate was already viewed before this design.",
            "Validation labels select a candidate; only normal training labels update the baseline.",
            "Both rules score full block traces retrospectively; no Hestia agent ran.",
            "The upstream event templates were derived from the full corpus.",
            "Upstream anomaly annotations are rule-derived, not security attack labels.",
        ],
    }
    run_id = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()[:20]
    destination = output_root / f"hdfs-refined-{run_id}"
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "results.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {"run_id": destination.name, "results_path": str(destination / "results.json"), **result}
