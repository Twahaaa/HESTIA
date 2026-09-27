"""Independent Loghub HDFS v1 anomaly benchmark; no auth or agent conclusions.

The benchmark case is one block trace, not an authentication session. Raw log
line order establishes the split; traces crossing boundaries are excluded.
Only explicitly labelled Normal training traces update the baseline, and only
Normal validation traces choose its threshold. Held-out labels are read after
all predictions are computed. No labels enter runtime evidence or MCP tools.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import re
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from hestia.evaluation.metrics import wilson

SOURCE_URL = "https://zenodo.org/records/8196385"
ARCHIVE_MD5 = "76a24b4d9a6164d543fb275f89773260"
BLOCK = re.compile(rb"(?<![\w])blk_-?\d+(?!\d)")
EVENT = re.compile(r"E\d+\Z")


class HDFSConfig(BaseModel):
    model_config = ConfigDict(frozen=True)
    schema_version: int = 1
    archive_md5: str = ARCHIVE_MD5
    train_fraction: float = Field(default=0.6, gt=0, lt=1)
    validation_fraction: float = Field(default=0.2, gt=0, lt=1)
    normal_alert_quantile: float = Field(default=0.95, gt=0, lt=1)


@dataclass(frozen=True)
class Trace:
    block_id: str
    event_ids: tuple[str, ...]


class TransitionBaseline:
    """Laplace-smoothed sequence likelihood, not a DeepLog reproduction."""

    def __init__(self) -> None:
        self.transitions: Counter[tuple[str, str]] = Counter()
        self.context: Counter[str] = Counter()
        self.vocabulary: set[str] = set()

    def learn(self, events: tuple[str, ...]) -> None:
        self.vocabulary.update(events)
        for pair in zip(("<start>", *events[:-1]), events, strict=True):
            self.transitions[pair] += 1
            self.context[pair[0]] += 1

    def score(self, events: tuple[str, ...]) -> float:
        return self.score_components(events)[0]

    def score_components(self, events: tuple[str, ...]) -> tuple[float, float]:
        """Mean and peak transition surprise from the same frozen normal model."""
        if not events or not self.vocabulary:
            raise ValueError("a trained baseline and a nonempty trace are required")
        choices = len(self.vocabulary) + 1  # reserve an unseen-event bucket
        surprises = (
            -math.log(
                (self.transitions[previous, current] + 1) / (self.context[previous] + choices)
            )
            for previous, current in zip(("<start>", *events[:-1]), events, strict=True)
        )
        total = peak = 0.0
        for value in surprises:
            total += value
            peak = max(peak, value)
        return total / len(events), peak


def source_order(archive: zipfile.ZipFile) -> tuple[dict[str, tuple[int, int]], int]:
    """First and last raw-log line for every block, including interleaved traces."""
    bounds: dict[str, tuple[int, int]] = {}
    lines = 0
    with archive.open("HDFS.log") as stream:
        for lines, raw in enumerate(stream, 1):
            for match in set(BLOCK.findall(raw)):
                block = match.decode("ascii")
                first = bounds[block][0] if block in bounds else lines
                bounds[block] = (first, lines)
    return bounds, lines


def _csv_rows(archive: zipfile.ZipFile, name: str):
    with archive.open(name) as raw, io.TextIOWrapper(raw, encoding="utf-8", newline="") as text:
        yield from csv.DictReader(text)


def load_labels(archive: zipfile.ZipFile) -> dict[str, bool]:
    labels: dict[str, bool] = {}
    for row in _csv_rows(archive, "preprocessed/anomaly_label.csv"):
        block, label = row["BlockId"], row["Label"]
        if not BLOCK.fullmatch(block.encode("ascii")) or label not in {"Normal", "Anomaly"}:
            raise ValueError("invalid HDFS block annotation")
        if block in labels:
            raise ValueError("duplicate HDFS block annotation")
        labels[block] = label == "Anomaly"
    return labels


def traces(archive: zipfile.ZipFile):
    """Parse the upstream event-sequence column; never treat Type as truth."""
    for row in _csv_rows(archive, "preprocessed/Event_traces.csv"):
        raw = row["Features"]
        if not raw.startswith("[") or not raw.endswith("]"):
            raise ValueError("invalid HDFS event trace")
        events = tuple(part.strip() for part in raw[1:-1].split(","))
        if not events or any(not EVENT.fullmatch(event) for event in events):
            raise ValueError("invalid HDFS event identifier")
        yield Trace(block_id=row["BlockId"], event_ids=events)


def _intervals(first_lines: list[int], train_fraction: float, validation_fraction: float):
    ordered = sorted(first_lines)
    if len(ordered) < 5 or train_fraction + validation_fraction >= 1:
        raise ValueError("at least five blocks and a nonempty held-out split are required")
    return ordered[int(len(ordered) * train_fraction)], ordered[
        int(len(ordered) * (train_fraction + validation_fraction))
    ]


def _split(first: int, last: int, training_end: int, validation_end: int) -> str:
    if last < training_end:
        return "training"
    if first >= training_end and last < validation_end:
        return "validation"
    if first >= validation_end:
        return "evaluation"
    return "cross_boundary"


def _confusion(rows: list[tuple[bool, bool]]) -> dict[str, object]:
    tp = sum(truth and predicted for truth, predicted in rows)
    fp = sum(not truth and predicted for truth, predicted in rows)
    fn = sum(truth and not predicted for truth, predicted in rows)
    tn = sum(not truth and not predicted for truth, predicted in rows)
    return {
        "normal": tn + fp,
        "anomalous": tp + fn,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
        "precision_ci95": wilson(tp, tp + fp),
        "recall_ci95": wilson(tp, tp + fn),
    }


def evaluate_hdfs(archive_path: Path, config_path: Path, output_root: Path) -> dict[str, object]:
    """Run a source-order holdout, writing immutable aggregate-only results."""
    config = HDFSConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
    if config.schema_version != 1:
        raise ValueError("unsupported HDFS benchmark config version")
    digest = hashlib.md5(archive_path.read_bytes()).hexdigest()  # noqa: S324 - upstream identity
    if digest != config.archive_md5:
        raise ValueError("HDFS archive differs from pinned upstream checksum")
    archive_sha256 = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    with zipfile.ZipFile(archive_path) as archive:
        expected = {"HDFS.log", "preprocessed/anomaly_label.csv", "preprocessed/Event_traces.csv"}
        if not expected.issubset(archive.namelist()):
            raise ValueError("HDFS v1 archive is missing required members")
        bounds, raw_lines = source_order(archive)
        labels = load_labels(archive)
        if set(bounds) != set(labels):
            raise ValueError("raw HDFS blocks and annotation ids do not match")
        train_end, validation_end = _intervals(
            [first for first, _ in bounds.values()],
            config.train_fraction,
            config.validation_fraction,
        )
        split_counts: Counter[str] = Counter()
        seen: set[str] = set()
        baseline = TransitionBaseline()
        # Training is restricted to completed Normal traces before the boundary.
        for trace in traces(archive):
            if trace.block_id in seen or trace.block_id not in labels:
                raise ValueError("duplicate or unlabelled HDFS event trace")
            seen.add(trace.block_id)
            split = _split(*bounds[trace.block_id], train_end, validation_end)
            split_counts[split] += 1
            if split == "training" and not labels[trace.block_id]:
                baseline.learn(trace.event_ids)
        if seen != set(labels) or not baseline.vocabulary:
            raise ValueError("trace coverage is incomplete or no normal training cases exist")
        # Only held-out normal validation scores influence the threshold.
        validation_scores = sorted(
            baseline.score(trace.event_ids)
            for trace in traces(archive)
            if _split(*bounds[trace.block_id], train_end, validation_end) == "validation"
            and not labels[trace.block_id]
        )
        if not validation_scores:
            raise ValueError("no normal validation cases exist")
        threshold = validation_scores[
            math.ceil(config.normal_alert_quantile * len(validation_scores)) - 1
        ]
        # Predictions are frozen before joining held-out truth.
        predictions = {
            trace.block_id: baseline.score(trace.event_ids) > threshold
            for trace in traces(archive)
            if _split(*bounds[trace.block_id], train_end, validation_end) == "evaluation"
        }
        rows = [(labels[block], prediction) for block, prediction in predictions.items()]
        anomaly_by_split: Counter[str] = Counter()
        for block, (first, last) in bounds.items():
            if labels[block]:
                anomaly_by_split[_split(first, last, train_end, validation_end)] += 1
        error_examples: dict[str, list[str]] = {"false_positive": [], "false_negative": []}
        for block in sorted(predictions):
            truth, predicted = labels[block], predictions[block]
            category = (
                "false_negative"
                if truth and not predicted
                else ("false_positive" if not truth and predicted else None)
            )
            if category is not None and len(error_examples[category]) < 3:
                error_examples[category].append(block)
    result: dict[str, object] = {
        "schema_version": 1,
        "benchmark": "Loghub HDFS v1 block-trace anomaly detection",
        "source": SOURCE_URL,
        "archive_sha256": archive_sha256,
        "config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        "unit": "completed block trace",
        "method": "Laplace-smoothed event-transition baseline; not DeepLog or Hestia agent",
        "split_policy": "first/last raw-log line; crossing traces excluded; no label-based split",
        "raw_log_lines": raw_lines,
        "blocks": len(bounds),
        "split_counts": {
            name: split_counts[name]
            for name in ("training", "validation", "evaluation", "cross_boundary")
        },
        "anomaly_counts_by_split": {
            name: anomaly_by_split[name]
            for name in ("training", "validation", "evaluation", "cross_boundary")
        },
        "training_normal": split_counts["training"]
        - sum(
            labels[block]
            for block, (first, last) in bounds.items()
            if _split(first, last, train_end, validation_end) == "training"
        ),
        "validation_normal": len(validation_scores),
        "threshold": threshold,
        "normal_alert_quantile": config.normal_alert_quantile,
        "holdout": _confusion(rows),
        "error_examples": error_examples,
        "limitations": [
            "Benchmark block anomalies are not security attacks or Hestia auth cases.",
            "Baseline only; no agent investigation or hosted inference was run.",
            "Upstream labels are rule-derived, not independently adjudicated.",
            "Full-trace scoring is retrospective; it does not measure early detection.",
            "Upstream event templates were derived from the full corpus, so template extraction is transductive.",
        ],
    }
    run_id = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()[:20]
    destination = output_root / f"hdfs-{run_id}"
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "results.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {"run_id": f"hdfs-{run_id}", "results_path": str(destination / "results.json"), **result}


def inspect_block(archive_path: Path, block_id: str, *, limit: int = 20) -> dict[str, object]:
    """Read-only source-qualified evidence, without consulting benchmark labels."""
    if not BLOCK.fullmatch(block_id.encode("ascii")) or not 1 <= limit <= 100:
        raise ValueError("invalid block id or evidence limit")
    matches: list[dict[str, object]] = []
    with zipfile.ZipFile(archive_path) as archive, archive.open("HDFS.log") as stream:
        for line_no, raw in enumerate(stream, 1):
            if block_id.encode("ascii") in set(BLOCK.findall(raw)):
                matches.append(
                    {
                        "source": "HDFS.log",
                        "line_no": line_no,
                        "text": raw.decode("utf-8", errors="replace").rstrip("\r\n"),
                    }
                )
                if len(matches) > limit:
                    break
    return {"block_id": block_id, "events": matches[:limit], "truncated": len(matches) > limit}
