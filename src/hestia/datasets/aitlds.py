"""AIT-LDS v2.0 auth.log loader and label sidecar reader."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from hestia.contracts import Event, LabelRecord, ParseFailure
from hestia.ingestion.parser import parse_file

EXPECTED_LABEL_COLUMNS = {
    "source",
    "line_no",
    "attack",
    "attack_family",
    "technique_ids",
}


def _normalize_label_source(source: str, expected_source: str | None) -> str:
    """Normalize label source paths to the actual parsed source name.

    AIT-LDS labels reference paths such as ``intranet_server/auth.log`` while
    the parsed events use ``auth.log``. When ``expected_source`` is provided,
    label keys are rewritten to match it; otherwise the basename is used.
    """
    source = source.strip()
    if expected_source is None:
        return Path(source).name
    return expected_source


def load_aitlds_labels(
    label_path: Path,
    expected_source: str | None = None,
) -> dict[tuple[str, int], LabelRecord]:
    """Read the AIT-LDS label sidecar CSV.

    Args:
        label_path: Path to the labels CSV file.
        expected_source: Source name used when parsing events. Label sources
            whose basename matches this value are normalized to it.

    Returns:
        Mapping from ``(source, line_no)`` to ``LabelRecord``.

    Raises:
        FileNotFoundError: If ``label_path`` does not exist.
        ValueError: If required columns are missing.
    """
    if not label_path.exists():
        raise FileNotFoundError(f"AIT-LDS label file not found: {label_path}")

    labels: dict[tuple[str, int], LabelRecord] = {}
    text = label_path.read_text(encoding="utf-8")
    if text.lstrip().startswith("{"):
        if expected_source is None:
            raise ValueError("JSONL annotations require an explicit source identifier")
        for line in text.splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            line_no = int(row["line"])
            if line_no < 1 or (expected_source, line_no) in labels:
                raise ValueError("Invalid or duplicate annotation line")
            names = row["labels"]
            if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
                raise ValueError("Annotation labels must be a list of strings")
            labels[(expected_source, line_no)] = LabelRecord(
                source=expected_source,
                line_no=line_no,
                attack=bool(names),
                attack_family=",".join(names) or None,
            )
        return labels
    with label_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError(f"AIT-LDS label CSV is empty: {label_path}")
        missing = EXPECTED_LABEL_COLUMNS - set(reader.fieldnames)
        if missing:
            raise ValueError(
                f"AIT-LDS label CSV missing columns: {sorted(missing)}; "
                f"expected {sorted(EXPECTED_LABEL_COLUMNS)}"
            )
        for row in reader:
            source = _normalize_label_source(row["source"], expected_source)
            line_no = int(row["line_no"])
            technique_ids_raw = row.get("technique_ids")
            technique_ids = None
            if technique_ids_raw:
                technique_ids = [tid.strip() for tid in technique_ids_raw.split(",") if tid.strip()]
            labels[(source, line_no)] = LabelRecord(
                source=source,
                line_no=line_no,
                attack=row["attack"].strip().lower() in {"1", "true", "yes"},
                attack_family=row.get("attack_family") or None,
                technique_ids=technique_ids,
            )
    return labels


def load_aitlds_events(
    log_path: Path,
    label_path: Path | None = None,
    source: str | None = None,
    default_year: int | None = None,
) -> tuple[list[Event], list[ParseFailure], dict[tuple[str, int], LabelRecord]]:
    """Load AIT-LDS auth.log events and optional labels.

    Args:
        log_path: Path to the auth.log file.
        label_path: Optional path to the labels CSV sidecar.
        source: Source name to tag events with; defaults to ``log_path.name``.
        default_year: Year to assume for traditional syslog timestamps.

    Returns:
        Tuple of ``(events, parse_failures, labels)``.

    Raises:
        FileNotFoundError: If ``log_path`` does not exist.
    """
    if not log_path.exists():
        raise FileNotFoundError(f"AIT-LDS log file not found: {log_path}")

    source_name = source or log_path.name
    labels: dict[tuple[str, int], LabelRecord] = {}
    if label_path is not None:
        labels = load_aitlds_labels(label_path, expected_source=source_name)

    with log_path.open(encoding="utf-8", errors="replace") as handle:
        events, failures = parse_file(source_name, handle, default_year=default_year)
    return events, failures, labels


def select_normal_pool(
    events: list[Event],
    labels: dict[tuple[str, int], LabelRecord],
    whole_clean_hosts_only: bool = True,
    *,
    complete_sources: frozenset[str] = frozenset(),
) -> list[Event]:
    """Select explicit benign labels, or absent labels in declared complete sources.

    Only declare complete_sources after verifying the dataset's attack annotation
    coverage. Absence of an annotation alone does not establish normality.
    """
    attacked_hosts = {
        event.host
        for event in events
        if (label := labels.get((event.source, event.line_no))) is not None and label.attack
    }
    result = []
    for event in events:
        label = labels.get((event.source, event.line_no))
        normal = not label.attack if label is not None else event.source in complete_sources
        if normal and (not whole_clean_hosts_only or event.host not in attacked_hosts):
            result.append(event)
    return result
