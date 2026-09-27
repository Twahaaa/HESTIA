"""Source-aware collection with one UTC normalization boundary."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from hestia.contracts import Event, ParseFailure
from hestia.datasets.profiles import DatasetProfile
from hestia.ingestion.parser import parse_line, parse_timestamp

_TIMESTAMP_RE = re.compile(
    r"^(?P<timestamp>(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)|"
    r"(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?))"
)
_MONTHS = {
    month: index
    for index, month in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}


class CollectedEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    event: Event
    raw_timestamp: str


class CollectionResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    profile: DatasetProfile
    content_hash: str
    raw_line_count: int
    events: tuple[CollectedEvent, ...]
    failures: tuple[ParseFailure, ...]


def collect_source(path: Path, profile: DatasetProfile) -> CollectionResult:
    """Collect a source, retaining every raw line and sorting parsed UTC events."""
    raw_bytes = path.read_bytes()
    lines = raw_bytes.decode("utf-8", errors="replace").splitlines(keepends=True)
    events: list[CollectedEvent] = []
    failures: list[ParseFailure] = []
    current_year = profile.default_year
    previous_month: int | None = None

    for line_no, raw_line in enumerate(lines, start=1):
        match = _TIMESTAMP_RE.match(raw_line.rstrip("\r\n"))
        raw_timestamp = match.group("timestamp") if match else None
        if raw_timestamp and not raw_timestamp[0].isdigit():
            month = _MONTHS[raw_timestamp[:3]]
            if previous_month is not None and previous_month >= 11 and month <= 2:
                current_year += 1
            previous_month = month
        elif raw_timestamp and re.match(r"^\d{4}-", raw_timestamp):
            current_year = int(raw_timestamp[:4])
            previous_month = int(raw_timestamp[5:7])

        result = parse_line(
            profile.source_path,
            line_no,
            raw_line,
            default_year=current_year,
            timezone=profile.timezone,
            dst_fold=profile.dst_fold,
        )
        if isinstance(result, Event):
            if result.timestamp.tzinfo is None:
                raise ValueError("Collector received a timezone-naive event")
            events.append(CollectedEvent(event=result, raw_timestamp=raw_timestamp or ""))
        else:
            if raw_timestamp:
                try:
                    timestamp = parse_timestamp(
                        raw_timestamp,
                        default_year=current_year,
                        timezone=profile.timezone,
                        dst_fold=profile.dst_fold,
                    )
                    result = result.model_copy(update={"timestamp": timestamp})
                except Exception:  # The parser's reason remains the authoritative failure.
                    pass
            failures.append(result)

    events.sort(key=lambda item: (item.event.timestamp, item.event.line_no))
    return CollectionResult(
        profile=profile,
        content_hash=hashlib.sha256(raw_bytes).hexdigest(),
        raw_line_count=len(lines),
        events=tuple(events),
        failures=tuple(failures),
    )


__all__ = ["CollectedEvent", "CollectionResult", "collect_source"]
