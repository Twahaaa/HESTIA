"""Loghub OpenSSH log loader."""

from __future__ import annotations

from pathlib import Path

from hestia.contracts import Event, ParseFailure
from hestia.ingestion.parser import parse_file


def load_loghub_openssh(
    path: Path,
    source: str = "loghub-openssh",
    default_year: int | None = None,
) -> tuple[list[Event], list[ParseFailure]]:
    """Load and parse a Loghub OpenSSH log file.

    Args:
        path: Path to the OpenSSH log file.
        source: Source name to tag events with.
        default_year: Year to assume for traditional syslog timestamps.

    Returns:
        Tuple of ``(events, parse_failures)``.

    Raises:
        FileNotFoundError: If ``path`` does not exist.
    """
    if not path.exists():
        raise FileNotFoundError(f"Loghub OpenSSH file not found: {path}")

    with path.open(encoding="utf-8", errors="replace") as handle:
        return parse_file(source, handle, default_year=default_year)
