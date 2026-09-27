"""Server-side resolution of a run's opaque evidence handles.

A report cites handles such as ``ev-3812f37983``. The reverse map that turns a
handle into a stored identifier lives in ``<artifact root>/cases/<run>.handles.json``.
It holds real identifiers and identity values, so it is read here, one handle at
a time, and never returned, logged or exported. A browser can ask for one handle
that the run actually cited or retrieved and gets back the exact stored line it
refers to; it cannot enumerate the map or ask for an arbitrary identifier.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hestia.config import Settings
from hestia.runs.cases import canonical_line
from hestia.store.repository import EvidenceRepository

RUN_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
HANDLE_PATTERN = re.compile(r"^(ev|se|rf)-[0-9a-f]{10}$")
_PSEUDONYM_PATTERN = re.compile(r"\b(?:host|user|target_user|src_ip|ruser)-\d{1,4}\b")
#: Lines returned when a cited handle is a whole session.
SESSION_LINE_LIMIT = 50

_KINDS = {"ev": "event", "se": "session", "rf": "reference"}


class CitationError(LookupError):
    """A handle could not be resolved. ``code`` says why, for the API."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class LocalMap:
    handles: dict[str, str]
    pseudonyms: dict[str, str]


def map_path(settings: Settings, run_id: str) -> Path:
    if not RUN_ID_PATTERN.fullmatch(run_id):
        raise CitationError("invalid_run_id", "run identifiers are 32 hexadecimal characters")
    return settings.redaction_map_root / f"{run_id}.handles.json"


def load_local_map(settings: Settings, run_id: str) -> LocalMap | None:
    """Read one run's reverse map, or None when it was never written."""
    from hestia.agent.redaction import read_local_maps

    path = map_path(settings, run_id)
    if not path.is_file():
        return None
    try:
        maps = read_local_maps(path)
    except (OSError, ValueError):
        return None
    return LocalMap(handles=maps["handles"], pseudonyms=maps["pseudonyms"])


def handle_kind(handle: str) -> str:
    return _KINDS.get(handle.split("-", 1)[0], "unknown")


def citable_handles(run: dict[str, Any]) -> set[str]:
    """Every handle the run's report cites or its trace retrieved."""
    handles: set[str] = set()
    for step in run.get("steps", ()):
        payload = json.loads(str(step["payload_json"]))
        handles.update(payload.get("evidence_handles") or ())
    report = run.get("report_json")
    if report:
        for finding in json.loads(str(report)).get("findings", ()):
            handles.update(finding.get("evidence_handles") or ())
    return handles


def mentioned_pseudonyms(texts: list[str], local: LocalMap | None) -> list[dict[str, str | None]]:
    """Resolve only the pseudonyms that actually appear in the given text."""
    found = sorted({match for text in texts for match in _PSEUDONYM_PATTERN.findall(text)})
    return [
        {"token": token, "value": None if local is None else local.pseudonyms.get(token)}
        for token in found
    ]


def resolve_citation(
    settings: Settings,
    repository: EvidenceRepository,
    run: dict[str, Any],
    handle: str,
) -> dict[str, Any]:
    """Return the stored evidence behind one handle of one run."""
    if not HANDLE_PATTERN.fullmatch(handle):
        raise CitationError("invalid_handle", "evidence handles look like ev-0123456789")
    if handle not in citable_handles(run):
        raise CitationError(
            "handle_not_in_run",
            "this run neither cited nor retrieved that handle",
        )
    local = load_local_map(settings, str(run["run_id"]))
    if local is None:
        raise CitationError(
            "map_missing",
            "the local handle map for this run is missing, so its citations cannot be "
            "resolved; runs recorded before handle maps were persisted stay unresolvable",
        )
    identifier = local.handles.get(handle)
    if identifier is None:
        raise CitationError("handle_unmapped", "the local map has no entry for that handle")

    kind = handle_kind(handle)
    base = {"handle": handle, "kind": kind}
    if kind == "event":
        row = repository.read_event(identifier)
        if row is None:
            raise CitationError(
                "evidence_missing", "the cited event is no longer in the evidence store"
            )
        return base | {"lines": [canonical_line(row)], "session": None, "reference": None}
    if kind == "session":
        row = repository.read_session(identifier)
        if row is None:
            raise CitationError(
                "evidence_missing", "the cited session is no longer in the evidence store"
            )
        session = json.loads(str(row["session_json"]))
        events = repository.read_session_events(
            identifier, after_ordinal=None, limit=SESSION_LINE_LIMIT
        )
        return base | {
            "lines": [canonical_line(event) for event in events],
            "lines_truncated": int(session.get("event_count") or 0) > len(events),
            "session": {
                "dataset_id": row["dataset_id"],
                "source": row["source_path"],
                "start": session.get("start_time"),
                "end": session.get("end_time"),
                "event_count": int(session.get("event_count") or 0),
            },
            "reference": None,
        }
    return base | {"lines": [], "session": None, "reference": _reference(settings, identifier)}


def _reference(settings: Settings, document_id: str) -> dict[str, Any]:
    from hestia.knowledge.contracts import read_index

    if not settings.knowledge_index.is_file():
        raise CitationError(
            "reference_unavailable", "the reference index is not built in this deployment"
        )
    document = read_index(settings.knowledge_index).by_id(document_id)
    if document is None:
        raise CitationError(
            "reference_unavailable",
            "the cited reference document is not in the current reference index",
        )
    return {
        "title": document.title,
        "collection": document.source.collection,
        "technique_ids": list(document.technique_ids),
        "snippet": document.snippet,
        "snippet_truncated": document.snippet_truncated,
        "source_uri": document.source.source_uri,
        "version": document.source.version,
        "attribution": document.source.attribution,
        "note": (
            "Reference material is attributed source text. A match does not establish "
            "that the case is this technique."
        ),
    }


__all__ = [
    "HANDLE_PATTERN",
    "RUN_ID_PATTERN",
    "CitationError",
    "LocalMap",
    "citable_handles",
    "handle_kind",
    "load_local_map",
    "map_path",
    "mentioned_pseudonyms",
    "resolve_citation",
]
