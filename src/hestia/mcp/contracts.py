"""Typed read-only tool contracts.

Every tool result carries its schema version, the request that produced it, the
source references a report may cite, and an explicit availability outcome. No
contract in this module has a verdict, severity, label or score-derived class:
tools retrieve facts, they do not decide whether evidence is malicious.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

TOOL_SCHEMA_VERSION = 1

#: Field names that must never appear in a runtime tool contract. Evaluation
#: annotations live in sidecars outside the evidence store and stay there.
FORBIDDEN_FIELD_NAMES = frozenset(
    {
        "attack",
        "attack_family",
        "ground_truth",
        "is_attack",
        "label",
        "labels",
        "malicious",
        "risk",
        "severity",
        "threat",
        "threat_score",
        "verdict",
    }
)

_ENTITY_TYPES = ("user", "host", "src_ip")
_IDENTIFIER = re.compile(r"\A[\w .:@/+\-]{1,1024}\Z", re.ASCII)
_LIKE_ESCAPE = re.compile(r"([\\%_])")


class ToolInputError(ValueError):
    """A caller supplied an argument this read boundary refuses to interpret."""


class SourceRef(BaseModel):
    """A stable, citable pointer to prepared evidence or reference material."""

    model_config = ConfigDict(frozen=True)

    evidence_ref: str = Field(description="Stable identifier a later report may cite.")
    dataset_id: str = Field(description="Prepared dataset identifier.")
    source_path: str = Field(description="Logical source path inside the dataset.")
    source_sha256: str = Field(description="Content digest of the imported source file.")
    line_no: int | None = Field(default=None, description="1-based source line, when known.")


class ToolResult(BaseModel):
    """Base envelope shared by every Hestia MCP tool result."""

    model_config = ConfigDict(frozen=True)

    schema_version: int = Field(default=TOOL_SCHEMA_VERSION)
    request_id: str = Field(description="Identifier of this tool invocation.")
    available: bool = Field(description="False when the requested facts cannot be retrieved.")
    unavailable_reason: str | None = Field(
        default=None, description="Explicit reason when available is false."
    )
    truncated: bool = Field(default=False, description="True when output was cut short.")
    truncation_reason: str | None = Field(default=None)
    next_cursor: str | None = Field(
        default=None, description="Opaque cursor for the next page, or null at the end."
    )
    source_refs: tuple[SourceRef, ...] = Field(default=())
    notes: tuple[str, ...] = Field(
        default=(), description="Coverage limitations that apply to this result."
    )


class EventRecord(BaseModel):
    """One prepared authentication event with its complete stored identity."""

    model_config = ConfigDict(frozen=True)

    event_id: str
    dataset_id: str
    source_path: str
    line_no: int
    timestamp: datetime
    raw_timestamp: str | None
    host: str
    process: str
    pid: int | None
    event_type: str
    user: str | None
    target_user: str | None
    src_ip: str | None
    src_port: int | None
    method: str | None
    command: str | None
    tty: str | None
    success: bool | None
    message: str
    raw_line: str
    raw_line_truncated: bool
    unmatched: bool
    unmatched_reason: str | None
    source_ref: SourceRef


class SessionRecord(BaseModel):
    """One prepared session. Structural counts only; no prioritization is implied."""

    model_config = ConfigDict(frozen=True)

    session_id: str
    dataset_id: str
    source_path: str
    host: str | None
    user: str | None
    src_ip: str | None
    src_port: int | None
    primary_method: str | None
    start_time: datetime
    end_time: datetime
    event_count: int
    failure_count: int
    gap_seconds: float
    has_escalation: bool
    has_persistence: bool
    source_ref: SourceRef


class SessionResult(ToolResult):
    session: SessionRecord | None = None


class EventResult(ToolResult):
    event: EventRecord | None = None


class EventPage(ToolResult):
    items: tuple[EventRecord, ...] = ()
    returned: int = 0


class EntityObservation(BaseModel):
    """One historical session summary observed strictly before the case boundary."""

    model_config = ConfigDict(frozen=True)

    session_id: str
    dataset_id: str
    source_path: str
    host: str | None
    user: str | None
    src_ip: str | None
    start_time: datetime
    end_time: datetime
    event_count: int
    failure_count: int
    source_ref: SourceRef


class EntityHistoryResult(ToolResult):
    """Counts of prior observations. These are observations, never severity."""

    entity_type: Literal["user", "host", "src_ip"] | None = None
    entity_id: str | None = None
    before: datetime | None = None
    window_start: datetime | None = None
    window_end: datetime | None = None
    entity_session_count: int = 0
    entity_event_count: int = 0
    store_session_denominator: int = 0
    distinct_hosts: int = 0
    distinct_users: int = 0
    distinct_src_ips: int = 0
    items: tuple[EntityObservation, ...] = ()
    returned: int = 0


class ModelObservation(BaseModel):
    """Readiness of one behavioral model for one entity of this session."""

    model_config = ConfigDict(frozen=True)

    model_id: str
    entity_kind: str
    entity_id: str | None
    ready: bool
    readiness_reason: str | None
    observation_count: int
    warmup_observations: int


class TrainingProvenance(BaseModel):
    """What the local normality training actually produced, without interpretation."""

    model_config = ConfigDict(frozen=True)

    readiness_recorded: bool
    ready: bool
    reason: str | None
    eligible_training_sessions: int | None
    artifact_count: int | None
    split_manifest_hash: str | None


class HistoricalContext(BaseModel):
    """Counts materialized strictly before the session start boundary."""

    model_config = ConfigDict(frozen=True)

    deployment_timezone: str
    auth_frequency_window_count: int
    user_first_seen: bool
    src_ip_first_seen: bool
    host_first_seen: bool
    user_observation_count: int
    src_ip_observation_count: int
    host_observation_count: int
    distinct_hosts_for_user: int
    distinct_users_for_src_ip: int
    distinct_users_for_host: int
    distinct_src_ips_for_host: int


class NormalityContextResult(ToolResult):
    """Normality explanation. Null scores mean not-ready, never benign."""

    session_id: str | None = None
    as_of: datetime | None = None
    historical_session_count: int = 0
    context: HistoricalContext | None = None
    models: tuple[ModelObservation, ...] = ()
    training_provenance: TrainingProvenance | None = None
    scores_available: bool = False


class ReferenceMatch(BaseModel):
    """One retrieved reference document with a transparent lexical score."""

    model_config = ConfigDict(frozen=True)

    document_id: str
    collection: str
    title: str
    technique_ids: tuple[str, ...]
    lexical_score: float
    matched_terms: tuple[tuple[str, float], ...]
    snippet: str
    snippet_truncated: bool
    snippet_start_line: int | None
    snippet_end_line: int | None
    source_uri: str
    source_sha256: str
    source_version: str
    attribution: str


class ReferencePage(ToolResult):
    query: str | None = None
    items: tuple[ReferenceMatch, ...] = ()
    returned: int = 0
    scoring_method: str = "deterministic lexical overlap; not a known/novel classifier"


class TechniqueResult(ToolResult):
    technique_id: str | None = None
    name: str | None = None
    description: str | None = None
    tactics: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ()
    data_sources: tuple[str, ...] = ()
    url: str | None = None
    snapshot_version: str | None = None
    attribution: str | None = None
    local_manifestations: tuple[ReferenceMatch, ...] = ()


def validate_limit(limit: int | None, *, default: int, maximum: int) -> int:
    """Clamp a caller-supplied page size to the configured bound."""
    if limit is None:
        return default
    if not isinstance(limit, int) or isinstance(limit, bool):
        raise ToolInputError("limit must be an integer")
    if limit < 1:
        raise ToolInputError("limit must be at least 1")
    return min(limit, maximum)


def validate_identifier(value: str, *, field: str, maximum: int = 512) -> str:
    """Accept a known-shaped identifier as data only; never as a path or expression."""
    if not isinstance(value, str):
        raise ToolInputError(f"{field} must be a string")
    candidate = value.strip()
    if not candidate:
        raise ToolInputError(f"{field} must not be empty")
    if len(candidate) > maximum:
        raise ToolInputError(f"{field} exceeds {maximum} characters")
    if "\x00" in candidate or "\n" in candidate or "\r" in candidate:
        raise ToolInputError(f"{field} contains control characters")
    if not _IDENTIFIER.match(candidate):
        raise ToolInputError(f"{field} contains unsupported characters")
    return candidate


def validate_entity_type(value: str) -> Literal["user", "host", "src_ip"]:
    if value not in _ENTITY_TYPES:
        raise ToolInputError(f"entity_type must be one of {_ENTITY_TYPES}")
    return value  # type: ignore[return-value]


def validate_query(value: str, *, maximum: int) -> str:
    """Treat search text strictly as data: no regex, SQL or shell is derived from it."""
    if not isinstance(value, str):
        raise ToolInputError("query must be a string")
    candidate = value.strip()
    if not candidate:
        raise ToolInputError("query must not be empty")
    if len(candidate) > maximum:
        raise ToolInputError(f"query exceeds {maximum} characters")
    if "\x00" in candidate:
        raise ToolInputError("query contains a null byte")
    return candidate


def like_pattern(value: str) -> str:
    """Escape LIKE wildcards so caller text can only ever match itself literally."""
    return f"%{_LIKE_ESCAPE.sub(r'\\\1', value)}%"


def validate_instant(value: str | None, *, field: str) -> datetime | None:
    """Require an explicit timezone so historical boundaries cannot drift."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ToolInputError(f"{field} must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ToolInputError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ToolInputError(f"{field} must include a timezone offset")
    return parsed.astimezone(UTC)


def validate_window(start: datetime | None, end: datetime | None) -> None:
    if start is not None and end is not None and start >= end:
        raise ToolInputError("start must be strictly before end")


def encode_cursor(values: tuple[str, ...]) -> str:
    payload = json.dumps(list(values), separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(payload).decode("ascii")


def decode_cursor(cursor: str | None, *, arity: int) -> tuple[str, ...] | None:
    """Decode an opaque cursor this server issued; reject anything else."""
    if cursor is None:
        return None
    if not isinstance(cursor, str) or len(cursor) > 1024:
        raise ToolInputError("cursor is not a cursor issued by this server")
    try:
        payload = json.loads(base64.urlsafe_b64decode(cursor.encode("ascii")))
    except (ValueError, binascii.Error, UnicodeEncodeError) as exc:
        raise ToolInputError("cursor is not a cursor issued by this server") from exc
    if not isinstance(payload, list) or len(payload) != arity:
        raise ToolInputError("cursor is not a cursor issued by this server")
    if not all(isinstance(item, str) for item in payload):
        raise ToolInputError("cursor is not a cursor issued by this server")
    return tuple(payload)


def truncate_text(value: str, *, maximum: int) -> tuple[str, bool]:
    """Cut oversized text and report the cut rather than hiding it."""
    if len(value) <= maximum:
        return value, False
    return value[:maximum] + "…[truncated]", True


__all__ = [
    "FORBIDDEN_FIELD_NAMES",
    "TOOL_SCHEMA_VERSION",
    "EntityHistoryResult",
    "EntityObservation",
    "EventPage",
    "EventRecord",
    "EventResult",
    "HistoricalContext",
    "ModelObservation",
    "NormalityContextResult",
    "ReferenceMatch",
    "ReferencePage",
    "SessionRecord",
    "SessionResult",
    "SourceRef",
    "TechniqueResult",
    "ToolInputError",
    "ToolResult",
    "TrainingProvenance",
    "decode_cursor",
    "encode_cursor",
    "like_pattern",
    "truncate_text",
    "validate_entity_type",
    "validate_identifier",
    "validate_instant",
    "validate_limit",
    "validate_query",
    "validate_window",
]
