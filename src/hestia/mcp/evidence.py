"""Evidence retrieval tools.

These functions return what the prepared store actually holds: sessions, their
ordered events, single events by identity, and a literal text search. They do not
rank, classify or judge anything. Unmatched evidence — records whose user or
source IP is missing — stays searchable in its own right so a missing field can
never hide escalation activity from an investigator.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from hestia.mcp.context import ToolContext, enforce_result_size
from hestia.mcp.contracts import (
    EventPage,
    EventRecord,
    EventResult,
    SessionRecord,
    SessionResult,
    SourceRef,
    ToolInputError,
    decode_cursor,
    encode_cursor,
    like_pattern,
    truncate_text,
    validate_identifier,
    validate_instant,
    validate_query,
    validate_window,
)

_UNAVAILABLE = "the prepared evidence store does not exist; run `hestia prepare-data` first"


def _source_ref(row: dict[str, Any], *, line_no: int | None, suffix: str) -> SourceRef:
    return SourceRef(
        evidence_ref=f"{row['dataset_id']}:{row['source_path']}:{suffix}",
        dataset_id=str(row["dataset_id"]),
        source_path=str(row["source_path"]),
        source_sha256=str(row["source_hash"]),
        line_no=line_no,
    )


def _event_record(row: dict[str, Any], *, max_chars: int) -> EventRecord:
    payload = json.loads(row["event_json"])
    event = payload["event"]
    raw_line, raw_truncated = truncate_text(
        str(payload.get("raw_line") or event["raw_message"]), maximum=max_chars
    )
    message, _ = truncate_text(str(event["message"]), maximum=max_chars)
    return EventRecord(
        event_id=str(row["event_id"]),
        dataset_id=str(row["dataset_id"]),
        source_path=str(row["source_path"]),
        line_no=int(row["line_no"]),
        timestamp=datetime.fromisoformat(str(row["timestamp"])),
        raw_timestamp=payload.get("raw_timestamp"),
        host=event["host"],
        process=event["process"],
        pid=event.get("pid"),
        event_type=event["event_type"],
        user=event.get("user"),
        target_user=event.get("target_user"),
        src_ip=event.get("src_ip"),
        src_port=event.get("src_port"),
        method=event.get("method"),
        command=event.get("command"),
        tty=event.get("tty"),
        success=event.get("success"),
        message=message,
        raw_line=raw_line,
        raw_line_truncated=raw_truncated,
        unmatched=bool(row["unmatched"]),
        unmatched_reason=row["unmatched_reason"],
        source_ref=_source_ref(row, line_no=int(row["line_no"]), suffix=str(row["event_id"])),
    )


def _session_record(row: dict[str, Any]) -> SessionRecord:
    session = json.loads(row["session_json"])
    return SessionRecord(
        session_id=str(row["session_id"]),
        dataset_id=str(row["dataset_id"]),
        source_path=str(row["source_path"]),
        host=session.get("host"),
        user=session.get("user"),
        src_ip=session.get("src_ip"),
        src_port=session.get("src_port"),
        primary_method=session.get("primary_method"),
        start_time=datetime.fromisoformat(session["start_time"]),
        end_time=datetime.fromisoformat(session["end_time"]),
        event_count=int(session["event_count"]),
        failure_count=int(session.get("failure_count", 0)),
        gap_seconds=float(session["gap_seconds"]),
        has_escalation=bool(session.get("has_escalation", False)),
        has_persistence=bool(session.get("has_persistence", False)),
        source_ref=_source_ref(row, line_no=None, suffix=str(row["session_id"])),
    )


def get_session(context: ToolContext, *, session_id: str) -> SessionResult:
    """Return one prepared session by its stable identifier."""
    call = context.begin()
    identifier = validate_identifier(session_id, field="session_id", maximum=1024)
    if not context.evidence_available():
        return SessionResult(
            request_id=call.request_id, available=False, unavailable_reason=_UNAVAILABLE
        )
    row = context.repository().read_session(identifier)
    if row is None:
        return SessionResult(
            request_id=call.request_id,
            available=False,
            unavailable_reason="no prepared session has that identifier",
        )
    record = _session_record(row)
    return SessionResult(
        request_id=call.request_id,
        available=True,
        session=record,
        source_refs=(record.source_ref,),
    )


def get_events(
    context: ToolContext,
    *,
    session_id: str,
    cursor: str | None = None,
    limit: int | None = None,
) -> EventPage:
    """Page a session's events in their stored order, without gaps or repeats."""
    call = context.begin()
    identifier = validate_identifier(session_id, field="session_id", maximum=1024)
    page_size = context.page_size(limit)
    decoded = decode_cursor(cursor, arity=1)
    after_ordinal = None
    if decoded is not None:
        try:
            after_ordinal = int(decoded[0])
        except ValueError as exc:
            raise ToolInputError("cursor is not a cursor issued by this server") from exc
    if not context.evidence_available():
        return EventPage(
            request_id=call.request_id, available=False, unavailable_reason=_UNAVAILABLE
        )
    repository = context.repository()
    if repository.read_session(identifier) is None:
        return EventPage(
            request_id=call.request_id,
            available=False,
            unavailable_reason="no prepared session has that identifier",
        )
    rows = repository.read_session_events(
        identifier, after_ordinal=after_ordinal, limit=page_size + 1
    )
    has_more = len(rows) > page_size
    rows = rows[:page_size]
    items = tuple(
        _event_record(row, max_chars=context.settings.mcp_max_snippet_chars) for row in rows
    )
    next_cursor = encode_cursor((str(rows[-1]["ordinal"]),)) if has_more and rows else None
    page = EventPage(
        request_id=call.request_id,
        available=True,
        items=items,
        returned=len(items),
        next_cursor=next_cursor,
        source_refs=tuple(item.source_ref for item in items),
    )
    return enforce_result_size(
        page, maximum_bytes=context.settings.mcp_max_result_bytes, items_field="items"
    )


def get_event(context: ToolContext, *, event_id: str) -> EventResult:
    """Return one event with its complete stored identity and original line."""
    call = context.begin()
    identifier = validate_identifier(event_id, field="event_id", maximum=1024)
    if not context.evidence_available():
        return EventResult(
            request_id=call.request_id, available=False, unavailable_reason=_UNAVAILABLE
        )
    row = context.repository().read_event(identifier)
    if row is None:
        return EventResult(
            request_id=call.request_id,
            available=False,
            unavailable_reason="no prepared event has that identifier",
        )
    record = _event_record(row, max_chars=context.settings.mcp_max_snippet_chars)
    return EventResult(
        request_id=call.request_id,
        available=True,
        event=record,
        source_refs=(record.source_ref,),
    )


def search_events(
    context: ToolContext,
    *,
    query: str | None = None,
    host: str | None = None,
    user: str | None = None,
    src_ip: str | None = None,
    start: str | None = None,
    end: str | None = None,
    membership: str = "any",
    cursor: str | None = None,
    limit: int | None = None,
) -> EventPage:
    """Search prepared events by literal text and bound filters.

    ``query`` is matched as a literal substring of the normalized message or the
    original raw line. It is never compiled as a regular expression, interpolated
    into SQL, expanded as a shell word or resolved as a path.
    """
    call = context.begin()
    if membership not in {"any", "unmatched", "sessionized"}:
        raise ToolInputError("membership must be any, unmatched or sessionized")
    text = (
        validate_query(query, maximum=context.settings.mcp_max_query_chars)
        if query is not None
        else None
    )
    filters = {
        "host": validate_identifier(host, field="host") if host is not None else None,
        "user": validate_identifier(user, field="user") if user is not None else None,
        "src_ip": validate_identifier(src_ip, field="src_ip") if src_ip is not None else None,
    }
    window_start = validate_instant(start, field="start")
    window_end = validate_instant(end, field="end")
    validate_window(window_start, window_end)
    if text is None and not any(filters.values()) and window_start is None and window_end is None:
        raise ToolInputError("provide a query, an entity filter or a time window")
    page_size = context.page_size(limit)
    after = decode_cursor(cursor, arity=2)
    if not context.evidence_available():
        return EventPage(
            request_id=call.request_id, available=False, unavailable_reason=_UNAVAILABLE
        )
    rows = context.repository().search_events(
        text_pattern=like_pattern(text) if text is not None else None,
        host=filters["host"],
        user=filters["user"],
        src_ip=filters["src_ip"],
        start=window_start,
        end=window_end,
        membership=membership,
        after=(after[0], after[1]) if after is not None else None,
        limit=page_size + 1,
    )
    call.check_deadline()
    has_more = len(rows) > page_size
    rows = rows[:page_size]
    items = tuple(
        _event_record(row, max_chars=context.settings.mcp_max_snippet_chars) for row in rows
    )
    next_cursor = (
        encode_cursor((str(rows[-1]["timestamp"]), str(rows[-1]["event_id"])))
        if has_more and rows
        else None
    )
    notes = [
        "Results are prepared evidence only; absence here is not evidence of absence.",
    ]
    if membership == "any":
        notes.append("Both sessionized and unmatched events are included.")
    page = EventPage(
        request_id=call.request_id,
        available=True,
        items=items,
        returned=len(items),
        next_cursor=next_cursor,
        source_refs=tuple(item.source_ref for item in items),
        notes=tuple(notes),
    )
    return enforce_result_size(
        page, maximum_bytes=context.settings.mcp_max_result_bytes, items_field="items"
    )


__all__ = ["get_event", "get_events", "get_session", "search_events"]
