"""Frozen data contracts shared across the Hestia pipeline."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
from pydantic import BaseModel, ConfigDict, Field


class Event(BaseModel):
    """A single parsed auth-log event."""

    model_config = ConfigDict(frozen=True)

    event_id: str = Field(..., description="Unique identifier for the event.")
    source: str = Field(..., description="Dataset or file source name.")
    line_no: int = Field(..., description="Original 1-based line number in the source file.")
    timestamp: datetime = Field(..., description="Parsed timestamp of the event.")
    host: str = Field(..., description="Host name reported in the log.")
    process: str = Field(..., description="Process name (e.g., sshd, su).")
    pid: int | None = Field(default=None, description="Process ID if available.")
    event_type: str = Field(..., description="Canonical event type (e.g., ssh_auth_success).")
    src_ip: str | None = Field(default=None, description="Source IP address if present.")
    src_port: int | None = Field(default=None, description="Source port if present.")
    user: str | None = Field(default=None, description="Principal being authenticated.")
    target_user: str | None = Field(default=None, description="Target identity for sudo/su.")
    method: str | None = Field(default=None, description="SSH method (publickey, password, etc.).")
    key_fingerprint: str | None = Field(
        default=None, description="SSH public-key fingerprint if present."
    )
    session_id: str | None = Field(default=None, description="PAM/session identifier if present.")
    command: str | None = Field(default=None, description="Exact command for sudo events.")
    tty: str | None = Field(default=None, description="Controlling terminal for sudo events.")
    pwd: str | None = Field(default=None, description="Working directory for sudo events.")
    uid: int | None = Field(default=None, description="Numeric UID from PAM session lines.")
    ruser: str | None = Field(default=None, description="Invoking/source user for su events.")
    success: bool | None = Field(default=None, description="Derived outcome flag if applicable.")
    new_account: str | None = Field(
        default=None, description="New account name for account_created."
    )
    added_group: str | None = Field(default=None, description="Added group for group_member_added.")
    message: str = Field(..., description="Normalized human-readable message.")
    raw_message: str = Field(..., description="Original raw log line/message.")


class Session(BaseModel):
    """A bounded sequence of events representing a user/session activity."""

    model_config = ConfigDict(frozen=True)

    session_id: str = Field(..., description="Unique session identifier.")
    source: str = Field(..., description="Dataset or file source name.")
    src_ip: str | None = Field(default=None, description="Source IP address if known.")
    user: str | None = Field(default=None, description="User name if known.")
    events: list[str] = Field(..., description="Ordered list of event_ids in the session.")
    start_time: datetime = Field(..., description="Timestamp of the first event.")
    end_time: datetime = Field(..., description="Timestamp of the last event.")
    event_count: int = Field(..., description="Number of events in the session.")
    gap_seconds: float = Field(..., description="Inter-event gap used to bound the session.")
    host: str | None = Field(default=None, description="Host name for cross-host pivoting.")
    src_port: int | None = Field(default=None, description="Primary connection source port.")
    primary_method: str | None = Field(
        default=None, description="Primary SSH method (publickey, password, etc.)."
    )
    key_fingerprint: str | None = Field(
        default=None, description="Fingerprint from session-opening ssh_auth_success."
    )
    has_escalation: bool = Field(
        default=False, description="Whether session contains sudo/su escalation."
    )
    has_persistence: bool = Field(
        default=False, description="Whether session contains account/group/password changes."
    )
    failure_count: int = Field(default=0, description="Count of failure events in the session.")


class ParseFailure(BaseModel):
    """A log line that could not be parsed."""

    model_config = ConfigDict(frozen=True)

    source: str = Field(..., description="Dataset or file source name.")
    line_no: int = Field(..., description="Original 1-based line number.")
    raw_line: str = Field(..., description="Unparsed raw line.")
    reason: str = Field(..., description="Human-readable reason for failure.")
    timestamp: datetime | None = Field(
        default=None, description="Timestamp if one could be extracted."
    )


class LabelRecord(BaseModel):
    """Eval-only sidecar label for a log line."""

    model_config = ConfigDict(frozen=True)

    source: str = Field(..., description="Dataset or file source name.")
    line_no: int = Field(..., description="Original 1-based line number.")
    attack: bool = Field(..., description="Whether this line is part of an attack.")
    attack_family: str | None = Field(default=None, description="Attack family if known.")
    technique_ids: list[str] | None = Field(
        default=None, description="MITRE technique IDs if known."
    )


def event_to_json(event: Event) -> str:
    """Serialize an ``Event`` to a JSON string."""
    return event.model_dump_json()


def event_from_json(raw: str) -> Event:
    """Deserialize an ``Event`` from a JSON string."""
    return Event.model_validate_json(raw)


def events_to_parquet(events: list[Event], path: Path) -> None:
    """Write a list of ``Event`` objects to a Parquet file with an explicit schema."""
    schema = _event_schema()
    if not events:
        empty = {field.name: pa.array([], type=field.type) for field in schema}
        pq.write_table(pa.Table.from_pydict(empty, schema=schema), path)
        return

    rows = [event.model_dump() for event in events]
    table = pa.Table.from_pylist(rows, schema=schema)
    pq.write_table(table, path)


def events_from_parquet(path: Path) -> list[Event]:
    """Read a list of ``Event`` objects from a Parquet file."""
    table = pq.read_table(path)
    return [Event.model_validate(row) for row in table.to_pylist()]


def sessions_to_parquet(sessions: list[Session], path: Path) -> None:
    """Write a list of ``Session`` objects to a Parquet file with an explicit schema."""
    schema = _session_schema()
    if not sessions:
        empty = {field.name: pa.array([], type=field.type) for field in schema}
        pq.write_table(pa.Table.from_pydict(empty, schema=schema), path)
        return

    rows = [session.model_dump() for session in sessions]
    table = pa.Table.from_pylist(rows, schema=schema)
    pq.write_table(table, path)


def sessions_from_parquet(path: Path) -> list[Session]:
    """Read a list of ``Session`` objects from a Parquet file."""
    table = pq.read_table(path)
    return [Session.model_validate(row) for row in table.to_pylist()]


def _event_schema() -> pa.Schema:
    """Return the explicit PyArrow schema for ``Event``."""
    return pa.schema(
        [
            pa.field("event_id", pa.string(), nullable=False),
            pa.field("source", pa.string(), nullable=False),
            pa.field("line_no", pa.int64(), nullable=False),
            pa.field("timestamp", pa.timestamp("us"), nullable=False),
            pa.field("host", pa.string(), nullable=False),
            pa.field("process", pa.string(), nullable=False),
            pa.field("pid", pa.int64(), nullable=True),
            pa.field("event_type", pa.string(), nullable=False),
            pa.field("src_ip", pa.string(), nullable=True),
            pa.field("src_port", pa.int64(), nullable=True),
            pa.field("user", pa.string(), nullable=True),
            pa.field("target_user", pa.string(), nullable=True),
            pa.field("method", pa.string(), nullable=True),
            pa.field("key_fingerprint", pa.string(), nullable=True),
            pa.field("session_id", pa.string(), nullable=True),
            pa.field("command", pa.string(), nullable=True),
            pa.field("tty", pa.string(), nullable=True),
            pa.field("pwd", pa.string(), nullable=True),
            pa.field("uid", pa.int64(), nullable=True),
            pa.field("ruser", pa.string(), nullable=True),
            pa.field("success", pa.bool_(), nullable=True),
            pa.field("new_account", pa.string(), nullable=True),
            pa.field("added_group", pa.string(), nullable=True),
            pa.field("message", pa.string(), nullable=False),
            pa.field("raw_message", pa.string(), nullable=False),
        ]
    )


def _session_schema() -> pa.Schema:
    """Return the explicit PyArrow schema for ``Session``."""
    return pa.schema(
        [
            pa.field("session_id", pa.string(), nullable=False),
            pa.field("source", pa.string(), nullable=False),
            pa.field("src_ip", pa.string(), nullable=True),
            pa.field("user", pa.string(), nullable=True),
            pa.field("events", pa.list_(pa.string()), nullable=False),
            pa.field("start_time", pa.timestamp("us"), nullable=False),
            pa.field("end_time", pa.timestamp("us"), nullable=False),
            pa.field("event_count", pa.int64(), nullable=False),
            pa.field("gap_seconds", pa.float64(), nullable=False),
            pa.field("host", pa.string(), nullable=True),
            pa.field("src_port", pa.int64(), nullable=True),
            pa.field("primary_method", pa.string(), nullable=True),
            pa.field("key_fingerprint", pa.string(), nullable=True),
            pa.field("has_escalation", pa.bool_(), nullable=False),
            pa.field("has_persistence", pa.bool_(), nullable=False),
            pa.field("failure_count", pa.int64(), nullable=False),
        ]
    )
