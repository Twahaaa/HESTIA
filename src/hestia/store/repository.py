"""Transactional SQLite repository for source-qualified evidence."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterable, Iterator
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from hestia.contracts import Event, Session
from hestia.ingestion.collector import CollectionResult
from hestia.normality.context import HistoricalSessionEvidence
from hestia.normality.scoring import CandidateSession
from hestia.store.schema import (
    MIGRATION_V2_SQL,
    MIGRATION_V3_SQL,
    SCHEMA_SQL,
    SCHEMA_VERSION,
    SUPPORTED_VERSIONS,
)


class SourceCollisionError(ValueError):
    """Raised when a logical source path is presented with different bytes."""


class ActiveRunConflict(RuntimeError):
    """Another case run is still pending or running. Only one may be active."""

    def __init__(self, run_id: str, case_id: str) -> None:
        super().__init__(f"case run {run_id} is still active")
        self.run_id = run_id
        self.case_id = case_id


class IdempotencyConflict(ValueError):
    """An idempotency key was reused for a different request."""

    def __init__(self, run_id: str) -> None:
        super().__init__("the idempotency key was already used for a different request")
        self.run_id = run_id


class EvidenceRepository:
    def __init__(self, path: Path) -> None:
        self.path = path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            connection.close()
            raise RuntimeError("SQLite foreign keys could not be enabled")
        return connection

    def initialize(self) -> None:
        """Create or migrate the store forward. Version-1 data is never rewritten."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in SUPPORTED_VERSIONS:
                raise RuntimeError(f"Unsupported evidence schema version: {version}")
            connection.executescript(SCHEMA_SQL)
            connection.executescript(MIGRATION_V2_SQL)
            connection.executescript(MIGRATION_V3_SQL)
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def schema_version(self) -> int:
        with self._connect() as connection:
            return int(connection.execute("PRAGMA user_version").fetchone()[0])

    def create_run(self, run_id: str, status: str, config: dict[str, object]) -> None:
        payload = json.dumps(config, sort_keys=True, separators=(",", ":"))
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT status, config_json FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if existing is not None and existing["config_json"] != payload:
                raise ValueError(f"Run id already has different configuration: {run_id}")
            connection.execute(
                "INSERT OR IGNORE INTO runs(run_id, status, config_json) VALUES (?, ?, ?)",
                (run_id, status, payload),
            )

    def set_run_status(self, run_id: str, status: str) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE runs SET status = ? WHERE run_id = ?", (status, run_id)
            )
            if cursor.rowcount != 1:
                raise KeyError(run_id)

    def import_source(
        self,
        collection: CollectionResult,
        sessions: Iterable[Session] = (),
        unmatched: Iterable[tuple[Event, str]] = (),
    ) -> bool:
        """Atomically import one source; return false for an identical prior import."""
        profile = collection.profile
        source_id = hashlib.sha256(
            f"{profile.dataset_id}\0{profile.source_path}".encode()
        ).hexdigest()
        session_list = list(sessions)
        unmatched_list = list(unmatched)
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT id, hash FROM sources WHERE dataset_id = ? AND path = ?",
                (profile.dataset_id, profile.source_path),
            ).fetchone()
            if existing is not None:
                if existing["hash"] != collection.content_hash:
                    raise SourceCollisionError(
                        f"Source content collision: {profile.dataset_id}/{profile.source_path}"
                    )
                return False

            connection.execute(
                "INSERT INTO sources(id, dataset_id, path, hash, profile_json) VALUES (?, ?, ?, ?, ?)",
                (
                    source_id,
                    profile.dataset_id,
                    profile.source_path,
                    collection.content_hash,
                    profile.model_dump_json(),
                ),
            )
            for collected in collection.events:
                event = collected.event
                event_payload = {
                    "event": event.model_dump(mode="json"),
                    "raw_timestamp": collected.raw_timestamp,
                    "raw_line": event.raw_message,
                }
                connection.execute(
                    """INSERT INTO events
                       (event_id, source_id, line_no, timestamp, host, user, src_ip, event_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        event.event_id,
                        source_id,
                        event.line_no,
                        event.timestamp.isoformat(),
                        event.host,
                        event.user,
                        event.src_ip,
                        json.dumps(event_payload, sort_keys=True, separators=(",", ":")),
                    ),
                )
            for failure in collection.failures:
                connection.execute(
                    "INSERT INTO parse_failures(source_id, line_no, reason, raw) VALUES (?, ?, ?, ?)",
                    (source_id, failure.line_no, failure.reason, failure.raw_line),
                )
            event_ids = {item.event.event_id for item in collection.events}
            for session in session_list:
                if session.source != profile.source_path:
                    raise ValueError("Session belongs to a different source")
                connection.execute(
                    """INSERT INTO sessions
                       (session_id, source_id, host, start, end, session_json)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        session.session_id,
                        source_id,
                        session.host or "",
                        session.start_time.isoformat(),
                        session.end_time.isoformat(),
                        session.model_dump_json(),
                    ),
                )
                for ordinal, event_id in enumerate(session.events):
                    if event_id not in event_ids:
                        raise ValueError("Session references an event outside its source")
                    connection.execute(
                        "INSERT INTO session_events(session_id, event_id, ordinal) VALUES (?, ?, ?)",
                        (session.session_id, event_id, ordinal),
                    )
            for event, reason in unmatched_list:
                if event.event_id not in event_ids:
                    raise ValueError("Unmatched event belongs to a different source")
                connection.execute(
                    "INSERT INTO unmatched_events(event_id, reason) VALUES (?, ?)",
                    (event.event_id, reason),
                )
        return True

    def table_counts(self) -> dict[str, int]:
        tables = (
            "sources",
            "events",
            "parse_failures",
            "sessions",
            "session_events",
            "unmatched_events",
            "runs",
            "candidates",
        )
        with self._connect() as connection:
            return {
                table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in tables
            }

    def iter_historical_sessions(
        self,
        *,
        as_of: datetime,
        exclude_session_id: str,
    ) -> Iterator[HistoricalSessionEvidence]:
        """Yield closed evidence strictly before a timezone-aware boundary."""
        if as_of.tzinfo is None or as_of.utcoffset() is None:
            raise ValueError("Historical query boundary must be timezone-aware")
        yield from self._iter_session_evidence(
            "WHERE s.end < ? AND s.session_id != ?",
            (as_of.astimezone(UTC).isoformat(), exclude_session_id),
        )

    def iter_session_evidence(
        self, *, dataset_id: str | None = None
    ) -> Iterator[HistoricalSessionEvidence]:
        """Yield all prepared closed sessions, optionally for one dataset."""
        if dataset_id is None:
            yield from self._iter_session_evidence("", ())
        else:
            yield from self._iter_session_evidence("WHERE src.dataset_id = ?", (dataset_id,))

    def _iter_session_evidence(
        self, where: str, parameters: tuple[object, ...]
    ) -> Iterator[HistoricalSessionEvidence]:
        query = f"""SELECT s.session_json, src.dataset_id, src.path
                    FROM sessions s
                    JOIN sources src ON src.id = s.source_id
                    {where}
                    ORDER BY s.start, s.session_id"""
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
            for row in rows:
                session = Session.model_validate_json(row["session_json"])
                event_rows = connection.execute(
                    """SELECT e.event_json
                       FROM session_events se
                       JOIN events e ON e.event_id = se.event_id
                       WHERE se.session_id = ?
                       ORDER BY se.ordinal""",
                    (session.session_id,),
                ).fetchall()
                events = tuple(
                    Event.model_validate(json.loads(event_row["event_json"])["event"])
                    for event_row in event_rows
                )
                yield HistoricalSessionEvidence(
                    session=session,
                    events=events,
                    evidence_ref=f"{row['dataset_id']}:{row['path']}:{session.session_id}",
                )

    def source_hashes(self, dataset_id: str) -> dict[str, str]:
        with self._connect() as connection:
            return {
                row["path"]: row["hash"]
                for row in connection.execute(
                    "SELECT path, hash FROM sources WHERE dataset_id = ? ORDER BY path",
                    (dataset_id,),
                )
            }

    # ------------------------------------------------------------------
    # Read-only investigative access (H2). These methods never mutate the
    # store, never interpolate caller text into SQL and never resolve a
    # caller-supplied filesystem path.
    # ------------------------------------------------------------------

    _EVENT_COLUMNS = """e.event_id, e.line_no, e.timestamp, e.event_json,
                        src.dataset_id, src.path AS source_path, src.hash AS source_hash,
                        u.reason AS unmatched_reason,
                        (u.event_id IS NOT NULL) AS unmatched"""
    _EVENT_FROM = """FROM events e
                     JOIN sources src ON src.id = e.source_id
                     LEFT JOIN unmatched_events u ON u.event_id = e.event_id"""

    @property
    def _EVENT_SELECT(self) -> str:  # noqa: N802 - internal SQL fragment
        return f"SELECT {self._EVENT_COLUMNS} {self._EVENT_FROM}"

    def read_session(self, session_id: str) -> dict[str, object] | None:
        """Return one prepared session with its source identity, or None."""
        with self._connect() as connection:
            row = connection.execute(
                """SELECT s.session_id, s.session_json, src.dataset_id,
                          src.path AS source_path, src.hash AS source_hash
                   FROM sessions s
                   JOIN sources src ON src.id = s.source_id
                   WHERE s.session_id = ?""",
                (session_id,),
            ).fetchone()
        return dict(row) if row is not None else None

    def read_session_events(
        self, session_id: str, *, after_ordinal: int | None, limit: int
    ) -> list[dict[str, object]]:
        """Return one ordinal-ordered page of a session's events."""
        clauses = ["se.session_id = ?"]
        parameters: list[object] = [session_id]
        if after_ordinal is not None:
            clauses.append("se.ordinal > ?")
            parameters.append(after_ordinal)
        parameters.append(limit)
        query = f"""SELECT se.ordinal, {self._EVENT_COLUMNS}
                    {self._EVENT_FROM}
                    JOIN session_events se ON se.event_id = e.event_id
                    WHERE {" AND ".join(clauses)}
                    ORDER BY se.ordinal
                    LIMIT ?"""
        with self._connect() as connection:
            return [dict(row) for row in connection.execute(query, tuple(parameters)).fetchall()]

    def read_event(self, event_id: str) -> dict[str, object] | None:
        """Return one prepared event by its complete stored identity."""
        with self._connect() as connection:
            row = connection.execute(
                f"{self._EVENT_SELECT} WHERE e.event_id = ?", (event_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    def search_events(
        self,
        *,
        text_pattern: str | None,
        host: str | None = None,
        user: str | None = None,
        src_ip: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        membership: str = "any",
        after: tuple[str, str] | None = None,
        limit: int,
    ) -> list[dict[str, object]]:
        """Page events by an escaped literal LIKE pattern and bound filters.

        ``text_pattern`` must already be escaped by the caller with
        :func:`hestia.mcp.contracts.like_pattern`; it is bound as a parameter and
        matched only against the stored message and raw line. ``membership``
        selects ``any``, ``unmatched`` or ``sessionized`` events so evidence with
        a missing user or source IP cannot hide escalation activity.
        """
        if membership not in {"any", "unmatched", "sessionized"}:
            raise ValueError("membership must be any, unmatched or sessionized")
        clauses: list[str] = []
        parameters: list[object] = []
        if text_pattern is not None:
            clauses.append(
                "(json_extract(e.event_json, '$.event.message') LIKE ? ESCAPE '\\'"
                " OR json_extract(e.event_json, '$.event.raw_message') LIKE ? ESCAPE '\\')"
            )
            parameters.extend((text_pattern, text_pattern))
        for column, value in (("host", host), ("user", user), ("src_ip", src_ip)):
            if value is not None:
                clauses.append(f"e.{column} = ?")
                parameters.append(value)
        if start is not None:
            clauses.append("e.timestamp >= ?")
            parameters.append(_utc_text(start))
        if end is not None:
            clauses.append("e.timestamp < ?")
            parameters.append(_utc_text(end))
        if membership == "unmatched":
            clauses.append("u.event_id IS NOT NULL")
        elif membership == "sessionized":
            clauses.append("u.event_id IS NULL")
        if after is not None:
            clauses.append("(e.timestamp, e.event_id) > (?, ?)")
            parameters.extend(after)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        parameters.append(limit)
        query = f"""{self._EVENT_SELECT}
                    {where}
                    ORDER BY e.timestamp, e.event_id
                    LIMIT ?"""
        with self._connect() as connection:
            return [dict(row) for row in connection.execute(query, tuple(parameters)).fetchall()]

    def count_sessions_before(self, before: datetime) -> int:
        """Total closed sessions in the store ending strictly before a boundary."""
        _require_aware(before)
        with self._connect() as connection:
            return int(
                connection.execute(
                    "SELECT COUNT(*) FROM sessions WHERE end < ?", (_utc_text(before),)
                ).fetchone()[0]
            )

    def read_entity_sessions(
        self,
        *,
        entity_type: str,
        entity_id: str,
        before: datetime,
        after: tuple[str, str] | None = None,
        limit: int | None = None,
    ) -> list[dict[str, object]]:
        """Return sessions for one entity that closed strictly before ``before``.

        The boundary is exclusive on purpose: a case must never see itself or any
        later evidence in its own history.
        """
        _require_aware(before)
        column = {
            "host": "s.host",
            "user": "json_extract(s.session_json, '$.user')",
            "src_ip": "json_extract(s.session_json, '$.src_ip')",
        }.get(entity_type)
        if column is None:
            raise ValueError("entity_type must be user, host or src_ip")
        clauses = [f"{column} = ?", "s.end < ?"]
        parameters: list[object] = [entity_id, _utc_text(before)]
        if after is not None:
            clauses.append("(s.start, s.session_id) > (?, ?)")
            parameters.extend(after)
        limit_sql = ""
        if limit is not None:
            limit_sql = "LIMIT ?"
            parameters.append(limit)
        query = f"""SELECT s.session_id, s.session_json, s.start, s.end,
                           src.dataset_id, src.path AS source_path, src.hash AS source_hash
                    FROM sessions s
                    JOIN sources src ON src.id = s.source_id
                    WHERE {" AND ".join(clauses)}
                    ORDER BY s.start, s.session_id
                    {limit_sql}"""
        with self._connect() as connection:
            return [dict(row) for row in connection.execute(query, tuple(parameters)).fetchall()]

    # ------------------------------------------------------------------
    # H3 case runs. Trace rows are append-only: a step is written once and
    # never updated, so a stored investigation cannot be quietly rewritten.
    # ------------------------------------------------------------------

    _RUN_STATES = ("pending", "running", "completed", "failed", "cancelled")
    _ALLOWED_TRANSITIONS = {
        "pending": ("running", "failed", "cancelled"),
        "running": ("completed", "failed", "cancelled"),
        "completed": (),
        "failed": (),
        "cancelled": (),
    }

    def save_case_run(self, run: object) -> None:
        """Upsert one case run, its new trace rows and its report, atomically.

        The state machine is enforced here rather than trusted from the caller:
        a terminal run cannot be reopened, and an unknown transition raises.
        """
        payload = run.model_dump(mode="json")  # type: ignore[attr-defined]
        with self._connect() as connection:
            self._write_case_run(connection, payload)

    def _write_case_run(self, connection: sqlite3.Connection, payload: dict) -> None:
        import json as _json

        run_id = str(payload["run_id"])
        state = str(payload["state"])
        if state not in self._RUN_STATES:
            raise ValueError(f"Unknown case run state: {state}")
        existing = connection.execute(
            "SELECT state FROM agent_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if existing is not None:
            previous = str(existing["state"])
            if previous != state and state not in self._ALLOWED_TRANSITIONS[previous]:
                raise ValueError(f"Illegal case run transition: {previous} -> {state}")
        connection.execute(
            """INSERT INTO agent_runs
               (run_id, case_id, session_id, state, provider, model, fixture,
                started_at, finished_at, incomplete_reason, case_json, usage_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(run_id) DO UPDATE SET
                   state = excluded.state,
                   finished_at = excluded.finished_at,
                   incomplete_reason = excluded.incomplete_reason,
                   usage_json = excluded.usage_json""",
            (
                run_id,
                payload["case"]["case_id"],
                payload["case"]["session_id"],
                state,
                payload["provider"],
                payload["model"],
                int(bool(payload["fixture"])),
                payload["started_at"],
                payload["finished_at"],
                payload["incomplete_reason"],
                _json.dumps(payload["case"], sort_keys=True, separators=(",", ":")),
                _json.dumps(payload["usage"], sort_keys=True, separators=(",", ":")),
            ),
        )
        for trace in payload.get("traces", ()):
            connection.execute(
                """INSERT OR IGNORE INTO agent_steps(run_id, step, kind, payload_json)
                   VALUES (?, ?, 'tool_call', ?)""",
                (
                    run_id,
                    int(trace["step"]),
                    _json.dumps(trace, sort_keys=True, separators=(",", ":")),
                ),
            )
        for hypothesis in payload.get("hypotheses", ()):
            connection.execute(
                """INSERT OR IGNORE INTO agent_steps(run_id, step, kind, payload_json)
                   VALUES (?, ?, 'hypothesis', ?)""",
                (
                    run_id,
                    int(hypothesis["step"]),
                    _json.dumps(hypothesis, sort_keys=True, separators=(",", ":")),
                ),
            )
        report = payload.get("report")
        grounding = payload.get("grounding")
        if report is not None:
            connection.execute(
                """INSERT INTO agent_reports
                   (run_id, schema_version, verdict, severity, confidence,
                    known_or_novel, grounded, report_json, grounding_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(run_id) DO UPDATE SET
                       verdict = excluded.verdict,
                       severity = excluded.severity,
                       confidence = excluded.confidence,
                       known_or_novel = excluded.known_or_novel,
                       grounded = excluded.grounded,
                       report_json = excluded.report_json,
                       grounding_json = excluded.grounding_json""",
                (
                    run_id,
                    int(report["schema_version"]),
                    report["verdict"],
                    report["severity"],
                    float(report["confidence"]),
                    report["known_or_novel"],
                    int(bool((grounding or {}).get("grounded"))),
                    _json.dumps(report, sort_keys=True, separators=(",", ":")),
                    _json.dumps(grounding or {}, sort_keys=True, separators=(",", ":")),
                ),
            )
        elif grounding is not None and not grounding.get("grounded"):
            # A refused report is not stored, but why it was refused is: failed
            # grounding is an outcome an analyst must be able to see.
            connection.execute(
                """INSERT OR IGNORE INTO agent_grounding_failures(run_id, grounding_json)
                   VALUES (?, ?)""",
                (run_id, _json.dumps(grounding, sort_keys=True, separators=(",", ":"))),
            )

    def read_case_run(self, run_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            workspace = (
                """, g.grounding_json AS failed_grounding_json,
                   i.previous_state AS interrupted_from, i.detected_at AS interrupted_at,
                   q.requested_at AS requested_at"""
                if version >= 3
                else ""
            )
            joins = (
                """LEFT JOIN agent_grounding_failures g ON g.run_id = r.run_id
                   LEFT JOIN agent_run_interruptions i ON i.run_id = r.run_id
                   LEFT JOIN agent_run_requests q ON q.run_id = r.run_id"""
                if version >= 3
                else ""
            )
            row = connection.execute(
                f"""SELECT r.*, p.report_json, p.grounding_json, p.grounded {workspace}
                   FROM agent_runs r
                   LEFT JOIN agent_reports p ON p.run_id = r.run_id
                   {joins}
                   WHERE r.run_id = ?""",
                (run_id,),
            ).fetchone()
            if row is None:
                return None
            steps = connection.execute(
                "SELECT step, kind, payload_json FROM agent_steps WHERE run_id = ?"
                " ORDER BY step, kind",
                (run_id,),
            ).fetchall()
        return dict(row) | {"steps": [dict(step) for step in steps]}

    def case_run_summary(self) -> dict[str, object]:
        """Counts by state plus the most recent run, for the status endpoint."""
        with self._connect() as connection:
            counts = {
                str(row["state"]): int(row["n"])
                for row in connection.execute(
                    "SELECT state, COUNT(*) AS n FROM agent_runs GROUP BY state"
                )
            }
            latest = connection.execute(
                """SELECT run_id, state, provider, model, fixture, started_at,
                          finished_at, incomplete_reason
                   FROM agent_runs ORDER BY started_at DESC, run_id DESC LIMIT 1"""
            ).fetchone()
        return {
            "counts": counts,
            "total": sum(counts.values()),
            "latest": dict(latest) if latest is not None else None,
        }

    # ------------------------------------------------------------------
    # H4 case workspace. One active run at a time is enforced inside a write
    # transaction, so two requests cannot both observe "no active run".
    # ------------------------------------------------------------------

    _ACTIVE_STATES = ("pending", "running")

    def request_case_run(
        self,
        run: object,
        *,
        idempotency_key: str,
        request: dict[str, object],
    ) -> tuple[str, bool]:
        """Register a pending run for an idempotent start request.

        Returns ``(run_id, created)``. Replaying a key with the same request
        returns the original run with ``created=False``.

        Raises:
            IdempotencyConflict: the key was used for a different request.
            ActiveRunConflict: another run is pending or running.
        """
        payload = run.model_dump(mode="json")  # type: ignore[attr-defined]
        if payload["state"] != "pending":
            raise ValueError("a requested run must start pending")
        request_json = json.dumps(request, sort_keys=True, separators=(",", ":"))
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute(
                "SELECT run_id, request_json FROM agent_run_requests WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if prior is not None:
                connection.rollback()
                if prior["request_json"] != request_json:
                    raise IdempotencyConflict(str(prior["run_id"]))
                return str(prior["run_id"]), False
            active = connection.execute(
                """SELECT run_id, case_id FROM agent_runs
                   WHERE state IN ('pending', 'running')
                   ORDER BY started_at LIMIT 1"""
            ).fetchone()
            if active is not None:
                connection.rollback()
                raise ActiveRunConflict(str(active["run_id"]), str(active["case_id"]))
            self._write_case_run(connection, payload)
            connection.execute(
                """INSERT INTO agent_run_requests
                   (idempotency_key, run_id, case_id, request_json, requested_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    idempotency_key,
                    payload["run_id"],
                    payload["case"]["case_id"],
                    request_json,
                    datetime.now(UTC).isoformat(),
                ),
            )
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
        return str(payload["run_id"]), True

    def active_case_runs(self) -> list[dict[str, object]]:
        with self._connect() as connection:
            return [
                dict(row)
                for row in connection.execute(
                    """SELECT run_id, case_id, session_id, state, started_at
                       FROM agent_runs WHERE state IN ('pending', 'running')
                       ORDER BY started_at"""
                )
            ]

    def mark_interrupted_runs(self, reason: str) -> list[str]:
        """End every pending or running run as failed and record the interruption.

        Called once at startup: a run that was active when the process stopped
        has no live worker any more, and pretending otherwise would leave it
        looking in progress forever. The run keeps its trace and gets no report.
        """
        now = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT run_id, state FROM agent_runs WHERE state IN ('pending', 'running')"
            ).fetchall()
            for row in rows:
                connection.execute(
                    """UPDATE agent_runs
                       SET state = 'failed', finished_at = ?, incomplete_reason = ?
                       WHERE run_id = ?""",
                    (now, reason, row["run_id"]),
                )
                connection.execute(
                    """INSERT OR IGNORE INTO agent_run_interruptions
                       (run_id, previous_state, detected_at) VALUES (?, ?, ?)""",
                    (row["run_id"], row["state"], now),
                )
        return [str(row["run_id"]) for row in rows]

    def mark_run_failed(self, run_id: str, reason: str) -> bool:
        """End one still-active run as failed. Terminal runs are left untouched."""
        with self._connect() as connection:
            cursor = connection.execute(
                """UPDATE agent_runs
                   SET state = 'failed', finished_at = ?, incomplete_reason = ?
                   WHERE run_id = ? AND state IN ('pending', 'running')""",
                (datetime.now(UTC).isoformat(), reason, run_id),
            )
            return cursor.rowcount == 1

    def dataset_ids(self) -> list[str]:
        with self._connect() as connection:
            return [
                str(row["dataset_id"])
                for row in connection.execute(
                    "SELECT DISTINCT dataset_id FROM sources ORDER BY dataset_id"
                )
            ]

    def list_case_sessions(self, *, dataset_id: str | None = None) -> list[dict[str, object]]:
        """Every prepared session with its latest prioritization score, if any.

        The score comes only from persisted candidate rows, which exist only when
        a ready model scored the session. No score is invented here.
        """
        where = "WHERE src.dataset_id = ?" if dataset_id is not None else ""
        parameters: tuple[object, ...] = (dataset_id,) if dataset_id is not None else ()
        query = f"""SELECT s.session_id, s.host, s.start, s.end, s.session_json,
                           src.dataset_id, src.path AS source_path,
                           (SELECT c.score FROM candidates c
                              WHERE c.session_id = s.session_id
                              ORDER BY c.created_at DESC LIMIT 1) AS score
                    FROM sessions s
                    JOIN sources src ON src.id = s.source_id
                    {where}
                    ORDER BY s.start, s.session_id"""
        with self._connect() as connection:
            return [dict(row) for row in connection.execute(query, parameters).fetchall()]

    def case_runs_for_session(self, session_id: str) -> list[dict[str, object]]:
        with self._connect() as connection:
            return [
                dict(row)
                for row in connection.execute(
                    """SELECT r.run_id, r.state, r.provider, r.model, r.fixture,
                              r.started_at, r.finished_at, r.incomplete_reason, r.usage_json,
                              p.verdict, p.grounded,
                              (g.run_id IS NOT NULL) AS grounding_failed,
                              (i.run_id IS NOT NULL) AS interrupted
                       FROM agent_runs r
                       LEFT JOIN agent_reports p ON p.run_id = r.run_id
                       LEFT JOIN agent_grounding_failures g ON g.run_id = r.run_id
                       LEFT JOIN agent_run_interruptions i ON i.run_id = r.run_id
                       WHERE r.session_id = ?
                       ORDER BY r.started_at DESC, r.run_id DESC""",
                    (session_id,),
                )
            ]

    def latest_run_states(self) -> dict[str, dict[str, object]]:
        """The most recent run per session, for the case queue."""
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT r.session_id, r.run_id, r.state, r.fixture, r.started_at
                   FROM agent_runs r
                   WHERE r.rowid = (SELECT r2.rowid FROM agent_runs r2
                                    WHERE r2.session_id = r.session_id
                                    ORDER BY r2.started_at DESC, r2.run_id DESC LIMIT 1)"""
            ).fetchall()
        return {str(row["session_id"]): dict(row) for row in rows}

    def record_disposition(
        self,
        *,
        disposition_id: str,
        case_id: str,
        session_id: str,
        run_id: str | None,
        disposition: str,
        note: str,
        actor: str,
        recorded_at: datetime,
    ) -> None:
        """Append one analyst review disposition. Earlier ones are kept as history."""
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO analyst_dispositions
                   (disposition_id, case_id, session_id, run_id, disposition, note,
                    actor, recorded_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    disposition_id,
                    case_id,
                    session_id,
                    run_id,
                    disposition,
                    note,
                    actor,
                    _utc_text(recorded_at),
                ),
            )

    def dispositions_for_case(self, case_id: str) -> list[dict[str, object]]:
        with self._connect() as connection:
            return [
                dict(row)
                for row in connection.execute(
                    """SELECT disposition_id, case_id, run_id, disposition, note, actor,
                              recorded_at
                       FROM analyst_dispositions WHERE case_id = ?
                       ORDER BY recorded_at DESC, rowid DESC""",
                    (case_id,),
                )
            ]

    def latest_dispositions(self) -> dict[str, dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT d.case_id, d.disposition, d.recorded_at
                   FROM analyst_dispositions d
                   WHERE d.rowid = (SELECT d2.rowid FROM analyst_dispositions d2
                                    WHERE d2.case_id = d.case_id
                                    ORDER BY d2.recorded_at DESC, d2.rowid DESC LIMIT 1)"""
            ).fetchall()
        return {str(row["case_id"]): dict(row) for row in rows}

    def clear_case_workspace(self) -> dict[str, int]:
        """Delete case runs, traces, reports and dispositions; keep all evidence.

        Only the designated demo workspace may call this. Prepared sources,
        events, sessions, parse failures and candidates are never touched.
        """
        tables = (
            "analyst_dispositions",
            "agent_run_requests",
            "agent_run_interruptions",
            "agent_grounding_failures",
            "agent_reports",
            "agent_steps",
            "agent_runs",
        )
        removed: dict[str, int] = {}
        with self._connect() as connection:
            for table in tables:
                removed[table] = connection.execute(f"DELETE FROM {table}").rowcount
        return removed

    def persist_candidate(self, run_id: str, candidate: CandidateSession) -> None:
        """Persist prioritization evidence without adding a threat verdict."""
        ready_scores = [
            score.raw_score for score in candidate.scores if score.raw_score is not None
        ]
        payload = json.dumps(asdict(candidate), sort_keys=True, separators=(",", ":"))
        candidate_id = hashlib.sha256(f"{run_id}\0{candidate.session_id}".encode()).hexdigest()
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO candidates
                   (candidate_id, run_id, session_id, score, explanation_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(run_id, session_id) DO UPDATE SET
                       score = excluded.score,
                       explanation_json = excluded.explanation_json""",
                (
                    candidate_id,
                    run_id,
                    candidate.session_id,
                    max(ready_scores) if ready_scores else None,
                    payload,
                    datetime.now(UTC).isoformat(),
                ),
            )


def _require_aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Historical query boundary must be timezone-aware")


def _utc_text(value: datetime) -> str:
    """Match the exact stored representation written by :meth:`import_source`."""
    _require_aware(value)
    return value.astimezone(UTC).isoformat()


__all__ = [
    "ActiveRunConflict",
    "EvidenceRepository",
    "IdempotencyConflict",
    "SourceCollisionError",
]
