"""SQLite evidence schema.

Version 1 is the H1 evidence store. Version 2 adds the H3 case-run tables beside
it with additive DDL only: no version-1 table, column or row is altered, so an
existing prepared store migrates in place without re-preparing evidence.
Version 3 adds the case workspace tables the same way: analyst review
dispositions, idempotent run requests, explicit interruption records and the
grounding outcome of runs whose report was refused. No earlier table is altered.
"""

SCHEMA_VERSION = 3
#: Versions this build can open and migrate forward from.
SUPPORTED_VERSIONS = (0, 1, 2, 3)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS sources (
    id TEXT PRIMARY KEY,
    dataset_id TEXT NOT NULL,
    path TEXT NOT NULL,
    hash TEXT NOT NULL,
    profile_json TEXT NOT NULL,
    UNIQUE(dataset_id, path),
    UNIQUE(dataset_id, path, hash)
);
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    line_no INTEGER NOT NULL CHECK(line_no > 0),
    timestamp TEXT NOT NULL,
    host TEXT NOT NULL,
    user TEXT,
    src_ip TEXT,
    event_json TEXT NOT NULL,
    UNIQUE(source_id, line_no)
);
CREATE TABLE IF NOT EXISTS parse_failures (
    source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    line_no INTEGER NOT NULL CHECK(line_no > 0),
    reason TEXT NOT NULL,
    raw TEXT NOT NULL,
    PRIMARY KEY(source_id, line_no)
);
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    start TEXT NOT NULL,
    end TEXT NOT NULL,
    session_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS session_events (
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    event_id TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    PRIMARY KEY(session_id, event_id),
    UNIQUE(session_id, ordinal)
);
CREATE TABLE IF NOT EXISTS unmatched_events (
    event_id TEXT PRIMARY KEY REFERENCES events(event_id) ON DELETE CASCADE,
    reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    config_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS candidates (
    candidate_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    score REAL,
    explanation_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(run_id, session_id)
);
CREATE INDEX IF NOT EXISTS idx_events_source_time ON events(source_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_host_time ON events(host, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_user_time ON events(user, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_src_ip_time ON events(src_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_session_events_event ON session_events(event_id, session_id);
CREATE INDEX IF NOT EXISTS idx_sessions_source_time ON sessions(source_id, start, end);
CREATE INDEX IF NOT EXISTS idx_candidates_run_score ON candidates(run_id, score);
"""

#: Additive version-2 DDL. Applied after SCHEMA_SQL on every initialize().
MIGRATION_V2_SQL = """
CREATE TABLE IF NOT EXISTS agent_runs (
    run_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    state TEXT NOT NULL CHECK(state IN
        ('pending', 'running', 'completed', 'failed', 'cancelled')),
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    fixture INTEGER NOT NULL CHECK(fixture IN (0, 1)),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    incomplete_reason TEXT,
    case_json TEXT NOT NULL,
    usage_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_steps (
    run_id TEXT NOT NULL REFERENCES agent_runs(run_id) ON DELETE CASCADE,
    step INTEGER NOT NULL CHECK(step >= 1),
    kind TEXT NOT NULL CHECK(kind IN ('tool_call', 'hypothesis')),
    payload_json TEXT NOT NULL,
    PRIMARY KEY(run_id, step, kind)
);
CREATE TABLE IF NOT EXISTS agent_reports (
    run_id TEXT PRIMARY KEY REFERENCES agent_runs(run_id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL,
    verdict TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    known_or_novel TEXT NOT NULL,
    grounded INTEGER NOT NULL CHECK(grounded IN (0, 1)),
    report_json TEXT NOT NULL,
    grounding_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_runs_session ON agent_runs(session_id, started_at);
CREATE INDEX IF NOT EXISTS idx_agent_runs_state ON agent_runs(state, started_at);
"""

#: Additive version-3 DDL for the case workspace. Applied after version 2.
#:
#: Dispositions are review records written by an analyst. They are deliberately
#: kept apart from dataset annotations and are never read by training or scoring,
#: so a review outcome can never become a label by accident.
MIGRATION_V3_SQL = """
CREATE TABLE IF NOT EXISTS analyst_dispositions (
    disposition_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    run_id TEXT REFERENCES agent_runs(run_id) ON DELETE SET NULL,
    disposition TEXT NOT NULL CHECK(disposition IN
        ('benign', 'suspicious', 'inconclusive', 'report_disputed')),
    note TEXT NOT NULL,
    actor TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_run_requests (
    idempotency_key TEXT PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE REFERENCES agent_runs(run_id) ON DELETE CASCADE,
    case_id TEXT NOT NULL,
    request_json TEXT NOT NULL,
    requested_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_run_interruptions (
    run_id TEXT PRIMARY KEY REFERENCES agent_runs(run_id) ON DELETE CASCADE,
    previous_state TEXT NOT NULL,
    detected_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_grounding_failures (
    run_id TEXT PRIMARY KEY REFERENCES agent_runs(run_id) ON DELETE CASCADE,
    grounding_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dispositions_case ON analyst_dispositions(case_id, recorded_at);
"""

__all__ = [
    "MIGRATION_V2_SQL",
    "MIGRATION_V3_SQL",
    "SCHEMA_SQL",
    "SCHEMA_VERSION",
    "SUPPORTED_VERSIONS",
]
