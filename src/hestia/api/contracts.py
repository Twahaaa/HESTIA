"""Typed request and response models for the case workspace API.

The frontend mirrors these in `frontend/src/api/contracts.ts`. They carry no
provider key and no handle map: a citation is resolved one handle at a time and
only the lines it refers to are returned.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

RunMode = Literal["fixture", "configured"]
DispositionValue = Literal["benign", "suspicious", "inconclusive", "report_disputed"]
Outcome = Literal[
    "in_progress",
    "report_published",
    "cancelled",
    "interrupted",
    "grounding_failed",
    "budget_exhausted",
    "provider_unavailable",
    "failed",
]


class ApiError(BaseModel):
    """Body of every workspace error, under FastAPI's ``detail`` key."""

    code: str
    message: str
    run_id: str | None = None
    case_id: str | None = None
    state: str | None = None


class Priority(BaseModel):
    score: float | None
    scored: bool
    reason: str | None


class ScoringStatus(BaseModel):
    available: bool
    ready_models: int
    total_models: int
    reason: str | None
    ordering: str
    note: str


class RunRef(BaseModel):
    run_id: str
    state: str
    fixture: bool
    started_at: str


class DispositionRef(BaseModel):
    disposition: DispositionValue
    recorded_at: str


class CaseSummary(BaseModel):
    case_id: str
    dataset_id: str
    source: str
    host: str | None
    user: str | None
    src_ip: str | None
    start: str
    end: str
    event_count: int
    failure_count: int
    priority: Priority
    latest_run: RunRef | None
    disposition: DispositionRef | None


class CasePage(BaseModel):
    items: list[CaseSummary]
    total: int
    limit: int
    offset: int
    dataset_id: str | None
    datasets: list[str]
    scoring: ScoringStatus


class EvidenceLine(BaseModel):
    event_id: str
    ordinal: int | None = None
    dataset_id: str
    source: str
    line_no: int
    timestamp: str
    raw_timestamp: str | None = None
    line: str
    event_type: str | None = None
    success: bool | None = None
    unmatched: bool
    unmatched_reason: str | None = None


class ParsedAttributes(BaseModel):
    has_escalation: bool
    has_persistence: bool
    primary_method: str | None
    note: str


class Usage(BaseModel):
    requests: int = 0
    tool_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    provider_attempts: int = 0
    key_rotations: int = 0
    estimated_cost_usd: float | None = None
    wall_seconds: float = 0.0


class Execution(BaseModel):
    kind: Literal["fixture", "hosted"]
    label: str


class RunSummary(BaseModel):
    run_id: str
    state: Literal["pending", "running", "completed", "failed", "cancelled"]
    outcome: Outcome
    provider: str
    model: str
    fixture: bool
    execution: Execution
    started_at: str
    finished_at: str | None
    incomplete_reason: str | None
    verdict: str | None
    usage: Usage


class Disposition(BaseModel):
    disposition_id: str
    case_id: str
    run_id: str | None
    disposition: DispositionValue
    note: str
    actor: str
    recorded_at: str


class CaseDetail(BaseModel):
    case_id: str
    dataset_id: str
    source: str
    host: str | None
    user: str | None
    src_ip: str | None
    start: str
    end: str
    event_count: int
    failure_count: int
    parsed_attributes: ParsedAttributes
    priority: Priority
    scoring: ScoringStatus
    events: list[EvidenceLine]
    events_shown: int
    events_truncated: bool
    runs: list[RunSummary]
    dispositions: list[Disposition]


class TraceStep(BaseModel):
    """One recorded step. Hypotheses are explicit tool calls, not hidden reasoning."""

    step: int
    kind: Literal["tool_call", "hypothesis"]
    tool: str | None = None
    request_summary: str | None = None
    available: bool | None = None
    unavailable_reason: str | None = None
    error: str | None = None
    returned: int | None = None
    evidence_count: int = 0
    evidence_handles: list[str] = Field(default_factory=list)
    duration_ms: int | None = None
    started_at: str | None = None
    truncated: bool | None = None
    claim: str | None = None
    support: list[str] = Field(default_factory=list)
    contradictions: list[str] = Field(default_factory=list)
    retained: bool | None = None


class GroundingIssue(BaseModel):
    kind: str
    detail: str
    handle: str | None = None


class Grounding(BaseModel):
    grounded: bool
    checked_handles: int = 0
    issues: list[GroundingIssue] = Field(default_factory=list)
    repair_attempted: bool = False
    note: str = ""


class RunDetail(RunSummary):
    case_id: str
    interrupted: bool
    cancel_requested: bool
    retry_allowed: bool
    report_available: bool
    grounding: Grounding | None
    steps: list[TraceStep]


class RunStartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: RunMode = "fixture"
    #: Required for a hosted provider: such a run sends redacted evidence out and
    #: may cost money, so it is never started by accident.
    confirm_hosted: bool = False


class RunStartResponse(BaseModel):
    created: bool
    run: RunDetail


class CancelResponse(BaseModel):
    run_id: str
    cancel_requested: bool
    note: str


class Citation(BaseModel):
    handle: str
    kind: Literal["event", "session", "reference", "unknown"]
    resolvable: bool
    reason: str | None = None


class ReportFinding(BaseModel):
    statement: str
    excerpt: str | None
    citations: list[Citation]


class PseudonymEntry(BaseModel):
    token: str
    value: str | None


class ReportView(BaseModel):
    run_id: str
    case_id: str
    schema_version: int
    execution: Execution
    provider: str
    model: str
    verdict: Literal["benign", "suspicious", "malicious", "insufficient_evidence"]
    verdict_note: str
    severity: str
    confidence: float
    summary: str
    findings: list[ReportFinding]
    known_or_novel: Literal["known", "potentially_novel", "uncertain"]
    known_or_novel_note: str
    technique_ids: list[str]
    recommended_actions: list[str]
    recommended_actions_note: str
    limitations: list[str]
    grounding: Grounding
    pseudonyms: list[PseudonymEntry]
    citations_resolvable: bool
    citation_note: str | None


class ReferenceView(BaseModel):
    title: str
    collection: str
    technique_ids: list[str]
    snippet: str
    snippet_truncated: bool
    source_uri: str
    version: str
    attribution: str
    note: str


class SessionView(BaseModel):
    dataset_id: str
    source: str
    start: str | None
    end: str | None
    event_count: int


class EvidenceResolution(BaseModel):
    handle: str
    kind: Literal["event", "session", "reference"]
    lines: list[EvidenceLine]
    lines_truncated: bool = False
    session: SessionView | None = None
    reference: ReferenceView | None = None


class DispositionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    disposition: DispositionValue
    note: str = Field(default="", max_length=2000)
    actor: str | None = Field(default=None, pattern=r"^[A-Za-z0-9 ._@-]{1,64}$")
    run_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")


class StoreStatus(BaseModel):
    available: bool
    schema_version: int | None
    reason: str | None


class ActiveRun(BaseModel):
    run_id: str
    case_id: str
    state: str
    started_at: str
    owned_by_this_process: bool
    cancel_requested: bool


class ProviderView(BaseModel):
    configured: bool
    provider: str | None
    model: str | None
    fixture: bool
    reason: str | None


class WorkspaceStatus(BaseModel):
    store: StoreStatus
    provider: ProviderView
    fixture_available: bool
    hosted_verified: bool
    hosted_note: str
    scoring: ScoringStatus
    active_run: ActiveRun | None
    recovered_interrupted_runs: int
    demo_workspace: bool
    fixture_pace_seconds: float
    budgets: dict[str, float | int]
    notes: list[str]


class ResetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirm: Literal["reset demo workspace"]


class ResetResponse(BaseModel):
    removed: dict[str, int]
    evidence_kept: bool
