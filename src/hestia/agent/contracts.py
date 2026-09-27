"""Case, trace and report contracts for the bounded investigation agent.

The report is the agent's own conclusion, and the contract makes its limits
explicit rather than implied. `insufficient_evidence` is a first-class verdict.
`known_or_novel` describes reference coverage in this deployment, not a claim
about the world: `potentially_novel` means the local reference corpus did not
cover the behavior, never that an attack is new globally. Every factual finding
carries the evidence handles it rests on, and a report that cites nothing
retrievable fails grounding rather than being published.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

REPORT_SCHEMA_VERSION = 1


class Verdict(StrEnum):
    benign = "benign"
    suspicious = "suspicious"
    malicious = "malicious"
    insufficient_evidence = "insufficient_evidence"


class Severity(StrEnum):
    none = "none"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Coverage(StrEnum):
    """How well the local reference corpus covered the observed behavior."""

    known = "known"
    potentially_novel = "potentially_novel"
    uncertain = "uncertain"


class RunState(StrEnum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


#: Terminal states a partial or failed run may end in. A run that stopped early
#: never reaches `completed`, so an incomplete investigation cannot be read as a
#: clean verdict.
INCOMPLETE_STATES = frozenset({RunState.failed, RunState.cancelled})


class CaseInput(BaseModel):
    """What the investigator hands the agent: references, never raw content."""

    model_config = ConfigDict(frozen=True)

    case_id: str
    session_id: str
    candidate_id: str | None = None
    opened_at: datetime
    session_start: datetime
    session_end: datetime
    dataset_id: str
    #: Exclusive boundary for anything historical the agent may consider.
    history_before: datetime

    @model_validator(mode="after")
    def validate_bounds(self) -> Self:
        for name in ("opened_at", "session_start", "session_end", "history_before"):
            value: datetime = getattr(self, name)
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"{name} must be timezone-aware")
        if self.session_end < self.session_start:
            raise ValueError("session_end must not precede session_start")
        if self.history_before > self.session_start:
            raise ValueError("history_before must not exceed session_start")
        return self


class ToolTrace(BaseModel):
    """One executed tool call, recorded whether it helped or not."""

    model_config = ConfigDict(frozen=True)

    step: int = Field(ge=1)
    tool: str
    arguments: dict[str, object]
    started_at: datetime
    duration_ms: int = Field(ge=0)
    available: bool
    unavailable_reason: str | None = None
    returned: int = Field(default=0, ge=0)
    #: Local handles the call put in front of the model, for grounding.
    evidence_handles: tuple[str, ...] = ()
    truncated: bool = False
    error: str | None = None


class Hypothesis(BaseModel):
    """A claim the agent held at some point, with what moved it."""

    model_config = ConfigDict(frozen=True)

    step: int = Field(ge=1)
    claim: str = Field(min_length=1)
    support: tuple[str, ...] = ()
    contradictions: tuple[str, ...] = ()
    retained: bool = Field(
        default=True, description="False when later evidence made the agent drop it."
    )


class Finding(BaseModel):
    """One factual statement, bound to the evidence it rests on."""

    model_config = ConfigDict(frozen=True)

    statement: str = Field(min_length=1)
    evidence_handles: tuple[str, ...] = Field(min_length=1)
    excerpt: str | None = None

    @model_validator(mode="after")
    def reject_blank_handles(self) -> Self:
        if any(not handle.strip() for handle in self.evidence_handles):
            raise ValueError("evidence handles must not be blank")
        return self


class Usage(BaseModel):
    """What the run actually consumed. Cost is the provider adapter's estimate."""

    model_config = ConfigDict(frozen=True)

    requests: int = Field(default=0, ge=0)
    tool_calls: int = Field(default=0, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)
    provider_attempts: int = Field(default=0, ge=0)
    key_rotations: int = Field(default=0, ge=0)
    #: HTTP 429 responses absorbed, and seconds spent waiting for key headroom.
    rate_limited: int = Field(default=0, ge=0)
    rate_limit_wait_seconds: float = Field(default=0.0, ge=0.0)
    #: Older tool results condensed to their handles to fit the context budget.
    compacted_tool_results: int = Field(default=0, ge=0)
    estimated_cost_usd: float | None = None
    wall_seconds: float = Field(default=0.0, ge=0.0)


class Report(BaseModel):
    """The agent's structured conclusion. Findings must be grounded to publish."""

    model_config = ConfigDict(frozen=True)

    schema_version: int = REPORT_SCHEMA_VERSION
    verdict: Verdict
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = Field(min_length=1)
    findings: tuple[Finding, ...] = ()
    known_or_novel: Coverage
    technique_ids: tuple[str, ...] = ()
    recommended_actions: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_consistency(self) -> Self:
        if self.verdict is Verdict.insufficient_evidence and self.severity is not Severity.none:
            raise ValueError("insufficient_evidence must carry severity 'none'")
        if self.verdict is Verdict.benign and self.severity not in {Severity.none, Severity.low}:
            raise ValueError("a benign verdict cannot carry medium or higher severity")
        if self.verdict is not Verdict.insufficient_evidence and not self.findings:
            raise ValueError("any verdict other than insufficient_evidence requires findings")
        return self


class GroundingIssue(BaseModel):
    """One reason a report could not be published as grounded."""

    model_config = ConfigDict(frozen=True)

    kind: str
    detail: str
    handle: str | None = None


class GroundingResult(BaseModel):
    """Citation existence and consistency only, never semantic truth."""

    model_config = ConfigDict(frozen=True)

    grounded: bool
    checked_handles: int = Field(default=0, ge=0)
    issues: tuple[GroundingIssue, ...] = ()
    repair_attempted: bool = False
    note: str = (
        "Grounding checks that citations exist, belong to this case and match the "
        "stored source. It does not judge whether a claim is true."
    )


class CaseRun(BaseModel):
    """The durable record of one investigation attempt."""

    model_config = ConfigDict(frozen=True)

    run_id: str
    case: CaseInput
    state: RunState
    provider: str
    model: str
    fixture: bool
    started_at: datetime
    finished_at: datetime | None = None
    traces: tuple[ToolTrace, ...] = ()
    hypotheses: tuple[Hypothesis, ...] = ()
    report: Report | None = None
    grounding: GroundingResult | None = None
    usage: Usage = Usage()
    incomplete_reason: str | None = None

    @model_validator(mode="after")
    def validate_terminal_state(self) -> Self:
        if self.state in INCOMPLETE_STATES and self.report is not None:
            raise ValueError("a failed or cancelled run must not carry a report")
        if self.state is RunState.completed and self.report is None:
            raise ValueError("a completed run must carry a report")
        if self.state in INCOMPLETE_STATES and not self.incomplete_reason:
            raise ValueError("a failed or cancelled run must record why it stopped")
        return self


__all__ = [
    "INCOMPLETE_STATES",
    "REPORT_SCHEMA_VERSION",
    "CaseInput",
    "CaseRun",
    "Coverage",
    "Finding",
    "GroundingIssue",
    "GroundingResult",
    "Hypothesis",
    "Report",
    "RunState",
    "Severity",
    "ToolTrace",
    "Usage",
    "Verdict",
]
