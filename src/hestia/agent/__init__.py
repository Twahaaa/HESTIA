"""Bounded, case-owning investigation agent.

One agent, one case, read-only tools, budgets it cannot negotiate, and a report
that must resolve its own citations before it is published.
"""

import os

# The framework prints a setup banner on first import. stdout carries MCP protocol
# and CLI JSON, so opt out before anything imports it.
os.environ.setdefault("PYDANTIC_AI_NO_BANNER", "1")

from hestia.agent.budgets import Budget, BudgetExceeded, BudgetLedger  # noqa: E402
from hestia.agent.contracts import (  # noqa: E402
    CaseInput,
    CaseRun,
    Coverage,
    Finding,
    GroundingResult,
    Hypothesis,
    Report,
    RunState,
    Severity,
    ToolTrace,
    Usage,
    Verdict,
)
from hestia.agent.grounding import validate_report  # noqa: E402
from hestia.agent.providers import (  # noqa: E402
    ProviderStatus,
    ProviderUnavailable,
    provider_status,
)
from hestia.agent.redaction import (  # noqa: E402
    RedactionError,
    Redactor,
    build_redactor,
)
from hestia.agent.runner import investigate  # noqa: E402

__all__ = [
    "Budget",
    "BudgetExceeded",
    "BudgetLedger",
    "CaseInput",
    "CaseRun",
    "Coverage",
    "Finding",
    "GroundingResult",
    "Hypothesis",
    "ProviderStatus",
    "ProviderUnavailable",
    "RedactionError",
    "Redactor",
    "Report",
    "RunState",
    "Severity",
    "ToolTrace",
    "Usage",
    "Verdict",
    "build_redactor",
    "investigate",
    "provider_status",
    "validate_report",
]
