"""Run-scoped read boundary for the investigative tools.

One context owns the settings, the read-only repository handle, the per-call
deadline and the result-size budget. Tools never open files or databases by a
caller-supplied path, and never widen this boundary.
"""

from __future__ import annotations

import logging
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypeVar

from hestia.config import Settings
from hestia.mcp.contracts import ToolResult

if TYPE_CHECKING:  # pragma: no cover - import cycle avoidance only
    from hestia.store.repository import EvidenceRepository

ResultT = TypeVar("ResultT", bound=ToolResult)

#: stdout is the MCP transport. Diagnostics go to stderr, always.
logger = logging.getLogger("hestia.mcp")


def configure_logging(level: int = logging.INFO) -> None:
    """Attach a stderr handler once so tool logs cannot corrupt the transport."""
    if any(
        isinstance(handler, logging.StreamHandler) and handler.stream is sys.stderr
        for handler in logger.handlers
    ):
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False


class DeadlineExceeded(RuntimeError):
    """A single tool call exhausted its configured time budget."""


@dataclass
class ToolCall:
    """Per-invocation state: identity, deadline and truncation bookkeeping."""

    request_id: str
    deadline: float
    notes: list[str] = field(default_factory=list)

    def check_deadline(self) -> None:
        if time.monotonic() > self.deadline:
            raise DeadlineExceeded("tool call exceeded its configured time budget")

    def expired(self) -> bool:
        return time.monotonic() > self.deadline


@dataclass
class ToolContext:
    """The only object a tool module is allowed to reach the outside world with."""

    settings: Settings

    def begin(self) -> ToolCall:
        return ToolCall(
            request_id=uuid.uuid4().hex,
            deadline=time.monotonic() + self.settings.mcp_tool_timeout_seconds,
        )

    def repository(self) -> EvidenceRepository:
        from hestia.store.repository import EvidenceRepository

        return EvidenceRepository(self.settings.evidence_database)

    def evidence_available(self) -> bool:
        return self.settings.evidence_database.is_file()

    def page_size(self, limit: int | None) -> int:
        from hestia.mcp.contracts import validate_limit

        return validate_limit(
            limit,
            default=self.settings.mcp_default_page_size,
            maximum=self.settings.mcp_max_page_size,
        )


def enforce_result_size(result: ResultT, *, maximum_bytes: int, items_field: str) -> ResultT:
    """Drop trailing items until the serialized result fits the configured budget.

    The caller keeps the page it can actually read, and the response says plainly
    that it was cut. Silent shrinking would make citations unverifiable.
    """
    items = getattr(result, items_field, ())
    if len(result.model_dump_json().encode()) <= maximum_bytes:
        return result
    has_returned = "returned" in type(result).model_fields

    def shrink(kept: list[object], reason: str, keep_cursor: str | None) -> ResultT:
        update: dict[str, object] = {
            items_field: tuple(kept),
            "truncated": True,
            "truncation_reason": reason,
            "next_cursor": keep_cursor,
        }
        if has_returned:
            update["returned"] = len(kept)
        return result.model_copy(update=update)

    dropped = f"result exceeded {maximum_bytes} bytes; trailing items were dropped"
    kept = list(items)
    while kept:
        kept.pop()
        current = shrink(kept, dropped, result.next_cursor if kept else None)
        if len(current.model_dump_json().encode()) <= maximum_bytes:
            return current
    return shrink([], f"a single item exceeded {maximum_bytes} bytes", None)


__all__ = [
    "DeadlineExceeded",
    "ToolCall",
    "ToolContext",
    "configure_logging",
    "enforce_result_size",
    "logger",
]
