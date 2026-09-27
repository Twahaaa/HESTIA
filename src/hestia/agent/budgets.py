"""Budgets the model cannot negotiate.

Every limit lives outside the conversation: the model is never told it may raise
one, and no tool can extend one. Exhausting a budget ends the run as incomplete
with the reason recorded, which is why a partial investigation can never present
itself as a finished verdict.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from hestia.config import Settings


class BudgetExceeded(RuntimeError):
    """A run consumed one of its configured budgets."""

    def __init__(self, budget: str, detail: str) -> None:
        super().__init__(f"{budget} budget exhausted: {detail}")
        self.budget = budget
        self.detail = detail


@dataclass(frozen=True)
class Budget:
    """Immutable limits for one case run."""

    max_turns: int
    max_tool_calls: int
    max_total_tokens: int
    max_wall_seconds: float
    max_retries: int
    request_timeout_seconds: float

    @classmethod
    def from_settings(cls, settings: Settings) -> Budget:
        return cls(
            max_turns=settings.agent_max_turns,
            max_tool_calls=settings.agent_max_tool_calls,
            max_total_tokens=settings.agent_max_total_tokens,
            max_wall_seconds=settings.agent_max_wall_seconds,
            max_retries=settings.agent_max_retries,
            request_timeout_seconds=settings.agent_request_timeout_seconds,
        )

    def usage_limits(self) -> Any:
        """Translate into the framework's own pre-request enforcement."""
        from pydantic_ai.usage import UsageLimits

        return UsageLimits(
            request_limit=self.max_turns,
            tool_calls_limit=self.max_tool_calls,
            total_tokens_limit=self.max_total_tokens,
        )

    def as_dict(self) -> dict[str, float | int]:
        return {
            "max_turns": self.max_turns,
            "max_tool_calls": self.max_tool_calls,
            "max_total_tokens": self.max_total_tokens,
            "max_wall_seconds": self.max_wall_seconds,
            "max_retries": self.max_retries,
            "request_timeout_seconds": self.request_timeout_seconds,
        }


@dataclass
class BudgetLedger:
    """Tracks consumption for the limits the framework does not enforce itself.

    The framework stops requests, tool calls and tokens before they happen. Wall
    clock and cancellation are this project's responsibility, checked at every
    tool boundary so a long investigation cannot run past its deadline between
    model turns.
    """

    budget: Budget
    started_at: float = field(default_factory=time.monotonic)
    tool_calls: int = 0
    cancelled: bool = False
    cancel_reason: str | None = None

    def cancel(self, reason: str = "cancelled by the operator") -> None:
        self.cancelled = True
        self.cancel_reason = reason

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self.started_at

    def remaining_seconds(self) -> float:
        return max(self.budget.max_wall_seconds - self.elapsed_seconds, 0.0)

    def check(self) -> None:
        """Raise if the run must stop now. Called at every tool boundary."""
        if self.cancelled:
            raise BudgetExceeded("cancellation", self.cancel_reason or "cancelled")
        if self.elapsed_seconds > self.budget.max_wall_seconds:
            raise BudgetExceeded(
                "wall_clock",
                f"{self.elapsed_seconds:.1f}s exceeded the {self.budget.max_wall_seconds:.1f}s limit",
            )

    def record_tool_call(self) -> None:
        """Count a tool call and refuse one past the ceiling.

        The framework also refuses this, one call earlier. Keeping an independent
        count means the ceiling still holds if a future toolset bypasses it.
        """
        if self.tool_calls >= self.budget.max_tool_calls:
            raise BudgetExceeded(
                "tool_calls",
                f"{self.tool_calls} calls reached the limit of {self.budget.max_tool_calls}",
            )
        self.tool_calls += 1


class CancellationToken:
    """An operator's request to stop a run, shared with the worker running it.

    Setting it never interrupts a tool call halfway. The run notices at its next
    tool boundary or when the model returns, and ends as ``cancelled`` without a
    report, which is the same path the budget ledger already guarantees.
    """

    def __init__(self) -> None:
        self._reason: str | None = None
        self._ledger: BudgetLedger | None = None

    @property
    def requested(self) -> bool:
        return self._reason is not None

    @property
    def reason(self) -> str | None:
        return self._reason

    def cancel(self, reason: str = "cancelled by the operator") -> None:
        if self._reason is None:
            self._reason = reason
        if self._ledger is not None:
            self._ledger.cancel(self._reason)

    def attach(self, ledger: BudgetLedger) -> None:
        self._ledger = ledger
        if self._reason is not None:
            ledger.cancel(self._reason)


__all__ = ["Budget", "BudgetExceeded", "BudgetLedger", "CancellationToken"]
