"""Case-run lifecycle: one worker, persistent state, explicit recovery.

At most one run is active. The rule is enforced in a SQLite write transaction
when a run is requested, so two concurrent start requests cannot both succeed,
and a repeated request with the same idempotency key returns the original run.

The worker is a single in-process thread. It is not durable: if the process
stops, the thread is gone. On the next start every run still recorded as pending
or running is therefore marked failed with an explicit interruption record and
can be retried as a new run. Nothing pretends a detached task survived.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from hestia.agent.budgets import CancellationToken
from hestia.config import AgentProvider, Settings

logger = logging.getLogger("hestia.runs")

INTERRUPTED_REASON = (
    "interrupted: the workspace process stopped while this run was active, so it did "
    "not finish and has no report; start a new run to retry"
)
SHUTDOWN_REASON = "cancelled: the workspace process shut down while this run was active"
ANALYST_CANCEL_REASON = "cancelled by the analyst"
FIXTURE_MODEL = "fixture-analyst"


class RunRequestError(RuntimeError):
    """A start or cancel request that cannot be honoured. Mapped to HTTP by the API."""

    def __init__(self, status: int, code: str, message: str, **extra: Any) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.extra = extra


@dataclass
class _Active:
    run_id: str
    token: CancellationToken
    thread: threading.Thread


class RunService:
    """Owns the single worker thread and the recovery performed at startup."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._lock = threading.Lock()
        self._active: _Active | None = None
        self.recovered_run_ids: list[str] = []
        self._initialized = False

    # -- store ---------------------------------------------------------------

    def repository(self) -> Any:
        """The evidence store, migrated forward once, or None when not prepared."""
        from hestia.store.repository import EvidenceRepository

        database = self.settings.evidence_database
        if not database.is_file():
            return None
        repository = EvidenceRepository(database)
        if not self._initialized:
            repository.initialize()
            self._initialized = True
        return repository

    def start(self) -> None:
        """Recover interrupted work. Called once when the process starts."""
        repository = self.repository()
        if repository is None:
            return
        self.recovered_run_ids = repository.mark_interrupted_runs(INTERRUPTED_REASON)
        if self.recovered_run_ids:
            logger.warning("marked %d interrupted case run(s)", len(self.recovered_run_ids))

    def shutdown(self, timeout: float = 5.0) -> None:
        """Ask an active run to stop and give it a moment to record that."""
        with self._lock:
            active = self._active
        if active is None:
            return
        active.token.cancel(SHUTDOWN_REASON)
        active.thread.join(timeout)

    # -- state ---------------------------------------------------------------

    def active_run(self) -> dict[str, Any] | None:
        repository = self.repository()
        if repository is None:
            return None
        rows = repository.active_case_runs()
        if not rows:
            return None
        row = rows[0]
        with self._lock:
            owned = self._active is not None and self._active.run_id == row["run_id"]
            cancel_requested = owned and self._active is not None and self._active.token.requested
        return {
            "run_id": row["run_id"],
            "case_id": row["case_id"],
            "state": row["state"],
            "started_at": row["started_at"],
            "owned_by_this_process": owned,
            "cancel_requested": cancel_requested,
        }

    def cancel_requested(self, run_id: str) -> bool:
        with self._lock:
            return (
                self._active is not None
                and self._active.run_id == run_id
                and self._active.token.requested
            )

    # -- lifecycle -------------------------------------------------------------

    def effective_settings(self, mode: str, *, confirm_hosted: bool) -> Settings:
        """Settings the run will use. Refuses rather than substituting a provider."""
        from hestia.agent.providers import provider_status

        if mode == "fixture":
            return self.settings.model_copy(
                update={"agent_provider": AgentProvider.fixture, "agent_model": FIXTURE_MODEL}
            )
        status = provider_status(self.settings)
        if not status.configured:
            raise RunRequestError(
                503,
                "provider_unavailable",
                status.reason or "the agent provider is not configured",
            )
        if not status.fixture and not confirm_hosted:
            raise RunRequestError(
                422,
                "hosted_confirmation_required",
                "a hosted run sends redacted evidence to the configured provider and may "
                "incur cost; resend with confirm_hosted=true to proceed",
            )
        return self.settings

    def request_run(
        self,
        *,
        case_id: str,
        session_id: str,
        idempotency_key: str,
        mode: str,
        confirm_hosted: bool,
    ) -> tuple[str, bool]:
        """Register and start one run, or return the run this key already started."""
        from hestia.agent.contracts import CaseInput, CaseRun, RunState
        from hestia.agent.providers import provider_status
        from hestia.store.repository import ActiveRunConflict, IdempotencyConflict

        repository = self.repository()
        if repository is None:
            raise RunRequestError(503, "store_unavailable", "evidence preparation has not been run")
        effective = self.effective_settings(mode, confirm_hosted=confirm_hosted)
        row = repository.read_session(session_id)
        if row is None:
            raise RunRequestError(404, "case_not_found", "no prepared session backs this case")
        session = json.loads(str(row["session_json"]))
        start = datetime.fromisoformat(session["start_time"])
        case = CaseInput(
            case_id=case_id,
            session_id=session_id,
            opened_at=datetime.now(UTC),
            session_start=start,
            session_end=datetime.fromisoformat(session["end_time"]),
            dataset_id=str(row["dataset_id"]),
            history_before=start,
        )
        status = provider_status(effective)
        run_id = uuid.uuid4().hex
        pending = CaseRun(
            run_id=run_id,
            case=case,
            state=RunState.pending,
            provider=status.provider or "unconfigured",
            model=status.model or "unconfigured",
            fixture=status.fixture,
            started_at=datetime.now(UTC),
        )
        with self._lock:
            try:
                stored_id, created = repository.request_case_run(
                    pending,
                    idempotency_key=idempotency_key,
                    request={"case_id": case_id, "mode": mode},
                )
            except IdempotencyConflict as exc:
                raise RunRequestError(
                    422,
                    "idempotency_key_reused",
                    "this idempotency key was already used for a different request",
                    run_id=exc.run_id,
                ) from exc
            except ActiveRunConflict as exc:
                raise RunRequestError(
                    409,
                    "run_active",
                    "another investigation is still active; one case runs at a time",
                    run_id=exc.run_id,
                    case_id=exc.case_id,
                ) from exc
            if not created:
                return stored_id, False
            token = CancellationToken()
            thread = threading.Thread(
                target=self._work,
                args=(effective, case, run_id, token),
                name=f"hestia-run-{run_id[:8]}",
                daemon=True,
            )
            self._active = _Active(run_id=run_id, token=token, thread=thread)
            thread.start()
        return run_id, True

    def cancel(self, run_id: str) -> dict[str, Any]:
        repository = self.repository()
        run = None if repository is None else repository.read_case_run(run_id)
        if run is None:
            raise RunRequestError(404, "run_not_found", "no case run has that identifier")
        if run["state"] not in {"pending", "running"}:
            raise RunRequestError(
                409,
                "run_not_active",
                f"the run already ended as {run['state']}; there is nothing to cancel",
                state=run["state"],
            )
        with self._lock:
            active = self._active
            if active is None or active.run_id != run_id:
                raise RunRequestError(
                    409,
                    "run_not_owned",
                    "this run is not executing in this workspace process, so it cannot be "
                    "cancelled here; restarting the workspace marks it interrupted",
                )
            active.token.cancel(ANALYST_CANCEL_REASON)
        return {"run_id": run_id, "cancel_requested": True}

    def wait(self, timeout: float) -> bool:
        """Join the current worker. For tests and orderly shutdown only."""
        with self._lock:
            active = self._active
        if active is None:
            return True
        active.thread.join(timeout)
        return not active.thread.is_alive()

    # -- worker ----------------------------------------------------------------

    def _work(
        self,
        settings: Settings,
        case: Any,
        run_id: str,
        token: CancellationToken,
    ) -> None:
        from hestia.agent.fixtures import workspace_demo_script
        from hestia.agent.runner import investigate
        from hestia.store.repository import EvidenceRepository

        repository = EvidenceRepository(settings.evidence_database)
        script = (
            workspace_demo_script(settings.agent_fixture_pace_seconds)
            if settings.agent_provider is AgentProvider.fixture
            else None
        )
        try:
            asyncio.run(
                investigate(
                    settings,
                    case,
                    fixture_script=script,
                    persist=repository.save_case_run,
                    run_id=run_id,
                    cancellation=token,
                    persist_progress=True,
                )
            )
        except Exception as exc:  # noqa: BLE001 - the run must still end visibly
            logger.error("case run %s ended with %s", run_id, type(exc).__name__)
            repository.mark_run_failed(run_id, f"workspace worker error: {type(exc).__name__}")
        finally:
            with self._lock:
                if self._active is not None and self._active.run_id == run_id:
                    self._active = None


__all__ = [
    "ANALYST_CANCEL_REASON",
    "INTERRUPTED_REASON",
    "RunRequestError",
    "RunService",
]
