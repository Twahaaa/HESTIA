"""Read-only SOC tools over stdio. stdout belongs to MCP; diagnostics go to stderr.

One server, every tool read-only. Nothing here writes to the evidence store, runs
a shell, opens a caller-supplied path or returns an evaluation label, and no tool
produces a rule-derived threat verdict: they retrieve source-qualified facts and
say plainly when a fact is unavailable or a model is not ready.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from hestia.config import Settings
from hestia.datasets.catalog import list_datasets as catalog
from hestia.datasets.catalog import summary
from hestia.mcp import evidence as evidence_tools
from hestia.mcp import history as history_tools
from hestia.mcp import knowledge as knowledge_tools
from hestia.mcp.context import DeadlineExceeded, ToolContext, configure_logging, logger
from hestia.mcp.contracts import (
    EntityHistoryResult,
    EventPage,
    EventResult,
    NormalityContextResult,
    ReferencePage,
    SessionResult,
    TechniqueResult,
    ToolInputError,
)
from hestia.normality.catalog import list_models

READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)


def _guard(name: str, call: Callable[[], Any]) -> Any:
    """Turn anticipated failures into readable tool errors, never tracebacks."""
    try:
        return call()
    except (ToolInputError, ValueError) as exc:
        raise ToolError(f"{name}: {exc}") from exc
    except DeadlineExceeded as exc:
        raise ToolError(f"{name}: {exc}") from exc
    except (OSError, KeyError) as exc:
        logger.exception("tool %s failed to read local evidence", name)
        raise ToolError(f"{name}: the requested local evidence could not be read") from exc


def create_server(settings: Settings | None = None) -> MCPServer:
    settings = settings or Settings()
    context = ToolContext(settings=settings)
    server = MCPServer("Hestia SOC Tools")

    @server.tool(annotations=READ_ONLY)
    def list_datasets() -> dict[str, Any]:
        """List local datasets and integrity status; no event labels are exposed."""
        return {"datasets": catalog(settings.data_root)}

    @server.tool(annotations=READ_ONLY)
    def get_dataset_summary(dataset_id: str) -> dict[str, Any]:
        """Inspect a known dataset identifier, not an arbitrary filesystem path."""
        return _guard("get_dataset_summary", lambda: summary(settings.data_root, dataset_id))

    @server.tool(annotations=READ_ONLY)
    def list_normality_models() -> dict[str, Any]:
        """List available estimators and their actual readiness."""
        return {"models": list_models(settings.artifact_root)}

    @server.tool(annotations=READ_ONLY)
    def get_session(session_id: str) -> SessionResult:
        """Retrieve one prepared session by its stable identifier."""
        return _guard(
            "get_session", lambda: evidence_tools.get_session(context, session_id=session_id)
        )

    @server.tool(annotations=READ_ONLY)
    def get_events(
        session_id: str, cursor: str | None = None, limit: int | None = None
    ) -> EventPage:
        """Page one session's events in stored order, with a cursor and no gaps."""
        return _guard(
            "get_events",
            lambda: evidence_tools.get_events(
                context, session_id=session_id, cursor=cursor, limit=limit
            ),
        )

    @server.tool(annotations=READ_ONLY)
    def get_event(event_id: str) -> EventResult:
        """Retrieve one event with its source line, raw text and stable reference."""
        return _guard("get_event", lambda: evidence_tools.get_event(context, event_id=event_id))

    @server.tool(annotations=READ_ONLY)
    def search_events(
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
        """Search prepared events by literal text, entity and UTC time window.

        The query is matched as a literal substring; it is never treated as a
        regular expression, SQL, a shell word or a filesystem path. Set
        membership to "unmatched" to search evidence that never joined a session.
        """
        return _guard(
            "search_events",
            lambda: evidence_tools.search_events(
                context,
                query=query,
                host=host,
                user=user,
                src_ip=src_ip,
                start=start,
                end=end,
                membership=membership,
                cursor=cursor,
                limit=limit,
            ),
        )

    @server.tool(annotations=READ_ONLY)
    def get_entity_history(
        entity_type: str,
        entity_id: str,
        before: str,
        cursor: str | None = None,
        limit: int | None = None,
    ) -> EntityHistoryResult:
        """Count what a user, host or source IP did strictly before a UTC boundary.

        Counts are prior observations, not a severity and not a verdict.
        """
        return _guard(
            "get_entity_history",
            lambda: history_tools.get_entity_history(
                context,
                entity_type=entity_type,
                entity_id=entity_id,
                before=before,
                cursor=cursor,
                limit=limit,
            ),
        )

    @server.tool(annotations=READ_ONLY)
    def get_normality_context(
        session_id: str, deployment_timezone: str = "UTC"
    ) -> NormalityContextResult:
        """Explain what was known about a session's entities before it started.

        Model readiness is reported honestly: while no session has explicit benign
        training eligibility, no anomaly score is produced at all.
        """
        return _guard(
            "get_normality_context",
            lambda: history_tools.get_normality_context(
                context, session_id=session_id, deployment_timezone=deployment_timezone
            ),
        )

    @server.tool(annotations=READ_ONLY)
    def search_attack_patterns(query: str, limit: int | None = None) -> ReferencePage:
        """Retrieve attributed reference material matching a query.

        Scores are transparent lexical overlap. A match is source material to
        read and cite, not a finding that the case is a known technique.
        """
        return _guard(
            "search_attack_patterns",
            lambda: knowledge_tools.search_attack_patterns(context, query=query, limit=limit),
        )

    @server.tool(annotations=READ_ONLY)
    def get_technique(technique_id: str) -> TechniqueResult:
        """Look up one pinned ATT&CK technique and its local manifestations.

        An identifier outside the pinned snapshot is reported as unavailable.
        """
        return _guard(
            "get_technique",
            lambda: knowledge_tools.get_technique(context, technique_id=technique_id),
        )

    return server


def main() -> None:
    configure_logging()
    create_server().run()


if __name__ == "__main__":
    main()
