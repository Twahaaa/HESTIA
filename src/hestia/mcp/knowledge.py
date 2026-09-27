"""Reference lookup tools over the pinned, attributed reference index.

These tools retrieve source material an investigator can read and cite. They do
not classify a case as a known technique or a novel one, and they never invent a
technique that the pinned snapshot does not contain: an unknown identifier is
reported as unavailable.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from hestia.knowledge import ReferenceIndex, read_index
from hestia.knowledge.contracts import ReferenceDocument
from hestia.knowledge.retrieval import LexicalIndex
from hestia.mcp.context import ToolContext, enforce_result_size
from hestia.mcp.contracts import (
    ReferenceMatch,
    ReferencePage,
    TechniqueResult,
    truncate_text,
    validate_identifier,
    validate_query,
)

_UNAVAILABLE = "no reference index has been built in this deployment; run `hestia knowledge-build`"


@lru_cache(maxsize=4)
def _load(path: Path, mtime: float, size: int) -> tuple[ReferenceIndex, LexicalIndex]:
    """Cache the parsed index per (path, mtime, size) so a rebuild is picked up."""
    del mtime, size
    index = read_index(path)
    return index, LexicalIndex(index.documents)


def _open_index(context: ToolContext) -> tuple[ReferenceIndex, LexicalIndex] | None:
    path = context.settings.knowledge_index
    if not path.is_file():
        return None
    stat = path.stat()
    return _load(path, stat.st_mtime, stat.st_size)


def _match(
    document: ReferenceDocument,
    *,
    score: float,
    matched_terms: tuple[tuple[str, float], ...],
    max_chars: int,
) -> ReferenceMatch:
    snippet, cut = truncate_text(document.snippet, maximum=max_chars)
    return ReferenceMatch(
        document_id=document.document_id,
        collection=document.source.collection,
        title=document.title,
        technique_ids=document.technique_ids,
        lexical_score=score,
        matched_terms=matched_terms,
        snippet=snippet,
        snippet_truncated=document.snippet_truncated or cut,
        snippet_start_line=document.snippet_start_line,
        snippet_end_line=document.snippet_end_line,
        source_uri=document.source.source_uri,
        source_sha256=document.source.sha256,
        source_version=document.source.version,
        attribution=document.source.attribution,
    )


def search_attack_patterns(
    context: ToolContext, *, query: str, limit: int | None = None
) -> ReferencePage:
    """Retrieve attributed reference documents whose text overlaps the query."""
    call = context.begin()
    text = validate_query(query, maximum=context.settings.mcp_max_query_chars)
    page_size = context.page_size(limit)
    opened = _open_index(context)
    if opened is None:
        return ReferencePage(
            request_id=call.request_id,
            available=False,
            unavailable_reason=_UNAVAILABLE,
            query=text,
        )
    index, lexical = opened
    results = lexical.search(text, limit=page_size)
    call.check_deadline()
    items = tuple(
        _match(
            result.document,
            score=result.score,
            matched_terms=result.matched_terms,
            max_chars=context.settings.mcp_max_snippet_chars,
        )
        for result in results
    )
    page = ReferencePage(
        request_id=call.request_id,
        available=True,
        query=text,
        items=items,
        returned=len(items),
        notes=index.coverage_notes,
    )
    return enforce_result_size(
        page, maximum_bytes=context.settings.mcp_max_result_bytes, items_field="items"
    )


def get_technique(context: ToolContext, *, technique_id: str) -> TechniqueResult:
    """Return one pinned ATT&CK technique and any local manifestations of it."""
    call = context.begin()
    identifier = validate_identifier(technique_id, field="technique_id", maximum=32).upper()
    opened = _open_index(context)
    if opened is None:
        return TechniqueResult(
            request_id=call.request_id,
            available=False,
            unavailable_reason=_UNAVAILABLE,
            technique_id=identifier,
        )
    index, _ = opened
    document = index.by_id(f"mitre-attack:{identifier}")
    manifestations = tuple(
        _match(
            item,
            score=0.0,
            matched_terms=(),
            max_chars=context.settings.mcp_max_snippet_chars,
        )
        for item in index.documents
        if item.source.collection == "cam-auth" and identifier in item.technique_ids
    )
    if document is None:
        return TechniqueResult(
            request_id=call.request_id,
            available=False,
            unavailable_reason=(
                f"{identifier} is not in the pinned ATT&CK subset held by this deployment"
            ),
            technique_id=identifier,
            local_manifestations=manifestations,
            notes=index.coverage_notes,
        )
    description, cut = truncate_text(
        document.snippet, maximum=context.settings.mcp_max_snippet_chars
    )
    result = TechniqueResult(
        request_id=call.request_id,
        available=True,
        technique_id=identifier,
        name=document.title.removeprefix(f"{identifier} ").strip() or None,
        description=description,
        tactics=document.tactics,
        platforms=document.platforms,
        data_sources=document.data_sources,
        url=document.url,
        snapshot_version=document.source.version,
        attribution=document.source.attribution,
        local_manifestations=manifestations,
        truncated=cut,
        truncation_reason="the technique description was truncated" if cut else None,
        notes=index.coverage_notes,
    )
    return enforce_result_size(
        result,
        maximum_bytes=context.settings.mcp_max_result_bytes,
        items_field="local_manifestations",
    )


__all__ = ["get_technique", "search_attack_patterns"]
