import pytest

from hestia.mcp.contracts import ToolInputError
from hestia.mcp.evidence import get_event, get_events, get_session, search_events


def test_session_and_events_carry_stable_source_references(context, session_id):
    result = get_session(context, session_id=session_id)
    assert result.available and result.session is not None
    assert result.session.source_ref.dataset_id == "fixture"
    assert len(result.session.source_ref.source_sha256) == 64
    assert result.schema_version == 1 and result.request_id

    page = get_events(context, session_id=session_id, limit=50)
    assert page.available and page.returned == result.session.event_count
    assert all(item.source_ref.line_no is not None for item in page.items)
    assert all(item.raw_line for item in page.items)


def test_pagination_has_no_duplicates_and_no_gaps(context, session_id):
    full = get_events(context, session_id=session_id, limit=50)
    collected = []
    cursor = None
    while True:
        page = get_events(context, session_id=session_id, cursor=cursor, limit=1)
        collected.extend(item.event_id for item in page.items)
        cursor = page.next_cursor
        if cursor is None:
            break
    assert collected == [item.event_id for item in full.items]
    assert len(set(collected)) == len(collected)


def test_search_is_time_bounded_and_strictly_ordered(context):
    everything = search_events(context, query="Accepted", limit=50)
    assert everything.returned >= 3
    timestamps = [item.timestamp for item in everything.items]
    assert timestamps == sorted(timestamps)

    bounded = search_events(
        context,
        query="Accepted",
        start="2025-01-02T00:00:00+00:00",
        end="2025-01-03T00:00:00+00:00",
        limit=50,
    )
    assert bounded.returned < everything.returned
    assert all(item.timestamp.day == 2 for item in bounded.items)


def test_search_treats_payloads_as_data(context):
    total = search_events(context, start="2000-01-01T00:00:00+00:00", limit=50)
    assert total.returned > 1

    for payload in ("'; DROP TABLE events; --", "%", "../../etc/passwd", "$(rm -rf /)", ".*"):
        result = search_events(context, query=payload, limit=50)
        assert result.available
        assert result.returned == 0, payload

    # "_" is a LIKE wildcard, so an unescaped pattern would match every line.
    underscore = search_events(context, query="_", limit=50)
    assert 0 < underscore.returned < total.returned
    assert all("_" in item.raw_line for item in underscore.items)
    assert context.repository().table_counts()["events"] > 0


def test_unmatched_evidence_stays_separately_searchable(context):
    unmatched = search_events(context, query="session opened", membership="unmatched", limit=10)
    assert unmatched.returned >= 1
    assert all(item.unmatched and item.unmatched_reason for item in unmatched.items)
    sessionized = search_events(context, query="session opened", membership="sessionized", limit=10)
    assert sessionized.returned == 0


def test_missing_identifiers_are_explicit_not_empty(context, empty_context):
    missing = get_session(context, session_id="fixture/auth.log:nope:2020-01-01T00:00:00+00:00")
    assert missing.available is False
    assert "no prepared session" in (missing.unavailable_reason or "")
    assert get_event(context, event_id="fixture/auth.log:9999").available is False

    unprepared = get_session(empty_context, session_id="anything:1")
    assert unprepared.available is False
    assert "prepare-data" in (unprepared.unavailable_reason or "")


def test_invalid_arguments_are_refused(context, session_id):
    with pytest.raises(ToolInputError):
        get_events(context, session_id=session_id, cursor="not-a-cursor")
    with pytest.raises(ToolInputError):
        get_events(context, session_id=session_id, limit=0)
    with pytest.raises(ToolInputError):
        search_events(context, query="x", start="2025-01-02T00:00:00")
    with pytest.raises(ToolInputError):
        search_events(
            context,
            query="x",
            start="2025-01-03T00:00:00+00:00",
            end="2025-01-02T00:00:00+00:00",
        )
    with pytest.raises(ToolInputError):
        search_events(context)
    with pytest.raises(ToolInputError):
        search_events(context, query="x" * 5000)
    with pytest.raises(ToolInputError):
        get_session(context, session_id="bad;rm -rf")


def test_oversized_pages_are_truncated_with_a_marker(prepared, session_id):
    from hestia.config import Settings
    from hestia.mcp.context import ToolContext

    tiny = ToolContext(
        settings=Settings(
            data_root=prepared.data_root,
            artifact_root=prepared.artifact_root,
            frontend_dist=prepared.frontend_dist,
            mcp_max_result_bytes=600,
        )
    )
    page = get_events(tiny, session_id=session_id, limit=50)
    assert page.truncated
    assert "bytes" in (page.truncation_reason or "")
    assert page.returned < 4


def test_raw_lines_longer_than_the_budget_are_marked(prepared, session_id):
    from hestia.config import Settings
    from hestia.mcp.context import ToolContext

    clipped = ToolContext(
        settings=Settings(
            data_root=prepared.data_root,
            artifact_root=prepared.artifact_root,
            frontend_dist=prepared.frontend_dist,
            mcp_max_snippet_chars=20,
        )
    )
    page = get_events(clipped, session_id=session_id, limit=1)
    assert page.items[0].raw_line_truncated
    assert page.items[0].raw_line.endswith("…[truncated]")
