# Investigative MCP tools

Hestia exposes one read-only MCP server over stdio. Every tool retrieves
source-qualified facts. No tool writes to the evidence store, runs a shell,
opens a caller-supplied filesystem path, returns an evaluation label, or decides
that evidence is malicious. Prioritization and judgement are not tool outputs.

Start the server directly, or let an MCP client spawn it:

```sh
uv run hestia mcp
```

Client configuration: command `uv`, arguments
`["run", "--directory", "/absolute/path/to/hestia", "hestia", "mcp"]`. stdout
carries the protocol; all diagnostics go to stderr.

## Shared result envelope

Every tool returns structured output with the same envelope fields.

| Field | Meaning |
| --- | --- |
| `schema_version` | Tool contract version; currently `1`. |
| `request_id` | Identifier of this invocation, for correlating logs. |
| `available` | `false` when the requested facts cannot be retrieved. |
| `unavailable_reason` | Why, in plain words. Never an empty result pretending to be an answer. |
| `truncated` / `truncation_reason` | Set when output was cut to fit the configured budget. |
| `next_cursor` | Opaque cursor for the next page, or `null` at the end. |
| `source_refs` | Stable `evidence_ref`, dataset, source path, SHA-256 and line number a report may cite. |
| `notes` | Coverage limitations that apply to this result. |

`available: false` and a not-ready model are ordinary outcomes. A client should
render them, not retry them away.

## Evidence tools

| Tool | Arguments | Returns |
| --- | --- | --- |
| `get_session` | `session_id` | One prepared session with its source reference. |
| `get_events` | `session_id`, `cursor?`, `limit?` | One page of the session's events in stored order. |
| `get_event` | `event_id` | One event with its parsed fields, original raw line and line number. |
| `search_events` | `query?`, `host?`, `user?`, `src_ip?`, `start?`, `end?`, `membership?`, `cursor?`, `limit?` | A page of matching events, ordered by timestamp then event id. |

`query` is matched as a **literal substring** of the normalized message or the
original raw line. It is never compiled as a regular expression, interpolated
into SQL, expanded as a shell word or resolved as a path; LIKE wildcards in the
text match themselves. `start` and `end` must carry a timezone offset; `start`
is inclusive and `end` is exclusive.

`membership` selects `any` (default), `unmatched` or `sessionized`. Records whose
user or source IP is missing never joined a session, so they are searchable in
their own right: a missing field must not hide escalation evidence.

## History and normality tools

| Tool | Arguments | Returns |
| --- | --- | --- |
| `get_entity_history` | `entity_type` (`user`/`host`/`src_ip`), `entity_id`, `before`, `cursor?`, `limit?` | Counts and a page of prior sessions for that entity. |
| `get_normality_context` | `session_id`, `deployment_timezone?` | Historical counts materialized before the session start, model readiness and training provenance. |

`before` is an **exclusive** boundary and must carry a timezone offset: only
sessions that closed strictly before it are counted, so a case can never see
itself or later evidence. `store_session_denominator` gives the number of
sessions in the whole store before the same boundary, so an entity count can be
read in proportion.

These counts are observations. They are not a severity, a baseline of proven
normal behavior, or a verdict. `get_normality_context` reports
`scores_available: false` and a per-model reason while no behavioral model is
ready; it does not invent a score. Missing labels do not make unlabelled traffic
normal.

## Reference tools

| Tool | Arguments | Returns |
| --- | --- | --- |
| `search_attack_patterns` | `query`, `limit?` | Attributed reference documents ranked by lexical overlap, with matched terms. |
| `get_technique` | `technique_id` | One pinned ATT&CK technique and its local manifestations. |

Reference material comes from a versioned index built offline:

```sh
uv run hestia knowledge-build --split-manifest artifacts/preparation/<run>-splits.json
```

The index holds two attributed collections: CAM-LDS authentication manifestations
keyed by the ATT&CK technique their directory names, and a pinned MITRE ATT&CK
Enterprise subset limited to auth-relevant techniques. Each document keeps its
source URI, content digest, version, required attribution and exact snippet line
range.

Refreshing the pinned ATT&CK snapshot reaches the network and therefore only
happens when a human asks for it:

```sh
uv run hestia knowledge-build --refresh-attack
```

A demo never triggers that fetch implicitly. A source file that any held-out
validation or evaluation split claims is excluded from the reference corpus, so
reference retrieval cannot quote evidence a later evaluation scores.

`lexical_score` is deterministic term overlap and `matched_terms` shows exactly
which query terms contributed. A match is source material to read and cite. It
does not establish that a case is a known technique, and its absence does not
establish novelty. A technique identifier outside the pinned subset is reported
as unavailable rather than invented.

## Catalog tools

`list_datasets`, `get_dataset_summary` and `list_normality_models` are unchanged
from the foundation. `get_dataset_summary` accepts a known dataset identifier,
never a filesystem path.

## Errors and limits

Anticipated failures — an unparseable cursor, a naive timestamp, an unsupported
entity type, an over-long query, an identifier with unsupported characters —
come back as a tool error with a readable message, which an MCP client reads as
`is_error` on the result rather than a raised exception. Unexpected failures are
logged to stderr and return a generic message; internals are not put on the wire.

Page size, result size in bytes, snippet length, query length and the per-call
time budget are configured through `HESTIA_MCP_*` environment variables. Pages
are cut at a whole item and the response says so.

## Smoke check

```sh
uv run python scripts/mcp_smoke.py
```

This spawns `hestia mcp` as a real stdio subprocess, verifies every registered
tool is annotated read-only, calls all of them against the local deployment and
prints what came back, including unavailable results.
