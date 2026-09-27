# Investigation agent

One agent owns one case. It chooses which read-only tools to call, may revise its
hypothesis when a result contradicts it, and decides whether it can report or must
abstain. It cannot exceed a budget, reach evidence past the case's historical
boundary, see a raw identifier, or publish a report whose citations do not resolve.

## Status right now

No hosted provider is configured in this repository, so **hosted operation is
unverified**. The pipeline is exercised end to end with a labelled deterministic
fixture model that contacts nothing. Separately, no behavioural model is trained
in this deployment, so the agent has no anomaly score to reason with — the honest
outcome for the current data is usually `insufficient_evidence`.

Check readiness without contacting anyone:

```sh
curl -s localhost:8000/api/agent/status
```

## What is sent to a provider

Nothing leaves the process except through `src/hestia/agent/redaction.py`. That
module rebuilds every tool result field by field from an allowlist, so a field
nobody listed is dropped rather than exported by default.

**Sent**, after transformation:

| Category | Form on the wire |
| --- | --- |
| Event identifiers | Opaque handles such as `ev-3f9c1a2b7d`. |
| Session identifiers | Opaque handles such as `se-1afe236bde`. |
| Reference documents | Opaque handles such as `rf-95094df1f9`, with title, technique ids, score, version and attribution. |
| Host, user, source IP, target user | Stable per-run pseudonyms such as `host-1`, `user-2`. |
| Event facts | Timestamp, process, event type, success flag, method, unmatched flag and reason. |
| Session facts | Start, end, event count, failure count, escalation and persistence flags, primary method. |
| Message and snippet text | Pseudonymized, IPs and long digests masked, length-capped, wrapped in `<untrusted-log-content>`. |
| Normality context | Historical counts, model readiness and the reason each model is not ready. |

**Never sent**, enforced by an outbound check that fails the call rather than
trimming it: raw log lines, raw messages, real event or session identifiers,
source paths, content digests, key fingerprints, evaluation labels of any kind,
credentials, API keys and environment variables.

Identifiers become handles for a concrete reason. A Hestia session identifier
embeds the host, source IP and user name, so forwarding it verbatim would undo
the pseudonymization of those same fields. The handle mapping stays in the
process, is what grounding resolves citations against, and is never written to a
log or an export.

Retrieved log and reference text is wrapped as untrusted content and the
instructions state that nothing inside it can grant a tool, raise a limit, change
the rules or reveal configuration. Forged envelope markers inside log text are
neutralized before wrapping.

## Configuration

All variables take the `HESTIA_` prefix and may live in `.env`.

| Variable | Meaning | Default |
| --- | --- | --- |
| `HESTIA_AGENT_PROVIDER` | `groq`, `openrouter` or `fixture`. | unset |
| `HESTIA_AGENT_MODEL` | Exact model identifier for that provider. Never guessed. | unset |
| `HESTIA_AGENT_API_KEY` | Provider secret. | unset |
| `HESTIA_AGENT_API_KEYS` | Alternative to the single key: ordered JSON list of 1–8 distinct keys for the **same** provider/model. | unset |
| `HESTIA_AGENT_MAX_TURNS` | Model requests per run. | 8 |
| `HESTIA_AGENT_MAX_TOOL_CALLS` | Tool calls per run. | 16 |
| `HESTIA_AGENT_MAX_TOTAL_TOKENS` | Input plus output tokens per run. | 120000 |
| `HESTIA_AGENT_MAX_WALL_SECONDS` | Wall-clock ceiling per run. | 180 |
| `HESTIA_AGENT_MAX_RETRIES` | Output-validation retries. | 2 |
| `HESTIA_AGENT_REQUEST_TIMEOUT_SECONDS` | Per-request provider timeout. | 60 |
| `HESTIA_AGENT_CONCURRENCY` | Active cases. Must be 1. | 1 |
| `HESTIA_AGENT_REDACTION_SALT` | Salt for local pseudonyms. Stays local. | unset |

An absent or incomplete configuration is an explicit unavailable status with an
actionable reason. There is no default model and no fallback to another provider.

### Multiple keys for one provider

Copy `.env.example` to a local `.env` and configure `HESTIA_AGENT_PROVIDER`
(`groq` or `openrouter`), its exact `HESTIA_AGENT_MODEL`, and **either**
`HESTIA_AGENT_API_KEY` **or** `HESTIA_AGENT_API_KEYS` (not both). The latter is
an ordered JSON array, for example
`HESTIA_AGENT_API_KEYS='["<first-key>","<second-key>"]'`; replace both
placeholders locally. Keep the real keys out of the source export and logs.

One case still has **one agent and one selected provider/model**. On an HTTP
429 rate limit, the current key is retired for that run and the next key
receives the *same model request*. OpenRouter also rotates on HTTP 402 **only**
when its error metadata explicitly says `openrouter_key_limit`. Account-wide
credit exhaustion, invalid keys, server errors, timeouts and local budget
exhaustion do not rotate. SDK automatic retries are disabled so each provider
attempt counts against the run's existing `HESTIA_AGENT_MAX_TURNS` ceiling;
tool/token/wall-clock budgets and cancellation remain in force. When all
keys hit a limit, the run ends incomplete with no report. The stored usage
includes a key-free provider-attempt count and rotation count. Groq may apply
limits across an organization, and OpenRouter 429s can originate upstream, so
additional keys are not guaranteed to resolve a rate limit. A new run is
required after an exhausted run; no provider fallback is implied.

Hosted behavior remains unverified without actual provider credentials. The
fixture path does not rotate and contacts no provider.

## Running a case

```sh
# Deterministic, contacts nothing, stored and reported as a fixture run:
uv run hestia investigate --session-id '<session id>' --fixture-provider

# Spawn the MCP server as a subprocess instead of running it in process:
uv run hestia investigate --session-id '<session id>' --fixture-provider --stdio
```

Session identifiers come from the MCP evidence tools or from the preparation
output. With a provider configured, drop `--fixture-provider`.

The case workspace starts the same runner through
`POST /api/cases/{case_id}/runs` with an `Idempotency-Key` header, one active run
at a time. `{"mode": "fixture"}` runs the fixture analyst. `{"mode": "configured",
"confirm_hosted": true}` uses the configured provider, and without that explicit
confirmation it is refused. See [the demo](DEMO.md).

### Worked example

Investigating one prepared OpenSSH session with the fixture analyst produces:

```json
{
  "state": "completed",
  "provider": "fixture",
  "model": "fixture-analyst",
  "fixture": true,
  "tool_calls": 4,
  "hypotheses": 1,
  "grounded": true,
  "verdict": "insufficient_evidence",
  "usage": {"requests": 6, "tool_calls": 4, "total_tokens": 2301, "wall_seconds": 0.587}
}
```

The trace shows which tools ran, in order: `get_session`, `get_events`,
`get_normality_context`, `search_attack_patterns`, then the recorded hypothesis.
The verdict is an abstention because no normality model is ready, and the report
says so in its limitations rather than implying the activity was normal.

## The report

| Field | Meaning |
| --- | --- |
| `verdict` | `benign`, `suspicious`, `malicious` or `insufficient_evidence`. |
| `severity` | `none` … `critical`. Forced to `none` for an abstention. |
| `confidence` | 0.0–1.0, the agent's own stated confidence. |
| `summary` | Prose conclusion. |
| `findings` | Statements, each carrying the evidence handles it rests on. |
| `known_or_novel` | `known`, `potentially_novel` or `uncertain`. |
| `technique_ids` | Techniques a reference tool actually returned. |
| `recommended_actions` | Suggestions for a human. Nothing is executed. |
| `limitations` | What the run could not establish. |

`potentially_novel` means the **local reference corpus did not cover** the
behavior. It is not a claim that an attack is new in the world.

## Grounding

Before a report is published, every citation is checked locally: the handle must
have been returned by a tool call in this run, must resolve to a stored
identifier, the cited event must exist, any quoted excerpt must appear in the
stored source line, and any named technique must exist in the pinned reference
snapshot.

This checks that citations exist and are consistent. It does not judge whether a
claim is true; semantic evaluation is a later phase. A report that fails gets one
bounded repair attempt with the specific problems named. If it still fails, the
run ends as `failed` and **no report is published**.

## Failure meanings

| Outcome | Meaning |
| --- | --- |
| `completed` | The run finished and its report passed grounding. |
| `failed` | A budget, provider, validation or grounding failure. No report. |
| `cancelled` | Stopped by an operator, a cancellation request or an orderly shutdown. No report. |
| `failed`, interrupted | The process stopped while the run was active. Marked on the next start and recorded separately. No report; retry as a new run. |
| `unavailable` | The provider or the session is not configured or not present. |

A run that stops early never reaches `completed`, so a partial investigation
cannot be read as a clean verdict. The stored run always records why it stopped.

## Storage

Case runs live in the same SQLite store as the evidence. Schema version 2 added
`agent_runs`, `agent_steps` and `agent_reports`. Version 3 adds
`analyst_dispositions`, `agent_run_requests` (idempotency keys),
`agent_run_interruptions` and `agent_grounding_failures`, the last of which keeps
the reasons a report was refused. Both migrations are additive: no earlier table,
column or row is altered, so an existing prepared store migrates in place without
re-preparing evidence. Trace rows are append-only: a step is written once and
never updated. Analyst dispositions are never read by training or scoring.

Running an investigation does not train, calibrate or otherwise change any
behavioural model.
