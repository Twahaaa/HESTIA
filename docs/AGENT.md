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

One case still has **one agent and one selected provider/model**. Rate limits
are paced rather than probed (`HESTIA_AGENT_RATE_LIMIT_PACING`, on by default):

- Each key is tracked separately. Before each request the key with headroom is
  chosen, preferring the current one. Once a key's response has carried
  `x-ratelimit-*` headers, its token budget is modelled as the provider
  reports it: `remaining` refilling steadily to the full per-minute limit over
  the reported reset time. Groq also reports requests per day. A key without
  headers yet uses optional configured per-key `..._TOKENS_PER_MINUTE` /
  `..._REQUESTS_PER_MINUTE` limits over a sliding 60 s window.
- On HTTP 429 the key cools down for the provider's `retry-after`, or 60 s if
  the header is missing, and the same model request goes to a key with
  headroom. A cooled key may be used again later in the run.
- If no key has headroom, the run waits in one-second steps, checking
  cancellation and the wall clock. The wait is capped by
  `HESTIA_AGENT_RATE_LIMIT_MAX_WAIT_SECONDS` (default 65, enough for an emptied
  per-minute budget to refill) and the remaining run time. A longer wait ends the run incomplete ("keys exhausted for now")
  instead of retrying.
- 429 responses use their own allowance (`HESTIA_AGENT_RATE_LIMITED_ATTEMPTS`,
  default 4), not the model's turns. Provider HTTP attempts per run are at
  most `HESTIA_AGENT_MAX_TURNS` plus that allowance.
- Pacing state is shared by runs in one process, so consecutive cases do not
  burst on an already-depleted key. Keys are never stored in it; only
  rate-limit headers are read.

OpenRouter also switches keys on HTTP 402 **only** when its error metadata
explicitly says `openrouter_key_limit`; that key is not used again. Account-wide
credit exhaustion, invalid keys, server errors, timeouts and local budget
exhaustion never rotate. SDK automatic retries are disabled so every HTTP
attempt is counted. Stored usage includes key-free counts of provider attempts,
rotations, 429 responses and seconds spent waiting. Limits shared by an
organization or imposed upstream (OpenRouter) cannot be avoided by switching to
another key from the same account. No provider fallback is implied.

With pacing turned off, the earlier behaviour applies: a limited key is retired
for that run, and every attempt counts against `HESTIA_AGENT_MAX_TURNS`.

**Turn budget and conclusion.** Before every model request the agent is told
how many turns it has left for gathering evidence. Two turns of
`HESTIA_AGENT_MAX_TURNS` are kept in reserve. After that, or once the tool-call
budget is spent, the evidence tools are withdrawn and the model is told to
report from what it has already retrieved. The report may honestly be
`insufficient_evidence`. The citation-repair pass also runs without evidence
tools. A case that would otherwise run out of turns mid-search therefore ends
with a report, and every report still passes citation checks before it is
published. Evaluation results record a digest of these instructions.

**Context size.** Free tiers can refuse a single oversized request. Groq's
free plan answers HTTP 413 when one request exceeds the per-minute token limit.
Set `HESTIA_AGENT_CONTEXT_TOKEN_BUDGET` (for example `5000` on an 8K-TPM key)
and, before each request, the oldest tool results are condensed to their
evidence handles once the estimated history exceeds it. The two newest results
are kept in full, and older reasoning text is dropped. Condensed handles remain
valid citations, because grounding checks the run's recorded tool calls, not
the chat history. Stored usage counts condensed results. Malformed tool calls
use the output-retry allowance (`HESTIA_AGENT_MAX_RETRIES`). A model that
produces them often may need a larger allowance, e.g. 4.

Three approved three-case hosted evaluations have run on Groq; see
`docs/EVALUATION.md`. Only the third used the refill model above. The
turn-budget conclusion was added afterwards and is verified offline only. The fixture path
does not rotate and contacts no provider.

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
