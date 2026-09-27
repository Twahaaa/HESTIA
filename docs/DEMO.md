# Case workspace demo

## Groq live walkthrough and pilot view

The interface now opens directly onto the case workspace. **Groq pilot** in the
top navigation (or `/#/pilot`) presents a read-only, public-safe summary of the
approved six-case Groq evaluation. It does not read the private label sidecar or
start a model call. Its outcomes and caveats are separate from any new workspace
investigation. The workspace shows a live activity card, elapsed time and each
recorded evidence-tool call as `/api/runs/{run_id}` updates. A pause means the
next step has not been recorded; it does not imply a specific provider action.

For a live hosted demonstration, use a workspace backed by the **prepared real
evidence store** (not the synthetic `demo-seed` volume), with `.env` configured
for `HESTIA_AGENT_PROVIDER=groq`, its model and key(s). Confirm the provider and
case in the UI, open a prepared case and choose **Run with Groq…**. The UI asks
for explicit confirmation before redacted evidence leaves the machine. It
shows tool calls, the grounded report if one completes, or an incomplete state
with no verdict if the provider or budgets stop the run. Only one run can be
active; the evaluator must not interpret a single live outcome as an addition
to the frozen six-case pilot. A prior OpenSSH session completed twice in
evaluation, but that dataset is unlabelled and a new run has no guaranteed
outcome. Check the workspace's configured budgets and evidence store before the
presentation. Do not seed or reset the real store for this walkthrough.

Run it against a **copy** of the prepared store. Workspace runs, reviews and
interruption records are written into the evidence store. A copy keeps the
evaluated `artifacts/evidence.sqlite3` byte-identical to the one the evaluation
results record. From the project root, after `npm run build` in `frontend/`
(Node 26.9):

```bash
mkdir -p artifacts/live-demo
cp artifacts/evidence.sqlite3 artifacts/live-demo/
cp -r artifacts/knowledge artifacts/normality artifacts/preparation artifacts/live-demo/
HESTIA_ARTIFACT_ROOT=artifacts/live-demo uv run uvicorn hestia.api.app:create_app --factory --host 127.0.0.1 --port 8010
```

Open <http://127.0.0.1:8010>. The queue pages through all 457 prepared
sessions; a case also opens directly at `#/cases/<case-id>`. `.env` supplies
the provider, model, keys and per-run budgets. Set
`HESTIA_AGENT_CONTEXT_TOKEN_BUDGET` (for example `5000`) on Groq's free plan,
so long investigations are condensed instead of refused with HTTP 413. A live
run can still stop on rate limits or the turn limit. When it does, it shows an
incomplete state with no verdict, which is the intended behaviour.

The scripted synthetic walkthrough below remains available under **Local
scripted walkthrough** in a case. It calls the real evidence tools but no
provider; it is not the Groq demonstration.

This walkthrough runs the case workspace on a small **synthetic** authentication
log that ships with the source. It needs Docker and nothing else: no API key, no
GPU and no dataset download.

The synthetic log uses documentation-only addresses (RFC 5737) and invented names.
It carries no annotations, so it is not labelled data, not proven benign and not
evaluation data. The investigation in this demo is run by the **fixture analyst**,
a deterministic script that calls the real evidence tools and contacts no
provider. It is labelled as a fixture everywhere it appears and is never presented
as a live model.

## Start

From the project root:

```sh
HESTIA_AGENT_FIXTURE_PACE_SECONDS=0.6 docker compose up --build -d
docker compose exec app hestia demo-seed
```

Open http://localhost:8000. The UI and the API are served from the same origin.

`demo-seed` prepares the synthetic log into the container's artifact volume, builds
the reference index from the pinned MITRE ATT&CK subset, and marks that volume as
a designated demo workspace. It refuses to run against an artifact root that
already holds evidence and is not a demo workspace. The pacing variable only
delays each scripted fixture turn so the investigation can be watched; leave it
unset (0) for instant fixture runs.

Before seeding, the workspace says that evidence preparation has not been run.
That is the expected empty state, not an error.

## Walk through a case

1. **Queue.** Eight cases are listed. Each one is *Unscored* and the queue is in
   session start-time order. No behavioural model is trained in this deployment,
   so no prioritization score exists. The page says so, and it says that a missing
   score is not evidence of normal behaviour. No case carries a threat label.
2. **Open a case.** Select `admin@demo-bastion`. The detail shows the exact stored
   log lines with source file, line number and time.
3. **Investigate.** Expand *Local scripted walkthrough* and choose *Run fixture
   investigation*. The run appears as
   *Running*, and each tool call joins the trace as it happens, showing the tool,
   what it asked for, how many evidence references it returned, and its duration.
   Recorded hypotheses appear as explicit steps. No private model reasoning is
   stored or shown.
4. **Report.** When the run completes, the report opens: *Insufficient evidence —
   the agent abstained*, severity `none`, labelled *Fixture run: deterministic
   scripted analyst, not a live model*. It lists findings with citations,
   reference coverage with its meaning, limitations, and review-only recommended
   actions.
5. **Open a citation.** Choose *Open event ev-…*. A panel shows the exact stored
   line behind the citation. Press Escape to close it; focus returns to the
   citation. Citations are resolved on the server one handle at a time. The local
   handle map is never sent to the browser.
6. **Record a review.** Under *Analyst review*, choose a disposition (Inconclusive,
   Benign after review, Suspicious after review, or Report disputed), add a note,
   and save. The disposition is kept with its actor and time. It is a review record
   only: it is not a training label, and it triggers no containment or remediation.
7. **Cancel and retry.** Open another case, start a run, and choose *Cancel run*.
   The run ends as *Cancelled — no report*, and nothing about it reads as a
   verdict. *Retry as a new fixture run* starts a fresh run.

To start over, choose *Reset demo workspace…* and confirm. This deletes every run,
trace, report, disposition and handle map in the demo workspace and keeps the
prepared evidence. Reset is refused on any workspace that `demo-seed` did not
mark, and it is refused while a run is active.

## What the states mean

| Shown as | Meaning |
| --- | --- |
| Unscored | No ready behavioural model scored the case. Not evidence of normality. |
| Running / Pending | The run has no report yet. |
| Report published | The run completed and every citation resolved locally. |
| Cancelled — no report | An analyst, or the process shutting down, stopped it. |
| Interrupted — no report | The process stopped while the run was active. It can be retried. |
| Report refused — citations failed validation | The agent's report cited evidence it could not back, even after one repair attempt. |
| Stopped — budget exhausted | A tool-call, token, request or time budget ran out. |
| Citation cannot be opened | This run's local handle map is missing, so its evidence cannot be resolved. |
| Potentially novel coverage | The local reference corpus did not cover the behaviour. Not a claim that an attack is new. |

One investigation runs at a time. Starting a second one while another is active
is refused, and the page links to the active case. If the API becomes
unreachable, the page says so and offers a retry. It does not show an empty or
stale workspace as current.

## Restart behaviour

Runs, traces, reports and dispositions are stored in the artifact volume and
survive `docker compose down` and `up` (as long as `-v` is not used). A run that
is active when the process stops cannot continue: on the next start it is marked
*Interrupted* and can be retried. On an orderly shutdown the active run is
cancelled instead.

## Without Docker

```sh
uv sync --locked
(cd frontend && npm ci && npm run build)
uv run python scripts/demo_server.py --artifact-root artifacts/demo-workspace --fresh --pace 0.6
```

Open http://127.0.0.1:8765. `--fresh` clears only an empty directory or one that
is already a designated demo workspace.

## Workspace API

| Method and path | Purpose |
| --- | --- |
| `GET /api/workspace` | Store, provider, scoring, active-run and demo status. Never contacts a provider. |
| `GET /api/cases?dataset=&limit=&offset=` | Paginated case queue with priority and readiness. |
| `GET /api/cases/{case_id}` | Case detail, canonical lines, runs and dispositions. |
| `POST /api/cases/{case_id}/runs` | Start a run. Requires an `Idempotency-Key` header. Body `{"mode": "fixture"}` or `{"mode": "configured", "confirm_hosted": true}`. |
| `GET /api/runs/{run_id}` | Run state and trace. |
| `POST /api/runs/{run_id}/cancel` | Request cancellation. |
| `GET /api/runs/{run_id}/report` | The report. Returns 409 for any run that did not complete. |
| `GET /api/runs/{run_id}/evidence/{handle}` | Resolve one handle that this run cited or retrieved. |
| `POST /api/cases/{case_id}/dispositions` | Record an analyst review disposition. |
| `POST /api/workspace/reset` | Demo workspace only. Body `{"confirm": "reset demo workspace"}`. |

A start request answers 202 for a new run and 200 when it replays an idempotency
key with the same request. It answers 409 `run_active` while another run is
active, 422 `idempotency_key_reused` when a key is reused for a different
request, and 503 `provider_unavailable` when `configured` mode has no provider.
No endpoint that can start paid work accepts GET, and no response carries a
provider key.

## Configuration added for the workspace

| Variable | Meaning | Default |
| --- | --- | --- |
| `HESTIA_AGENT_FIXTURE_PACE_SECONDS` | Delay before each scripted fixture turn, 0–5. Fixture runs only. | 0 |
| `HESTIA_ANALYST_NAME` | Actor recorded on a disposition when none is given. There is no sign-in, so this is a label, not an identity. | `local-analyst` |

## Current limitations

- No behavioural model is trained, so cases are unscored and investigations have
  no anomaly score. The honest outcome is usually an abstention.
- Hosted workspace runs require explicit confirmation. The six-case Groq
  evaluation pilot is measured separately, but its partial completion does not
  establish reliable completion for a new live workspace run. The synthetic
  walkthrough in this document remains a fixture run.
- The fixture analyst demonstrates the pipeline. Its findings restate retrieved
  fields and are not an assessment.
- One workspace process owns investigations for a store. Do not run
  `hestia investigate` against the same store while the workspace is starting,
  because startup marks every active run as interrupted.
- There is no authentication. The actor on a disposition is whatever name is
  entered.
- Replay speed, split and seed controls are not provided. Evidence is prepared
  in batch; the queue can be filtered to any prepared dataset.

## Checks

```sh
uv run pytest -q
cd frontend
npm ci && npm run lint && npm test && npm run build
npx playwright install chromium   # or set HESTIA_E2E_CHANNEL=chrome to use Google Chrome
npm run test:e2e
```

`npm run test:e2e` starts its own seeded demo server. To run the same end-to-end
tests against a running container, set `HESTIA_E2E_BASE_URL=http://127.0.0.1:8000`
after running `hestia demo-seed` in it. The tests reset that demo workspace.
