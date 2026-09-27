# Hestia

Evidence-led SOC triage for Linux authentication logs.

Hestia provides deterministic parsing, sessionization, reusable behavioral model
primitives, a dataset catalog, a read-only MCP server, one bounded investigation
agent, and a React case workspace for reviewing cases against their cited
evidence. Real authentication normality training and hosted-agent acceptance
remain incomplete. A separate, explicitly labelled public HDFS anomaly
benchmark measures an offline baseline, not the investigation agent; see
[evaluation status](docs/EVALUATION.md).

## Run with Docker

```sh
docker compose up --build
```

Open http://localhost:8000. No API key or GPU is needed for the foundation.
The runtime serves the compiled frontend and API together. Raw data is mounted
read-only; model and investigation artifacts use a persistent Docker volume.

For a guided walkthrough on bundled synthetic data, with no credentials needed,
see the [case workspace demo](docs/DEMO.md):

```sh
docker compose up --build -d
docker compose exec app hestia demo-seed
```

## Develop

Use uv 0.12.17 and Node 26.9.0 (versions are pinned for reproducibility).

```sh
uv sync --locked
uv run uvicorn hestia.api.app:create_app --factory --reload
# In another terminal:
cd frontend
npm ci
npm run dev
```

Open http://localhost:5173. Vite proxies `/api` to port 8000.
For container-based development use
`docker compose -f compose.yaml -f compose.dev.yaml up --build`.

## Data and tools

```sh
uv run hestia doctor
uv run hestia import-data --source-root /path/to/dataset-collection
uv run hestia parse /path/to/auth.log --source dataset/host/auth.log --year 2022
uv run hestia mcp
```

The import source contains `ait-lds-v2.0`, `cam-lds`, and `loghub-openssh` directories.
Only authentication logs, matching AIT annotations and dataset metadata are copied.
The legacy AIT directory name does not determine its release version: the current
import contract is release 2.1. Manifests record relative paths, sizes and SHA-256.
Import rejects byte conflicts and supports repeat runs. After import, the source
collection is not needed at runtime. See [data notes](docs/DATA.md).

The MCP process uses stdio and exposes eleven read-only tools: the catalog tools
`list_datasets`, `get_dataset_summary` and `list_normality_models`; the evidence
tools `get_session`, `get_events`, `get_event` and `search_events`; the history
tools `get_entity_history` and `get_normality_context`; and the reference tools
`search_attack_patterns` and `get_technique`. Configure clients with command
`uv`, arguments `["run", "--directory", "/absolute/path/to/hestia", "hestia", "mcp"]`.
Do not send stdout logging into its protocol stream.

Every result carries `schema_version`, `request_id`, `available`, an explicit
`unavailable_reason`, truncation markers, a cursor and citable `source_refs`:

```json
{
  "schema_version": 1,
  "request_id": "b6d1…",
  "available": true,
  "unavailable_reason": null,
  "truncated": false,
  "next_cursor": "WyIwIl0=",
  "returned": 1,
  "items": [{"event_id": "…", "line_no": 44, "raw_line": "…", "unmatched": false}],
  "source_refs": [{"evidence_ref": "…", "source_sha256": "…", "line_no": 44}]
}
```

Build the reference index before using the reference tools, then smoke-test the
server through a real stdio client:

```sh
uv run hestia knowledge-build --split-manifest artifacts/preparation/<run>-splits.json
uv run python scripts/mcp_smoke.py
```

Tools retrieve facts; they do not produce threat verdicts, and they report
not-ready models and unavailable references explicitly. See [tool reference](docs/TOOLS.md).

## Investigate a case

One bounded agent owns one case, chooses which read-only tools to call and returns
an attributable report or an explicit abstention. Everything sent to a hosted
provider passes a redaction boundary first, and a report is published only once its
citations resolve against the local store.

```sh
uv run hestia investigate --session-id '<session id>' --fixture-provider
curl -s localhost:8000/api/agent/status
```

`--fixture-provider` runs a labelled deterministic local model that contacts
nothing, so the pipeline can be demonstrated without credentials. No hosted
provider is configured in this repository, so hosted operation is unverified. See
[agent reference](docs/AGENT.md) for the exact data sent to a provider, the
configuration variables, the budgets and what each failure state means.

## Review cases in the workspace

The workspace lists prepared sessions as cases. Cases are unscored until a
behavioural model is trained, and a missing score is never shown as evidence of
normal behaviour. From a case you can start a bounded investigation, watch its
tool calls, open any cited line, and record a review disposition. A run that did
not complete has no report. Fixture runs are always labelled as fixtures.
Dispositions are review records only: they are not training labels, and nothing in
Hestia performs containment or remediation. See [the demo](docs/DEMO.md) for the
walkthrough, the API and the current limitations.

## Verify

```sh
uv run pytest -q
uv run ruff check src tests scripts
uv run ruff format --check src tests scripts
cd frontend
npm run lint
npm test
npm run build
npm run test:e2e   # needs `npx playwright install chromium` or HESTIA_E2E_CHANNEL=chrome
```

See [architecture](docs/ARCHITECTURE.md) for the proposed system and current boundary.
For a detailed, presentation-ready walkthrough of the codebase, demo, measured
results and limitations, see the [presentation guide](docs/PRESENTATION-GUIDE.md).
To produce a standalone source snapshot:
`uv run python scripts/export_source.py /path/to/new/hestia-source`.
