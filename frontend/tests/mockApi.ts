import { vi } from "vitest";

type Handler = (
  init?: RequestInit,
) => { status?: number; body: unknown } | "network";

/** Route fetch calls by path prefix. The longest matching prefix wins. */
export function mockApi(routes: Record<string, Handler | unknown>) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    const path = url.split("?")[0];
    const key = Object.keys(routes)
      .filter(
        (prefix) =>
          path === prefix ||
          path.startsWith(`${prefix}/`) ||
          path.startsWith(prefix),
      )
      .sort((a, b) => b.length - a.length)[0];
    if (key === undefined) throw new TypeError(`unrouted ${url}`);
    const route = routes[key];
    const result =
      typeof route === "function"
        ? (route as Handler)(init)
        : { status: 200, body: route };
    if (result === "network") throw new TypeError("Failed to fetch");
    const status = result.status ?? 200;
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => result.body,
    } as Response;
  });
  vi.stubGlobal("fetch", fetchMock);
  return { fetchMock, calls };
}

export const health = { status: "ok", agent_status: "unconfigured" };

export const scoring = {
  available: false,
  ready_models: 0,
  total_models: 1,
  reason:
    "no behavioural model is ready: no sessions have explicit normal training eligibility",
  ordering: "session start time",
  note: "A missing score means no ready model scored the case. It is not evidence that the activity is normal.",
};

export const workspace = {
  store: { available: true, schema_version: 3, reason: null },
  provider: {
    configured: false,
    provider: null,
    model: null,
    fixture: false,
    reason: "no agent provider is configured; set HESTIA_AGENT_PROVIDER",
  },
  fixture_available: true,
  hosted_verified: false,
  hosted_note:
    "Hosted-provider runs have not been acceptance-tested in this build.",
  scoring,
  active_run: null,
  recovered_interrupted_runs: 0,
  demo_workspace: true,
  fixture_pace_seconds: 0,
  budgets: { max_tool_calls: 16 },
  notes: [],
};

export const datasets = {
  datasets: [{ dataset_id: "ait-auth", status: "not_imported", file_count: 0 }],
};

export const models = {
  models: [
    {
      model_id: "login_hour_rarity",
      primitive: "counts",
      ready: false,
      status: "not_ready",
      parent_model_id: null,
      warmup_observations: 250,
    },
  ],
};

export const preparation = {
  status: "available",
  counts: {
    sources: 3,
    events: 1200,
    parse_failures: 17,
    sessions: 44,
    unmatched_events: 83,
  },
  unmatched: { count: 83, matched_count: 1117, percent_of_events: 6.9 },
  readiness: {
    ready: false,
    ready_models: 0,
    total_models: 1,
    reasons: ["insufficient training observations"],
  },
};

export const CASE_ID = "case-0123456789abcdef0123";
export const RUN_ID = "0123456789abcdef0123456789abcdef";

export const caseSummary = {
  case_id: CASE_ID,
  dataset_id: "synthetic-demo",
  source: "synthetic-demo/auth.log",
  host: "demo-bastion",
  user: "admin",
  src_ip: "198.51.100.23",
  start: "2026-03-03T09:12:11Z",
  end: "2026-03-03T09:12:18Z",
  event_count: 3,
  failure_count: 3,
  priority: { score: null, scored: false, reason: scoring.reason },
  latest_run: null,
  disposition: null,
};

export const casePage = {
  items: [caseSummary],
  total: 1,
  limit: 20,
  offset: 0,
  dataset_id: null,
  datasets: ["synthetic-demo"],
  scoring,
};

const usage = {
  requests: 6,
  tool_calls: 4,
  input_tokens: 1000,
  output_tokens: 200,
  total_tokens: 1200,
  estimated_cost_usd: null,
  wall_seconds: 0.6,
};

export function runSummary(state: string, outcome: string, extra: object = {}) {
  return {
    run_id: RUN_ID,
    state,
    outcome,
    provider: "fixture",
    model: "fixture-analyst",
    fixture: true,
    execution: {
      kind: "fixture",
      label: "Fixture run: deterministic scripted analyst, not a live model",
    },
    started_at: "2026-09-25T10:00:00Z",
    finished_at: state === "running" ? null : "2026-09-25T10:00:01Z",
    incomplete_reason: null,
    verdict: state === "completed" ? "insufficient_evidence" : null,
    usage,
    ...extra,
  };
}

export const steps = [
  {
    step: 1,
    kind: "tool_call",
    tool: "get_session",
    request_summary: "the case session",
    available: true,
    returned: 0,
    evidence_count: 1,
    evidence_handles: ["se-1111111111"],
    duration_ms: 12,
    support: [],
    contradictions: [],
  },
  {
    step: 2,
    kind: "tool_call",
    tool: "get_events",
    request_summary: "limit=10",
    available: true,
    returned: 3,
    evidence_count: 1,
    evidence_handles: ["ev-2222222222"],
    duration_ms: 9,
    support: [],
    contradictions: [],
  },
  {
    step: 3,
    kind: "tool_call",
    tool: "get_normality_context",
    request_summary: "the case session",
    available: true,
    returned: 0,
    evidence_count: 0,
    evidence_handles: [],
    duration_ms: 4,
    support: [],
    contradictions: [],
  },
  {
    step: 4,
    kind: "hypothesis",
    claim: "The outcome cannot be characterised.",
    support: ["no behavioural model is ready"],
    contradictions: [],
    retained: true,
    evidence_count: 0,
    evidence_handles: [],
  },
];

export function runDetail(state: string, outcome: string, extra: object = {}) {
  return {
    ...runSummary(state, outcome),
    case_id: CASE_ID,
    interrupted: outcome === "interrupted",
    cancel_requested: false,
    retry_allowed: state === "failed" || state === "cancelled",
    report_available: state === "completed",
    grounding: null,
    steps,
    ...extra,
  };
}

export function caseDetail(runs: object[] = []) {
  return {
    ...caseSummary,
    parsed_attributes: {
      has_escalation: false,
      has_persistence: false,
      primary_method: null,
      note: "Parsed from the log lines by the session builder. These are structural attributes, not a threat assessment.",
    },
    scoring,
    events: [
      {
        event_id: "e1",
        ordinal: 0,
        dataset_id: "synthetic-demo",
        source: "synthetic-demo/auth.log",
        line_no: 3,
        timestamp: "2026-03-03T09:12:11Z",
        line: "Mar  3 09:12:11 demo-bastion sshd[2140]: Failed password for invalid user admin from 198.51.100.23 port 41022 ssh2",
        event_type: "auth_failure",
        success: false,
        unmatched: false,
      },
    ],
    events_shown: 1,
    events_truncated: false,
    runs,
    dispositions: [],
  };
}

export const report = {
  run_id: RUN_ID,
  case_id: CASE_ID,
  schema_version: 1,
  execution: {
    kind: "fixture",
    label: "Fixture run: deterministic scripted analyst, not a live model",
  },
  provider: "fixture",
  model: "fixture-analyst",
  verdict: "insufficient_evidence",
  verdict_note:
    "The agent abstained: the retrieved evidence did not support a conclusion.",
  severity: "none",
  confidence: 0.2,
  summary: "Scripted fixture analyst abstained.",
  findings: [
    {
      statement: "The first retrieved event has type 'auth_failure'.",
      excerpt: null,
      citations: [
        {
          handle: "ev-2222222222",
          kind: "event",
          resolvable: true,
          reason: null,
        },
      ],
    },
  ],
  known_or_novel: "uncertain",
  known_or_novel_note:
    "Reference coverage could not be established from the retrieved material.",
  technique_ids: [],
  recommended_actions: ["Have an analyst review the cited evidence directly."],
  recommended_actions_note:
    "Recommendations are for analyst review only. Hestia performs no containment or remediation.",
  limitations: [
    "This run used the deterministic fixture model, not a hosted provider.",
  ],
  grounding: {
    grounded: true,
    checked_handles: 2,
    issues: [],
    repair_attempted: false,
    note: "Grounding checks that citations exist. It does not judge whether a claim is true.",
  },
  pseudonyms: [{ token: "host-1", value: "demo-bastion" }],
  citations_resolvable: true,
  citation_note: null,
};

export const evidence = {
  handle: "ev-2222222222",
  kind: "event",
  lines: [caseDetail().events[0]],
  lines_truncated: false,
  session: null,
  reference: null,
};

export function baseRoutes(extra: Record<string, unknown> = {}) {
  return {
    "/api/health": health,
    "/api/workspace": workspace,
    "/api/datasets": datasets,
    "/api/normality/models": models,
    "/api/preparation": preparation,
    "/api/cases": casePage,
    ...extra,
  };
}
