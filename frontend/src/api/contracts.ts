// Mirrors src/hestia/api/contracts.py. Keep both sides in step.

export type RunState =
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";
export type Outcome =
  | "in_progress"
  | "report_published"
  | "cancelled"
  | "interrupted"
  | "grounding_failed"
  | "budget_exhausted"
  | "provider_unavailable"
  | "failed";
export type DispositionValue =
  | "benign"
  | "suspicious"
  | "inconclusive"
  | "report_disputed";
export type Verdict =
  | "benign"
  | "suspicious"
  | "malicious"
  | "insufficient_evidence";
export type Coverage = "known" | "potentially_novel" | "uncertain";

export type ApiErrorBody = {
  code: string;
  message: string;
  run_id?: string | null;
  case_id?: string | null;
  state?: string | null;
};

export type Priority = {
  score: number | null;
  scored: boolean;
  reason: string | null;
};

export type ScoringStatus = {
  available: boolean;
  ready_models: number;
  total_models: number;
  reason: string | null;
  ordering: string;
  note: string;
};

export type CaseSummary = {
  case_id: string;
  dataset_id: string;
  source: string;
  host: string | null;
  user: string | null;
  src_ip: string | null;
  start: string;
  end: string;
  event_count: number;
  failure_count: number;
  priority: Priority;
  latest_run: {
    run_id: string;
    state: RunState;
    fixture: boolean;
    started_at: string;
  } | null;
  disposition: { disposition: DispositionValue; recorded_at: string } | null;
};

export type CasePage = {
  items: CaseSummary[];
  total: number;
  limit: number;
  offset: number;
  dataset_id: string | null;
  datasets: string[];
  scoring: ScoringStatus;
};

export type EvidenceLine = {
  event_id: string;
  ordinal?: number | null;
  dataset_id: string;
  source: string;
  line_no: number;
  timestamp: string;
  raw_timestamp?: string | null;
  line: string;
  event_type?: string | null;
  success?: boolean | null;
  unmatched: boolean;
  unmatched_reason?: string | null;
};

export type Usage = {
  requests: number;
  tool_calls: number;
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
  estimated_cost_usd: number | null;
  wall_seconds: number;
};

export type Execution = { kind: "fixture" | "hosted"; label: string };

export type RunSummary = {
  run_id: string;
  state: RunState;
  outcome: Outcome;
  provider: string;
  model: string;
  fixture: boolean;
  execution: Execution;
  started_at: string;
  finished_at: string | null;
  incomplete_reason: string | null;
  verdict: string | null;
  usage: Usage;
};

export type Disposition = {
  disposition_id: string;
  case_id: string;
  run_id: string | null;
  disposition: DispositionValue;
  note: string;
  actor: string;
  recorded_at: string;
};

export type CaseDetail = Omit<CaseSummary, "latest_run" | "disposition"> & {
  parsed_attributes: {
    has_escalation: boolean;
    has_persistence: boolean;
    primary_method: string | null;
    note: string;
  };
  scoring: ScoringStatus;
  events: EvidenceLine[];
  events_shown: number;
  events_truncated: boolean;
  runs: RunSummary[];
  dispositions: Disposition[];
};

export type TraceStep = {
  step: number;
  kind: "tool_call" | "hypothesis";
  tool?: string | null;
  request_summary?: string | null;
  available?: boolean | null;
  unavailable_reason?: string | null;
  error?: string | null;
  returned?: number | null;
  evidence_count: number;
  evidence_handles: string[];
  duration_ms?: number | null;
  started_at?: string | null;
  truncated?: boolean | null;
  claim?: string | null;
  support: string[];
  contradictions: string[];
  retained?: boolean | null;
};

export type GroundingIssue = {
  kind: string;
  detail: string;
  handle?: string | null;
};

export type Grounding = {
  grounded: boolean;
  checked_handles: number;
  issues: GroundingIssue[];
  repair_attempted: boolean;
  note: string;
};

export type RunDetail = RunSummary & {
  case_id: string;
  interrupted: boolean;
  cancel_requested: boolean;
  retry_allowed: boolean;
  report_available: boolean;
  grounding: Grounding | null;
  steps: TraceStep[];
};

export type RunStartResponse = { created: boolean; run: RunDetail };

export type Citation = {
  handle: string;
  kind: "event" | "session" | "reference" | "unknown";
  resolvable: boolean;
  reason?: string | null;
};

export type ReportView = {
  run_id: string;
  case_id: string;
  schema_version: number;
  execution: Execution;
  provider: string;
  model: string;
  verdict: Verdict;
  verdict_note: string;
  severity: string;
  confidence: number;
  summary: string;
  findings: {
    statement: string;
    excerpt: string | null;
    citations: Citation[];
  }[];
  known_or_novel: Coverage;
  known_or_novel_note: string;
  technique_ids: string[];
  recommended_actions: string[];
  recommended_actions_note: string;
  limitations: string[];
  grounding: Grounding;
  pseudonyms: { token: string; value: string | null }[];
  citations_resolvable: boolean;
  citation_note: string | null;
};

export type EvidenceResolution = {
  handle: string;
  kind: "event" | "session" | "reference";
  lines: EvidenceLine[];
  lines_truncated: boolean;
  session: {
    dataset_id: string;
    source: string;
    start: string | null;
    end: string | null;
    event_count: number;
  } | null;
  reference: {
    title: string;
    collection: string;
    technique_ids: string[];
    snippet: string;
    snippet_truncated: boolean;
    source_uri: string;
    version: string;
    attribution: string;
    note: string;
  } | null;
};

export type ActiveRun = {
  run_id: string;
  case_id: string;
  state: RunState;
  started_at: string;
  owned_by_this_process: boolean;
  cancel_requested: boolean;
};

export type ProviderView = {
  configured: boolean;
  provider: string | null;
  model: string | null;
  fixture: boolean;
  reason: string | null;
};

export type WorkspaceStatus = {
  store: {
    available: boolean;
    schema_version: number | null;
    reason: string | null;
  };
  provider: ProviderView;
  fixture_available: boolean;
  hosted_verified: boolean;
  hosted_note: string;
  scoring: ScoringStatus;
  active_run: ActiveRun | null;
  recovered_interrupted_runs: number;
  demo_workspace: boolean;
  fixture_pace_seconds: number;
  budgets: Record<string, number>;
  notes: string[];
};

export type Health = { status: string; agent_status: string };

export type Dataset = {
  dataset_id: string;
  status: string;
  file_count: number;
  bytes?: number;
};

export type Model = {
  model_id: string;
  primitive: string;
  ready: boolean;
  status: string;
  parent_model_id: string | null;
  warmup_observations: number;
  readiness_reason?: string | null;
};

export type Preparation = {
  status: "not_created" | "available" | "unavailable";
  counts: {
    sources: number;
    events: number;
    parse_failures: number;
    sessions: number;
    unmatched_events: number;
  };
  unmatched: {
    count: number;
    matched_count: number;
    percent_of_events: number | null;
  };
  readiness: {
    ready: boolean;
    ready_models: number;
    total_models: number;
    reasons: string[];
  };
};
