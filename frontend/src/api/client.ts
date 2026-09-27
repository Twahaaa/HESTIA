import type {
  ApiErrorBody,
  CaseDetail,
  CasePage,
  Dataset,
  Disposition,
  DispositionValue,
  EvidenceResolution,
  Health,
  Model,
  Preparation,
  ReportView,
  RunDetail,
  RunStartResponse,
  WorkspaceStatus,
} from "./contracts";

/** The API answered, but refused or failed the request. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly body: ApiErrorBody | null;

  constructor(status: number, body: ApiErrorBody | null, fallback: string) {
    super(body?.message ?? fallback);
    this.name = "ApiError";
    this.status = status;
    this.code = body?.code ?? `http_${status}`;
    this.body = body;
  }
}

/** The API could not be reached at all. Distinct so the UI can say so. */
export class ApiUnreachable extends Error {
  constructor(cause: unknown) {
    super("The workspace API could not be reached.");
    this.name = "ApiUnreachable";
    this.cause = cause;
  }
}

/** True for failures that may pass on their own: no answer, or a gateway error. */
export function isTransient(error: unknown): boolean {
  if (error instanceof ApiUnreachable) return true;
  return (
    error instanceof ApiError &&
    [502, 503, 504].includes(error.status) &&
    error.body === null
  );
}

function errorBody(payload: unknown): ApiErrorBody | null {
  if (payload && typeof payload === "object" && "detail" in payload) {
    const detail = (payload as { detail: unknown }).detail;
    if (
      detail &&
      typeof detail === "object" &&
      "code" in detail &&
      "message" in detail
    ) {
      return detail as ApiErrorBody;
    }
    if (Array.isArray(detail)) {
      return { code: "invalid_request", message: "The request was not valid." };
    }
  }
  return null;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      headers: { Accept: "application/json", ...(init.headers ?? {}) },
    });
  } catch (cause) {
    if (init.signal?.aborted) throw cause;
    throw new ApiUnreachable(cause);
  }
  let payload: unknown = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  if (!response.ok) {
    throw new ApiError(
      response.status,
      errorBody(payload),
      `Service returned ${response.status}`,
    );
  }
  return payload as T;
}

function post<T>(
  path: string,
  body: unknown,
  init: RequestInit = {},
): Promise<T> {
  return request<T>(path, {
    ...init,
    method: "POST",
    headers: { "Content-Type": "application/json", ...(init.headers ?? {}) },
    body: JSON.stringify(body),
  });
}

const segment = encodeURIComponent;

export const api = {
  health: (signal?: AbortSignal) => request<Health>("/api/health", { signal }),
  workspace: (signal?: AbortSignal) =>
    request<WorkspaceStatus>("/api/workspace", { signal }),
  datasets: (signal?: AbortSignal) =>
    request<{ datasets: Dataset[] }>("/api/datasets", { signal }),
  models: (signal?: AbortSignal) =>
    request<{ models: Model[] }>("/api/normality/models", { signal }),
  preparation: (signal?: AbortSignal) =>
    request<Preparation>("/api/preparation", { signal }),
  cases: (
    query: { dataset?: string | null; limit: number; offset: number },
    signal?: AbortSignal,
  ) => {
    const params = new URLSearchParams({
      limit: String(query.limit),
      offset: String(query.offset),
    });
    if (query.dataset) params.set("dataset", query.dataset);
    return request<CasePage>(`/api/cases?${params}`, { signal });
  },
  caseDetail: (caseId: string, signal?: AbortSignal) =>
    request<CaseDetail>(`/api/cases/${segment(caseId)}`, { signal }),
  startRun: (
    caseId: string,
    options: {
      mode: "fixture" | "configured";
      confirmHosted?: boolean;
      idempotencyKey: string;
    },
  ) =>
    post<RunStartResponse>(
      `/api/cases/${segment(caseId)}/runs`,
      { mode: options.mode, confirm_hosted: options.confirmHosted ?? false },
      { headers: { "Idempotency-Key": options.idempotencyKey } },
    ),
  run: (runId: string, signal?: AbortSignal) =>
    request<RunDetail>(`/api/runs/${segment(runId)}`, { signal }),
  cancelRun: (runId: string) =>
    post<{ run_id: string; cancel_requested: boolean; note: string }>(
      `/api/runs/${segment(runId)}/cancel`,
      {},
    ),
  report: (runId: string, signal?: AbortSignal) =>
    request<ReportView>(`/api/runs/${segment(runId)}/report`, { signal }),
  evidence: (runId: string, handle: string, signal?: AbortSignal) =>
    request<EvidenceResolution>(
      `/api/runs/${segment(runId)}/evidence/${segment(handle)}`,
      {
        signal,
      },
    ),
  recordDisposition: (
    caseId: string,
    body: {
      disposition: DispositionValue;
      note: string;
      actor?: string;
      run_id?: string;
    },
  ) => post<Disposition>(`/api/cases/${segment(caseId)}/dispositions`, body),
  resetDemo: () =>
    post<{ removed: Record<string, number>; evidence_kept: boolean }>(
      "/api/workspace/reset",
      {
        confirm: "reset demo workspace",
      },
    ),
};

export function newIdempotencyKey(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto)
    return crypto.randomUUID();
  return `k${Date.now().toString(36)}${Math.random().toString(36).slice(2, 12)}`;
}

export function describeError(error: unknown): string {
  if (error instanceof ApiUnreachable) return error.message;
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error) return error.message;
  return "Something went wrong.";
}
