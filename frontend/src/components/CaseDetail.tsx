import { useEffect, useRef, useState } from "react";
import {
  ApiError,
  api,
  describeError,
  isTransient,
  newIdempotencyKey,
} from "../api/client";
import type {
  CaseDetail as Detail,
  RunDetail,
  WorkspaceStatus,
} from "../api/contracts";
import {
  formatTime,
  formatWindow,
  OUTCOME_LABELS,
  plural,
  STATE_LABELS,
} from "../format";
import { useRun } from "../hooks/useRun";
import { DispositionForm } from "./DispositionForm";
import { EvidenceDrawer } from "./EvidenceDrawer";
import { InvestigationTrace } from "./InvestigationTrace";
import { ReportView } from "./ReportView";

type Props = {
  caseId: string;
  workspace: WorkspaceStatus | null;
  selectedRunId: string | null;
  onSelectRun: (runId: string | null) => void;
  onOpenCase: (caseId: string) => void;
  onBack: () => void;
  onChanged: () => void;
};

type Mode = "fixture" | "configured";

function usageLine(run: {
  usage: RunDetail["usage"];
  fixture: boolean;
}): string {
  const usage = run.usage;
  const cost = run.fixture
    ? "no provider cost (fixture)"
    : usage.estimated_cost_usd === null
      ? "cost not reported"
      : `estimated $${usage.estimated_cost_usd.toFixed(4)} (adapter estimate, not a bill)`;
  return `${plural(usage.requests, "model request")} · ${plural(usage.tool_calls, "tool call")} · ${usage.total_tokens.toLocaleString()} tokens · ${usage.wall_seconds.toFixed(1)} s · ${cost}`;
}

function RunOutcome({
  run,
  onRetry,
  retryDisabled,
}: {
  run: RunDetail;
  onRetry: () => void;
  retryDisabled: boolean;
}) {
  if (run.state === "completed") return null;
  if (run.state === "pending" || run.state === "running") {
    return (
      <p role="status" className="run-progress">
        {run.cancel_requested
          ? "Cancel requested. The run stops at its next tool boundary and will end without a report."
          : `${STATE_LABELS[run.state]}. There is no report until the run completes and its citations resolve.`}
      </p>
    );
  }
  return (
    <div className="run-ended" role="status">
      <h4>{OUTCOME_LABELS[run.outcome]}</h4>
      <p>{run.incomplete_reason}</p>
      <p className="muted">
        This run did not produce a report, so nothing here is a verdict.
      </p>
      {run.grounding && !run.grounding.grounded ? (
        <div>
          <p>
            The agent's report was refused after{" "}
            {run.grounding.repair_attempted
              ? "one repair attempt"
              : "validation"}
            :
          </p>
          <ul>
            {run.grounding.issues.map((issue) => (
              <li key={`${issue.kind}-${issue.handle}`}>
                {issue.kind.replaceAll("_", " ")}
                {issue.handle ? ` (${issue.handle})` : ""}: {issue.detail}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {run.retry_allowed ? (
        <button type="button" onClick={onRetry} disabled={retryDisabled}>
          Retry as a new fixture run
        </button>
      ) : null}
    </div>
  );
}

export function CaseDetail({
  caseId,
  workspace,
  selectedRunId,
  onSelectRun,
  onOpenCase,
  onBack,
  onChanged,
}: Props) {
  const [detail, setDetail] = useState<Detail | null>(null);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<{
    message: string;
    activeCase?: string;
  } | null>(null);
  const [confirmHosted, setConfirmHosted] = useState(false);
  const [evidenceHandle, setEvidenceHandle] = useState<string | null>(null);
  const pendingKey = useRef<{ mode: Mode; key: string } | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);

  // biome-ignore lint/correctness/useExhaustiveDependencies: attempt triggers a reload.
  useEffect(() => {
    const controller = new AbortController();
    setError("");
    api
      .caseDetail(caseId, controller.signal)
      .then((next) => {
        setDetail(next);
      })
      .catch((caught: unknown) => {
        if (!controller.signal.aborted) setError(describeError(caught));
      });
    return () => controller.abort();
  }, [caseId, attempt]);

  // Move focus to the case once it has loaded, so keyboard and screen-reader users
  // land on what they selected (the queue is hidden on narrow screens).
  const focused = useRef(false);
  useEffect(() => {
    if (detail && !focused.current) {
      focused.current = true;
      heading.current?.focus();
    }
  }, [detail]);

  const runId = selectedRunId ?? detail?.runs[0]?.run_id ?? null;
  const poll = useRun(runId);
  const run = poll.run && poll.run.run_id === runId ? poll.run : null;
  const lastState = useRef<string | null>(null);

  useEffect(() => {
    if (!run) return;
    const previous = lastState.current;
    lastState.current = `${run.run_id}:${run.state}`;
    const sameRun = previous?.startsWith(`${run.run_id}:`);
    if (sameRun && previous !== lastState.current && poll.status === "done") {
      setAttempt((value) => value + 1);
      onChanged();
    }
  }, [run, poll.status, onChanged]);

  const provider = workspace?.provider;
  const hostedAvailable = Boolean(provider?.configured && !provider.fixture);
  const active = workspace?.active_run ?? null;
  const runActive =
    run !== null && (run.state === "pending" || run.state === "running");
  const blocked = runActive || (active !== null && active.run_id !== runId);

  async function start(mode: Mode) {
    setStarting(true);
    setStartError(null);
    // Reuse the key while retrying after a lost response, so a request that did
    // reach the server is not started twice.
    if (!pendingKey.current || pendingKey.current.mode !== mode) {
      pendingKey.current = { mode, key: newIdempotencyKey() };
    }
    try {
      const response = await api.startRun(caseId, {
        mode,
        confirmHosted: mode === "configured",
        idempotencyKey: pendingKey.current.key,
      });
      pendingKey.current = null;
      setConfirmHosted(false);
      onSelectRun(response.run.run_id);
      setAttempt((value) => value + 1);
      onChanged();
    } catch (caught) {
      if (!isTransient(caught)) pendingKey.current = null;
      if (caught instanceof ApiError && caught.code === "run_active") {
        setStartError({
          message:
            "Another investigation is still active. One case runs at a time.",
          activeCase: caught.body?.case_id ?? undefined,
        });
        onChanged();
      } else {
        setStartError({ message: describeError(caught) });
      }
    } finally {
      setStarting(false);
    }
  }

  async function cancel() {
    if (!run) return;
    try {
      await api.cancelRun(run.run_id);
      poll.retry();
    } catch (caught) {
      setStartError({ message: describeError(caught) });
    }
  }

  if (error) {
    return (
      <section className="detail panel" aria-labelledby="case-title">
        <button type="button" className="secondary back" onClick={onBack}>
          Back to cases
        </button>
        <h2 id="case-title">Case unavailable</h2>
        <p role="alert" className="inline-error">
          {error}
        </p>
        <button type="button" onClick={() => setAttempt(attempt + 1)}>
          Retry
        </button>
      </section>
    );
  }
  if (!detail || detail.case_id !== caseId) {
    return (
      <section className="detail panel" aria-busy="true">
        <p role="status">Loading case…</p>
      </section>
    );
  }

  const latestFinished = detail.runs.find(
    (item) => item.state !== "running" && item.state !== "pending",
  );

  return (
    <section className="detail" aria-labelledby="case-title">
      <div className="panel">
        <button type="button" className="secondary back" onClick={onBack}>
          Back to cases
        </button>
        <p className="eyebrow">CASE · {detail.dataset_id.toUpperCase()}</p>
        <h2 id="case-title" ref={heading} tabIndex={-1}>
          {detail.user ?? "unknown user"}@{detail.host ?? "unknown host"}
        </h2>
        <p className="muted">{formatWindow(detail.start, detail.end)}</p>
        <dl className="facts">
          <div>
            <dt>Source IP</dt>
            <dd>{detail.src_ip ?? "not recorded"}</dd>
          </div>
          <div>
            <dt>Events</dt>
            <dd>{detail.event_count}</dd>
          </div>
          <div>
            <dt>Recorded failures</dt>
            <dd>{detail.failure_count}</dd>
          </div>
          <div>
            <dt>Priority</dt>
            <dd>
              {detail.priority.scored
                ? detail.priority.score?.toFixed(2)
                : "Unscored"}
            </dd>
          </div>
        </dl>
        {!detail.priority.scored ? (
          <p className="muted">
            {detail.priority.reason}. This is not evidence of normal behaviour.
          </p>
        ) : null}
        <p className="muted">Source: {detail.source}</p>
      </div>

      <div className="panel investigate">
        <h3>Investigation</h3>
        <p className="muted">
          The fixture analyst is a deterministic script. It calls the real
          evidence tools, contacts no provider and is labelled as a fixture
          everywhere it appears.
        </p>
        <div className="actions">
          <button
            type="button"
            onClick={() => start("fixture")}
            disabled={starting || blocked}
          >
            {starting ? "Starting…" : "Run fixture investigation"}
          </button>
          {hostedAvailable ? (
            <button
              type="button"
              className="secondary"
              onClick={() => setConfirmHosted(true)}
              disabled={starting || blocked}
            >
              Run hosted investigation…
            </button>
          ) : null}
          {runActive && run ? (
            <button
              type="button"
              className="danger"
              onClick={cancel}
              disabled={run.cancel_requested}
            >
              {run.cancel_requested ? "Cancelling…" : "Cancel run"}
            </button>
          ) : null}
        </div>
        {confirmHosted && provider ? (
          <fieldset className="confirm">
            <legend>Send redacted evidence to a hosted provider?</legend>
            <p>
              A hosted run sends redacted evidence to {provider.provider} (
              {provider.model}) and may incur cost. Hosted runs have not been
              acceptance-tested in this build.
            </p>
            <button
              type="button"
              onClick={() => start("configured")}
              disabled={starting}
            >
              Send and run
            </button>
            <button
              type="button"
              className="secondary"
              onClick={() => setConfirmHosted(false)}
            >
              Cancel
            </button>
          </fieldset>
        ) : null}
        {!hostedAvailable && provider && !provider.configured ? (
          <p className="muted">
            Hosted runs are unavailable: {provider.reason}
          </p>
        ) : null}
        {blocked && !runActive && active ? (
          <p className="warning-text">
            Another investigation is active. One case runs at a time.{" "}
            {active.case_id !== caseId ? (
              <button
                type="button"
                className="link-button"
                onClick={() => onOpenCase(active.case_id)}
              >
                Open that case
              </button>
            ) : null}
          </p>
        ) : null}
        {startError ? (
          <div role="alert" className="inline-error">
            <p>{startError.message}</p>
            {startError.activeCase && startError.activeCase !== caseId ? (
              <button
                type="button"
                className="link-button"
                onClick={() => onOpenCase(startError.activeCase as string)}
              >
                Open the active case
              </button>
            ) : null}
          </div>
        ) : null}
        {latestFinished ? (
          <p className="muted usage">
            Last finished run used {usageLine(latestFinished)}.
          </p>
        ) : null}

        {detail.runs.length > 0 ? (
          <div className="run-history">
            <h4>Runs for this case</h4>
            <ul>
              {detail.runs.map((item) => (
                <li key={item.run_id}>
                  <button
                    type="button"
                    className="run-item"
                    aria-current={item.run_id === runId ? "true" : undefined}
                    onClick={() => onSelectRun(item.run_id)}
                  >
                    <span className={`chip state-${item.state}`}>
                      {STATE_LABELS[item.state]}
                    </span>
                    <span>{OUTCOME_LABELS[item.outcome]}</span>
                    <span className="muted">
                      {formatTime(item.started_at)} ·{" "}
                      {item.fixture ? "fixture" : item.provider}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        ) : (
          <p className="empty">Not investigated yet.</p>
        )}
      </div>

      {runId ? (
        <div className="panel run-view" aria-live="off">
          {poll.status === "lost" ||
          poll.status === "stopped" ||
          poll.status === "error" ? (
            <div role="alert" className="inline-error">
              <p>{poll.error}</p>
              <button type="button" onClick={poll.retry}>
                {poll.status === "error" ? "Try again" : "Resume"}
              </button>
            </div>
          ) : null}
          {poll.status === "reconnecting" ? (
            <p role="status" className="warning-text">
              Connection interrupted; retrying…
            </p>
          ) : null}
          {!run ? (
            poll.status === "loading" ? (
              <p role="status">Loading run…</p>
            ) : null
          ) : (
            <>
              <div className="report-head">
                <p className="eyebrow">RUN {run.run_id.slice(0, 8)}</p>
                <span className={`badge ${run.execution.kind}`}>
                  {run.execution.label}
                </span>
              </div>
              <p className="muted">
                {STATE_LABELS[run.state]} · started {formatTime(run.started_at)}
                {run.finished_at
                  ? ` · finished ${formatTime(run.finished_at)}`
                  : ""}{" "}
                · {usageLine(run)}
              </p>
              <RunOutcome
                run={run}
                onRetry={() => start("fixture")}
                retryDisabled={
                  starting || (active !== null && active.run_id !== run.run_id)
                }
              />
              <InvestigationTrace
                run={run}
                onOpenEvidence={setEvidenceHandle}
              />
              {run.report_available ? (
                <ReportView
                  runId={run.run_id}
                  onOpenEvidence={setEvidenceHandle}
                />
              ) : null}
            </>
          )}
        </div>
      ) : null}

      <div className="panel">
        <div className="section-title">
          <h3>Session evidence</h3>
          <span>{detail.events_shown}</span>
        </div>
        <p className="muted">
          Canonical stored lines with their source and line number.
          {detail.events_truncated ? " Only the first lines are shown." : ""}
        </p>
        <ol className="log-lines">
          {detail.events.map((line) => (
            <li key={line.event_id}>
              <p className="line-source">
                {line.source}:{line.line_no} · {formatTime(line.timestamp)}
                {line.event_type ? ` · ${line.event_type}` : ""}
              </p>
              <pre>{line.line}</pre>
            </li>
          ))}
        </ol>
        <p className="muted">{detail.parsed_attributes.note}</p>
      </div>

      <DispositionForm
        key={`${detail.case_id}-${detail.runs.length}`}
        caseId={detail.case_id}
        runs={detail.runs}
        history={detail.dispositions}
        onSaved={() => {
          setAttempt((value) => value + 1);
          onChanged();
        }}
      />

      {evidenceHandle && run ? (
        <EvidenceDrawer
          runId={run.run_id}
          handle={evidenceHandle}
          onClose={() => setEvidenceHandle(null)}
        />
      ) : null}
    </section>
  );
}
