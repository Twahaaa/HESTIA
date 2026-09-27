import type { RunDetail, TraceStep } from "../api/contracts";

type Props = {
  run: RunDetail;
  onOpenEvidence: (handle: string) => void;
};

function ToolStep({
  step,
  onOpenEvidence,
}: {
  step: TraceStep;
  onOpenEvidence: (handle: string) => void;
}) {
  const failed = step.available === false || Boolean(step.error);
  return (
    <li className={`trace-step${failed ? " unavailable" : ""}`}>
      <div className="trace-head">
        <span className="step-no">{step.step}</span>
        <code>{step.tool}</code>
        <span className="muted">{step.duration_ms ?? 0} ms</span>
      </div>
      <p className="trace-request">Asked for: {step.request_summary}</p>
      <p className="trace-result">
        {step.error
          ? `Tool call failed (${step.error}).`
          : step.available === false
            ? `Unavailable: ${step.unavailable_reason ?? "no reason recorded"}`
            : `${step.returned ?? 0} returned · ${step.evidence_count} evidence reference(s)${step.truncated ? " · truncated" : ""}`}
      </p>
      {step.evidence_handles.length > 0 ? (
        <div className="handles">
          {step.evidence_handles.slice(0, 6).map((handle) => (
            <button
              key={handle}
              type="button"
              className="link-button"
              onClick={() => onOpenEvidence(handle)}
            >
              Open {handle}
            </button>
          ))}
          {step.evidence_handles.length > 6 ? (
            <span className="muted">
              +{step.evidence_handles.length - 6} more
            </span>
          ) : null}
        </div>
      ) : null}
    </li>
  );
}

export function InvestigationTrace({ run, onOpenEvidence }: Props) {
  const toolCalls = run.steps.filter(
    (step) => step.kind === "tool_call",
  ).length;
  const latest = run.steps.at(-1);
  return (
    <section className="trace" aria-labelledby={`trace-${run.run_id}`}>
      <div className="section-title">
        <h3 id={`trace-${run.run_id}`}>Investigation trace</h3>
        <span>{toolCalls} tool call(s)</span>
      </div>
      <p className="muted">
        Tool calls and the hypotheses the analyst explicitly recorded. No
        private model reasoning is stored or shown.
      </p>
      <p className="visually-hidden" aria-live="polite">
        {run.state === "running" && latest
          ? `Step ${latest.step}: ${latest.kind === "tool_call" ? latest.tool : "hypothesis recorded"}`
          : ""}
      </p>
      {run.steps.length === 0 ? (
        <p className="empty">
          {run.state === "pending" || run.state === "running"
            ? "Waiting for the first tool call…"
            : "No steps were recorded before the run ended."}
        </p>
      ) : (
        <ol className="trace-list">
          {run.steps.map((step) =>
            step.kind === "tool_call" ? (
              <ToolStep
                key={`t${step.step}`}
                step={step}
                onOpenEvidence={onOpenEvidence}
              />
            ) : (
              <li key={`h${step.step}`} className="trace-step hypothesis">
                <div className="trace-head">
                  <span className="step-no">{step.step}</span>
                  <strong>Recorded hypothesis</strong>
                  <span className="muted">
                    {step.retained === false ? "dropped" : "held"}
                  </span>
                </div>
                <p>{step.claim}</p>
                {step.support.length > 0 ? (
                  <p className="muted">Support: {step.support.join("; ")}</p>
                ) : null}
                {step.contradictions.length > 0 ? (
                  <p className="muted">
                    Contradicted by: {step.contradictions.join("; ")}
                  </p>
                ) : null}
              </li>
            ),
          )}
        </ol>
      )}
    </section>
  );
}
