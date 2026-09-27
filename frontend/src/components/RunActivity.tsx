import { useEffect, useState } from "react";
import type { RunDetail } from "../api/contracts";
import type { RunPollStatus } from "../hooks/useRun";

type Props = { run: RunDetail; connection: RunPollStatus };

function elapsed(started: string, now: number): string {
  const seconds = Math.max(0, Math.floor((now - Date.parse(started)) / 1000));
  const minutes = Math.floor(seconds / 60);
  return `${minutes}:${String(seconds % 60).padStart(2, "0")}`;
}

export function RunActivity({ run, connection }: Props) {
  const [now, setNow] = useState(Date.now());
  const active = run.state === "running" || run.state === "pending";
  useEffect(() => {
    if (!active) return;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [active]);

  const latest = run.steps.at(-1);
  const headline = !active
    ? "Investigation ended"
    : run.cancel_requested
      ? "Stopping the investigation"
      : connection === "lost" ||
          connection === "error" ||
          connection === "stopped"
        ? "Connection to run lost"
        : latest
          ? "Evidence gathering in progress"
          : "Waiting for the first recorded step";
  const description = !active
    ? "The recorded trace and outcome are shown below."
    : run.cancel_requested
      ? "The run stops after its current model response or at the next tool boundary."
      : connection === "lost" ||
          connection === "error" ||
          connection === "stopped"
        ? "The run may still be active. Resume polling to see its latest state."
        : latest
          ? `Last recorded: ${latest.kind === "tool_call" ? latest.tool : "explicit hypothesis"}. Waiting for the next recorded step or final report.`
          : "A provider response or tool call has not been recorded yet. No conclusion is available.";

  return (
    <section
      className={`run-activity${active ? " is-active" : ""}`}
      aria-label="Run activity"
    >
      <div className="activity-heading">
        <span className="activity-indicator" aria-hidden="true" />
        <div>
          <h3>{headline}</h3>
          <p>{description}</p>
        </div>
        <span className="activity-time">
          Elapsed{" "}
          {elapsed(
            run.started_at,
            active ? now : Date.parse(run.finished_at ?? run.started_at),
          )}
        </span>
      </div>
      <div className="activity-stats">
        <span>
          <strong>
            {run.steps.filter((step) => step.kind === "tool_call").length}
          </strong>{" "}
          recorded tool calls
        </span>
        <span>
          <strong>
            {run.steps.filter((step) => step.kind === "hypothesis").length}
          </strong>{" "}
          explicit hypotheses
        </span>
        <span>
          <strong>
            {run.steps.reduce((total, step) => total + step.evidence_count, 0)}
          </strong>{" "}
          evidence references returned
        </span>
      </div>
      <p className="visually-hidden" aria-live="polite">
        {active && latest ? `Latest recorded step ${latest.step}` : ""}
      </p>
    </section>
  );
}
