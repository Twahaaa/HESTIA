import { useEffect, useState } from "react";
import { api, describeError } from "../api/client";
import type {
  Dataset,
  Health,
  Model,
  Preparation,
  WorkspaceStatus as Status,
} from "../api/contracts";

type Snapshot = {
  health: Health;
  workspace: Status;
  datasets: Dataset[];
  models: Model[];
  preparation: Preparation;
};

type Props = {
  refreshKey: number;
  onStatus: (status: Status | null) => void;
  onReset: () => void;
};

export function WorkspaceStatus({ refreshKey, onStatus, onReset }: Props) {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [confirming, setConfirming] = useState(false);
  const [resetMessage, setResetMessage] = useState("");

  // biome-ignore lint/correctness/useExhaustiveDependencies: attempt and refreshKey trigger reloads.
  useEffect(() => {
    const controller = new AbortController();
    setError("");
    Promise.all([
      api.health(controller.signal),
      api.workspace(controller.signal),
      api.datasets(controller.signal),
      api.models(controller.signal),
      api.preparation(controller.signal),
    ])
      .then(([health, workspace, data, normality, preparation]) => {
        setSnapshot({
          health,
          workspace,
          datasets: data.datasets,
          models: normality.models,
          preparation,
        });
        onStatus(workspace);
      })
      .catch((caught: unknown) => {
        if (controller.signal.aborted) return;
        setError(describeError(caught));
        onStatus(null);
      });
    return () => controller.abort();
  }, [attempt, refreshKey]);

  // While a run is active, re-check every few seconds so controls elsewhere in
  // the workspace unblock when it ends. Stops as soon as nothing is active.
  const activeRunId = snapshot?.workspace.active_run?.run_id ?? null;
  // biome-ignore lint/correctness/useExhaustiveDependencies: each new snapshot re-arms the timer.
  useEffect(() => {
    if (!activeRunId) return;
    const timer = setTimeout(() => setAttempt((value) => value + 1), 3000);
    return () => clearTimeout(timer);
  }, [activeRunId, snapshot]);

  async function reset() {
    setResetMessage("");
    try {
      const result = await api.resetDemo();
      const runs = result.removed.agent_runs ?? 0;
      const dispositions = result.removed.analyst_dispositions ?? 0;
      setResetMessage(
        `Demo workspace reset: removed ${runs} run(s) and ${dispositions} disposition(s). Prepared evidence was kept.`,
      );
      setConfirming(false);
      onReset();
    } catch (caught) {
      setResetMessage(`Reset refused: ${describeError(caught)}`);
    }
  }

  if (error) {
    return (
      <section role="alert" className="panel status-error">
        <h2>Unable to reach the workspace</h2>
        <p>{error}</p>
        <p className="muted">
          Nothing is shown as current until the API answers again. Stored runs
          and dispositions are unaffected.
        </p>
        <button type="button" onClick={() => setAttempt(attempt + 1)}>
          Try again
        </button>
      </section>
    );
  }
  if (!snapshot) {
    return (
      <p role="status" className="loading-line">
        Loading workspace status…
      </p>
    );
  }

  const { workspace, preparation } = snapshot;
  const parentModels = snapshot.models.filter((m) => !m.parent_model_id);
  const provider = workspace.provider;

  return (
    <section className="workspace-status" aria-label="Workspace status">
      <div className="status">
        <span className="dot" aria-hidden="true" />
        <strong>
          Service {snapshot.health.status === "ok" ? "online" : "unavailable"}
        </strong>
        <span>
          Evidence store ·{" "}
          {workspace.store.available
            ? `schema v${workspace.store.schema_version}`
            : (workspace.store.reason ?? "unavailable")}
        </span>
        {workspace.demo_workspace ? (
          <span className="badge demo">Synthetic demo workspace</span>
        ) : null}
      </div>
      <div className="status-grid">
        <div>
          <p className="eyebrow">INVESTIGATION PROVIDER</p>
          {provider.configured && !provider.fixture ? (
            <p>
              Configured: {provider.provider} / {provider.model}.{" "}
              <span className="muted">
                {" "}
                A small Groq evaluation pilot has been measured; live workspace
                completion is not established by it.
              </span>
            </p>
          ) : provider.configured && provider.fixture ? (
            <p>Configured provider is the local fixture analyst.</p>
          ) : (
            <p>
              No hosted provider configured.{" "}
              <span className="muted">{provider.reason}</span>
            </p>
          )}
          <p className="muted">
            Fixture runs are always available: a deterministic scripted analyst,
            labelled as a fixture and never presented as a live model.
          </p>
        </div>
        <div>
          <p className="eyebrow">PRIORITIZATION</p>
          <p>
            {workspace.scoring.available
              ? `${workspace.scoring.ready_models} of ${workspace.scoring.total_models} models ready`
              : "Unavailable — cases are unscored"}
          </p>
          {workspace.scoring.reason ? (
            <p className="muted">{workspace.scoring.reason}</p>
          ) : null}
          <p className="muted">{workspace.scoring.note}</p>
        </div>
        <div>
          <p className="eyebrow">ACTIVE INVESTIGATION</p>
          {workspace.active_run ? (
            <p>
              One run is {workspace.active_run.state}
              {workspace.active_run.cancel_requested
                ? " (cancel requested)"
                : ""}
              . One case runs at a time.
            </p>
          ) : (
            <p>None running.</p>
          )}
          {workspace.recovered_interrupted_runs > 0 ? (
            <p className="warning-text">
              {workspace.recovered_interrupted_runs} run(s) were interrupted by
              a restart and marked as such. They have no report and can be
              retried.
            </p>
          ) : null}
        </div>
      </div>

      <details className="panel collapsible">
        <summary>Evidence collections, preparation and model readiness</summary>
        <div className="grid">
          <section>
            <div className="section-title">
              <h2>Evidence collections</h2>
              <span>
                {snapshot.datasets.length.toString().padStart(2, "0")}
              </span>
            </div>
            {snapshot.datasets.length === 0 ? (
              <p>No collections registered.</p>
            ) : (
              snapshot.datasets.map((d) => (
                <article key={d.dataset_id} className="status-item">
                  <div>
                    <h3>{d.dataset_id}</h3>
                    <p>
                      {d.file_count.toLocaleString()}{" "}
                      {d.file_count === 1 ? "file" : "files"}
                      {d.bytes !== undefined
                        ? ` · ${(d.bytes / 1024 / 1024).toFixed(1)} MB`
                        : ""}
                    </p>
                  </div>
                  <span className="badge">{d.status.replaceAll("_", " ")}</span>
                </article>
              ))
            )}
          </section>
          <section>
            <div className="section-title">
              <h2>Behavioral models</h2>
              <span>{parentModels.length.toString().padStart(2, "0")}</span>
            </div>
            <p className="muted">
              Model code is available. Training and calibration are required
              before scoring cases.
            </p>
            {parentModels.map((m) => (
              <article key={m.model_id} className="status-item">
                <div>
                  <h3>{m.model_id.replaceAll("_", " ")}</h3>
                  <p>{m.primitive}</p>
                </div>
                <span className="badge">{m.ready ? "Ready" : "Untrained"}</span>
              </article>
            ))}
          </section>
        </div>
        <div className="preparation-counts">
          <div>
            <strong>{preparation.counts.sources.toLocaleString()}</strong>
            <span>Sources</span>
          </div>
          <div>
            <strong>{preparation.counts.events.toLocaleString()}</strong>
            <span>Events</span>
          </div>
          <div>
            <strong>{preparation.counts.sessions.toLocaleString()}</strong>
            <span>Sessions</span>
          </div>
          <div>
            <strong>
              {preparation.counts.parse_failures.toLocaleString()}
            </strong>
            <span>Parse failures retained</span>
          </div>
        </div>
        <div className="preparation-detail">
          <div>
            <p className="eyebrow">UNMATCHED EVENTS</p>
            <p>
              <strong>{preparation.unmatched.count.toLocaleString()}</strong>{" "}
              retained outside complete sessions
              {preparation.unmatched.percent_of_events === null
                ? ""
                : ` · ${preparation.unmatched.percent_of_events}% of events`}
            </p>
          </div>
          <div>
            <p className="eyebrow">READINESS GATE</p>
            <p>
              {preparation.readiness.ready_models} of{" "}
              {preparation.readiness.total_models} model artifacts verified ·
              preparation {preparation.status.replaceAll("_", " ")}
            </p>
            {preparation.readiness.reasons.length > 0 ? (
              <ul>
                {preparation.readiness.reasons.map((reason) => (
                  <li key={reason}>{reason}</li>
                ))}
              </ul>
            ) : (
              <p>No open readiness reasons reported.</p>
            )}
          </div>
        </div>
      </details>

      {workspace.demo_workspace ? (
        <div className="reset">
          {confirming ? (
            <fieldset className="confirm">
              <legend>Reset the synthetic demo workspace?</legend>
              <p>
                This deletes every case run, trace, report and disposition in
                this demo workspace. Prepared evidence is kept.
              </p>
              <button type="button" className="danger" onClick={reset}>
                Confirm reset
              </button>
              <button
                type="button"
                className="secondary"
                onClick={() => setConfirming(false)}
              >
                Keep everything
              </button>
            </fieldset>
          ) : (
            <button
              type="button"
              className="secondary"
              onClick={() => setConfirming(true)}
              disabled={workspace.active_run !== null}
            >
              Reset demo workspace…
            </button>
          )}
          {resetMessage ? <p role="status">{resetMessage}</p> : null}
        </div>
      ) : null}
    </section>
  );
}
