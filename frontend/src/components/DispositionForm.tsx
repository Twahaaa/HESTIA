import { type FormEvent, useId, useState } from "react";
import { api, describeError } from "../api/client";
import type {
  Disposition,
  DispositionValue,
  RunSummary,
} from "../api/contracts";
import { DISPOSITION_LABELS, DISPOSITIONS, formatTime } from "../format";

type Props = {
  caseId: string;
  runs: RunSummary[];
  history: Disposition[];
  onSaved: () => void;
};

/** Review dispositions only. Nothing here contains, blocks or remediates anything. */
export function DispositionForm({ caseId, runs, history, onSaved }: Props) {
  const [value, setValue] = useState<DispositionValue | "">("");
  const [note, setNote] = useState("");
  const [actor, setActor] = useState("");
  const [runId, setRunId] = useState<string>(runs[0]?.run_id ?? "");
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const id = useId();
  const completedRuns = runs.filter((run) => run.state === "completed");

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!value) {
      setError("Choose a disposition first.");
      return;
    }
    setSaving(true);
    setError("");
    setMessage("");
    try {
      const saved = await api.recordDisposition(caseId, {
        disposition: value,
        note,
        ...(actor.trim() ? { actor: actor.trim() } : {}),
        ...(runId ? { run_id: runId } : {}),
      });
      setMessage(
        `Saved “${DISPOSITION_LABELS[saved.disposition]}” by ${saved.actor}.`,
      );
      setValue("");
      setNote("");
      onSaved();
    } catch (caught) {
      setError(describeError(caught));
    } finally {
      setSaving(false);
    }
  }

  return (
    <section className="panel disposition" aria-labelledby={`${id}-title`}>
      <h3 id={`${id}-title`}>Analyst review</h3>
      <p className="muted">
        A disposition records your review of this case. It is not a training
        label, and it triggers no containment or remediation.
      </p>
      <form onSubmit={submit}>
        <fieldset>
          <legend>Disposition</legend>
          {DISPOSITIONS.map((option) => {
            const disabled =
              option.value === "report_disputed" && completedRuns.length === 0;
            return (
              <label
                key={option.value}
                className={`radio${disabled ? " disabled" : ""}`}
              >
                <input
                  type="radio"
                  name={`${id}-disposition`}
                  value={option.value}
                  checked={value === option.value}
                  disabled={disabled}
                  onChange={() => {
                    setValue(option.value);
                    if (
                      option.value === "report_disputed" &&
                      completedRuns[0]
                    ) {
                      setRunId(completedRuns[0].run_id);
                    }
                  }}
                />
                <span>
                  <strong>{option.label}</strong>{" "}
                  <span className="muted">{option.help}</span>
                  {disabled ? (
                    <span className="muted"> Needs a published report.</span>
                  ) : null}
                </span>
              </label>
            );
          })}
        </fieldset>
        {runs.length > 0 ? (
          <label className="field">
            <span>Regarding run</span>
            <select
              value={runId}
              onChange={(event) => setRunId(event.target.value)}
            >
              {value !== "report_disputed" ? (
                <option value="">No specific run</option>
              ) : null}
              {(value === "report_disputed" ? completedRuns : runs).map(
                (run) => (
                  <option key={run.run_id} value={run.run_id}>
                    {formatTime(run.started_at)} · {run.state}
                    {run.fixture ? " · fixture" : ""}
                  </option>
                ),
              )}
            </select>
          </label>
        ) : null}
        <label className="field">
          <span>Note (optional)</span>
          <textarea
            value={note}
            maxLength={2000}
            rows={3}
            onChange={(event) => setNote(event.target.value)}
          />
        </label>
        <label className="field">
          <span>
            Your name (optional, recorded as given; there is no sign-in)
          </span>
          <input
            value={actor}
            maxLength={64}
            pattern="[A-Za-z0-9 ._@\-]{1,64}"
            onChange={(event) => setActor(event.target.value)}
          />
        </label>
        <button type="submit" disabled={saving}>
          {saving ? "Saving…" : "Save disposition"}
        </button>
        {error ? (
          <p role="alert" className="inline-error">
            {error}
          </p>
        ) : null}
        {message ? <p role="status">{message}</p> : null}
      </form>
      <h4>Review history</h4>
      {history.length === 0 ? (
        <p className="empty">No disposition recorded yet.</p>
      ) : (
        <ol className="history">
          {history.map((item) => (
            <li key={item.disposition_id}>
              <strong>{DISPOSITION_LABELS[item.disposition]}</strong> ·{" "}
              {item.actor} · {formatTime(item.recorded_at)}
              {item.note ? <p>{item.note}</p> : null}
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
