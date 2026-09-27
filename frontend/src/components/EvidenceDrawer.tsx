import { type KeyboardEvent, useEffect, useRef, useState } from "react";
import { api, describeError } from "../api/client";
import type { EvidenceResolution } from "../api/contracts";
import { formatTime } from "../format";

type Props = {
  runId: string;
  handle: string;
  onClose: () => void;
};

/**
 * Shows the exact stored lines behind one citation.
 *
 * A modal dialog: focus moves to the close button on open, Tab stays inside,
 * Escape closes, and focus returns to whatever opened it.
 */
export function EvidenceDrawer({ runId, handle, onClose }: Props) {
  const [evidence, setEvidence] = useState<EvidenceResolution | null>(null);
  const [error, setError] = useState("");
  const dialog = useRef<HTMLDivElement>(null);
  const closeButton = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const controller = new AbortController();
    setEvidence(null);
    setError("");
    api
      .evidence(runId, handle, controller.signal)
      .then(setEvidence)
      .catch((caught: unknown) => {
        if (!controller.signal.aborted) setError(describeError(caught));
      });
    return () => controller.abort();
  }, [runId, handle]);

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    closeButton.current?.focus();
    return () => previous?.focus?.();
  }, []);

  function onKeyDown(event: KeyboardEvent) {
    if (event.key === "Escape") {
      event.stopPropagation();
      onClose();
      return;
    }
    if (event.key !== "Tab" || !dialog.current) return;
    const focusable = dialog.current.querySelectorAll<HTMLElement>(
      "button, [href], [tabindex]:not([tabindex='-1'])",
    );
    if (focusable.length === 0) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  return (
    <div className="drawer-backdrop">
      <div
        ref={dialog}
        className="drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby="drawer-title"
        onKeyDown={onKeyDown}
      >
        <div className="drawer-head">
          <h2 id="drawer-title">Evidence {handle}</h2>
          <button
            ref={closeButton}
            type="button"
            className="secondary"
            onClick={onClose}
          >
            Close
          </button>
        </div>
        {error ? (
          <p role="alert" className="inline-error">
            This citation cannot be opened: {error}
          </p>
        ) : !evidence ? (
          <p role="status">Resolving citation locally…</p>
        ) : (
          <div className="drawer-body">
            {evidence.session ? (
              <p className="muted">
                Session in {evidence.session.dataset_id} ·{" "}
                {evidence.session.source} · {formatTime(evidence.session.start)}{" "}
                to {formatTime(evidence.session.end)} ·{" "}
                {evidence.session.event_count} event(s)
              </p>
            ) : null}
            {evidence.lines.length > 0 ? (
              <ol className="log-lines">
                {evidence.lines.map((line) => (
                  <li key={line.event_id}>
                    <p className="line-source">
                      {line.source}:{line.line_no} ·{" "}
                      {formatTime(line.timestamp)}
                      {line.unmatched
                        ? ` · outside a complete session (${line.unmatched_reason})`
                        : ""}
                    </p>
                    <pre>{line.line}</pre>
                  </li>
                ))}
              </ol>
            ) : null}
            {evidence.lines_truncated ? (
              <p className="muted">
                Only the first lines of this session are shown.
              </p>
            ) : null}
            {evidence.reference ? (
              <div className="reference">
                <h3>{evidence.reference.title}</h3>
                <p className="muted">
                  {evidence.reference.collection} · {evidence.reference.version}{" "}
                  · {evidence.reference.source_uri}
                </p>
                <p>
                  Techniques:{" "}
                  {evidence.reference.technique_ids.join(", ") || "none listed"}
                </p>
                <pre>{evidence.reference.snippet}</pre>
                <p className="muted">{evidence.reference.attribution}</p>
                <p className="muted">{evidence.reference.note}</p>
              </div>
            ) : null}
          </div>
        )}
      </div>
    </div>
  );
}
