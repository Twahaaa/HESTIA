import { useEffect, useState } from "react";
import { api, describeError } from "../api/client";
import type { ReportView as Report } from "../api/contracts";
import { VERDICT_LABELS } from "../format";

type Props = {
  runId: string;
  onOpenEvidence: (handle: string) => void;
};

export function ReportView({ runId, onOpenEvidence }: Props) {
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);

  // biome-ignore lint/correctness/useExhaustiveDependencies: attempt triggers a retry.
  useEffect(() => {
    const controller = new AbortController();
    setReport(null);
    setError("");
    api
      .report(runId, controller.signal)
      .then(setReport)
      .catch((caught: unknown) => {
        if (!controller.signal.aborted) setError(describeError(caught));
      });
    return () => controller.abort();
  }, [runId, attempt]);

  if (error) {
    return (
      <div role="alert" className="inline-error">
        <p>The report could not be loaded: {error}</p>
        <button type="button" onClick={() => setAttempt(attempt + 1)}>
          Retry
        </button>
      </div>
    );
  }
  if (!report) return <p role="status">Loading report…</p>;

  return (
    <article className="report" aria-labelledby={`report-${runId}`}>
      <div className="report-head">
        <p className="eyebrow">AGENT REPORT</p>
        <span className={`badge ${report.execution.kind}`}>
          {report.execution.label}
        </span>
      </div>
      <h3 id={`report-${runId}`}>{VERDICT_LABELS[report.verdict]}</h3>
      <p className="muted">{report.verdict_note}</p>
      <dl className="facts">
        <div>
          <dt>Severity</dt>
          <dd>{report.severity}</dd>
        </div>
        <div>
          <dt>Stated confidence</dt>
          <dd>{Math.round(report.confidence * 100)}%</dd>
        </div>
        <div>
          <dt>Reference coverage</dt>
          <dd>{report.known_or_novel.replaceAll("_", " ")}</dd>
        </div>
        <div>
          <dt>Citations</dt>
          <dd>
            {report.grounding.checked_handles} checked ·{" "}
            {report.grounding.grounded ? "all resolved" : "failed validation"}
          </dd>
        </div>
      </dl>
      <p>{report.summary}</p>

      <section>
        <h4>Findings</h4>
        {report.findings.length === 0 ? (
          <p className="empty">The report makes no factual findings.</p>
        ) : (
          <ol className="findings">
            {report.findings.map((finding) => (
              <li
                key={`${finding.statement}|${finding.citations.map((c) => c.handle).join(",")}`}
              >
                <p>{finding.statement}</p>
                {finding.excerpt ? (
                  <blockquote>{finding.excerpt}</blockquote>
                ) : null}
                <div className="handles">
                  {finding.citations.map((citation) =>
                    citation.resolvable ? (
                      <button
                        key={citation.handle}
                        type="button"
                        className="link-button citation"
                        onClick={() => onOpenEvidence(citation.handle)}
                      >
                        Open {citation.kind} {citation.handle}
                      </button>
                    ) : (
                      <span key={citation.handle} className="chip quiet">
                        {citation.handle} · cannot be opened: {citation.reason}
                      </span>
                    ),
                  )}
                </div>
              </li>
            ))}
          </ol>
        )}
        {report.citation_note ? (
          <p className="warning-text">{report.citation_note}</p>
        ) : null}
      </section>

      <section>
        <h4>Known technique references</h4>
        <p>
          {report.technique_ids.length > 0
            ? report.technique_ids.join(", ")
            : "No technique identifier was cited."}
        </p>
        <p className="muted">{report.known_or_novel_note}</p>
      </section>

      <section>
        <h4>Uncertainty and limitations</h4>
        {report.limitations.length > 0 ? (
          <ul>
            {report.limitations.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        ) : (
          <p className="muted">The report states no limitations.</p>
        )}
        <p className="muted">{report.grounding.note}</p>
      </section>

      <section>
        <h4>Recommended review actions</h4>
        {report.recommended_actions.length > 0 ? (
          <ul>
            {report.recommended_actions.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        ) : (
          <p className="muted">None given.</p>
        )}
        <p className="muted">{report.recommended_actions_note}</p>
      </section>

      {report.pseudonyms.length > 0 ? (
        <section>
          <h4>Pseudonyms in this report</h4>
          <p className="muted">
            The provider only ever saw these pseudonyms. They are resolved here,
            locally.
          </p>
          <dl className="facts">
            {report.pseudonyms.map((entry) => (
              <div key={entry.token}>
                <dt>{entry.token}</dt>
                <dd>{entry.value ?? "not resolvable"}</dd>
              </div>
            ))}
          </dl>
        </section>
      ) : null}
    </article>
  );
}
