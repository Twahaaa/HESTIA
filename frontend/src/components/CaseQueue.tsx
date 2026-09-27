import { useEffect, useState } from "react";
import { api, describeError } from "../api/client";
import type { CasePage } from "../api/contracts";
import {
  DISPOSITION_LABELS,
  formatWindow,
  plural,
  STATE_LABELS,
} from "../format";

const PAGE_SIZE = 20;

type Props = {
  selectedCaseId: string | null;
  onSelect: (caseId: string) => void;
  refreshKey: number;
};

export function CaseQueue({ selectedCaseId, onSelect, refreshKey }: Props) {
  const [dataset, setDataset] = useState<string>("");
  const [offset, setOffset] = useState(0);
  const [page, setPage] = useState<CasePage | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [attempt, setAttempt] = useState(0);

  // biome-ignore lint/correctness/useExhaustiveDependencies: attempt and refreshKey trigger reloads.
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    api
      .cases(
        { dataset: dataset || null, limit: PAGE_SIZE, offset },
        controller.signal,
      )
      .then((next) => {
        setPage(next);
        setLoading(false);
      })
      .catch((caught: unknown) => {
        if (controller.signal.aborted) return;
        setError(describeError(caught));
        setLoading(false);
      });
    return () => controller.abort();
  }, [dataset, offset, attempt, refreshKey]);

  const first = page && page.total > 0 ? page.offset + 1 : 0;
  const last = page ? Math.min(page.offset + page.items.length, page.total) : 0;

  return (
    <section className="queue panel" aria-labelledby="queue-title">
      <div className="section-title">
        <h2 id="queue-title">Cases</h2>
        <span>{page ? page.total.toLocaleString() : "…"}</span>
      </div>
      {page ? (
        <p className="muted queue-note">
          {page.scoring.available
            ? "Ordered by prioritization score, then time."
            : `Unscored · ordered by ${page.scoring.ordering}. ${page.scoring.reason ?? ""}`}{" "}
          A missing score is not evidence of normal behaviour.
        </p>
      ) : null}
      {page && page.datasets.length > 1 ? (
        <label className="field">
          <span>Dataset</span>
          <select
            value={dataset}
            onChange={(event) => {
              setDataset(event.target.value);
              setOffset(0);
            }}
          >
            <option value="">All prepared datasets</option>
            {page.datasets.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
        </label>
      ) : null}

      {error ? (
        <div role="alert" className="inline-error">
          <p>Cases could not be loaded: {error}</p>
          <button type="button" onClick={() => setAttempt(attempt + 1)}>
            Retry
          </button>
        </div>
      ) : loading && !page ? (
        <ul
          className="case-list skeleton"
          aria-busy="true"
          aria-label="Loading cases"
        >
          <li />
          <li />
          <li />
        </ul>
      ) : page && page.items.length === 0 ? (
        <p className="empty">
          {page.total === 0 && !dataset
            ? "No prepared cases. Prepare evidence or seed the synthetic demo workspace first."
            : "No cases in this dataset."}
        </p>
      ) : page ? (
        <ul className="case-list" aria-busy={loading}>
          {page.items.map((item) => (
            <li key={item.case_id}>
              <button
                type="button"
                className="case-item"
                aria-current={
                  item.case_id === selectedCaseId ? "true" : undefined
                }
                onClick={() => onSelect(item.case_id)}
              >
                <span className="case-when">
                  {formatWindow(item.start, item.end)}
                </span>
                <span className="case-who">
                  {item.user ?? "unknown user"}@{item.host ?? "unknown host"}
                  {item.src_ip ? ` from ${item.src_ip}` : ""}
                </span>
                <span className="case-meta">
                  {plural(item.event_count, "event")} ·{" "}
                  {plural(item.failure_count, "failure")} · {item.dataset_id}
                </span>
                <span className="chips">
                  <span className="chip">
                    {item.priority.scored
                      ? `Priority ${item.priority.score?.toFixed(2)}`
                      : "Unscored"}
                  </span>
                  {item.latest_run ? (
                    <span className={`chip state-${item.latest_run.state}`}>
                      {item.latest_run.fixture ? "Fixture run · " : "Run · "}
                      {STATE_LABELS[item.latest_run.state]}
                    </span>
                  ) : (
                    <span className="chip quiet">Not investigated</span>
                  )}
                  {item.disposition ? (
                    <span className="chip reviewed">
                      Reviewed:{" "}
                      {DISPOSITION_LABELS[item.disposition.disposition]}
                    </span>
                  ) : null}
                </span>
              </button>
            </li>
          ))}
        </ul>
      ) : null}

      {page && page.total > PAGE_SIZE ? (
        <nav className="pager" aria-label="Case pages">
          <button
            type="button"
            className="secondary"
            disabled={page.offset === 0 || loading}
            onClick={() => setOffset(Math.max(0, page.offset - PAGE_SIZE))}
          >
            Previous
          </button>
          <span>
            {first}–{last} of {page.total.toLocaleString()}
          </span>
          <button
            type="button"
            className="secondary"
            disabled={last >= page.total || loading}
            onClick={() => setOffset(page.offset + PAGE_SIZE)}
          >
            Next
          </button>
        </nav>
      ) : null}
    </section>
  );
}
