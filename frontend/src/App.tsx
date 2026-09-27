import { useCallback, useEffect, useState } from "react";
import type { WorkspaceStatus as Status } from "./api/contracts";
import { CaseDetail } from "./components/CaseDetail";
import { CaseQueue } from "./components/CaseQueue";
import { WorkspaceStatus } from "./components/WorkspaceStatus";

type Selection = { caseId: string | null; runId: string | null };

const CASE_ID = /^case-[0-9a-f]{20}$/;
const RUN_ID = /^[0-9a-f]{32}$/;

/** Deep links are plain hashes: `#/cases/<case>` or `#/cases/<case>/runs/<run>`. */
function readHash(): Selection {
  const [, root, caseId, runs, runId] = window.location.hash
    .replace(/^#/, "")
    .split("/");
  if (root !== "cases" || !caseId || !CASE_ID.test(caseId))
    return { caseId: null, runId: null };
  return {
    caseId,
    runId: runs === "runs" && runId && RUN_ID.test(runId) ? runId : null,
  };
}

function writeHash(selection: Selection) {
  const hash = selection.caseId
    ? `#/cases/${selection.caseId}${selection.runId ? `/runs/${selection.runId}` : ""}`
    : "";
  if (window.location.hash !== hash) {
    window.history.pushState(null, "", hash || window.location.pathname);
  }
}

export function App() {
  const [selection, setSelection] = useState<Selection>(readHash);
  const [workspace, setWorkspace] = useState<Status | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    const sync = () => setSelection(readHash());
    window.addEventListener("popstate", sync);
    window.addEventListener("hashchange", sync);
    return () => {
      window.removeEventListener("popstate", sync);
      window.removeEventListener("hashchange", sync);
    };
  }, []);

  const select = useCallback((next: Selection) => {
    setSelection(next);
    writeHash(next);
  }, []);

  const refresh = useCallback(() => setRefreshKey((value) => value + 1), []);

  return (
    <>
      <a className="skip-link" href="#workspace">
        Skip to the case workspace
      </a>
      <main>
        <header>
          <a className="brand" href="#/">
            H<span aria-hidden="true">✦</span>HESTIA
          </a>
          <span className="eyebrow">SOC WORKSPACE / CASE REVIEW</span>
        </header>
        <section className="intro">
          <p className="eyebrow">EVIDENCE BEFORE CONCLUSIONS</p>
          <h1>Review authentication cases against their evidence.</h1>
          <p className="lede">
            Choose a prepared session, run a bounded investigation, inspect
            every cited line and record your own review. Unfinished runs never
            become verdicts.
          </p>
        </section>
        <WorkspaceStatus
          refreshKey={refreshKey}
          onStatus={setWorkspace}
          onReset={refresh}
        />
        <div
          id="workspace"
          className="workspace"
          data-view={selection.caseId ? "detail" : "queue"}
          tabIndex={-1}
        >
          <CaseQueue
            selectedCaseId={selection.caseId}
            refreshKey={refreshKey}
            onSelect={(caseId) => select({ caseId, runId: null })}
          />
          {selection.caseId ? (
            <CaseDetail
              key={selection.caseId}
              caseId={selection.caseId}
              workspace={workspace}
              selectedRunId={selection.runId}
              onSelectRun={(runId) =>
                select({ caseId: selection.caseId, runId })
              }
              onOpenCase={(caseId) => select({ caseId, runId: null })}
              onBack={() => select({ caseId: null, runId: null })}
              onChanged={refresh}
            />
          ) : (
            <section className="detail panel placeholder">
              <h2>No case selected</h2>
              <p className="muted">
                Choose a case from the queue to see its canonical log lines,
                investigate it and record a review.
              </p>
            </section>
          )}
        </div>
        <footer>
          Hestia / Evidence-led SOC triage <span>Workspace 0.4</span>
        </footer>
      </main>
    </>
  );
}
