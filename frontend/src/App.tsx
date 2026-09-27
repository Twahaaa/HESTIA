import { useCallback, useEffect, useState } from "react";
import type { WorkspaceStatus as Status } from "./api/contracts";
import { CaseDetail } from "./components/CaseDetail";
import { CaseQueue } from "./components/CaseQueue";
import { PilotResults } from "./components/PilotResults";
import { WorkspaceStatus } from "./components/WorkspaceStatus";

type Selection = {
  view: "cases" | "pilot";
  caseId: string | null;
  runId: string | null;
};

const CASE_ID = /^case-[0-9a-f]{20}$/;
const RUN_ID = /^[0-9a-f]{32}$/;

/** Deep links are plain hashes: `#/pilot`, `#/cases/<case>` or `#/cases/<case>/runs/<run>`. */
function readHash(): Selection {
  const [, root, caseId, runs, runId] = window.location.hash
    .replace(/^#/, "")
    .split("/");
  if (root === "pilot") return { view: "pilot", caseId: null, runId: null };
  if (root !== "cases" || !caseId || !CASE_ID.test(caseId))
    return { view: "cases", caseId: null, runId: null };
  return {
    view: "cases",
    caseId,
    runId: runs === "runs" && runId && RUN_ID.test(runId) ? runId : null,
  };
}

function writeHash(selection: Selection) {
  const hash =
    selection.view === "pilot"
      ? "#/pilot"
      : selection.caseId
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
  const inPilot = selection.view === "pilot";

  return (
    <>
      <a
        className="skip-link"
        href={inPilot ? "#pilot-content" : "#workspace"}
        onClick={(event) => {
          // Move focus only: the hash is the router, so changing it to the
          // target's id would close the open case.
          event.preventDefault();
          document
            .getElementById(inPilot ? "pilot-content" : "workspace")
            ?.focus();
        }}
      >
        Skip to the {inPilot ? "pilot results" : "case workspace"}
      </a>
      <div className="app-shell">
        <header className="app-header">
          <a className="brand" href="#/">
            <span aria-hidden="true">✦</span> HESTIA
          </a>
          <nav className="app-nav" aria-label="Main navigation">
            <a href="#/" aria-current={!inPilot ? "page" : undefined}>
              Case workspace
            </a>
            <a href="#/pilot" aria-current={inPilot ? "page" : undefined}>
              Groq pilot
            </a>
          </nav>
          <span className="app-mode">EVIDENCE-LED INVESTIGATION</span>
        </header>
        <main>
          {inPilot ? (
            <PilotResults />
          ) : (
            <>
              <section className="workspace-heading">
                <div>
                  <p className="eyebrow">INVESTIGATION / AUTHENTICATION</p>
                  <h1>Case workspace</h1>
                  <p>
                    Follow a live run from source evidence to a grounded report
                    and analyst review.
                  </p>
                </div>
                <span className="workspace-heading-note">
                  ONE ACTIVE CASE AT A TIME
                </span>
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
                  onSelect={(caseId) =>
                    select({ view: "cases", caseId, runId: null })
                  }
                />
                {selection.caseId ? (
                  <CaseDetail
                    key={selection.caseId}
                    caseId={selection.caseId}
                    workspace={workspace}
                    selectedRunId={selection.runId}
                    onSelectRun={(runId) =>
                      select({ view: "cases", caseId: selection.caseId, runId })
                    }
                    onOpenCase={(caseId) =>
                      select({ view: "cases", caseId, runId: null })
                    }
                    onBack={() =>
                      select({ view: "cases", caseId: null, runId: null })
                    }
                    onChanged={refresh}
                  />
                ) : (
                  <section className="detail panel placeholder">
                    <p className="eyebrow">START HERE</p>
                    <h2>Select a case</h2>
                    <p className="muted">
                      Choose a prepared session from the queue to inspect its
                      source lines, start an investigation and review the
                      result.
                    </p>
                    <p className="muted">
                      An unscored case has not been assessed by a trained
                      behavioural model.
                    </p>
                  </section>
                )}
              </div>
            </>
          )}
          <footer>
            Hestia · Evidence-led case review{" "}
            <span>Reports require grounded citations</span>
          </footer>
        </main>
      </div>
    </>
  );
}
