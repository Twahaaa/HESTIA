/** Public-safe, frozen presentation of the measured 2026-09-27 Groq pilot.
 * Figures are reproduced from docs/EVALUATION.md, not read from private labels
 * or mutable evaluation artifacts. No API call or provider request occurs here.
 */
const cases = [
  {
    id: "01",
    label: "AIT · normal",
    result: "No report",
    detail: "Rate-limit allowance reached",
    kind: "incomplete",
  },
  {
    id: "02",
    label: "CAM · attack",
    result: "No report",
    detail: "Rate-limit allowance reached",
    kind: "incomplete",
  },
  {
    id: "03",
    label: "AIT · normal",
    result: "False positive",
    detail: "Repeated login failures called malicious",
    kind: "false-positive",
  },
  {
    id: "04",
    label: "CAM · attack",
    result: "True positive",
    detail: "Login followed by sudo reading /etc/shadow",
    kind: "true-positive",
  },
  {
    id: "05",
    label: "AIT · normal",
    result: "No report",
    detail: "Turn limit reached",
    kind: "incomplete",
  },
  {
    id: "06",
    label: "CAM · attack",
    result: "Abstained",
    detail: "Insufficient evidence from one login",
    kind: "abstained",
  },
] as const;

export function PilotResults() {
  return (
    <section
      id="pilot-content"
      className="pilot-page"
      aria-labelledby="pilot-title"
      tabIndex={-1}
    >
      <div className="pilot-header">
        <p className="eyebrow">MEASURED RUN / 27 SEP 2026</p>
        <h1 id="pilot-title">Six-case Groq pilot</h1>
        <p>
          One approved, labelled evaluation run on Groq{" "}
          <code>openai/gpt-oss-120b</code>. These are historical results, not
          the state of the live case workspace.
        </p>
        <span className="chip quiet">
          Pilot only · not a detection-accuracy claim
        </span>
      </div>

      <section className="pilot-metrics" aria-label="Pilot outcomes">
        <div>
          <strong>
            3 <small>/ 6</small>
          </strong>
          <span>Reports published</span>
          <p>All citations in those reports resolved to stored evidence.</p>
        </div>
        <div>
          <strong>
            1 <small>TP</small>
          </strong>
          <span>Attack called malicious</span>
          <p>One CAM case, under upstream dataset conventions.</p>
        </div>
        <div>
          <strong>
            1 <small>FP</small>
          </strong>
          <span>Normal called malicious</span>
          <p>One AIT case, under upstream dataset conventions.</p>
        </div>
        <div>
          <strong>
            4 <small>/ 6</small>
          </strong>
          <span>No decisive verdict</span>
          <p>
            Three operational failures and one insufficient-evidence report.
          </p>
        </div>
      </section>

      <div className="pilot-columns">
        <section
          className="panel pilot-breakdown"
          aria-labelledby="pilot-cases"
        >
          <div className="section-title">
            <h2 id="pilot-cases">Case outcomes</h2>
            <span>6 CASES</span>
          </div>
          <p className="muted">
            Each row is one evaluated case. Labels were joined after all model
            runs finished.
          </p>
          <ol className="pilot-case-list">
            {cases.map((item) => (
              <li key={item.id}>
                <span className="pilot-index">{item.id}</span>
                <div>
                  <strong>{item.result}</strong>
                  <p>{item.detail}</p>
                </div>
                <span className={`pilot-truth ${item.kind}`}>{item.label}</span>
              </li>
            ))}
          </ol>
        </section>
        <aside className="panel pilot-reading" aria-labelledby="pilot-reading">
          <p className="eyebrow">HOW TO READ THIS</p>
          <h2 id="pilot-reading">What the numbers establish</h2>
          <dl className="pilot-facts">
            <div>
              <dt>Precision</dt>
              <dd>
                0.50 <small>95% interval 0.09–0.91</small>
              </dd>
            </div>
            <div>
              <dt>Technique match</dt>
              <dd>
                0 / 3 <small>attack cases</small>
              </dd>
            </div>
            <div>
              <dt>Hosted traffic</dt>
              <dd>
                108 <small>HTTP attempts; 17 rate-limited</small>
              </dd>
            </div>
            <div>
              <dt>Usage</dt>
              <dd>
                197,357{" "}
                <small>tokens · ~$0.034 list-price estimate, not a bill</small>
              </dd>
            </div>
          </dl>
          <h3>Limits on interpretation</h3>
          <ul className="pilot-limits">
            <li>
              Only six cases and two decisive outcomes; the uncertainty interval
              is wide.
            </li>
            <li>
              Every attack is CAM and every normal case is AIT. Dataset style
              can confound detection.
            </li>
            <li>
              Truth follows upstream dataset conventions, not individual human
              review.
            </li>
            <li>
              CAM technique documents remain in the reference index; technique
              scoring is not a fair independent test.
            </li>
            <li>
              Three missing reports were operational failures, not benign
              predictions.
            </li>
          </ul>
        </aside>
      </div>
      <p className="pilot-source">
        Source: the approved labelled pilot recorded in{" "}
        <code>docs/EVALUATION.md</code>. The private label sidecar, raw run
        records and source logs are not part of this view.
      </p>
    </section>
  );
}
