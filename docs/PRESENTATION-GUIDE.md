# Hestia: codebase context and presentation guide

This guide is for a teammate preparing slides about the **current implementation**.
It separates the working authentication case workspace, the offline HDFS anomaly
benchmark, and capabilities that still lack real-data or hosted-provider evidence.
Read it alongside [architecture](ARCHITECTURE.md), the [demo walkthrough](DEMO.md),
the [agent contract](AGENT.md), the [MCP tool reference](TOOLS.md), and the
[evaluation details](EVALUATION.md). The numbers below describe runs recorded
for this build; rerun the commands and update slide figures if the code or data
changes. None of these results establishes that the hosted agent detects attacks.

## 1. One-minute explanation

Hestia is an evidence-led investigation workspace for Linux authentication
logs. It parses log lines into typed events and bounded sessions, retains
records it cannot fully parse or assign to sessions, and stores source-qualified
evidence in SQLite. One bounded agent can choose among eleven read-only tools
from one local MCP server to investigate a case. A provider-bound redaction
layer changes identifiers to local handles and pseudonyms before any hosted
call; citation validation checks a completed report against retrieved evidence
before it is published. A React workspace lets a person inspect the queue,
follow a run, open exact source lines and record a review disposition.

The workspace can be demonstrated **offline** using a clearly labelled
deterministic fixture analyst. Real hosted calls have **not** been tested, and
the authentication normality models have **not** been trained on eligible real
data. Separately, a public HDFS v1 experiment supplies *measured* anomaly
baseline results for file-block traces. HDFS blocks are not authentication
sessions, its labels are not security-attack labels, and that experiment has
not run Hestia's investigation agent.

**Useful opening line:** “Hestia connects source-citable log evidence to a
bounded, inspectable investigation workflow. We can demonstrate the workflow;
we report the public anomaly benchmark separately and are explicit about what
has not yet been validated.”

## 2. The problem and the system's actual role

- Log volume makes manual investigation slow. An analyst needs the exact line,
  source, timestamp and surrounding context behind a claim—not just an alarm.
- An unusual pattern is not automatically an intrusion. A tool retrieves facts;
  the model, when configured, decides what to ask next and may abstain.
- The case queue is intended to prioritize scored sessions, but no real
  authentication model artifact exists today. The current queue says
  **Unscored**, in time order. “No score” does not mean “normal.”
- A published report is a *model conclusion with mechanically valid citations*,
  not independently verified semantic truth. A failed, cancelled or interrupted
  investigation has **no report**.
- An analyst disposition is a human review record. It is not a dataset label,
  does not retrain a model and triggers no automated response.

Avoid describing Hestia as a trained SOC detector or its offline fixture as a
live LLM. The separate HDFS benchmark is a useful research measurement, but
does not remove either restriction.

## 3. Architecture to draw on a slide

Draw the authentication workflow as one left-to-right flow, with labels kept
outside the runtime lane:

```text
Public/bundled auth logs → source profiles → parser + UTC collection
    → events + parse failures → session builder + unmatched events
    → embedded SQLite evidence store → case queue / case detail
                                      ↘ one case-owning agent
                                         ↔ one local read-only MCP server (11 tools)
                                         → provider redaction boundary (hosted mode)
                                         → bounded tool trace + structured report
                                         → local citation validation
                                         → report / evidence drawer / analyst review

Separate lane: curated normal sessions → behavioral model training
                                     → calibration → candidate score (not ready now)
Separate boundary: evaluation-only labels → offline metrics, never runtime tools
```

The frontend and FastAPI API are served from the same origin in Docker. The
local MCP server communicates over stdio; there are not multiple specialist
agents or separate vector/database services. SQLite holds runtime evidence,
candidate records, agent runs, steps, reports and review dispositions. A
persisted run trace records explicit tool calls and hypotheses, **not** a
provider's private chain of thought. See `docs/ARCHITECTURE.md` for the compact
diagram.

On a **different slide**, draw the HDFS experiment as a separate offline
research lane:

```text
Public HDFS v1 archive → block IDs + event-template traces
                       → source-order train / validation / evaluation
                       → normal-only transition baseline
                       → validation-selected trace scoring + threshold
                       → held-out anomaly metrics + inspectable raw lines
```

There is no arrow from HDFS into the authentication SQLite store, case queue
or hosted agent. Adding that arrow would suggest an integration that has not
been built.

## 4. Where things live in the code

- `src/hestia/contracts.py`: typed `Event` and `Session` structures. Source and
  original 1-based line number remain available for evidence checks.
- `src/hestia/datasets/`: dataset adapters, allowlisted import and deterministic
  split manifests. AIT annotations live on a separate curation/evaluation
  boundary; missing annotations do not make a source benign.
- `src/hestia/ingestion/`: parsing, source-qualified UTC collection,
  sessionization and structured tokenization. Parse failures and events without
  enough identity to join a session are retained, not dropped.
- `src/hestia/store/`: versioned SQLite schema and repository queries. The
  workspace uses evidence schema version 3; migrations are additive.
- `src/hestia/normality/`: feature extraction, five parent behavioral
  primitives, drift tracking, readiness, normal-only training and held-out
  normal calibration mechanics. **These are working algorithms and tests, not
  proof of trained models in the deployed authentication workspace.**
- `src/hestia/knowledge/`: attributed lexical reference retrieval over a
  subset of CAM-LDS manifestations and a pinned MITRE ATT&CK Enterprise auth
  subset. A matching reference is context to inspect, not a verdict or proof
  that a technique occurred.
- `src/hestia/mcp/`: one read-only stdio server. All tools return availability
  and provenance; tools do not assign a malicious label or execute remediation.
- `src/hestia/agent/`: case contracts, provider adapters, bounded runner,
  fixture analyst, outbound redaction and citation checks. `providers.py`
  supports Groq and OpenRouter; `rotation.py` switches among configured keys
  **within one provider/model** on specific provider limits. No hosted success
  is implied by those offline-tested adapters.
- `src/hestia/runs/`: case identity, single-active-run lifecycle,
  interruption/cancellation recovery, local citation resolution and the
  synthetic demo seed.
- `src/hestia/api/`: FastAPI status, workspace, case, run, report and review
  endpoints. A paid run is initiated only through an explicitly confirmed
  POST; a GET cannot start inference.
- `frontend/src/`: React/TypeScript case queue, detail, live trace, report,
  evidence drawer and review form. `frontend/e2e/` exercises real API flows
  on desktop and an emulated 390px viewport.
- `src/hestia/evaluation/`: separate offline evaluation. The auth evaluator
  accepts privately reviewed event labels, checks split hashes and reports
  undefined metrics as null. `hdfs.py` and `hdfs_refined.py` implement the
  distinct public HDFS block-trace experiment.
- `scripts/export_source.py` and `scripts/audit_release.py`: export a reviewed
  source allowlist and check it for private artifacts/credentials. The source
  export omits bulk datasets, trained artifacts, local key/handle maps and Git
  metadata.

## 5. Data and the actual readiness gate

The selected authentication preparation contains **12,777 parsed events**
from **906 sources**, **520 parse failures**, **457 sessions** and **10,682
unmatched events**. By dataset: AIT auth contributes 6,673 parsed events and
38 sessions; CAM auth contributes 4,159 events and 303 sessions; and the
Loghub OpenSSH sample contributes 1,945 events and 116 sessions. These are
preparation/coverage counts, **not** attack prevalence or detection results.

All **457 authentication sessions are excluded** from real normal-data splits
because no selected source has the required proof of benign eligibility.
There are **zero eligible normal training sessions**, no real trained
normality artifact, and zero persisted candidate scores. The two Half-Space
Trees models require **250 explicitly eligible observations per relevant
host/source-IP entity** before their scores are ready. The smaller user
features and transition models also cannot be treated as trained real-data
models in this deployment. Separate normal validation/test evidence is needed
before reporting a calibrated alert rate. No missing label is assumed to mean
normal. See [preparation](PREPARATION.md) and [data contract](DATA.md).

### What normality would contribute if data supported it

The feature code can describe login hour, recent authentication frequency,
success/failure proportions, event sequences and user/host/source-IP history.
Normal-only training would learn earlier behavior; later held-out normal
observations would calibrate a threshold; scoring must not teach the model
about the session being scored. A prioritization score is investigative
context, never a security verdict. Present this as a **designed and
mechanically tested path** with an explicit real-data gate, not a completed
evaluation result.

## 6. Evidence and agent safeguards worth explaining

**One case, one bounded investigation.** The runner can make up to the
configured number of requests and tool calls within token and wall-time
limits. One active workspace run is enforced in a database write transaction;
request idempotency avoids charging again if a start response is lost.

**Source-qualified, read-only tools.** The eleven MCP tools include dataset
and model catalogs; `get_session`, `get_events`, `get_event`, `search_events`;
entity history and normality readiness; and attributed reference search and
technique lookup. Tool results explicitly say when evidence is unavailable or
truncated. Searches are bounded and historical queries exclude the case and
future sessions. See [tool reference](TOOLS.md).

**Outbound data boundary.** The agent cannot send raw source paths, real
identifiers, credentials or evaluation labels directly to a provider. Tool
payloads are rebuilt from allowlisted fields; identifiers become opaque
handles and host/user/IP values become per-run pseudonyms. Retrieved text is
marked as untrusted. The reversible map remains local so cited handles can
be resolved after the run. This mechanism has offline tests; no hosted
provider behavior has been acceptance-tested.

**Grounding and failure.** Before publication, a citation must have been
retrieved by the run and resolve in local evidence; literal excerpts and
named reference techniques are checked for consistency. A failed check gets
one bounded repair attempt and then a **no-report** failure. These checks
verify citation existence and consistency, **not** whether the finding's
interpretation is true. The workspace also shows cancellation, interruption,
rate-limit/key exhaustion and other incomplete outcomes rather than turning
them into a benign verdict.

**Provider adapters and keys.** Groq and OpenRouter share the same runner but
have explicit adapters. A local `.env` can specify one key or an ordered
list for the *same* provider/model. Each key is paced within the provider's
reported rate limits. A 429 cools that key down for `retry-after`, and the
request moves to a key with headroom. Waits are capped, and 429s have a
separate small allowance, so total attempts stay bounded. Switching keys never
makes a partial report publishable, and account-wide limits may affect every
key. Pacing is verified offline. A three-case hosted Groq evaluation (before
pacing) ended without reports after 429s used up its attempts. See
`docs/EVALUATION.md`. Do not put keys on slides or in a source snapshot.

## 7. What a reviewer can actually see in the UI

1. A queue of prepared sessions, dataset filter, paging and a visible
   **Unscored** explanation where candidate scores are absent.
2. A case detail with source/line/time and parsed attributes, which are not
   presented as threat assessments.
3. A start action clearly labelled fixture or configured-hosted. Configured
   hosted mode requires explicit confirmation and valid server-side settings.
4. A live trace listing tools, requested context, evidence count, duration,
   unavailable responses and any explicitly recorded hypotheses.
5. A completed report with findings, evidence handles, uncertainty,
   reference-coverage note, limitations and suggested review actions. The
   fixture's report **abstains** with severity `none`.
6. A citation drawer opening exactly one source line on demand. Handles are
   resolved on the server, not by shipping a mapping to the browser.
7. A review-only disposition with actor label and timestamp. Cancelled or
   interrupted runs have no report; an API outage is displayed as an outage.

The main workspace API is `GET /api/workspace`, `GET /api/cases`, `GET
/api/cases/{case_id}`, `POST /api/cases/{case_id}/runs`, `GET
/api/runs/{run_id}`, `GET /api/runs/{run_id}/report`, `GET
/api/runs/{run_id}/evidence/{handle}` and `POST
/api/cases/{case_id}/dispositions`. See [demo](DEMO.md) for exact request
contracts, error codes and a walkthrough.

## 8. A demo that does not overclaim

For a **live Groq demonstration**, use the prepared real evidence workspace,
not the synthetic seed below. The redesigned UI opens to the case queue. Choose
a real session, select **Run with Groq…**, confirm the outbound hosted request,
and watch the run activity card and recorded evidence-tool timeline. An
incomplete run has no verdict. The **Groq pilot** navigation view is a frozen,
read-only six-case historical result with its uncertainty and confounds. It is
not the result of the case currently on screen; see [DEMO.md](DEMO.md) for the
live-workspace setup and [EVALUATION.md](EVALUATION.md) for the pilot figures.

The optional local scripted walkthrough is reproducible without provider
availability. Use the synthetic workspace; it needs neither an API key nor the
bulk datasets:

```sh
docker compose up --build -d
docker compose exec app hestia demo-seed
```

Open <http://localhost:8000>. The demo seed refuses to overwrite an unrelated
artifact store. Follow [DEMO.md](DEMO.md): open `admin@demo-bastion`, show the
canonical lines, expand *Local scripted walkthrough* and start *Run fixture
investigation*, pause at the live tool trace, open an event citation, then
record *Inconclusive* (or another review-only disposition). The expected conclusion is **Insufficient evidence**,
not a fabricated malicious or clean verdict. On another case, cancel the
fixture run and point out that cancellation produces **no report**.

Suggested narration during the live trace: “The single agent can request
additional evidence through read-only tools. The UI records the steps we
actually observed; it does not expose private model reasoning. This demo uses
a scripted fixture to prove the workflow and guardrails, not to prove a live
model's judgment.”

Keep the HDFS benchmark to a **separate results slide**; it is a CLI/offline
experiment, not a button in the authentication workspace. A fallback video
or screenshot should be made and labelled *recorded fixture demo* if the
presenter needs one; no recorded fallback is bundled with this source.

## 9. The public HDFS benchmark: what it does and what it does not

The separate Loghub HDFS v1 dataset uses **file-block traces** rather than
user logins. The benchmark archive contains raw `HDFS.log`, block-level
`Normal`/`Anomaly` labels and preprocessed event-template traces. Hestia's
offline command checks the pinned archive digest, scans raw log lines to
identify each block's first and last line, and creates source-order train,
validation and evaluation splits. Traces crossing a boundary are excluded;
neither the upstream `Type` nor `Label` column is a predictor feature.

The run processed **11,175,629 raw lines** and **575,061 labelled blocks**.
There were **272,913** wholly training cases, **51,053** wholly validation
cases, **115,013** wholly evaluation cases, and **136,082 cross-boundary cases
excluded**. The basic Laplace-smoothed event-transition baseline learns from
**262,641 explicitly normal training traces**. Normal validation traces set
its alert threshold. This is **not a DeepLog implementation**, and it never
invokes the authentication agent.

On the **same 115,013 evaluated blocks** (1,679 labelled anomalous and
113,334 labelled normal):

- Original transition-surprise baseline: **1,629 true positives**, **50 false
  negatives**, **6,936 false positives**, **106,398 true negatives**;
  precision **19.0%**, recall **97.0%**, F1 **0.318**.
- Exploratory refinement: combine mean transition surprise, peak surprise
  and rarity of trace length in normal training. Four fixed candidates and
  three normal-validation threshold quantiles were compared on validation;
  the rule with highest validation precision subject to at least 95%
  validation recall was frozen before evaluating. It produced **1,679 TP**,
  **0 FN**, **1,235 FP**, **112,099 TN**; precision **57.6%**, recall
  **100.0% on this cohort**, F1 **0.731**.

Do not headline “100% detection” without the qualification *on this cohort*.
The refined result is **exploratory**: the earlier full evaluation aggregate
had already been seen before the refinement was designed. The upstream
anomaly labels were produced by rules, event templates came from the entire
corpus (transductive preprocessing), scoring sees completed traces rather
than detecting early, and excluding 136,082 crossing traces changes the
population measured. None of the HDFS labels proves an attack, and no
HDFS-specific investigation-agent accuracy has been measured. A further
independent public-data test is needed before claiming generalization.

Use [EVALUATION.md](EVALUATION.md) for the reproducible commands, source
attribution, exact selection policy and the interpretation of uncertainty
intervals. Dataset bulk files are downloaded separately and are **not** in
the shareable source tree.

## 10. Evidence for engineering quality

The reviewed source snapshot was built from an explicit allowlist and audited
for private artifacts, keys and paths. The latest full Python suite passed
**246 tests** with **one opt-in hosted smoke skipped**. Ruff check and format
checks passed; a separate exported-source installation ran the same suite
successfully. The frontend has **23 component/unit tests** and **12 Chrome
end-to-end cases** covering desktop and an emulated 390px viewport from its
last independent review. The exported Docker image builds and the unconfigured
API starts healthy. The hosted endpoint is **not** thereby acceptance-tested.

These checks support reproducibility and the particular behaviors they test;
they do not measure threat-verdict correctness. If presenting a later commit,
rerun the suites and update the counts rather than treating these figures as
permanent guarantees.

## 11. Suggested slide sequence (14 slides)

1. **Title and research question.** “Can a bounded evidence-using agent make
   log investigations more inspectable?” Subtitle the project as Linux
   authentication triage; place the HDFS anomaly experiment in a separate
   evaluation track.
2. **Why this matters.** Manual log volume, missing context, vague alert
   explanations and the need for source-citable findings. Do not introduce a
   measured improvement here; this is the motivation.
3. **Objective and boundaries.** One agent, one read-only MCP server, embedded
   evidence store, human review. Clarify anomaly versus intrusion and
   fixture-versus-hosted distinctions.
4. **Architecture diagram.** Use the authentication lane in Section 3. Draw
   labels outside runtime and show the redaction and citation gates.
5. **Data ingestion and evidence.** Show one original auth line becoming a
   typed event with source, timestamp and line number; mention unmatched
   events and parse failures are retained.
6. **Normality design and readiness.** Describe the five behavioral
   primitives and their intended input. Put the **0 eligible real training
   sessions / 250 HST warmup** gate prominently, not in a footnote.
7. **Investigation agent and MCP.** Show one example tool sequence from the
   fixture and explain how a later tool may revise an explicit hypothesis.
   The tools retrieve; they do not declare attacks.
8. **Guardrails and evidence quality.** Show bounded turns/tools, redacted
   provider payloads, opaque handles, local citation resolution and the
   no-report outcome after failed grounding.
9. **Workspace and analyst control.** Queue → detail → trace → report →
   citation drawer → review disposition. Annotate the fixture label visibly.
10. **Live or recorded fixture walkthrough.** Follow Section 8. Explain why
    abstention is the accurate current demonstration outcome.
11. **Separate HDFS evaluation design.** Show block traces, chronological
    source-order splitting, normal-only model learning, validation policy,
    crossing-trace exclusion and held-out metric definitions.
12. **Measured HDFS results.** Compare the two confusion matrices from
    Section 9 with four visible counts each. State both precision and recall;
    do not omit the 1,235 remaining false alerts or the exploratory status.
13. **What was verified versus unverified.** Put offline tests, source audit
    and Docker checks beside the unresolved hosted-agent and auth-model
    acceptance gates. Distinguish citation existence from semantic truth.
14. **Next work and takeaway.** Independently test the HDFS refinement on
    new public data; design and measure an HDFS investigation path only if
    desired; curate enough labelled auth data if claiming auth detection.
    Close with the contribution: a bounded, evidence-inspectable workflow
    and honest measurement boundaries.

For screenshots, take them from a fresh seeded synthetic demo. Useful frames
are the unscored queue, one canonical source line, the live tool trace, an
open citation and the analyst disposition. Caption every fixture screenshot
*Synthetic fixture run — not a live model*. For the HDFS results slide,
plot TP/FP/FN/TN counts or precision/recall for the two offline rules and
label it *Loghub HDFS v1 block-trace benchmark, exploratory refinement*.

## 12. Questions a reviewer may ask

**“Is the LLM trained on our logs?”** No. The hosted investigation model is
chosen through a provider adapter; it has not been fine-tuned here. The
normality primitives would train on explicitly eligible normal sessions,
but none of the currently selected auth sessions qualifies. The HDFS
transition baseline is a separate trained offline model.

**“Where does a malicious label come from?”** The auth MCP tools do not
return one. An investigation report can express the agent's conclusion when
configured, but hosted correctness has not been measured. Offline benchmark
labels are available to evaluation code only; HDFS `Anomaly` is not the same
as malicious.

**“Does a citation prove the conclusion?”** No. It proves the model cited
retrieved, locally resolvable evidence and that literal excerpts agree with
stored lines. Semantic support requires separate human review.

**“Why is the demo's answer insufficient evidence?”** The dataset is
synthetic and unlabelled, no real authentication model is ready, and the
fixture analyst is deliberately scripted to avoid inventing an attack
verdict. This exercises the workflow without manufacturing accuracy.

**“What makes it agent-first?”** A single case-owning agent can choose among
read-only tools, request more evidence, record and revise hypotheses, then
produce a structured, grounded report or abstain. It is bounded by external
budgets and does not have autonomous containment powers.

**“Can rotating keys overcome every free-tier limit?”** No. Hestia paces each
key within its reported limits and waits a bounded time for headroom, but
attempts and waits stay capped per run. Limits shared at the provider/account
level affect every key from that account. Hosted acceptance is still open.

**“Why did the refined HDFS result improve so much?”** On validation, all
48 misses of the original baseline were very short traces, while most false
alerts were longer. Length rarity and peak surprise were therefore tested
as simple trace features. The measured gain on the already-viewed evaluation
cohort is exploratory and may reflect properties of the benchmark's
rule-derived labels; independent confirmation is still required.

**“Can this be deployed as an automatic incident responder?”** No. The
workspace offers analyst review, not automated containment or remediation.
No live hosted verdict quality or auth-normality readiness has been verified.

## 13. Source and attribution reminders for slides

- AIT auth subset: [AIT-LDS release 2.1](https://zenodo.org/records/19483937).
- CAM auth manifestations: [CAM-LDS](https://zenodo.org/records/18390561).
- OpenSSH and HDFS v1: [Loghub](https://github.com/logpai/loghub); cite
  Zhu et al., *Loghub: A Large Collection of System Log Datasets for
  AI-driven Log Analytics*, ISSRE 2023. Follow upstream notices before
  redistributing the data itself.
- Technique reference: the project's pinned, attributed MITRE ATT&CK
  Enterprise auth-relevant subset; a match is reference context, not an
  observed attack technique.

This repository's shareable source snapshot does not include bulk datasets,
training artifacts, stored investigations or local credentials. Use synthetic
demo screenshots and the public-source links above when assembling slides.
