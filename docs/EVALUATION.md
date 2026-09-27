# Evaluation status

## Separate public HDFS anomaly benchmark

Hestia also offers an **offline benchmark baseline**, separate from its
authentication case agent. Obtain the full Loghub **HDFS v1** archive from
[Zenodo record 8196385](https://zenodo.org/records/8196385) as `HDFS_v1.zip`
and run:

```sh
uv run hestia evaluate-hdfs --archive /path/to/HDFS_v1.zip \
  --config evaluation/configs/hdfs.json
uv run hestia inspect-hdfs --archive /path/to/HDFS_v1.zip \
  --block-id blk_-3544583377289625738
```

The pinned upstream archive has MD5 `76a24b4d9a6164d543fb275f89773260`;
the evaluator checks it and records its SHA-256. It does not download data or
include bulk logs in the source archive. Results are written immutably under
`artifacts/evaluation/hdfs-<id>/results.json`; a repeat with the same inputs
refuses to replace them.

One HDFS case is a **completed file-block trace**. A raw-log scan records its
first and last source line. Source-order boundaries allocate earlier traces to
training, later traces to validation, and the latest to evaluation; traces
crossing a boundary are excluded. Only explicitly `Normal` training traces
update a Laplace-smoothed event-transition baseline. Only `Normal` validation
traces set a fixed 95th-percentile alert threshold. The untouched test traces
are scored before their `Normal`/`Anomaly` labels are joined. `inspect-hdfs`
returns bounded, source-line-qualified raw evidence without labels. The
`Event_traces.csv` `Type` and `Label` columns never become model features.

The full public run used 11,175,629 raw lines and 575,061 labelled block traces.
Of these, 272,913 fell wholly before the training boundary, 51,053 wholly
inside validation, 115,013 wholly inside evaluation, and **136,082 crossed
boundaries and were excluded**. The measured holdout contained 1,679 anomalous
and 113,334 normal traces. The simple baseline produced 1,629 true positives,
50 false negatives, 6,936 false positives and 106,398 true negatives:
precision **0.190**, recall **0.970**, F1 **0.318**. These are benchmark
*anomaly* labels, not confirmed attacks, and are **baseline results**, not
Hestia agent or DeepLog performance. The high false-positive count is a real
limitation, not a result to hide. Full configuration, uncertainty intervals and
input digests are in the local result artifact.

The upstream labels are derived by handcrafted rules. Upstream event templates
were made using the entire log corpus, so template extraction is transductive;
this evaluation does not measure a parser trained only on earlier logs. Full
block-trace scoring is retrospective, not early detection. Source order is a
proxy for chronology; cross-boundary exclusions may change the test
population. The public data is [Loghub](https://github.com/logpai/loghub),
Zhu et al., *Loghub: A Large Collection of System Log Datasets for AI-driven
Log Analytics*, ISSRE 2023; its dataset license notice and attribution terms
must accompany any redistributed copy. Hestia's source export redistributes
none of the HDFS dataset.

### Validation-selected trace baseline (exploratory)

Run `uv run hestia evaluate-hdfs-refined --archive /path/to/HDFS_v1.zip` to
compare the original mean transition surprise against four **fixed** trace
features: mean surprise, mean plus normal-trained length rarity, mean plus
peak transition surprise, and their combination. Each candidate's alert
threshold is the 95th, 97th or 99th percentile of **normal validation**
scores. From those 12 options, the evaluator selects the highest validation
precision with at least 95% validation recall. Ties favor higher recall and
the simpler rule. The transition counts and length distribution learn only
from earlier explicitly normal training traces; anomaly labels are used to
compare candidates on validation, never as a feature or for training the
sequence model. The selection and thresholds are frozen before scoring the
evaluation traces.

The validation analysis found that all 48 of the original baseline's missed
anomalies were **two-event traces**, while 2,223 of 2,475 false alerts were
11–20-event traces. For a varied source-order/length sample (not a random
sample), `HDFS.log:6858771` and `HDFS.log:6858806` show a missed two-line
trace, whereas a 13-line false alert spans `HDFS.log:6856067–6860955` and
includes allocation, receiving and storage. These observations motivated the
predeclared length and peak features; they do not establish why upstream
assigned its rule-derived labels.

Validation chose **mean + length rarity + peak surprise** with the 99th-
percentile normal threshold (2.3997858903). On the *same* 115,013-case
evaluation cohort as the original baseline, the frozen choice produced
**1,679 TP, 0 FN, 1,235 FP and 112,099 TN**: precision **0.576**, recall
**1.000**, F1 **0.731**. False alerts fell from 6,936 to 1,235 while
retaining all labelled anomalies *on this dataset*. Exact counts, 95% Wilson
intervals and the entire validation grid are in the immutable local result
under `artifacts/evaluation/hdfs-refined-<id>/results.json`. This is an
**exploratory comparison**, not an untouched confirmatory result: the prior
full-cohort aggregate had already been examined before this experiment was
designed. The rule-derived labels, globally preprocessed templates, excluded
cross-boundary traces and retrospective full-trace scoring further limit
generalization. A 100% measured recall here is not a guarantee for new logs.

## Authentication evaluation

Hestia measures stored investigations without sending evidence to a model during
evaluation. Run `hestia evaluate --config evaluation/configs/local.json` after
preparing evidence. It writes a hash-identified, immutable result under
`artifacts/evaluation/`; a repeated identical measurement refuses to overwrite it.
The config references local preparation manifests and the local reference index;
these are not included in the public source archive. Prepare them as described in
`docs/DEMO.md` before running the command from an exported copy.

## Ground truth and denominators

Evaluation annotations are optional, private JSONL sidecars with one row per
reviewed event: `event_id`, `dataset_id`, `source_path`, `line_no`, `truth`
(`attack`, `normal`, `unknown`), and `annotation_source`. A mismatch against the
prepared event's source and line is rejected. The sidecar is read only by the
offline evaluator and never entered into runtime evidence, training, scoring,
MCP tools, or provider requests.

An attack-labelled event makes its session an attack case even if other events
are normal or unknown. A session is normal only if **all** constituent events
are explicitly labelled normal. Any other session is unknown. Unmatched events
stay outside session truth and appear separately in event coverage; their
labels must be reviewed independently. Only frozen `evaluation` split sessions
enter the held-out confusion matrix. Absent reports and
`insufficient_evidence` are abstentions, never benign predictions. Unknown
truth is counted separately, not included in the labelled denominator.
Precision, recall, F1, Wilson intervals and decision coverage are null when
their denominators are zero. False alerts per normal hour require measured
normal time exposure, not a count of sessions. Citation validity is a structural
check, not a human semantic-grounding assessment.

## Current local result

The first offline run on the current local evidence store (2026-09-27) found
12,777 events, 457 sessions, 10,682 unmatched events, **zero** candidate scores,
**zero** evaluation-split sessions, and no supplied evaluation labels. Every
prepared session is `excluded`; no real normality model or calibrated alert
budget exists. No hosted provider run has been made. Accuracy, latency, semantic
grounding, and false-alert rate therefore remain **unmeasured**, not zero or
perfect. The local fixture analyst is a mechanics demonstration, not a model
under test. The local result and its exact input digests live in
`artifacts/evaluation/` and are deliberately omitted from source exports.

For human semantic review, sample reports before seeing aggregate scores and
grade each finding as supported, contradicted, or unassessable against the
underlying source lines. Separately mark whether uncertainty is stated,
recommendations are proportionate and actionable, and any technique inference
claims more than the reference can support. Record two independent reviewer
judgments and adjudicate disagreements. A citation resolving successfully does
not pass this rubric by itself.

## Investigation agent evaluation

`hestia evaluate-agent --config evaluation/configs/agent-smoke.json` evaluates
the case-owning agent itself, separately from the HDFS baseline above (which is
not an agent result). Cases are chosen from store structure only: for each
configured dataset, sessions are ordered by `sha256("<seed>:<session_id>")`, and
sessions whose source file is searchable in the reference index are excluded.
The order is interleaved by dataset, so `--limit-cases N` stays stratified. The
agent's case brief carries a masked dataset name, because a dataset name can
act as a label (CAM-LDS logs were captured during attack steps). Labels are
read only after every run has finished.

It reports outcomes (verdicts, abstentions, incomplete runs by cause), citation
validity (structural, with repair attempts and issue kinds), tool use per tool
and per run, run and tool latency, requests, provider attempts, key rotations
and tokens. For hosted runs with a configured list price it also reports a
list-price cost estimate, which is not a billed amount. Each run's record and
the result are written once under `artifacts/evaluation/agent-<id>/`.

- `--mode fixture` (default) runs the deterministic scripted analyst. The result
  is labelled `fixture_mechanics_only`. It tests the harness and is **never**
  model accuracy. Its token counts are framework estimates.
- `--mode hosted --plan` prints the exact provider, model, cases, request and
  token ceilings, worst-case list-price cost, a description of outbound data, and
  an approval token. Contacts nothing.
- `--mode hosted --approve <token>` runs only if the local configuration names
  that same provider and model and the token matches the plan. Anything else
  refuses; there is no fallback to the fixture or to another provider.

A case starts only if its full token reserve and request ceiling still fit.
Pydantic AI checks token limits after each response, so one pass can overshoot
by at most one request.

**Current status (2026-09-27).** A six-case fixture run (two sessions each
from AIT, CAM and OpenSSH) completed with 6/6 cited abstentions, 6/6
structurally valid citations, and 24 tool calls. This confirms the mechanics
only.

**First hosted run (Groq `openai/gpt-oss-120b`, 3 cases, one per dataset,
before rate-limit pacing existed).** All three cases ended **incomplete, with
no report**, because each used its 8-attempt ceiling:
- 24 HTTP attempts: 17 succeeded and 7 were HTTP 429, with 7 key switches.
- 16 tool calls, none unavailable.
- 32,040 provider-reported tokens, a list-price estimate of $0.0058 (not a
  billed amount).
- Run p50 5.5 s / p95 7.0 s.

Completion was 0/3. Abstention and citation validity are therefore undefined.
This describes provider limits and the turn budget on 3 cases. It is **not**
an accuracy result. Pacing (see `docs/AGENT.md`) was added afterwards. 429s now
use a separate allowance (4 per case), so the per-case HTTP ceiling is
turns + 4.

**Second hosted run (same 3 cases, 12-turn evaluation budget chosen after the
first run ran out of turns, first pacing version).** It got 9 HTTP 200s and 0
429s, but completion was again 0/3. The first case made 9 requests in 12 s and
8 tool calls, then stopped. The pacer had applied a full 60-second window per
key and judged no key ready within its 45 s wait cap. The other two cases
stopped immediately on that shared state, with no requests. This used 26,169
tokens ($0.0047 list price). The pacer now follows the provider's continuously
refilling budget, waits up to 65 s, pauses for headroom between cases, and
records each key's rate-limit numbers (never keys) after every case.

**Third hosted run (same cases and budget, corrected pacing).**
- **Rate limits:** 34 HTTP requests, 31 × 200, **0 × 429**, and 3 × 400 that
  the framework retried (most likely malformed tool calls). Paced waits
  totalled 103 s. Every key reported 8,000 tokens per minute.
- **OpenSSH case:** completed with a **malicious** verdict (high severity,
  confidence 0.85, ATT&CK T1110.001 password guessing), 3 findings and 8
  citations, all structurally valid.
- **AIT and CAM cases:** reached the 12-turn request limit while still
  searching, with no report.
- **Totals:** completion 1/3, run p50 50 s, 106,167 tokens ($0.019 list price).

The dataset is unlabelled and the findings have not been human-reviewed, so the
verdict's correctness is **unknown**. This is behaviour on 3 cases, not
accuracy.

Since then the agent is told its remaining turn budget, and must conclude from
retrieved evidence once its gathering turns are used (see `docs/AGENT.md`).
The evaluation budget is 16 turns.

**Fourth hosted run (16 turns, budget-aware conclusion).**
- **Requests:** 38 HTTP attempts: 28 × 200, 7 × 400, 2 × 429, 1 × 413.
- **OpenSSH case:** again completed as **malicious** / T1110.001, with 5
  structurally valid citations.
- **AIT case:** failed on HTTP 413 after 9 requests. A single request most
  likely exceeded the free plan's 8,000 tokens-per-minute limit.
- **CAM case:** failed after using up its output retries. This was most likely
  because of malformed tool calls, which Groq rejects with HTTP 400.
- **Totals:** completion 1/3, 75,050 tokens ($0.013 list price).

Correctness remains unknown.

Since then, older tool results are condensed to their evidence handles so each
request stays under a configured size, and the evaluation allows 4 output
retries. A second config, `evaluation/configs/agent-smoke-qwen.json`, runs the
same cases on Groq's free-plan `qwen/qwen3.8-27b` for a same-case comparison.
**AIT-only hosted run (gpt-oss-120b, 2 AIT cases).**
- **Requests:** 30 HTTP attempts, 27 × 200 and 3 × 400. There were no 429s
  and no 413s. 24 older tool results were condensed.
- **Case completed:** one case reported **`insufficient_evidence`**. Its
  session held a single authentication failure, and no anomaly score was
  available.
- **Case failed:** the previously failing case now gathered for 13 turns, then
  failed on an HTTP 400 at the turn where it had to conclude.
- **Totals:** 59,205 tokens ($0.010 list price), run p50 28 s. This covers AIT
  only and is not an accuracy result.

Case correctness is **not measurable** on the current data. The 8
upstream-labelled AIT attack lines are all outside sessions: 7 are unmatched
events and 1 is a parse failure, so no labelled attack reaches a session-owning
case. CAM-LDS has no per-line labels. OpenSSH_2k is unlabelled. Missing labels
are never treated as benign. Measuring correctness needs reviewed,
source-qualified labels for selected sessions (normal as well as attack), or
unmatched privilege-escalation lines promoted into investigable cases.

### Labelled AIT + CAM pilot (upstream-convention labels)

`hestia label-sources` derives **evaluation-only** labels from each dataset's
own published convention and writes them to a private sidecar
(`artifacts/evaluation/labels/`, never exported). It also writes a manifest
recording the store, label and rule hashes.

- **AIT-LDS V2.1** ([Zenodo 19483937](https://zenodo.org/records/19483937),
  CC BY-NC-SA 4.0): a line listed in its `labels/` file is attack. Every other
  event is normal, because upstream states that unlisted events "can be
  considered to be labeled as 'normal'". The command refuses to run if the
  upstream labels directory is missing.
- **CAM-LDS `manifestations_filtered`**
  ([Zenodo 18390561](https://zenodo.org/records/18390561), CC BY 4.0): these are
  logs that are direct consequences of attacks, so every event is attack. A
  session's ATT&CK technique set comes from `techniques/<T####-###>/` folders
  with the same content hash. One log can be filed under several techniques.
- **OpenSSH** gets no label and stays unknown.

This produces 10,832 labelled events (AIT 7 attack and 6,666 normal; CAM 4,159
attack), and technique sets for 302 of the 303 CAM sessions. Adopting AIT's
"unlisted = normal" rule applies to **evaluation labels only**. The H1 policy
("unlabelled = unknown") and the normality training gate (0 eligible sessions)
are unchanged.

`evaluation/configs/agent-labelled.json` selects 3 AIT and 3 CAM sessions
without looking at labels (seed 20260927, same budget as the AIT-only run).
Labels are opened only after every run has finished. Scoring adds a
confusion matrix with Wilson intervals, and a technique match for attack cases
with a known technique set:

- **exact:** a proposed ID is in the set;
- **parent:** only the base technique agrees;
- **mismatch**, **none proposed**, or **no report.**

Every case counts in the technique-match denominator.

The results carry these caveats, and each result file records them:

- The labels are rule-derived upstream conventions, not reviewed per event.
- **Dataset confound:** every attack case is CAM and every normal case is AIT,
  so a detector of dataset style would score the same.
- **Technique leakage:** the reference index holds CAM documents filed under the
  same techniques, so technique matches are inflated.
- **Sample size:** n=6, so the intervals are wide.

The fixture run (`agent-f742f21a09e6bc08db3f`) checks mechanics only. The
scripted analyst abstains on all six cases, so every technique case is scored
`none_proposed`.

**Hosted pilot (Groq `openai/gpt-oss-120b`, 6 cases, one run each).**

- **Reports:** 3 of 6 cases produced one, and all 3 had valid citations. The
  other 3 stopped for operational reasons: two used up their rate-limit
  allowance and one reached the turn limit.
- **Detection:** 1 true positive and 1 false positive; 4 abstained.
  - The true positive is a CAM login, then `sudo` reading `/etc/shadow`.
  - The false positive is an AIT user with repeated login failures over two
    days, which the upstream convention labels normal.
  - Precision 0.50 (Wilson 95% 0.09–0.91). Recall 1.00 (0.21–1.00), from a
    single decided attack case.
- **Technique match:** 0 of 3. The model proposed no ATT&CK IDs.
- **Cost:** 108 HTTP attempts (17 × 429) and 197K tokens, about $0.03 at list
  price.

This is a **pilot**, not a detection-accuracy claim. Only two cases were
decided, and the caveats above apply in full.

## Next measurement gate

Obtain source-qualified reviewed labels and explicitly eligible normal training
observations, with separate grouped normal validation and evaluation sets. HST
requires 250 eligible observations per relevant host/source-IP model. Rebuild
the reference index with held-out CAM sources excluded before evaluating them.
Freeze the actual prompt, model revision, provider configuration, calibration
and budgets, and run the four matched ablation arms (normality only, fixed
context, evidence tools, and full context). Record order, repeats, usage and
cost; add human-reviewed semantic-grounding rubrics. Do not claim model
superiority or a trained SOC detector before those results exist. No dataset
bulk files or private annotations are redistributed in the source snapshot.
