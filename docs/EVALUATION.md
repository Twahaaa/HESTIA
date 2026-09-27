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
