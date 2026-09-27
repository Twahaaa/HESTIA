# Evidence preparation

Hestia keeps preparation separate from training, scoring, and evaluation. Preparation
normalizes source timestamps, retains parse failures and unmatched events, and writes
runtime evidence without exposing evaluation labels. An absent evidence database or model
artifact is reported as not ready; it is never treated as benign evidence.

## Prepare evidence

Install the locked environment, inspect the available command options, and prepare one
configured dataset with an explicit session gap:

```sh
uv sync --locked
uv run hestia prepare-data --help
uv run hestia prepare-data --dataset ait-auth --run-id local-ait --gap-seconds 300
```

Use a new run identifier for a materially different preparation configuration. Source
profiles provide the year and timezone policy; do not substitute the current year for
syslog records that omit it. Repeat preparation is expected to preserve stable evidence
identifiers and counts.

## Train eligible normal evidence

Training consumes only the explicitly curated reference split. The generated manifest
excludes current datasets because no selected source declares sufficient benign coverage;
the command records that unmet gate without weakening eligibility or warmup:

```sh
uv run hestia train-normality \
  --split-manifest artifacts/preparation/local-ait-splits.json \
  --deployment-timezone UTC
```

When eligible normal records exist, model artifacts are stored with training hashes,
versions, entity identity, feature schema, seed, and observation counts. Scoring abstains
for each entity model until its registry warmup is met; HalfSpaceTrees remains at 250.

## Calibrate on held-out normal validation

Calibration reads an evaluation-only JSON sidecar whose rows contain `evidence_ref`,
`raw_score`, and `normal_validation`. It refuses non-normal rows and freezes deterministic
tie handling before test scoring:

```sh
uv run hestia calibrate-normality \
  --scores artifacts/preparation/normal-validation-scores.json \
  --max-alerts-per-batch 5
```

Do not reuse evaluation labels to select training records or calibration thresholds.

## Inspect the public status

Start the API and query its label-free preparation summary:

```sh
uv run uvicorn hestia.api.app:create_app --factory
curl --fail --silent http://localhost:8000/api/preparation | python -m json.tool
```

The response includes source, event, parse-failure, session, and unmatched-event counts,
plus artifact readiness reasons. It does not contain event labels or evaluation results.
