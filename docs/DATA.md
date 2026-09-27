# Dataset contract

- AIT authentication logs: [public dataset](https://zenodo.org/records/19483937), release 2.1. Import `full/gather/*/logs/auth.log*`, matching `full/labels/*/logs/auth.log*`, and `full/dataset.yaml`.
- CAM authentication manifestations: [public dataset](https://zenodo.org/records/18390561). Preserve the `manifestations_filtered` relative hierarchy for technique, step and sequence identity. Only `auth.log` is copied; unrelated alert streams are excluded.
- OpenSSH: [Loghub sample](https://github.com/logpai/loghub/tree/master/OpenSSH). Import `OpenSSH_2k.log` once, excluding the duplicate `auth.log`.
- HDFS v1 is a separate offline anomaly benchmark ([Loghub/Zenodo](https://zenodo.org/records/8196385)); it is not imported as an auth dataset or exposed as a threat-verdict case. Its raw blocks and label sidecar stay outside runtime evidence. See `docs/EVALUATION.md`.

Dataset releases retain their own licensing and attribution requirements. Bulk data
is excluded from source exports. Review upstream terms before redistributing data.
The importer does not fetch data or grant redistribution rights.

Labels belong to the evaluation/curation boundary. Neither the API nor MCP catalog
returns per-event attack labels. Missing annotations do not establish benignness.
`select_normal_pool` only treats unlabelled entries as normal when the caller
explicitly declares that source's annotation coverage complete. Do not make that
declaration for Loghub merely because its sample is unlabelled.

Source identifiers must be relative and unique. CAM parsing requires an explicit
source identifier and year. Syslog input lacks timezone/year in some formats; the
parser is a low-level primitive returning naive timestamps. A dataset-aware UTC
collector is planned before model training. Preserve original line numbers and
all parse failures. Sessionization partitions by source, host, IP and user;
unmatched events remain available separately.

Model primitives are code, not trained weights. Cold scores cannot be interpreted
as benign verdicts. Training requires a documented normal-only pool, warmup,
validation and frozen evaluation splits. Serialized estimator blobs are for trusted
local artifacts only; their hashes are integrity checks, not authentication. Never
load uploaded or downloaded pickle data through the registry.

Structured-field tokenization leaves raw log text intact and is not a hosted-model
redaction boundary. Outbound provider data controls must be implemented before
hosted inference is enabled.
