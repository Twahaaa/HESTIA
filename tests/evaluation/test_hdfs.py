import csv
import hashlib
import io
import json
import zipfile

import pytest

from hestia.evaluation.hdfs import (
    TransitionBaseline,
    _split,
    evaluate_hdfs,
    inspect_block,
)


def _archive(tmp_path, *, duplicate=False, size=12, anomalies=(10,)):
    path = tmp_path / "HDFS_v1.zip"
    labels = io.StringIO()
    writer = csv.writer(labels)
    writer.writerow(("BlockId", "Label"))
    rows = io.StringIO()
    traces = csv.writer(rows)
    traces.writerow(("BlockId", "Label", "Type", "Features", "TimeInterval", "Latency"))
    raw = []
    for index in range(size):
        block = f"blk_{index}"
        anomaly = index in anomalies
        writer.writerow((block, "Anomaly" if anomaly else "Normal"))
        traces.writerow(
            (
                block,
                "Fail" if anomaly else "Success",
                "",
                "[E9,E9]" if anomaly else "[E1,E2]",
                "",
                "",
            )
        )
        raw.append(f"081109 203615 148 INFO dfs.DataNode: block {block} complete\n")
    if duplicate:
        writer.writerow(("blk_10", "Normal"))
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("HDFS.log", "".join(raw))
        archive.writestr("preprocessed/anomaly_label.csv", labels.getvalue())
        archive.writestr("preprocessed/Event_traces.csv", rows.getvalue())
    config = tmp_path / "hdfs.json"
    config.write_text(json.dumps({"archive_md5": hashlib.md5(path.read_bytes()).hexdigest()}))
    return path, config


def test_source_ordered_public_format_and_held_out_metrics(tmp_path):
    archive, config = _archive(tmp_path)
    result = evaluate_hdfs(archive, config, tmp_path / "results")
    assert result["split_counts"] == {
        "training": 7,
        "validation": 2,
        "evaluation": 3,
        "cross_boundary": 0,
    }
    assert result["training_normal"] == 7
    assert result["validation_normal"] == 2
    assert result["holdout"]["tp"] == 1
    assert result["holdout"]["tn"] == 2
    assert result["holdout"]["f1"] == 1.0
    assert inspect_block(archive, "blk_10", limit=1)["events"][0]["line_no"] == 11
    assert "Anomaly" not in json.dumps(inspect_block(archive, "blk_10"))
    with pytest.raises(FileExistsError):
        evaluate_hdfs(archive, config, tmp_path / "results")


def test_crossing_trace_is_never_used_for_training_or_testing():
    assert _split(1, 30, 10, 20) == "cross_boundary"
    assert _split(10, 25, 10, 20) == "cross_boundary"
    assert _split(20, 21, 10, 20) == "evaluation"


def test_labels_are_not_features_and_archive_identity_is_checked(tmp_path):
    baseline = TransitionBaseline()
    baseline.learn(("E1", "E2"))
    assert baseline.score(("E9", "E9")) > baseline.score(("E1", "E2"))
    archive, config = _archive(tmp_path, duplicate=True)
    with pytest.raises(ValueError, match="duplicate"):
        evaluate_hdfs(archive, config, tmp_path / "results")
    config.write_text(json.dumps({"archive_md5": "0" * 32}))
    with pytest.raises(ValueError, match="checksum"):
        evaluate_hdfs(archive, config, tmp_path / "results")
    with pytest.raises(ValueError, match="invalid block"):
        inspect_block(archive, "../blk_10")
