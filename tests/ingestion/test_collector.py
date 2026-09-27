from datetime import UTC, datetime
from pathlib import Path

from hestia.datasets.profiles import DatasetProfile, derive_ait_year
from hestia.ingestion.collector import collect_source


def _profile(**updates: object) -> DatasetProfile:
    values: dict[str, object] = {
        "dataset_id": "fixture",
        "source_path": "fixture/auth.log",
        "default_year": 2024,
        "timezone": "UTC",
        "timezone_provenance": "test fixture",
        "timestamp_uncertainty": "none",
        "annotation_coverage": "unknown",
    }
    values.update(updates)
    return DatasetProfile.model_validate(values)


def test_ait_year_is_derived_from_metadata(tmp_path: Path) -> None:
    metadata = tmp_path / "dataset.yaml"
    metadata.write_text("start: '2022-01-21T00:00:00'\nend: '2022-01-25T00:00:00'\n")
    assert derive_ait_year(metadata) == 2022


def test_collection_handles_rollover_mixed_formats_and_sorted_order(tmp_path: Path) -> None:
    source = tmp_path / "auth.log"
    source.write_text(
        "Dec 31 23:59:59 host sshd[1]: Invalid user old from 10.0.0.1\n"
        "2025-01-01T00:00:02+00:00 host sshd[2]: Invalid user new from 10.0.0.2\n"
        "Jan  1 00:00:01 host sshd[3]: Invalid user middle from 10.0.0.3\n"
    )
    result = collect_source(source, _profile())
    assert result.raw_line_count == 3
    assert [item.event.user for item in result.events] == ["old", "middle", "new"]
    assert [item.event.timestamp for item in result.events] == [
        datetime(2024, 12, 31, 23, 59, 59, tzinfo=UTC),
        datetime(2025, 1, 1, 0, 0, 1, tzinfo=UTC),
        datetime(2025, 1, 1, 0, 0, 2, tzinfo=UTC),
    ]
    assert result.events[0].raw_timestamp == "Dec 31 23:59:59"
    assert result.events[0].event.raw_message.startswith("Dec 31")


def test_dst_ambiguity_is_retained_as_failure_without_policy(tmp_path: Path) -> None:
    source = tmp_path / "auth.log"
    source.write_text("Nov  3 01:30:00 host sshd[1]: Invalid user user from 10.0.0.1\n")
    result = collect_source(source, _profile(timezone="America/New_York"))
    assert not result.events
    assert len(result.failures) == 1
    assert "Ambiguous local timestamp" in result.failures[0].reason
    assert result.failures[0].raw_line.startswith("Nov  3 01:30:00")


def test_dst_fold_policy_produces_aware_utc(tmp_path: Path) -> None:
    source = tmp_path / "auth.log"
    source.write_text("Nov  3 01:30:00 host sshd[1]: Invalid user user from 10.0.0.1\n")
    result = collect_source(source, _profile(timezone="America/New_York", dst_fold=1))
    assert result.events[0].event.timestamp == datetime(2024, 11, 3, 6, 30, tzinfo=UTC)


def test_unsupported_line_is_not_lost(tmp_path: Path) -> None:
    source = tmp_path / "auth.log"
    raw = "not a supported line\n"
    source.write_text(raw)
    result = collect_source(source, _profile())
    assert result.raw_line_count == 1
    assert result.failures[0].raw_line == raw.rstrip("\n")


def test_crlf_source_parses_without_changing_raw_timestamp(tmp_path: Path) -> None:
    source = tmp_path / "auth.log"
    source.write_bytes(b"Jan  1 00:00:00 host sshd[1]: Invalid user user from 10.0.0.1\r\n")
    result = collect_source(source, _profile())
    assert len(result.events) == 1
    assert not result.failures
    assert result.events[0].raw_timestamp == "Jan  1 00:00:00"
