"""Isolated evidence and reference fixtures for the investigative tool tests.

The fixtures are visibly synthetic so no test can be mistaken for evidence that
a real model was trained or that real traffic was proven benign.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from hestia.config import Settings
from hestia.datasets.profiles import DatasetProfile
from hestia.ingestion.collector import collect_source
from hestia.ingestion.sessionization import sessionize_events
from hestia.knowledge import build_reference_index, write_index
from hestia.knowledge.attack import AttackSnapshot
from hestia.mcp.context import ToolContext
from hestia.store.repository import EvidenceRepository

FIXTURE_LOG = """\
Jan  2 03:04:05 fixture-host sshd[11]: Failed password for invalid user alice from 198.51.100.7 port 2201 ssh2
Jan  2 03:04:07 fixture-host sshd[11]: Failed password for invalid user alice from 198.51.100.7 port 2201 ssh2
Jan  2 03:04:09 fixture-host sshd[11]: Accepted password for alice from 198.51.100.7 port 2201 ssh2
Jan  2 03:04:11 fixture-host sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow
Jan  2 03:05:00 fixture-host sshd[12]: Accepted publickey for bob from 203.0.113.9 port 2202 ssh2
Jan  3 09:00:00 fixture-host sshd[13]: Accepted password for alice from 198.51.100.7 port 2203 ssh2
Jan  3 09:00:30 fixture-host CRON[99]: pam_unix(cron:session): session opened for user root
not a parseable authentication line at all
"""


def _profile(source_path: str) -> DatasetProfile:
    return DatasetProfile(
        dataset_id="fixture",
        source_path=source_path,
        default_year=2025,
        timezone="UTC",
        timezone_provenance="synthetic fixture",
        timestamp_uncertainty="none",
        annotation_coverage="none",
    )


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        data_root=tmp_path / "data",
        artifact_root=tmp_path / "artifacts",
        frontend_dist=tmp_path / "no-ui",
        mcp_default_page_size=25,
        mcp_max_page_size=50,
    )


@pytest.fixture
def prepared(settings: Settings, tmp_path: Path) -> Settings:
    """Import one synthetic source into an isolated evidence store."""
    source = tmp_path / "auth.log"
    source.write_text(FIXTURE_LOG, encoding="utf-8")
    repository = EvidenceRepository(settings.evidence_database)
    repository.initialize()
    collection = collect_source(source, _profile("fixture/auth.log"))
    events = [item.event for item in collection.events]
    sessions, unmatched = sessionize_events(events, gap_seconds=300)
    repository.import_source(
        collection, sessions, ((event, "missing user or source IP") for event in unmatched)
    )
    return settings


@pytest.fixture
def context(prepared: Settings) -> ToolContext:
    return ToolContext(settings=prepared)


@pytest.fixture
def empty_context(tmp_path: Path) -> ToolContext:
    """A deployment where nothing has been prepared or built yet."""
    empty = tmp_path / "empty"
    return ToolContext(
        settings=Settings(
            data_root=empty / "data",
            artifact_root=empty / "artifacts",
            frontend_dist=empty / "no-ui",
        )
    )


@pytest.fixture
def session_id(context: ToolContext) -> str:
    repository = context.repository()
    rows = repository.read_entity_sessions(
        entity_type="host",
        entity_id="fixture-host",
        before=datetime(2030, 1, 1, tzinfo=UTC),
    )
    assert rows, "the fixture must produce at least one session"
    return str(rows[0]["session_id"])


@pytest.fixture
def reference_settings(settings: Settings, tmp_path: Path) -> Settings:
    """Build a tiny reference index from a synthetic CAM tree and ATT&CK subset."""
    technique_dir = (
        settings.data_root
        / "raw/cam-auth/manifestations_filtered/techniques/T1110-001/step-1/fixture-host/logs/log"
    )
    technique_dir.mkdir(parents=True)
    (technique_dir / "auth.log").write_text(FIXTURE_LOG, encoding="utf-8")
    snapshot = AttackSnapshot(
        attack_version="19.2",
        source_url="https://example.invalid/enterprise-attack-19.2.json",
        upstream_sha256="0" * 64,
        attribution="MITRE ATT&CK® synthetic fixture subset; attribution is required.",
        filter_rule="synthetic fixture",
        retrieved_at=datetime(2026, 1, 1, tzinfo=UTC),
        techniques=(
            {
                "technique_id": "T1110.001",
                "name": "Password Guessing",
                "description": "Adversaries guess passwords to gain access to accounts.",
                "url": "https://attack.mitre.org/techniques/T1110/001",
                "tactics": ("credential-access",),
                "platforms": ("Linux",),
                "data_sources": ("User Account: User Account Authentication",),
            },
        ),
    )
    index = build_reference_index(settings.data_root, attack_snapshot=snapshot)
    write_index(index, settings.knowledge_index)
    return settings


@pytest.fixture
def reference_context(reference_settings: Settings) -> ToolContext:
    return ToolContext(settings=reference_settings)


@pytest.fixture
def split_manifest_writer():
    """Write a minimal split manifest without going through the H1 builder."""
    return _write_split_manifest


def _write_split_manifest(path: Path, *, source_path: str, item_id: str, split: str) -> Path:
    payload = {
        "schema_version": 1,
        "strategy": "fixture",
        "coverage_claims": ["fixture"],
        "source_hashes": {source_path: "a" * 64},
        "entries": [
            {
                "item_id": item_id,
                "split": split,
                "content_hash": "a" * 64,
                "host": "fixture-host",
                "campaign_id": None,
                "reason": "fixture",
            }
        ],
        "manifest_hash": "b" * 64,
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path
