"""A designated, visibly synthetic demo workspace.

`hestia demo-seed` prepares a small synthetic authentication log into an empty
artifact root and marks that root as a demo workspace. Only a marked workspace
can be reset, and a reset removes case runs, traces, reports, dispositions and
handle maps while leaving prepared evidence untouched. A store that already holds
evidence and carries no marker is never seeded or reset.

Every address in the log is from the documentation ranges of RFC 5737 and every
name is invented. Nothing here is evidence about a real system, and the data set
carries no annotations, so it cannot be mistaken for labelled or benign data.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from hestia.config import Settings

DEMO_DATASET_ID = "synthetic-demo"
DEMO_SOURCE_PATH = "synthetic-demo/auth.log"

SYNTHETIC_LOG = """\
Mar  3 08:58:01 demo-bastion sshd[2101]: Accepted publickey for maya from 192.0.2.10 port 50122 ssh2
Mar  3 08:58:40 demo-bastion sudo: maya : TTY=pts/0 ; PWD=/home/maya ; USER=root ; COMMAND=/usr/bin/systemctl status nginx
Mar  3 09:12:11 demo-bastion sshd[2140]: Failed password for invalid user admin from 198.51.100.23 port 41022 ssh2
Mar  3 09:12:14 demo-bastion sshd[2140]: Failed password for invalid user admin from 198.51.100.23 port 41022 ssh2
Mar  3 09:12:18 demo-bastion sshd[2140]: Failed password for invalid user admin from 198.51.100.23 port 41022 ssh2
Mar  3 09:12:23 demo-bastion sshd[2140]: Failed password for invalid user oracle from 198.51.100.23 port 41022 ssh2
Mar  3 09:12:29 demo-bastion sshd[2140]: Failed password for invalid user test from 198.51.100.23 port 41022 ssh2
Mar  3 10:05:00 demo-bastion sshd[2203]: Failed password for leo from 203.0.113.44 port 60311 ssh2
Mar  3 10:05:06 demo-bastion sshd[2203]: Accepted password for leo from 203.0.113.44 port 60311 ssh2
Mar  3 10:05:31 demo-bastion sudo: leo : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/cat /etc/shadow
Mar  3 10:06:02 demo-bastion sudo: leo : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/crontab -e
Mar  3 13:30:45 demo-app sshd[3310]: Accepted publickey for deploy from 192.0.2.30 port 51900 ssh2
Mar  3 13:31:02 demo-app sudo: deploy : TTY=pts/0 ; PWD=/srv/app ; USER=root ; COMMAND=/usr/bin/systemctl restart app
Mar  3 21:47:19 demo-app sshd[3402]: Accepted password for maya from 203.0.113.80 port 49000 ssh2
Mar  3 21:47:55 demo-app sshd[3402]: Received disconnect from 203.0.113.80 port 49000:11: disconnected by user
Mar  4 02:14:09 demo-app CRON[3519]: pam_unix(cron:session): session opened for user root by (uid=0)
Mar  4 07:59:12 demo-bastion sshd[2290]: Accepted publickey for maya from 192.0.2.10 port 50310 ssh2
this line is deliberately unparseable so a parse failure is retained
"""


class DemoWorkspaceError(RuntimeError):
    """The artifact root is not, and must not become, a demo workspace."""


def is_demo_workspace(settings: Settings) -> bool:
    return settings.demo_marker.is_file()


def seed_demo_workspace(settings: Settings) -> dict[str, Any]:
    """Prepare the synthetic log into a new or already-designated demo workspace."""
    from hestia.datasets.profiles import DatasetProfile
    from hestia.ingestion.collector import collect_source
    from hestia.ingestion.sessionization import sessionize_events
    from hestia.store.repository import EvidenceRepository

    database = settings.evidence_database
    if database.exists() and not is_demo_workspace(settings):
        raise DemoWorkspaceError(
            f"{database} already exists and is not a designated demo workspace; "
            "point HESTIA_ARTIFACT_ROOT at an empty directory to seed a demo"
        )
    settings.artifact_root.mkdir(parents=True, exist_ok=True)
    source = settings.artifact_root / "demo" / "auth.log"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(SYNTHETIC_LOG, encoding="utf-8")
    profile = DatasetProfile(
        dataset_id=DEMO_DATASET_ID,
        source_path=DEMO_SOURCE_PATH,
        default_year=2026,
        timezone="UTC",
        timezone_provenance="synthetic demo log; timezone declared, not observed",
        timestamp_uncertainty="none",
        annotation_coverage="none",
    )
    repository = EvidenceRepository(database)
    repository.initialize()
    collection = collect_source(source, profile)
    events = [item.event for item in collection.events]
    sessions, unmatched = sessionize_events(events, gap_seconds=300)
    imported = repository.import_source(
        collection, sessions, ((event, "missing user or source IP") for event in unmatched)
    )
    settings.demo_marker.write_text(
        json.dumps(
            {
                "designated_demo_workspace": True,
                "dataset_id": DEMO_DATASET_ID,
                "seeded_at": datetime.now(UTC).isoformat(),
                "note": (
                    "Synthetic demo workspace. Reset from the workspace removes case runs "
                    "and dispositions here only; prepared evidence is kept."
                ),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    reference = _build_reference_index(settings)
    return {
        "artifact_root": str(settings.artifact_root),
        "dataset_id": DEMO_DATASET_ID,
        "imported": imported,
        "events": len(events),
        "sessions": len(sessions),
        "unmatched": len(unmatched),
        "parse_failures": len(collection.failures),
        "reference_index": reference,
        "note": "Synthetic data. It is not labelled, not benign-proven, and not evaluation data.",
    }


def _build_reference_index(settings: Settings) -> str:
    """Build the reference index from the pinned ATT&CK subset when it is present."""
    from hestia.knowledge import (
        SNAPSHOT_FILENAME,
        build_reference_index,
        read_snapshot,
        write_index,
    )

    if settings.knowledge_index.is_file():
        return "already present"
    snapshot_path = settings.attack_reference_root / SNAPSHOT_FILENAME
    if not snapshot_path.is_file():
        return "not built: no pinned ATT&CK snapshot in the data root"
    index = build_reference_index(settings.data_root, attack_snapshot=read_snapshot(snapshot_path))
    write_index(index, settings.knowledge_index)
    return f"built with {len(index.documents)} documents"


def reset_demo_workspace(settings: Settings) -> dict[str, Any]:
    """Clear case activity in a designated demo workspace. Evidence is kept."""
    from hestia.store.repository import EvidenceRepository

    if not is_demo_workspace(settings):
        raise DemoWorkspaceError("this artifact root is not a designated demo workspace")
    repository = EvidenceRepository(settings.evidence_database)
    repository.initialize()
    if repository.active_case_runs():
        raise DemoWorkspaceError("a case run is still active; cancel it before resetting")
    removed = repository.clear_case_workspace()
    maps = 0
    if settings.redaction_map_root.is_dir():
        for path in settings.redaction_map_root.glob("*.handles.json"):
            path.unlink()
            maps += 1
    return {"removed": removed | {"handle_maps": maps}, "evidence_kept": True}


__all__ = [
    "DEMO_DATASET_ID",
    "SYNTHETIC_LOG",
    "DemoWorkspaceError",
    "is_demo_workspace",
    "reset_demo_workspace",
    "seed_demo_workspace",
]
