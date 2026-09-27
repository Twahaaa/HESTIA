"""Pinned MITRE ATT&CK Enterprise reference records.

The snapshot is pinned by version and digest and kept in the repository as a
filtered, auth-relevant subset. Nothing here reaches the network unless a
human explicitly asks for a refresh: a demo must never silently depend on an
upstream fetch, and a refresh must be reproducible when it does happen.
"""

from __future__ import annotations

import hashlib
import json
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from hestia.knowledge.contracts import ReferenceDocument, ReferenceSource

ATTACK_VERSION = "19.2"
ATTACK_SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    f"enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json"
)
ATTACK_ATTRIBUTION = (
    "MITRE ATT&CK® Enterprise "
    f"v{ATTACK_VERSION}, © The MITRE Corporation, https://attack.mitre.org/. "
    "Redistributed under the ATT&CK Terms of Use; attribution is required."
)
#: A technique is auth-relevant when ATT&CK itself says it is observed in these
#: data sources. The rule is stated here so the subset is reproducible rather
#: than curated by hand.
AUTH_DATA_SOURCES = ("Logon Session", "User Account", "Active Directory")

SNAPSHOT_FILENAME = f"enterprise-attack-auth-{ATTACK_VERSION}.json"


class AttackSnapshot(BaseModel):
    """The filtered subset actually stored in this repository."""

    model_config = ConfigDict(frozen=True)

    schema_version: int = 1
    attack_version: str
    source_url: str
    upstream_sha256: str
    attribution: str
    filter_rule: str
    retrieved_at: datetime
    techniques: tuple[dict[str, Any], ...]


class AttackRefreshRefused(RuntimeError):
    """A network refresh was attempted without an explicit human request."""


def _external_id(stix: dict[str, Any]) -> str | None:
    for reference in stix.get("external_references", ()):
        if reference.get("source_name") == "mitre-attack":
            return reference.get("external_id")
    return None


def _external_url(stix: dict[str, Any]) -> str | None:
    for reference in stix.get("external_references", ()):
        if reference.get("source_name") == "mitre-attack":
            return reference.get("url")
    return None


def filter_bundle(bundle: dict[str, Any], *, extra_ids: frozenset[str] = frozenset()) -> list[dict]:
    """Keep only auth-relevant, current techniques plus explicitly required ids."""
    kept: list[dict[str, Any]] = []
    for stix in bundle.get("objects", ()):
        if (
            stix.get("type") != "attack-pattern"
            or stix.get("revoked")
            or stix.get("x_mitre_deprecated")
        ):
            continue
        technique_id = _external_id(stix)
        if technique_id is None:
            continue
        data_sources = tuple(stix.get("x_mitre_data_sources", ()) or ())
        auth_relevant = any(
            any(source.startswith(prefix) for prefix in AUTH_DATA_SOURCES)
            for source in data_sources
        )
        if not auth_relevant and technique_id not in extra_ids:
            continue
        kept.append(
            {
                "technique_id": technique_id,
                "name": stix.get("name", ""),
                "description": stix.get("description", ""),
                "url": _external_url(stix),
                "tactics": tuple(
                    phase.get("phase_name", "")
                    for phase in stix.get("kill_chain_phases", ())
                    if phase.get("kill_chain_name") == "mitre-attack"
                ),
                "platforms": tuple(stix.get("x_mitre_platforms", ()) or ()),
                "data_sources": data_sources,
            }
        )
    return sorted(kept, key=lambda item: item["technique_id"])


def fetch_bundle(url: str, *, confirmed: bool, timeout: float = 120.0) -> tuple[bytes, str]:
    """Download an upstream STIX bundle. ``confirmed`` must be an explicit choice."""
    if not confirmed:
        raise AttackRefreshRefused(
            "refreshing the ATT&CK snapshot requires an explicit --refresh-attack request"
        )
    if not url.startswith("https://"):
        raise ValueError("the ATT&CK snapshot URL must be https")
    with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 - https enforced
        payload = response.read()
    return payload, hashlib.sha256(payload).hexdigest()


def build_snapshot(
    raw_bundle: bytes,
    *,
    source_url: str,
    extra_ids: frozenset[str] = frozenset(),
) -> AttackSnapshot:
    """Reduce an upstream bundle to the pinned auth-relevant subset."""
    bundle = json.loads(raw_bundle)
    return AttackSnapshot(
        attack_version=ATTACK_VERSION,
        source_url=source_url,
        upstream_sha256=hashlib.sha256(raw_bundle).hexdigest(),
        attribution=ATTACK_ATTRIBUTION,
        filter_rule=(
            "attack-pattern objects that are neither revoked nor deprecated and whose "
            f"x_mitre_data_sources start with one of {AUTH_DATA_SOURCES}, plus the "
            "technique ids referenced by the local CAM-LDS reference corpus"
        ),
        retrieved_at=datetime.now(UTC),
        techniques=tuple(filter_bundle(bundle, extra_ids=extra_ids)),
    )


def write_snapshot(snapshot: AttackSnapshot, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(snapshot.model_dump_json(indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def read_snapshot(path: Path) -> AttackSnapshot:
    return AttackSnapshot.model_validate_json(path.read_text(encoding="utf-8"))


def build_attack_documents(snapshot: AttackSnapshot) -> tuple[ReferenceDocument, ...]:
    """Turn the pinned subset into retrievable, attributed reference documents."""
    documents: list[ReferenceDocument] = []
    for record in snapshot.techniques:
        technique_id = str(record["technique_id"])
        description = str(record.get("description") or "")
        documents.append(
            ReferenceDocument(
                document_id=f"mitre-attack:{technique_id}",
                title=f"{technique_id} {record.get('name', '')}".strip(),
                technique_ids=(technique_id,),
                tactics=tuple(record.get("tactics", ())),
                platforms=tuple(record.get("platforms", ())),
                data_sources=tuple(record.get("data_sources", ())),
                url=record.get("url"),
                indexed_text=f"{technique_id} {record.get('name', '')}\n{description}",
                snippet=description or str(record.get("name", "")),
                snippet_truncated=False,
                source=ReferenceSource(
                    collection="mitre-attack",
                    source_uri=snapshot.source_url,
                    sha256=snapshot.upstream_sha256,
                    version=snapshot.attack_version,
                    attribution=snapshot.attribution,
                ),
            )
        )
    return tuple(documents)


__all__ = [
    "ATTACK_ATTRIBUTION",
    "ATTACK_SOURCE_URL",
    "ATTACK_VERSION",
    "AUTH_DATA_SOURCES",
    "SNAPSHOT_FILENAME",
    "AttackRefreshRefused",
    "AttackSnapshot",
    "build_attack_documents",
    "build_snapshot",
    "fetch_bundle",
    "filter_bundle",
    "read_snapshot",
    "write_snapshot",
]
