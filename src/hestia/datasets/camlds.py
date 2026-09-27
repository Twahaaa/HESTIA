"""CAM-LDS attack-step manifestation loader."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from hestia.contracts import Event, ParseFailure
from hestia.ingestion.parser import parse_file


class CamldsManifestation(BaseModel):
    """An auth-relevant CAM-LDS attack-step manifestation."""

    model_config = ConfigDict(frozen=True)

    technique_id: str | None = Field(
        default=None, description="MITRE ATT&CK technique ID if known."
    )
    tactic: str | None = Field(default=None, description="MITRE ATT&CK tactic.")
    step_id: str | None = Field(
        default=None, description="CAM-LDS step identifier from the directory name."
    )
    sequence_id: str | None = Field(
        default=None, description="CAM-LDS sequence identifier if under sequences/."
    )
    host: str | None = Field(
        default=None, description="Host/role directory containing the auth.log."
    )
    manifestation: str = Field(..., description="Description of the manifestation or path summary.")
    evidence: str | None = Field(default=None, description="Evidence or observables.")
    data_source: str = Field(..., description="Data source this manifestation applies to.")
    auth_log_path: Path | None = Field(
        default=None, description="Path to discovered auth.log file."
    )
    related_log_paths: dict[str, Path] = Field(
        default_factory=dict,
        description="Sibling log files keyed by relative name.",
    )


def _derive_ids(relative_path: Path) -> tuple[str | None, str | None, str | None]:
    """Infer CAM-LDS IDs from the relative path under manifestations_filtered/."""
    parts = relative_path.parts
    technique_id: str | None = None
    step_id: str | None = None
    sequence_id: str | None = None

    for idx, part in enumerate(parts):
        if part == "techniques" and idx + 1 < len(parts):
            technique_id = parts[idx + 1]
        elif part == "steps" and idx + 1 < len(parts):
            step_id = parts[idx + 1]
        elif part == "sequences" and idx + 1 < len(parts):
            sequence_id = parts[idx + 1]

    return technique_id, step_id, sequence_id


def _discover_related_logs(auth_log_path: Path) -> dict[str, Path]:
    """Find sibling log files around an auth.log path."""
    related: dict[str, Path] = {}
    log_dir = auth_log_path.parent
    candidates = {
        "attackmate_json": log_dir.parent / "attacker" / "logs" / "attackmate.json",
        "syslog": log_dir / "syslog",
        "messages": log_dir / "messages",
        "audit_log": log_dir / "audit" / "audit.log",
    }
    for key, candidate in candidates.items():
        if candidate.exists():
            related[key] = candidate
    return related


def _load_csv_or_json(path: Path) -> list[CamldsManifestation]:
    """Retain legacy CSV/JSON loading behavior for file inputs."""
    suffix = path.suffix.lower()
    raw_rows: list[dict[str, str]]
    if suffix == ".json":
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, list):
            raw_rows = [dict(row) for row in data]
        elif isinstance(data, dict) and "manifestations" in data:
            raw_rows = [dict(row) for row in data["manifestations"]]
        else:
            raise ValueError("CAM-LDS JSON must be a list or contain a 'manifestations' key")
    elif suffix in {".csv", ".txt"}:
        with path.open(newline="", encoding="utf-8") as handle:
            raw_rows = list(csv.DictReader(handle))
    else:
        raise ValueError(f"Unsupported CAM-LDS file format: {suffix}")

    manifestations: list[CamldsManifestation] = []
    for row in raw_rows:
        data_source = (row.get("data_source") or "").lower()
        if "auth" in data_source:
            manifestations.append(
                CamldsManifestation(
                    technique_id=row.get("technique_id") or None,
                    tactic=row.get("tactic") or None,
                    manifestation=row["manifestation"],
                    evidence=row.get("evidence") or None,
                    data_source=row["data_source"],
                )
            )
    return manifestations


def load_camlds_manifestations(path: Path) -> list[CamldsManifestation]:
    """Load CAM-LDS manifestations and filter to auth-relevant ones.

    If ``path`` is a directory, it is treated as the extracted CAM-LDS
    ``manifestations_filtered`` tree. The function recursively discovers
    ``auth.log`` files and derives technique/step/sequence IDs from the
    directory layout. If ``path`` is a file, legacy CSV/JSON loading is used.

    Args:
        path: Path to a directory tree or a CSV/JSON file.

    Returns:
        Manifestations whose ``data_source`` is ``auth.log`` (directory mode)
        or mentions ``auth`` (file mode).

    Raises:
        FileNotFoundError: If ``path`` does not exist.
        ValueError: If the file format is unsupported.
    """
    if not path.exists():
        raise FileNotFoundError(f"CAM-LDS file not found: {path}")

    if path.is_file():
        return _load_csv_or_json(path)

    manifestations: list[CamldsManifestation] = []
    base = path / "manifestations_filtered" if path.name != "manifestations_filtered" else path

    for auth_log_path in sorted(base.rglob("auth.log")):
        relative = auth_log_path.relative_to(base)
        technique_id, step_id, sequence_id = _derive_ids(relative)
        host = relative.parts[2] if len(relative.parts) >= 3 else None
        related = _discover_related_logs(auth_log_path)
        manifestations.append(
            CamldsManifestation(
                technique_id=technique_id,
                step_id=step_id,
                sequence_id=sequence_id,
                host=host,
                manifestation=f"CAM-LDS auth.log at {relative.as_posix()}",
                data_source="auth.log",
                auth_log_path=auth_log_path,
                related_log_paths=related,
            )
        )

    return manifestations


def parse_camlds_auth_log(
    run: CamldsManifestation,
    *,
    source: str,
    default_year: int,
) -> tuple[list[Event], list[ParseFailure]]:
    """Parse the auth.log file referenced by a CAM-LDS manifestation.

    Args:
        run: Manifestation with a non-None ``auth_log_path``.

    Returns:
        Tuple of ``(events, parse_failures)``.

    Raises:
        ValueError: If ``run`` has no ``auth_log_path``.
    """
    if run.auth_log_path is None:
        raise ValueError("CamldsManifestation has no auth_log_path")

    with run.auth_log_path.open(encoding="utf-8", errors="replace") as handle:
        return parse_file(source, handle, default_year=default_year)
