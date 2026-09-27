"""CAM-LDS authentication reference documents.

The CAM-LDS ``manifestations_filtered/techniques`` tree names an ATT&CK technique
per directory, so each auth.log under it is attributed reference material for that
technique. Documents are built only from sources that are not part of any held-out
split, so reference retrieval can never quote the evidence a later evaluation
scores. Every snippet keeps its file digest and exact line range.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from pathlib import Path

from hestia.knowledge.contracts import ReferenceDocument, ReferenceSource

CAM_DATASET_ID = "cam-auth"
CAM_ROOT = "cam-auth/manifestations_filtered"
CAM_ATTRIBUTION = (
    "CAM-LDS cyber attack manifestation log dataset, https://zenodo.org/records/18390561. "
    "Reused under its upstream terms; attribution is required."
)


def technique_id_from_directory(name: str) -> str | None:
    """Translate a ``T1078-003`` directory name into the ATT&CK id ``T1078.003``."""
    parts = name.split("-")
    if len(parts) != 2 or not parts[0].startswith("T") or not parts[0][1:].isdigit():
        return None
    base, sub = parts
    if not sub.isdigit():
        return None
    return base if sub == "000" else f"{base}.{sub}"


def _digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _snippet(path: Path, *, max_lines: int, max_chars: int) -> tuple[str, bool, int, int]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    kept = [line for line in lines if line.strip()][:max_lines]
    truncated = len([line for line in lines if line.strip()]) > len(kept)
    text = "\n".join(kept)
    if len(text) > max_chars:
        text = text[:max_chars]
        truncated = True
    return text, truncated, 1, len(kept)


def build_cam_documents(
    data_root: Path,
    *,
    excluded_source_paths: Iterable[str] = (),
    max_files_per_technique: int = 3,
    max_lines: int = 40,
    max_chars: int = 4_000,
) -> tuple[tuple[ReferenceDocument, ...], tuple[str, ...]]:
    """Build the CAM reference documents and report which sources were excluded.

    Returns ``(documents, excluded)`` where ``excluded`` lists the dataset-relative
    source paths that were skipped because they belong to a held-out split.
    """
    excluded_set = set(excluded_source_paths)
    base = data_root / "raw" / CAM_ROOT / "techniques"
    if not base.is_dir():
        return (), ()

    documents: list[ReferenceDocument] = []
    skipped: set[str] = set()
    for technique_dir in sorted(p for p in base.iterdir() if p.is_dir()):
        technique_id = technique_id_from_directory(technique_dir.name)
        if technique_id is None:
            continue
        taken = 0
        for auth_log in sorted(technique_dir.rglob("auth.log")):
            if taken >= max_files_per_technique:
                break
            relative = auth_log.relative_to(data_root / "raw").as_posix()
            if relative in excluded_set:
                skipped.add(relative)
                continue
            if auth_log.stat().st_size == 0:
                continue
            snippet, truncated, start_line, end_line = _snippet(
                auth_log, max_lines=max_lines, max_chars=max_chars
            )
            if not snippet.strip():
                continue
            parts = auth_log.relative_to(technique_dir).parts
            step = parts[0] if parts else technique_dir.name
            host = parts[1] if len(parts) > 1 else "unknown"
            documents.append(
                ReferenceDocument(
                    document_id=f"cam-auth:{technique_dir.name}:{step}:{host}",
                    title=(f"CAM-LDS {technique_id} manifestation, step {step}, host {host}"),
                    technique_ids=(technique_id,),
                    indexed_text=f"{technique_id} {step} {host}\n{snippet}",
                    snippet=snippet,
                    snippet_truncated=truncated,
                    snippet_start_line=start_line,
                    snippet_end_line=end_line,
                    source=ReferenceSource(
                        collection="cam-auth",
                        source_uri=relative,
                        sha256=_digest(auth_log),
                        version="manifestations_filtered",
                        attribution=CAM_ATTRIBUTION,
                    ),
                )
            )
            taken += 1
    return tuple(documents), tuple(sorted(skipped))


__all__ = [
    "CAM_ATTRIBUTION",
    "CAM_DATASET_ID",
    "CAM_ROOT",
    "build_cam_documents",
    "technique_id_from_directory",
]
