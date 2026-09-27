"""Versioned reference-index contracts.

A reference document is attributed source material, not a judgement. Retrieval
over this index ranks candidates a human or agent can read and cite; it never
decides that a session is a known technique or a novel one.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

KNOWLEDGE_SCHEMA_VERSION = 1

Collection = Literal["cam-auth", "mitre-attack"]


class ReferenceSource(BaseModel):
    """Where a reference document came from, exactly enough to re-check it."""

    model_config = ConfigDict(frozen=True)

    collection: Collection
    source_uri: str = Field(description="Dataset-relative path or pinned upstream URL.")
    sha256: str = Field(description="Digest of the exact bytes the snippet was taken from.")
    version: str = Field(description="Dataset or snapshot version this came from.")
    attribution: str = Field(min_length=1, description="Required upstream attribution.")


class ReferenceDocument(BaseModel):
    """One retrievable reference document with an exact, citable snippet."""

    model_config = ConfigDict(frozen=True)

    document_id: str
    title: str
    technique_ids: tuple[str, ...] = ()
    tactics: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ()
    data_sources: tuple[str, ...] = ()
    url: str | None = None
    indexed_text: str = Field(min_length=1, description="Text the lexical retriever sees.")
    snippet: str = Field(min_length=1)
    snippet_truncated: bool = False
    snippet_start_line: int | None = None
    snippet_end_line: int | None = None
    source: ReferenceSource


class ReferenceIndex(BaseModel):
    """A reproducible, hash-identified snapshot of the local reference corpus."""

    model_config = ConfigDict(frozen=True)

    schema_version: int = KNOWLEDGE_SCHEMA_VERSION
    built_at: datetime
    documents: tuple[ReferenceDocument, ...]
    collections: tuple[Collection, ...]
    excluded_source_paths: tuple[str, ...] = ()
    exclusion_rule: str = Field(min_length=1)
    coverage_notes: tuple[str, ...] = ()
    index_hash: str = ""

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        if self.built_at.tzinfo is None or self.built_at.utcoffset() is None:
            raise ValueError("built_at must be timezone-aware")
        identifiers = [document.document_id for document in self.documents]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("document_id values must be unique")
        expected = index_digest(self.documents, self.excluded_source_paths, self.exclusion_rule)
        if self.index_hash and self.index_hash != expected:
            raise ValueError("index_hash does not match the indexed content")
        return self

    def by_id(self, document_id: str) -> ReferenceDocument | None:
        return next(
            (item for item in self.documents if item.document_id == document_id),
            None,
        )


def index_digest(
    documents: tuple[ReferenceDocument, ...],
    excluded_source_paths: tuple[str, ...],
    exclusion_rule: str,
) -> str:
    """Digest the indexed content only, so a rebuild at a new time still matches."""
    payload = json.dumps(
        {
            "schema_version": KNOWLEDGE_SCHEMA_VERSION,
            "documents": [document.model_dump(mode="json") for document in documents],
            "excluded_source_paths": sorted(excluded_source_paths),
            "exclusion_rule": exclusion_rule,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def write_index(index: ReferenceIndex, path: Path) -> None:
    """Persist the index atomically next to the other local artifacts."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(index.model_dump_json(indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def read_index(path: Path) -> ReferenceIndex:
    """Read and validate an index, including its content digest."""
    return ReferenceIndex.model_validate_json(path.read_text(encoding="utf-8"))


__all__ = [
    "KNOWLEDGE_SCHEMA_VERSION",
    "Collection",
    "ReferenceDocument",
    "ReferenceIndex",
    "ReferenceSource",
    "index_digest",
    "read_index",
    "write_index",
]
