"""Transparent lexical retrieval over the local reference corpus.

The corpus is small, so a deterministic BM25 ranking over plain tokens is enough
and, unlike an opaque embedding, it can explain itself: every match reports which
query terms contributed and by how much. A score here means "this text shares
these words with your query". It is not a probability, not a similarity to an
attack, and not a decision that a session is a known or a novel technique.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from hestia.knowledge.contracts import ReferenceDocument

_TOKEN = re.compile(r"[a-z0-9][a-z0-9_.\-]*", re.ASCII)
_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "for",
        "from",
        "has",
        "in",
        "is",
        "it",
        "its",
        "of",
        "on",
        "or",
        "that",
        "the",
        "this",
        "to",
        "was",
        "were",
        "with",
    }
)
_K1 = 1.5
_B = 0.75


def tokenize(text: str) -> list[str]:
    """Lowercase word tokens; no regular expression is ever taken from the caller."""
    return [
        token
        for token in _TOKEN.findall(text.lower())
        if token not in _STOPWORDS and len(token) > 1
    ]


@dataclass(frozen=True)
class ScoredDocument:
    document: ReferenceDocument
    score: float
    matched_terms: tuple[tuple[str, float], ...]


class LexicalIndex:
    """A deterministic BM25 index built once per server process."""

    def __init__(self, documents: tuple[ReferenceDocument, ...]) -> None:
        self.documents = documents
        self._tokens = [Counter(tokenize(document.indexed_text)) for document in documents]
        self._lengths = [sum(counts.values()) for counts in self._tokens]
        self._average_length = sum(self._lengths) / len(self._lengths) if self._lengths else 0.0
        frequency: Counter[str] = Counter()
        for counts in self._tokens:
            frequency.update(counts.keys())
        self._document_frequency = frequency

    def _idf(self, term: str) -> float:
        total = len(self.documents)
        seen = self._document_frequency.get(term, 0)
        if total == 0 or seen == 0:
            return 0.0
        return math.log(1 + (total - seen + 0.5) / (seen + 0.5))

    def search(self, query: str, *, limit: int) -> list[ScoredDocument]:
        """Rank documents by BM25 and break ties on document_id for reproducibility."""
        terms = tokenize(query)
        if not terms or not self.documents:
            return []
        results: list[ScoredDocument] = []
        for index, document in enumerate(self.documents):
            counts = self._tokens[index]
            length = self._lengths[index] or 1
            contributions: list[tuple[str, float]] = []
            for term in dict.fromkeys(terms):
                occurrences = counts.get(term, 0)
                if not occurrences:
                    continue
                denominator = occurrences + _K1 * (
                    1 - _B + _B * length / (self._average_length or 1)
                )
                contribution = self._idf(term) * occurrences * (_K1 + 1) / denominator
                if contribution > 0:
                    contributions.append((term, round(contribution, 6)))
            if not contributions:
                continue
            results.append(
                ScoredDocument(
                    document=document,
                    score=round(sum(value for _, value in contributions), 6),
                    matched_terms=tuple(
                        sorted(contributions, key=lambda item: (-item[1], item[0]))
                    ),
                )
            )
        results.sort(key=lambda item: (-item.score, item.document.document_id))
        return results[:limit]


__all__ = ["LexicalIndex", "ScoredDocument", "tokenize"]
