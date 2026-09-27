"""Deterministic additive-smoothed in-session transition modeling."""

from __future__ import annotations

import math
from collections import Counter

from pydantic import BaseModel, ConfigDict, Field


class TransitionScore(BaseModel):
    """Immutable decomposed surprise evidence for one Event-type sequence."""

    model_config = ConfigDict(frozen=True)

    transition_count: int = Field(ge=0)
    has_transitions: bool
    mean_negative_log_probability: float | None
    max_negative_log_probability: float | None
    unseen_transition_count: int = Field(ge=0)


class TransitionModel:
    """First-order categorical model with deterministic Laplace smoothing."""

    def __init__(self, *, alpha: float = 1.0) -> None:
        if not math.isfinite(alpha) or alpha <= 0.0:
            raise ValueError("Transition smoothing alpha must be positive and finite")
        self.alpha = alpha
        self._transition_counts: Counter[tuple[str, str]] = Counter()
        self._outgoing_counts: Counter[str] = Counter()
        self._vocabulary: set[str] = set()
        self.observation_count = 0

    def score(self, event_types: tuple[str, ...]) -> TransitionScore:
        """Score ordered canonical Event types without changing learned state."""
        self._validate(event_types)
        pairs = tuple(zip(event_types, event_types[1:], strict=False))
        if not pairs:
            return TransitionScore(
                transition_count=0,
                has_transitions=False,
                mean_negative_log_probability=None,
                max_negative_log_probability=None,
                unseen_transition_count=0,
            )

        candidate_vocabulary = self._vocabulary.union(event_types)
        vocabulary_size = max(len(candidate_vocabulary), 1)
        surprises: list[float] = []
        unseen = 0
        for source, target in pairs:
            count = self._transition_counts[(source, target)]
            unseen += count == 0
            probability = (count + self.alpha) / (
                self._outgoing_counts[source] + self.alpha * vocabulary_size
            )
            surprises.append(-math.log(probability))
        return TransitionScore(
            transition_count=len(pairs),
            has_transitions=True,
            mean_negative_log_probability=sum(surprises) / len(surprises),
            max_negative_log_probability=max(surprises),
            unseen_transition_count=unseen,
        )

    def learn(self, event_types: tuple[str, ...]) -> None:
        """Increment counts for one closed Session's ordered Event types."""
        self._validate(event_types)
        self._vocabulary.update(event_types)
        for pair in zip(event_types, event_types[1:], strict=False):
            self._transition_counts[pair] += 1
            self._outgoing_counts[pair[0]] += 1
        self.observation_count += 1

    @staticmethod
    def _validate(event_types: tuple[str, ...]) -> None:
        if any(not isinstance(event_type, str) or not event_type for event_type in event_types):
            raise ValueError("Transition inputs must be non-empty canonical Event types")


__all__ = ["TransitionModel", "TransitionScore"]
