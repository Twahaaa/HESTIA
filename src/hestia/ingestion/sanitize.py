"""Structured-field tokenization only. Raw text is NOT redacted.

Do not use this helper as a hosted-provider data redaction boundary.
"""

from __future__ import annotations

from hestia.contracts import Event, Session

DEFAULT_SENSITIVE_FIELDS = ("user", "src_ip", "host")


class Sanitizer:
    """Reversible tokenization sanitizer for sensitive event/session fields."""

    def __init__(
        self,
        sensitive_fields: tuple[str, ...] = DEFAULT_SENSITIVE_FIELDS,
        prefix: str = "TOKEN_",
    ) -> None:
        """Initialize the sanitizer.

        Args:
            sensitive_fields: Tuple of field names to tokenize.
            prefix: Token prefix.
        """
        self.sensitive_fields = sensitive_fields
        self.prefix = prefix
        self.token_map: dict[str, str] = {}
        self.reverse_map: dict[str, str] = {}
        self._counters: dict[str, int] = {}

    def _tokenize(self, field: str, value: str) -> str:
        """Return a stable token for ``value`` in ``field``."""
        key = f"{field}:{value}"
        if key in self.token_map:
            return self.token_map[key]
        token_id = self._counters.get(field, 0)
        token = f"{self.prefix}{field}_{token_id}"
        self._counters[field] = token_id + 1
        self.token_map[key] = token
        self.reverse_map[token] = value
        return token

    def sanitize_event(self, event: Event) -> Event:
        """Return a sanitized copy of ``event`` with sensitive fields tokenized."""
        updates: dict[str, str | None] = {}
        for field in self.sensitive_fields:
            value = getattr(event, field)
            if value is not None:
                updates[field] = self._tokenize(field, value)
        return event.model_copy(update=updates)

    def sanitize_session(self, session: Session) -> Session:
        """Return a sanitized copy of ``session`` with sensitive fields tokenized."""
        updates: dict[str, str | None] = {}
        for field in self.sensitive_fields:
            if field in {"user", "src_ip", "host"}:
                value = getattr(session, field)
                if value is not None:
                    updates[field] = self._tokenize(field, value)
        return session.model_copy(update=updates)

    def desanitize_event(self, event: Event) -> Event:
        """Restore original values in ``event`` using the reverse map."""
        updates: dict[str, str | None] = {}
        for field in self.sensitive_fields:
            value = getattr(event, field)
            if value is not None and value in self.reverse_map:
                updates[field] = self.reverse_map[value]
        return event.model_copy(update=updates)

    def to_dict(self) -> dict[str, str]:
        """Serialize the token-to-original-value map to a dictionary."""
        return dict(self.reverse_map)

    @classmethod
    def from_dict(
        cls,
        data: dict[str, str],
        sensitive_fields: tuple[str, ...] = DEFAULT_SENSITIVE_FIELDS,
        prefix: str = "TOKEN_",
    ) -> Sanitizer:
        """Restore a sanitizer from a persisted reverse map."""
        sanitizer = cls(sensitive_fields=sensitive_fields, prefix=prefix)
        sanitizer.reverse_map = dict(data)
        # Rebuild token_map and counters from reverse_map.
        for token, value in data.items():
            # Infer field from token prefix, e.g. TOKEN_user_0 -> user
            if token.startswith(prefix):
                remainder = token[len(prefix) :]
                for field in sensitive_fields:
                    if remainder.startswith(f"{field}_"):
                        sanitizer.token_map[f"{field}:{value}"] = token
                        break
        # Recompute counters to avoid collisions on new values.
        for token in data:
            if token.startswith(prefix):
                remainder = token[len(prefix) :]
                for field in sensitive_fields:
                    if remainder.startswith(f"{field}_"):
                        try:
                            token_id = int(remainder[len(field) + 1 :])
                        except ValueError:
                            token_id = 0
                        sanitizer._counters[field] = max(
                            sanitizer._counters.get(field, 0), token_id + 1
                        )
                        break
        return sanitizer


def sanitize_events(
    events: list[Event],
    sanitizer: Sanitizer | None = None,
) -> tuple[list[Event], Sanitizer]:
    """Sanitize a list of events.

    Returns:
        Tuple of ``(sanitized_events, sanitizer)``.
    """
    if sanitizer is None:
        sanitizer = Sanitizer()
    return [sanitizer.sanitize_event(event) for event in events], sanitizer


def sanitize_sessions(
    sessions: list[Session],
    sanitizer: Sanitizer | None = None,
) -> tuple[list[Session], Sanitizer]:
    """Sanitize a list of sessions.

    Returns:
        Tuple of ``(sanitized_sessions, sanitizer)``.
    """
    if sanitizer is None:
        sanitizer = Sanitizer()
    return [sanitizer.sanitize_session(session) for session in sessions], sanitizer
