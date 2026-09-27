"""The provider-bound payload boundary.

Everything that leaves this process for a hosted provider passes through here.
This is deliberately *not* `ingestion/sanitize.py`: that helper tokenizes
structured fields for local processing and its own docstring says it is not a
provider redaction boundary. This module is that boundary.

Three rules hold:

1. **Allowlist, not denylist.** A tool result is rebuilt field by field from a
   per-tool allowlist. A field nobody listed is dropped, so adding a field to a
   tool contract cannot silently start exporting it.
2. **Identifiers become local handles.** Evidence and session identifiers embed
   host, source IP and user name, so sending them raw would defeat pseudonymizing
   those same fields. The model sees short opaque handles; the mapping stays
   local and is what grounding resolves citations against.
3. **Retrieved text is data, never instruction.** Log lines and reference
   snippets are wrapped in an explicit untrusted-content envelope, and the
   system prompt tells the model that nothing inside it can grant a tool,
   change a budget or reveal configuration.
"""

from __future__ import annotations

import hmac
import json
import re
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any

#: Fields of an event a provider may see, after pseudonymization.
_EVENT_FIELDS = (
    "timestamp",
    "process",
    "event_type",
    "success",
    "method",
    "message",
    "unmatched",
    "unmatched_reason",
)
#: Fields of a session summary a provider may see.
_SESSION_FIELDS = (
    "start_time",
    "end_time",
    "event_count",
    "failure_count",
    "has_escalation",
    "has_persistence",
    "primary_method",
)
#: Pseudonymized identity fields. Values are replaced, never removed, so the
#: model can still reason about "the same user appearing twice".
_PSEUDONYM_FIELDS = ("host", "user", "target_user", "src_ip", "ruser")
#: Never sent under any configuration.
FORBIDDEN_KEYS = frozenset(
    {
        "api_key",
        "attack",
        "attack_family",
        "authorization",
        "content_hash",
        "credential",
        "env",
        "environment",
        "ground_truth",
        "is_attack",
        "key_fingerprint",
        "label",
        "labels",
        "password",
        "raw_line",
        "raw_message",
        "secret",
        "source_path",
        "source_sha256",
        "token",
    }
)

UNTRUSTED_OPEN = "<untrusted-log-content>"
UNTRUSTED_CLOSE = "</untrusted-log-content>"
_ENVELOPE_MARKERS = re.compile(r"</?untrusted-log-content>", re.IGNORECASE)
#: Long hex runs are digests or fingerprints; they carry no analytic value here.
_HEX_RUN = re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class Redactor:
    """Builds provider payloads and keeps the reverse mapping local.

    The maps never leave this object. They are what turns a cited handle back
    into a real evidence identifier during grounding, and they are excluded from
    logs and from the source export.
    """

    salt: bytes
    _handles: dict[str, str] = field(default_factory=dict)
    _reverse_handles: dict[str, str] = field(default_factory=dict)
    _pseudonyms: dict[tuple[str, str], str] = field(default_factory=dict)
    _counters: dict[str, int] = field(default_factory=dict)

    # -- identifiers ----------------------------------------------------

    def handle(self, kind: str, identifier: str) -> str:
        """Return a stable, opaque handle for one real identifier."""
        if identifier in self._handles:
            return self._handles[identifier]
        digest = hmac.new(self.salt, f"{kind}\0{identifier}".encode(), sha256).hexdigest()
        token = f"{kind}-{digest[:10]}"
        self._handles[identifier] = token
        self._reverse_handles[token] = identifier
        return token

    def resolve(self, handle: str) -> str | None:
        """Return the real identifier a handle refers to, or None if unknown."""
        return self._reverse_handles.get(handle)

    @property
    def issued_handles(self) -> frozenset[str]:
        return frozenset(self._reverse_handles)

    # -- identity fields ------------------------------------------------

    def pseudonym(self, field_name: str, value: str) -> str:
        """Return a stable per-run pseudonym, e.g. ``host-1``.

        Counters make the payload readable for a model without reintroducing the
        real name. The mapping is local and reversible for the analyst.
        """
        key = (field_name, value)
        if key in self._pseudonyms:
            return self._pseudonyms[key]
        index = self._counters.get(field_name, 0) + 1
        self._counters[field_name] = index
        token = f"{field_name}-{index}"
        self._pseudonyms[key] = token
        return token

    def resolve_pseudonym(self, token: str) -> str | None:
        """Turn a pseudonym the model used back into the real value, locally."""
        for (_, value), issued in self._pseudonyms.items():
            if issued == token:
                return value
        return None

    def pseudonym_map(self) -> dict[str, str]:
        """Local-only reverse map, for an analyst reading a stored report."""
        return {token: value for (_, value), token in self._pseudonyms.items()}

    # -- text ------------------------------------------------------------

    def redact_text(self, text: str, *, max_chars: int = 400) -> str:
        """Pseudonymize identities inside free text and neutralize markers."""
        cleaned = _ENVELOPE_MARKERS.sub("[marker removed]", text)
        for (field_name, value), token in sorted(
            self._pseudonyms.items(), key=lambda item: -len(item[0][1])
        ):
            if value and value in cleaned:
                cleaned = cleaned.replace(value, token)
        cleaned = _IPV4.sub("[ip]", cleaned)
        cleaned = _HEX_RUN.sub("[digest]", cleaned)
        if len(cleaned) > max_chars:
            cleaned = cleaned[:max_chars] + "…[truncated]"
        return cleaned

    def wrap_untrusted(self, text: str) -> str:
        """Mark retrieved content as data the model must not obey."""
        return f"{UNTRUSTED_OPEN}{text}{UNTRUSTED_CLOSE}"

    # -- tool payloads ----------------------------------------------------

    def redact_event(self, event: dict[str, Any]) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "handle": self.handle("ev", str(event["event_id"])),
        }
        for name in _PSEUDONYM_FIELDS:
            value = event.get(name)
            if isinstance(value, str) and value:
                payload[name] = self.pseudonym(name, value)
        for name in _EVENT_FIELDS:
            if name in event and event[name] is not None:
                payload[name] = event[name]
        if isinstance(payload.get("message"), str):
            payload["message"] = self.wrap_untrusted(self.redact_text(payload["message"]))
        return payload

    def redact_session(self, session: dict[str, Any]) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "handle": self.handle("se", str(session["session_id"])),
        }
        for name in _PSEUDONYM_FIELDS:
            value = session.get(name)
            if isinstance(value, str) and value:
                payload[name] = self.pseudonym(name, value)
        for name in _SESSION_FIELDS:
            if name in session and session[name] is not None:
                payload[name] = session[name]
        return payload

    def redact_reference(self, match: dict[str, Any]) -> dict[str, Any]:
        """Reference material keeps its attribution but not its local file path."""
        snippet = self.redact_text(str(match.get("snippet") or ""), max_chars=600)
        return {
            "handle": self.handle("rf", str(match["document_id"])),
            "collection": match.get("collection"),
            "title": match.get("title"),
            "technique_ids": match.get("technique_ids", ()),
            "lexical_score": match.get("lexical_score"),
            "source_version": match.get("source_version"),
            "attribution": match.get("attribution"),
            "snippet": self.wrap_untrusted(snippet),
        }

    def assert_clean(self, payload: Any) -> None:
        """Fail loudly if a forbidden key survived into a provider payload."""
        for key in _walk_keys(payload):
            if key.lower() in FORBIDDEN_KEYS:
                raise RedactionError(f"forbidden key reached the provider payload: {key}")
        text = json.dumps(payload, default=str)
        for real in self._reverse_handles.values():
            if real and real in text:
                raise RedactionError("a real evidence identifier reached the provider payload")


class RedactionError(RuntimeError):
    """A payload failed its own outbound check, so nothing is sent."""


def _walk_keys(value: Any) -> list[str]:
    keys: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            keys.append(str(key))
            keys.extend(_walk_keys(item))
    elif isinstance(value, list | tuple):
        for item in value:
            keys.extend(_walk_keys(item))
    return keys


def write_local_maps(redactor: Redactor, path: Path) -> None:
    """Persist the reverse maps beside the run, locally and only locally.

    A stored report cites opaque handles, so without this file those citations
    become unresolvable once the process exits and an analyst could not retrieve
    the evidence behind a finding. The file lives under the artifact root, which
    is git-ignored and excluded from the source export, and it is never sent to a
    provider or written to a log.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "note": (
            "Local-only reverse map for one case run. Contains real identifiers and "
            "identity values. Do not export, publish or send to a provider."
        ),
        "handles": {handle: real for handle, real in sorted(redactor._reverse_handles.items())},
        "pseudonyms": dict(sorted(redactor.pseudonym_map().items())),
    }
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def read_local_maps(path: Path) -> dict[str, dict[str, str]]:
    """Read a stored reverse map so an analyst can resolve a report's citations."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {
        "handles": dict(payload.get("handles", {})),
        "pseudonyms": dict(payload.get("pseudonyms", {})),
    }


def build_redactor(salt: str | None) -> Redactor:
    """Create a redactor. An absent salt still yields per-run-stable handles."""
    material = (salt or "hestia-local-redaction").encode()
    return Redactor(salt=material)


__all__ = [
    "FORBIDDEN_KEYS",
    "UNTRUSTED_CLOSE",
    "UNTRUSTED_OPEN",
    "RedactionError",
    "Redactor",
    "build_redactor",
    "read_local_maps",
    "write_local_maps",
]
