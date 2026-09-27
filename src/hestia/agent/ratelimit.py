"""Client-side pacing so one provider's rate limits are respected, not probed.

Each configured key (same provider, same model) is tracked separately, because
providers such as Groq meter tokens and requests per organisation. Before every
request the pacer picks a key with headroom, waiting a bounded time if none has
any. After a 429 the key cools down for the provider's ``retry-after`` instead of
being tried again at once. Nothing here stores a key: keys are referred to by
position, and headers are matched to a key through a short in-memory digest.

Sources of truth: when a key's last response carried token headers, its budget
is modelled as the provider describes it, refilling steadily from ``remaining``
to the full limit over the reported reset time. Only a key without headers yet
falls back to locally observed usage in a sliding 60 s window against a
configured per-minute limit.
"""

from __future__ import annotations

import hashlib
import re
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

#: Assumed cooldown after a 429 that carried no retry-after header.
DEFAULT_COOLDOWN_SECONDS = 60.0
_WINDOW_SECONDS = 60.0
_DURATION = re.compile(r"(\d+(?:\.\d+)?)(ms|h|m|s)")


def parse_duration(value: str | None) -> float | None:
    """Parse ``retry-after`` seconds or Groq's ``2m59.56s`` / ``250ms`` resets."""
    if value is None:
        return None
    text = value.strip()
    try:
        return max(float(text), 0.0)
    except ValueError:
        pass
    parts = _DURATION.findall(text)
    if not parts or "".join(number + unit for number, unit in parts) != text:
        return None
    scale = {"h": 3600.0, "m": 60.0, "s": 1.0, "ms": 0.001}
    return sum(float(number) * scale[unit] for number, unit in parts)


def _int(value: str | None) -> int | None:
    try:
        return int(float(value)) if value is not None else None
    except ValueError:
        return None


def fingerprint(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()[:16]


@dataclass(frozen=True)
class RateLimitPolicy:
    """Limits this deployment will respect per key, and how long it may wait."""

    #: Per-key tokens per minute. None: learn it from provider headers.
    tokens_per_minute: int | None = None
    #: Per-key requests per minute. None: learn nothing, rely on 429 cooldowns.
    requests_per_minute: int | None = None
    #: Longest single wait for headroom; a longer one ends the run cleanly. At
    #: least a minute, so an emptied per-minute budget can always refill.
    max_wait_seconds: float = 65.0
    #: Assumed size of the first request on a key, before any usage is seen.
    first_request_tokens: int = 2_000


@dataclass
class _KeyState:
    window: deque[tuple[float, int]] = field(default_factory=deque)
    cooldown_until: float = 0.0
    last_request_tokens: int | None = None
    header_tpm: int | None = None
    tokens_remaining: int | None = None
    tokens_reset_at: float = 0.0
    tokens_observed_at: float | None = None
    requests_remaining: int | None = None
    requests_reset_at: float = 0.0
    pending_retry_after: float | None = None

    def prune(self, now: float) -> None:
        while self.window and now - self.window[0][0] >= _WINDOW_SECONDS:
            self.window.popleft()


class KeyPacer:
    """Per-key headroom for one provider/model; shared by every run in a process."""

    def __init__(
        self,
        key_fingerprints: tuple[str, ...],
        policy: RateLimitPolicy,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not key_fingerprints:
            raise ValueError("at least one key is required")
        self.policy = policy
        self._clock = clock
        self._index = {digest: position for position, digest in enumerate(key_fingerprints)}
        self._keys = [_KeyState() for _ in key_fingerprints]
        self._lock = threading.Lock()

    # -- observations ----------------------------------------------------------

    def observe(self, key: str, status: int, headers: Mapping[str, str]) -> None:
        """Record rate-limit headers from one HTTP response for ``key``."""
        position = self._index.get(fingerprint(key))
        if position is None:
            return
        now = self._clock()
        with self._lock:
            state = self._keys[position]
            limit = _int(headers.get("x-ratelimit-limit-tokens"))
            if limit:
                state.header_tpm = limit
            remaining = _int(headers.get("x-ratelimit-remaining-tokens"))
            reset = parse_duration(headers.get("x-ratelimit-reset-tokens"))
            if remaining is not None and reset is not None:
                state.tokens_remaining, state.tokens_reset_at = remaining, now + reset
                state.tokens_observed_at = now
            requests = _int(headers.get("x-ratelimit-remaining-requests"))
            requests_reset = parse_duration(headers.get("x-ratelimit-reset-requests"))
            if requests is not None and requests_reset is not None:
                state.requests_remaining = requests
                state.requests_reset_at = now + requests_reset
            if status == 429:
                state.pending_retry_after = parse_duration(headers.get("retry-after"))

    def record_success(self, position: int, tokens: int) -> None:
        now = self._clock()
        with self._lock:
            state = self._keys[position]
            state.window.append((now, max(tokens, 0)))
            state.last_request_tokens = max(tokens, 1)

    def retire(self, position: int) -> None:
        """A per-key hard limit (e.g. a credit cap) that no wait will clear."""
        with self._lock:
            self._keys[position].cooldown_until = float("inf")

    def record_limited(self, position: int) -> float:
        """Cool the key down after a 429; returns the cooldown applied."""
        now = self._clock()
        with self._lock:
            state = self._keys[position]
            wait = state.pending_retry_after
            state.pending_retry_after = None
            cooldown = DEFAULT_COOLDOWN_SECONDS if wait is None else wait
            state.cooldown_until = max(state.cooldown_until, now + cooldown)
            return cooldown

    # -- decisions -----------------------------------------------------------------

    def _tpm(self, state: _KeyState) -> int | None:
        return state.header_tpm or self.policy.tokens_per_minute

    def estimate(self, position: int, hint: int | None = None) -> int:
        """Expected tokens of the next request: the caller's hint or last size plus growth."""
        state = self._keys[position]
        if hint is not None:
            guess = hint
        elif state.last_request_tokens is None:
            guess = self.policy.first_request_tokens
        else:
            guess = int(state.last_request_tokens * 1.25)
        tpm = self._tpm(state)
        return min(guess, tpm) if tpm else guess

    def _available_at(self, position: int, now: float, hint: int | None = None) -> float:
        state = self._keys[position]
        state.prune(now)
        ready = max(now, state.cooldown_until)
        need = self.estimate(position, hint)
        if state.requests_remaining == 0 and state.requests_reset_at > now:
            ready = max(ready, state.requests_reset_at)
        tpm = self._tpm(state)
        if state.tokens_observed_at is not None and state.tokens_remaining is not None:
            ready = max(ready, self._refilled_at(state, need, tpm))
        elif tpm:
            used = sum(tokens for _, tokens in state.window)
            for stamp, tokens in state.window:
                if used + need <= tpm:
                    break
                used -= tokens
                ready = max(ready, stamp + _WINDOW_SECONDS)
        rpm = self.policy.requests_per_minute
        if rpm and len(state.window) >= rpm:
            ready = max(ready, state.window[len(state.window) - rpm][0] + _WINDOW_SECONDS)
        return ready

    @staticmethod
    def _refilled_at(state: _KeyState, need: int, tpm: int | None) -> float:
        """When the provider-reported budget covers ``need``, refilling linearly."""
        assert state.tokens_observed_at is not None and state.tokens_remaining is not None
        remaining, observed = state.tokens_remaining, state.tokens_observed_at
        if tpm:
            need = min(need, tpm)
        if remaining >= need:
            return observed
        span = state.tokens_reset_at - observed
        if not tpm or span <= 0 or tpm <= remaining:
            return state.tokens_reset_at
        rate = (tpm - remaining) / span
        return observed + (need - remaining) / rate

    def snapshot(self) -> list[dict[str, float | int | None]]:
        """Key-free view of each key's rate-limit state, by position, for evidence."""
        now = self._clock()
        with self._lock:
            return [
                {
                    "key_position": position,
                    "provider_tokens_per_minute": state.header_tpm,
                    "tokens_remaining": state.tokens_remaining,
                    "seconds_to_token_reset": (
                        round(max(state.tokens_reset_at - now, 0.0), 3)
                        if state.tokens_observed_at is not None
                        else None
                    ),
                    "requests_remaining_today": state.requests_remaining,
                    "cooling_seconds": round(max(state.cooldown_until - now, 0.0), 3)
                    if state.cooldown_until != float("inf")
                    else None,
                    "requests_last_minute": len(state.window),
                }
                for position, state in enumerate(self._keys)
            ]

    def choose(self, preferred: int, hint: int | None = None) -> tuple[int, float]:
        """The key to use next and how long to wait for it (0 if ready now).

        The current key is kept while it has headroom; otherwise the key that is
        ready soonest is chosen. ``hint`` is the expected size of the request.
        """
        now = self._clock()
        with self._lock:
            ready = {
                position: self._available_at(position, now, hint)
                for position in range(len(self._keys))
            }
            best = min(ready, key=lambda position: (ready[position], position != preferred))
            return best, max(ready[best] - now, 0.0)


_SHARED: dict[tuple[str, str, tuple[str, ...], RateLimitPolicy], KeyPacer] = {}
_SHARED_LOCK = threading.Lock()


def shared_pacer(
    provider: str, model: str, keys: tuple[str, ...], policy: RateLimitPolicy
) -> KeyPacer:
    """One pacer per provider/model/key set, so consecutive runs share headroom."""
    digests = tuple(fingerprint(key) for key in keys)
    with _SHARED_LOCK:
        cache_key = (provider, model, digests, policy)
        if cache_key not in _SHARED:
            _SHARED[cache_key] = KeyPacer(digests, policy)
        return _SHARED[cache_key]


def reset_shared_pacers() -> None:
    """Forget all shared pacing state (process restart equivalent; used by tests)."""
    with _SHARED_LOCK:
        _SHARED.clear()


__all__ = [
    "DEFAULT_COOLDOWN_SECONDS",
    "KeyPacer",
    "RateLimitPolicy",
    "fingerprint",
    "parse_duration",
    "reset_shared_pacers",
    "shared_pacer",
]
