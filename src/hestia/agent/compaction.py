"""Keep each model request under a provider's per-request token ceiling.

Free provider tiers can cap a single request (Groq's free plan refuses any
request larger than its per-minute token limit with HTTP 413). An investigation
grows with every tool result, so once the history's estimated size passes the
configured budget, the oldest tool results are replaced by a compact stub that
keeps their evidence handles. Nothing is lost for grounding: citations are
checked against the run's recorded tool traces, not against the chat history,
so a compacted handle stays citable. The newest results are left intact.
"""

from __future__ import annotations

import math
from dataclasses import replace
from typing import Any

from pydantic_ai.messages import (
    ModelMessage,
    ModelMessagesTypeAdapter,
    ModelRequest,
    ModelResponse,
    ThinkingPart,
    ToolReturnPart,
)

#: Conservative characters per token for JSON-heavy payloads.
CHARS_PER_TOKEN = 3
COMPACTED_NOTE = (
    "Earlier result condensed to save context. Its evidence handles remain valid "
    "citations; call the tool again only if you need the full content."
)


def estimate_tokens(messages: list[ModelMessage]) -> int:
    return math.ceil(len(ModelMessagesTypeAdapter.dump_json(messages)) / CHARS_PER_TOKEN)


def _handles(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "handle" and isinstance(item, str):
                found.append(item)
            elif key == "session_handles" and isinstance(item, list):
                found.extend(str(handle) for handle in item)
            else:
                found.extend(_handles(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(_handles(item))
    return found


def _stub(part: ToolReturnPart) -> ToolReturnPart:
    content = part.content
    handles = list(dict.fromkeys(_handles(content)))
    return replace(
        part,
        content={
            "compacted": True,
            "available": content.get("available") if isinstance(content, dict) else None,
            "handles": handles,
            "note": COMPACTED_NOTE,
        },
    )


def _is_stub(part: ToolReturnPart) -> bool:
    return isinstance(part.content, dict) and part.content.get("compacted") is True


def compact_history(
    messages: list[ModelMessage], budget_tokens: int, *, keep_recent: int = 2
) -> list[ModelMessage]:
    """Condense the oldest tool results until the estimate fits ``budget_tokens``.

    The last ``keep_recent`` requests are never condensed, and tool call/return
    pairing is preserved because only return *content* changes. Reasoning text
    from older responses is dropped first; it is never needed for grounding.
    """
    if estimate_tokens(messages) <= budget_tokens:
        return messages
    result = list(messages)
    request_positions = [i for i, message in enumerate(result) if isinstance(message, ModelRequest)]
    protected = set(request_positions[-keep_recent:]) if keep_recent else set()
    last_response = max(
        (i for i, message in enumerate(result) if isinstance(message, ModelResponse)), default=-1
    )
    for index, message in enumerate(result):
        if isinstance(message, ModelResponse) and index != last_response:
            kept = [part for part in message.parts if not isinstance(part, ThinkingPart)]
            if len(kept) != len(message.parts):
                result[index] = replace(message, parts=kept)
    for index in request_positions:
        if estimate_tokens(result) <= budget_tokens:
            break
        if index in protected:
            continue
        message = result[index]
        assert isinstance(message, ModelRequest)
        parts = [
            _stub(part) if isinstance(part, ToolReturnPart) and not _is_stub(part) else part
            for part in message.parts
        ]
        result[index] = replace(message, parts=parts)
    return result


__all__ = ["CHARS_PER_TOKEN", "COMPACTED_NOTE", "compact_history", "estimate_tokens"]
