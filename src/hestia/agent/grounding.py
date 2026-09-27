"""Deterministic citation validation.

This checks that a report's citations exist, belong to this case, and match what
the store actually holds. It does not judge whether a claim is true — semantic
evaluation belongs to H5. A report whose citations cannot be resolved is returned
as report-invalid rather than published, after at most one bounded repair attempt.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from hestia.agent.contracts import GroundingIssue, GroundingResult, Report
from hestia.agent.redaction import Redactor

if TYPE_CHECKING:  # pragma: no cover
    from hestia.store.repository import EvidenceRepository


def validate_report(
    report: Report,
    *,
    redactor: Redactor,
    retrieved_handles: frozenset[str],
    repository: EvidenceRepository | None,
    technique_ids: frozenset[str],
    repair_attempted: bool = False,
) -> GroundingResult:
    """Check every citation in ``report`` against what this run actually saw."""
    issues: list[GroundingIssue] = []
    checked = 0

    for finding in report.findings:
        for handle in finding.evidence_handles:
            checked += 1
            if handle not in retrieved_handles:
                issues.append(
                    GroundingIssue(
                        kind="uncited_handle",
                        detail=("the report cites a handle that no tool call in this run returned"),
                        handle=handle,
                    )
                )
                continue
            identifier = redactor.resolve(handle)
            if identifier is None:
                issues.append(
                    GroundingIssue(
                        kind="unresolvable_handle",
                        detail="the handle has no local mapping to a stored identifier",
                        handle=handle,
                    )
                )
                continue
            if repository is not None and handle.startswith("ev-"):
                row = repository.read_event(identifier)
                if row is None:
                    issues.append(
                        GroundingIssue(
                            kind="missing_evidence",
                            detail="the cited event is not in the evidence store",
                            handle=handle,
                        )
                    )
                elif finding.excerpt:
                    issues.extend(_check_excerpt(finding.excerpt, row, handle))

    for technique_id in report.technique_ids:
        checked += 1
        if technique_id not in technique_ids:
            issues.append(
                GroundingIssue(
                    kind="unknown_technique",
                    detail=(
                        "the report names a technique that is not in the pinned "
                        "reference snapshot for this deployment"
                    ),
                    handle=technique_id,
                )
            )

    return GroundingResult(
        grounded=not issues,
        checked_handles=checked,
        issues=tuple(issues),
        repair_attempted=repair_attempted,
    )


def _check_excerpt(excerpt: str, row: dict[str, Any], handle: str) -> list[GroundingIssue]:
    """An excerpt must be a literal substring of the canonical stored line."""
    import json

    payload = json.loads(row["event_json"])
    canonical = str(payload.get("raw_line") or payload["event"]["raw_message"])
    normalized = " ".join(excerpt.split())
    if normalized and normalized not in " ".join(canonical.split()):
        return [
            GroundingIssue(
                kind="excerpt_mismatch",
                detail="the quoted excerpt does not appear in the stored source line",
                handle=handle,
            )
        ]
    return []


def repair_instruction(result: GroundingResult) -> str:
    """One concrete correction request, naming only what actually failed."""
    kinds = sorted({issue.kind for issue in result.issues})
    detail = "; ".join(f"{issue.kind}: {issue.handle}" for issue in result.issues[:10])
    return (
        "Your report failed citation validation and was not accepted. "
        f"Problems found: {', '.join(kinds)}. Specifically: {detail}. "
        "Cite only handles that the tool results in this conversation actually "
        "returned, quote excerpts exactly as they appear in those results, and "
        "name only technique identifiers a reference tool returned. If you cannot "
        "support a finding that way, remove it, and return "
        "verdict='insufficient_evidence' with severity='none' if nothing remains."
    )


__all__ = ["repair_instruction", "validate_report"]
