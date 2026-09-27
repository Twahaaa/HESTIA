import pytest

from hestia.agent.contracts import (
    Coverage,
    Finding,
    Report,
    Severity,
    Verdict,
)
from hestia.agent.grounding import repair_instruction, validate_report
from hestia.agent.redaction import build_redactor


def _report(**overrides):
    base = {
        "verdict": Verdict.suspicious,
        "severity": Severity.medium,
        "confidence": 0.6,
        "summary": "Repeated failures preceded a success.",
        "findings": (
            Finding(statement="Two failures preceded a success.", evidence_handles=("ev-1",)),
        ),
        "known_or_novel": Coverage.uncertain,
    }
    return Report(**(base | overrides))


def test_a_grounded_report_passes(repository, prepared):
    redactor = build_redactor("salt")
    rows = repository.search_events(text_pattern=None, limit=1)
    handle = redactor.handle("ev", str(rows[0]["event_id"]))
    result = validate_report(
        _report(findings=(Finding(statement="An event exists.", evidence_handles=(handle,)),)),
        redactor=redactor,
        retrieved_handles=frozenset({handle}),
        repository=repository,
        technique_ids=frozenset(),
    )
    assert result.grounded
    assert result.checked_handles == 1
    assert "does not judge whether a claim is true" in result.note


def test_fabricated_handle_fails_validation(repository):
    redactor = build_redactor("salt")
    result = validate_report(
        _report(findings=(Finding(statement="Invented.", evidence_handles=("ev-deadbeef",)),)),
        redactor=redactor,
        retrieved_handles=frozenset(),
        repository=repository,
        technique_ids=frozenset(),
    )
    assert not result.grounded
    assert [issue.kind for issue in result.issues] == ["uncited_handle"]


def test_citing_a_handle_the_run_never_retrieved_fails(repository):
    """A handle can be real and still uncited if no tool call in this run saw it."""
    redactor = build_redactor("salt")
    rows = repository.search_events(text_pattern=None, limit=1)
    handle = redactor.handle("ev", str(rows[0]["event_id"]))
    result = validate_report(
        _report(findings=(Finding(statement="Real but uncited.", evidence_handles=(handle,)),)),
        redactor=redactor,
        retrieved_handles=frozenset(),
        repository=repository,
        technique_ids=frozenset(),
    )
    assert not result.grounded
    assert result.issues[0].kind == "uncited_handle"


def test_missing_evidence_in_the_store_fails(repository):
    redactor = build_redactor("salt")
    handle = redactor.handle("ev", "fixture/auth.log:9999")
    result = validate_report(
        _report(findings=(Finding(statement="Ghost event.", evidence_handles=(handle,)),)),
        redactor=redactor,
        retrieved_handles=frozenset({handle}),
        repository=repository,
        technique_ids=frozenset(),
    )
    assert not result.grounded
    assert result.issues[0].kind == "missing_evidence"


def test_mismatched_excerpt_fails(repository):
    redactor = build_redactor("salt")
    rows = repository.search_events(text_pattern=None, limit=1)
    handle = redactor.handle("ev", str(rows[0]["event_id"]))
    result = validate_report(
        _report(
            findings=(
                Finding(
                    statement="Quoted something never logged.",
                    evidence_handles=(handle,),
                    excerpt="root logged in from 10.0.0.1 with a stolen key",
                ),
            )
        ),
        redactor=redactor,
        retrieved_handles=frozenset({handle}),
        repository=repository,
        technique_ids=frozenset(),
    )
    assert not result.grounded
    assert result.issues[0].kind == "excerpt_mismatch"


def test_matching_excerpt_passes(repository):
    import json

    redactor = build_redactor("salt")
    rows = repository.search_events(text_pattern=None, limit=1)
    row = rows[0]
    canonical = json.loads(row["event_json"])["raw_line"]
    handle = redactor.handle("ev", str(row["event_id"]))
    result = validate_report(
        _report(
            findings=(
                Finding(
                    statement="Quoted the stored line.",
                    evidence_handles=(handle,),
                    excerpt=canonical[10:40],
                ),
            )
        ),
        redactor=redactor,
        retrieved_handles=frozenset({handle}),
        repository=repository,
        technique_ids=frozenset(),
    )
    assert result.grounded, result.issues


def test_unknown_technique_fails_validation(repository):
    redactor = build_redactor("salt")
    handle = redactor.handle("ev", "x")
    result = validate_report(
        _report(
            findings=(Finding(statement="s", evidence_handles=(handle,)),),
            technique_ids=("T9999",),
        ),
        redactor=redactor,
        retrieved_handles=frozenset({handle}),
        repository=None,
        technique_ids=frozenset({"T1110.001"}),
    )
    assert not result.grounded
    assert any(issue.kind == "unknown_technique" for issue in result.issues)


def test_repair_instruction_names_only_real_problems(repository):
    redactor = build_redactor("salt")
    result = validate_report(
        _report(findings=(Finding(statement="x", evidence_handles=("ev-nope",)),)),
        redactor=redactor,
        retrieved_handles=frozenset(),
        repository=repository,
        technique_ids=frozenset(),
    )
    instruction = repair_instruction(result)
    assert "uncited_handle" in instruction
    assert "insufficient_evidence" in instruction
    assert "excerpt_mismatch" not in instruction


def test_report_contract_rejects_incoherent_conclusions():
    with pytest.raises(ValueError, match="severity 'none'"):
        _report(verdict=Verdict.insufficient_evidence, severity=Severity.high)
    with pytest.raises(ValueError, match="benign verdict"):
        _report(verdict=Verdict.benign, severity=Severity.high)
    with pytest.raises(ValueError, match="requires findings"):
        _report(findings=())
    with pytest.raises(ValueError, match="at least 1"):
        Finding(statement="unsupported", evidence_handles=())
