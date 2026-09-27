import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from hestia.knowledge import build_reference_index, held_out_source_paths, write_index
from hestia.knowledge.attack import AttackRefreshRefused, fetch_bundle, filter_bundle
from hestia.knowledge.cam import technique_id_from_directory
from hestia.knowledge.contracts import read_index
from hestia.knowledge.retrieval import LexicalIndex
from hestia.mcp.contracts import ToolInputError
from hestia.mcp.knowledge import get_technique, search_attack_patterns


def test_technique_directory_names_map_to_attack_ids():
    assert technique_id_from_directory("T1110-001") == "T1110.001"
    assert technique_id_from_directory("T1078-000") == "T1078"
    assert technique_id_from_directory("not-a-technique") is None


def test_index_is_reproducible_and_hash_verified(reference_settings):
    first = read_index(reference_settings.knowledge_index)
    rebuilt = build_reference_index(
        reference_settings.data_root,
        attack_snapshot=None,
    )
    assert first.index_hash
    assert first.index_hash != rebuilt.index_hash  # the ATT&CK subset changes the content
    again = build_reference_index(reference_settings.data_root, attack_snapshot=None)
    assert again.index_hash == rebuilt.index_hash


def test_corrupt_index_hash_is_rejected(reference_settings, tmp_path: Path):
    payload = json.loads(reference_settings.knowledge_index.read_text(encoding="utf-8"))
    payload["index_hash"] = "d" * 64
    broken = tmp_path / "broken.json"
    broken.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="index_hash"):
        read_index(broken)


def test_held_out_sources_are_excluded_from_the_reference_corpus(
    reference_settings, tmp_path: Path, split_manifest_writer
):
    source = (
        "cam-auth/manifestations_filtered/techniques/T1110-001/step-1/"
        "fixture-host/logs/log/auth.log"
    )
    manifest = split_manifest_writer(
        tmp_path / "splits.json",
        source_path=source,
        item_id=f"{source}:fixture-host:198.51.100.7:alice:2025-01-02T03:04:05+00:00",
        split="evaluation",
    )
    assert held_out_source_paths((manifest,)) == (source,)
    index = build_reference_index(reference_settings.data_root, split_manifests=(manifest,))
    assert index.documents == ()
    assert source in index.excluded_source_paths
    assert "cannot quote evidence" in index.exclusion_rule


def test_reference_search_is_transparent_and_attributed(reference_context):
    page = search_attack_patterns(reference_context, query="password guessing", limit=5)
    assert page.available and page.returned >= 1
    top = page.items[0]
    assert top.lexical_score > 0
    assert top.matched_terms and all(score > 0 for _, score in top.matched_terms)
    assert top.attribution and top.source_sha256
    assert "not a known/novel classifier" in page.scoring_method
    assert any("do not establish" in note for note in page.notes)


def test_reference_search_ranking_is_deterministic(reference_context):
    first = search_attack_patterns(reference_context, query="ssh failed password", limit=5)
    second = search_attack_patterns(reference_context, query="ssh failed password", limit=5)
    assert [item.document_id for item in first.items] == [item.document_id for item in second.items]


def test_lexical_index_ties_break_on_document_id():
    from hestia.knowledge.contracts import ReferenceDocument, ReferenceSource

    def document(identifier: str):
        return ReferenceDocument(
            document_id=identifier,
            title=identifier,
            indexed_text="identical text for both documents",
            snippet="identical text for both documents",
            source=ReferenceSource(
                collection="cam-auth",
                source_uri=identifier,
                sha256="e" * 64,
                version="fixture",
                attribution="fixture",
            ),
        )

    index = LexicalIndex((document("b"), document("a")))
    ranked = index.search("identical text", limit=5)
    assert [item.document.document_id for item in ranked] == ["a", "b"]


def test_unknown_technique_is_unavailable_not_invented(reference_context):
    result = get_technique(reference_context, technique_id="T9999")
    assert result.available is False
    assert result.name is None and result.description is None
    assert "not in the pinned ATT&CK subset" in (result.unavailable_reason or "")


def test_known_technique_returns_attribution_and_local_manifestations(reference_context):
    result = get_technique(reference_context, technique_id="T1110.001")
    assert result.available
    assert result.name == "Password Guessing"
    assert result.snapshot_version == "19.2"
    assert "MITRE ATT&CK" in (result.attribution or "")
    assert result.local_manifestations
    assert result.local_manifestations[0].source_sha256


def test_reference_tools_are_unavailable_without_an_index(empty_context):
    page = search_attack_patterns(empty_context, query="anything")
    assert page.available is False and "knowledge-build" in (page.unavailable_reason or "")
    technique = get_technique(empty_context, technique_id="T1110.001")
    assert technique.available is False


def test_reference_queries_are_validated(reference_context):
    with pytest.raises(ToolInputError):
        search_attack_patterns(reference_context, query="   ")
    with pytest.raises(ToolInputError):
        search_attack_patterns(reference_context, query="x" * 1000)
    with pytest.raises(ToolInputError):
        get_technique(reference_context, technique_id="T1110.001; DROP TABLE events")


def test_attack_refresh_requires_an_explicit_request():
    with pytest.raises(AttackRefreshRefused):
        fetch_bundle("https://example.invalid/bundle.json", confirmed=False)
    with pytest.raises(ValueError, match="https"):
        fetch_bundle("http://example.invalid/bundle.json", confirmed=True)


def test_attack_filter_keeps_only_current_auth_relevant_records():
    bundle = {
        "objects": [
            {
                "type": "attack-pattern",
                "name": "Kept",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T0001", "url": "u"}
                ],
                "x_mitre_data_sources": ["Logon Session: Logon Session Creation"],
            },
            {
                "type": "attack-pattern",
                "name": "Unrelated",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T0002"}],
                "x_mitre_data_sources": ["Network Traffic: Network Traffic Flow"],
            },
            {
                "type": "attack-pattern",
                "name": "Deprecated",
                "x_mitre_deprecated": True,
                "external_references": [{"source_name": "mitre-attack", "external_id": "T0003"}],
                "x_mitre_data_sources": ["User Account: User Account Authentication"],
            },
            {"type": "intrusion-set", "name": "Not a technique"},
        ]
    }
    kept = {item["technique_id"] for item in filter_bundle(bundle)}
    assert kept == {"T0001"}
    with_extra = {
        item["technique_id"] for item in filter_bundle(bundle, extra_ids=frozenset({"T0002"}))
    }
    assert with_extra == {"T0001", "T0002"}


def test_index_records_coverage_limitations(tmp_path: Path, settings):
    index = build_reference_index(settings.data_root)
    write_index(index, settings.knowledge_index)
    assert index.documents == ()
    assert any("not present" in note for note in index.coverage_notes)
    assert any("no mitre att&ck snapshot" in note.lower() for note in index.coverage_notes)
    assert index.built_at.tzinfo is not None
    assert index.built_at < datetime(2100, 1, 1, tzinfo=UTC)
