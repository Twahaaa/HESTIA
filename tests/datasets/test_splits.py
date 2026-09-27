from datetime import UTC, datetime, timedelta

from hestia.datasets.splits import SplitItem, build_split_manifest, cam_campaign_id


def _item(index: int, **updates: object) -> SplitItem:
    values: dict[str, object] = {
        "item_id": f"item-{index}",
        "source_path": f"cam/{index}/auth.log",
        "timestamp": datetime(2025, 1, 1, tzinfo=UTC) + timedelta(days=index),
        "host": f"host-{index}",
        "content_hash": f"hash-{index}",
        "campaign_id": f"campaign-{index}",
        "eligible": True,
        "eligibility_reason": "explicit fixture normal declaration",
    }
    values.update(updates)
    return SplitItem.model_validate(values)


def test_manifest_is_deterministic_and_content_hashed() -> None:
    items = [_item(index) for index in range(10)]
    first = build_split_manifest(items)
    second = build_split_manifest(list(reversed(items)))
    assert first == second
    assert len(first.manifest_hash) == 64
    assert first.source_hashes["cam/0/auth.log"] == "hash-0"


def test_unlabelled_unknown_is_explicitly_excluded_not_benign() -> None:
    unknown = _item(
        0,
        eligible=False,
        campaign_id=None,
        eligibility_reason="OpenSSH is unlabelled; normality is unknown",
    )
    manifest = build_split_manifest([unknown])
    assert manifest.entries[0].split == "excluded"
    assert "unknown" in manifest.entries[0].reason


def test_duplicate_and_campaign_groups_cannot_leak() -> None:
    items = [_item(index) for index in range(8)]
    items[5] = _item(5, content_hash=items[0].content_hash)
    items[6] = _item(6, campaign_id=items[1].campaign_id)
    manifest = build_split_manifest(items, reference_fraction=0.4, validation_fraction=0.3)
    splits = {entry.item_id: entry.split for entry in manifest.entries}
    assert splits["item-0"] == splits["item-5"]
    assert splits["item-1"] == splits["item-6"]


def test_host_link_is_transitive_with_campaign_and_content() -> None:
    items = [
        _item(0, host="shared"),
        _item(1, host="shared", campaign_id="bridge"),
        _item(2, campaign_id="bridge", content_hash="duplicate"),
        _item(3, content_hash="duplicate"),
        _item(4),
    ]
    manifest = build_split_manifest(items, reference_fraction=0.3, validation_fraction=0.3)
    splits = {entry.item_id: entry.split for entry in manifest.entries}
    assert len({splits[f"item-{index}"] for index in range(4)}) == 1


def test_cam_campaign_is_derived_across_catalog_views() -> None:
    scenario = "1_validaccount_localaccount-24"
    sequence = f"cam-auth/manifestations_filtered/sequences/{scenario}/host/logs/log/auth.log"
    technique = (
        f"cam-auth/manifestations_filtered/techniques/T1078/{scenario}/host/logs/log/auth.log"
    )
    assert cam_campaign_id(sequence) == scenario
    assert cam_campaign_id(technique) == scenario

    manifest = build_split_manifest(
        [
            _item(0, source_path=sequence, campaign_id=None),
            _item(1, source_path=technique, campaign_id=None),
            _item(2),
        ],
        reference_fraction=0.4,
        validation_fraction=0.3,
    )
    entries = {entry.item_id: entry for entry in manifest.entries}
    assert entries["item-0"].campaign_id == scenario
    assert entries["item-0"].split == entries["item-1"].split
