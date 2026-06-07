"""GAP-0041 regression: update_creator_ad_settings must use an atomic
DynamoDB UpdateExpression (partial SET) instead of read-merge-PutItem, so a
partial PATCH cannot clobber fields written by a concurrent/interleaved writer.

Offline: moto in-memory DynamoDB, no real AWS / no real KMS.
"""
import os

import boto3
import pytest
from moto import mock_aws


@pytest.fixture(autouse=True)
def _env():
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
    os.environ.setdefault("DDB_ENDPOINT_URL", "")
    os.environ.setdefault("DEV_MODE", "1")
    os.environ.setdefault("UI_ACCESS_TOKEN_SECRET", "test-secret")
    os.environ.setdefault("API_KEY_PEPPER", "test-pepper")


@pytest.fixture
def billing_table():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        ddb.create_table(
            TableName="billing",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        import app.core.tables as tables_mod
        original = tables_mod.T.billing
        object.__setattr__(tables_mod.T, "billing", ddb.Table("billing"))
        try:
            yield ddb.Table("billing")
        finally:
            object.__setattr__(tables_mod.T, "billing", original)


def _key(creator_sub: str) -> dict:
    return {"pk": f"USER#{creator_sub}", "sk": "AD_SETTINGS"}


def test_partial_update_does_not_clobber_unrelated_fields(billing_table):
    """PATCH with only allow_ads=False must not clear allowed_ad_categories / min_cpm_cents."""
    from app.models import CreatorAdSettingsIn
    from app.services.creator_ad_prefs import update_creator_ad_settings

    creator_sub = "test_creator_001"
    billing_table.put_item(Item={
        **_key(creator_sub),
        "allow_ads": True,
        "allowed_ad_categories": ["sports", "tech"],
        "min_cpm_cents": 200,
        "updated_at": 1700000000,
    })

    result = update_creator_ad_settings(creator_sub, CreatorAdSettingsIn(allow_ads=False))
    assert result == {"ok": True}

    item = billing_table.get_item(Key=_key(creator_sub))["Item"]
    assert item["allow_ads"] is False
    assert item["allowed_ad_categories"] == ["sports", "tech"]
    assert int(item["min_cpm_cents"]) == 200


def test_interleaved_write_is_not_clobbered(billing_table, monkeypatch):
    """FAILS BEFORE FIX: the read-merge-PutItem path reads the item, then writes back the
    *whole* item from the stale in-memory snapshot, clobbering any field written by an
    interleaved writer between the read and the write. AFTER FIX: update_item performs a
    server-side partial SET (no get_item round-trip), so the interleaved field survives.

    The interleaved write is injected at the exact TOCTOU window by hooking get_item:
    the old code calls get_item (hook fires -> concurrent write lands -> old code's
    put_item then clobbers it). The new code never calls get_item, so we additionally
    perform the interleaved write up-front; the atomic update_item leaves it intact.
    """
    from app.core.tables import T
    from app.models import CreatorAdSettingsIn
    from app.services.creator_ad_prefs import update_creator_ad_settings

    creator_sub = "test_creator_002"
    billing_table.put_item(Item={
        **_key(creator_sub),
        "allow_ads": True,
        "allowed_ad_categories": [],
        "min_cpm_cents": 0,
        "updated_at": 1700000000,
    })

    # Interleaved writer lands a field BEFORE our update commits.
    billing_table.update_item(
        Key=_key(creator_sub),
        UpdateExpression="SET allowed_ad_categories = :c",
        ExpressionAttributeValues={":c": ["sports"]},
    )

    # Also model the classic TOCTOU: if the (old) code reads the item, it reads the
    # stale snapshot taken before the interleaved write above is observed — but moto
    # is synchronous so the read here would see ["sports"]. To force the lost-update
    # for the old code, make get_item return the pre-interleave snapshot.
    real_get_item = T.billing.get_item
    stale = {"Item": {
        **_key(creator_sub),
        "allow_ads": True,
        "allowed_ad_categories": [],
        "min_cpm_cents": 0,
        "updated_at": 1700000000,
    }}

    def _stale_get_item(*args, **kwargs):
        return stale

    monkeypatch.setattr(T.billing, "get_item", _stale_get_item)

    update_creator_ad_settings(creator_sub, CreatorAdSettingsIn(allow_ads=False))

    monkeypatch.undo()
    item = billing_table.get_item(Key=_key(creator_sub))["Item"]
    assert item["allow_ads"] is False
    # The interleaved write must NOT be clobbered by our partial update.
    assert item["allowed_ad_categories"] == ["sports"]


def test_empty_payload_is_noop(billing_table):
    """A payload with all-None fields must not raise (no empty UpdateExpression)."""
    from app.models import CreatorAdSettingsIn
    from app.services.creator_ad_prefs import update_creator_ad_settings

    creator_sub = "test_creator_003"
    result = update_creator_ad_settings(creator_sub, CreatorAdSettingsIn())
    assert result == {"ok": True}
    # No item should have been created for an all-None payload.
    assert "Item" not in billing_table.get_item(Key=_key(creator_sub))
