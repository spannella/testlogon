"""Regression tests for GAP-0006.

Legacy ``record_ad_impression()`` had no fraud check, so an authenticated user
could replay ``event_type=complete`` events to drive unbounded fake ad-revenue
credits. These tests assert that a fraudulent impression is short-circuited by
the fraud gate (no revenue credit, no ledger entry) while clean impressions and
fraud-service outages still proceed (fail-open).

Offline only: in-memory + moto DynamoDB, no real AWS.
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
    os.environ.setdefault("VOD_ADS_ENABLED", "1")
    os.environ.setdefault("VOD_AD_CPM_CENTS", "500")


@pytest.fixture
def ddb_tables():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        ddb.create_table(
            TableName="VideoMetadata",
            KeySchema=[{"AttributeName": "video_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "video_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
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
        ddb.create_table(
            TableName="AdImpressions",
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

        originals = {
            "video_metadata": tables_mod.T.video_metadata,
            "billing": tables_mod.T.billing,
            "ad_impressions": tables_mod.T.ad_impressions,
        }
        object.__setattr__(tables_mod.T, "video_metadata", ddb.Table("VideoMetadata"))
        object.__setattr__(tables_mod.T, "billing", ddb.Table("billing"))
        object.__setattr__(tables_mod.T, "ad_impressions", ddb.Table("AdImpressions"))

        yield ddb

        for name, orig in originals.items():
            object.__setattr__(tables_mod.T, name, orig)


def _seed_video(ddb, video_id, owner_id="alice"):
    ddb.Table("VideoMetadata").put_item(Item={
        "video_id": video_id,
        "owner_user_id": owner_id,
        "title": f"Test Video {video_id}",
        "status": "published",
        "visibility": "public",
        "created_at": 1000,
        "updated_at": 1000,
        "source_type": "upload",
        "drm_enabled": False,
        "access_mode": "ad_supported",
        "price_cents": 0,
        "duration_seconds": 600,
        "ads_free_for_subscribers": False,
        "ad_impression_count": 0,
        "ad_revenue_cents": 0,
    })


def _billing_ledger_entries(ddb):
    items = ddb.Table("billing").scan().get("Items", [])
    return [i for i in items if i.get("type") == "ad_revenue_credit"]


def _revenue_cents(ddb, video_id):
    item = ddb.Table("VideoMetadata").get_item(
        Key={"video_id": video_id}
    ).get("Item", {})
    return int(item.get("ad_revenue_cents", 0))


class _Result:
    """Stand-in for FraudCheckResult."""

    def __init__(self, flagged, score=90):
        self.flagged = flagged
        self.score = score
        self.rule_scores = {"bot_ua": score}
        self.details = {"rule": "bot_ua"}


def test_fraudulent_complete_does_not_credit_revenue(ddb_tables, monkeypatch):
    """Core GAP-0006 regression: a flagged completion must NOT credit revenue.

    FAILS before the fix (revenue credited, ledger written, ok=True);
    PASSES after the fix (blocked=True, no revenue, no ledger entry).
    """
    _seed_video(ddb_tables, "v_fraud")

    recorded = {}

    monkeypatch.setattr(
        "app.services.ad_fraud_prevention.check_fraud",
        lambda **kw: _Result(flagged=True),
    )

    def _record(**kw):
        recorded.update(kw)
        return {}

    monkeypatch.setattr(
        "app.services.ad_fraud_prevention.record_fraud_event", _record
    )

    from app.services.ad_placement import record_ad_impression

    result = record_ad_impression(
        video_id="v_fraud",
        user_id="u_attacker",
        slot_type="pre_roll",
        slot_index=0,
        creative_id="cr_1",
        event_type="complete",
        ip_address="1.2.3.4",
        user_agent="bot/1.0",
        view_time_ms=0,
    )

    # Event is blocked.
    assert result.get("ok") is False
    assert result.get("blocked") is True

    # No revenue credited and no ledger entry written.
    assert _revenue_cents(ddb_tables, "v_fraud") == 0
    assert _billing_ledger_entries(ddb_tables) == []

    # Fraud event was recorded for audit (matches serving-path behaviour).
    assert recorded.get("user_id") == "u_attacker"
    assert recorded.get("event_type") == "complete"


def test_clean_complete_still_credits_revenue(ddb_tables, monkeypatch):
    """A non-flagged completion proceeds normally and credits revenue."""
    _seed_video(ddb_tables, "v_clean")

    monkeypatch.setattr(
        "app.services.ad_fraud_prevention.check_fraud",
        lambda **kw: _Result(flagged=False, score=0),
    )

    from app.services.ad_placement import record_ad_impression

    result = record_ad_impression(
        video_id="v_clean",
        user_id="u_real",
        slot_type="pre_roll",
        slot_index=0,
        creative_id="cr_1",
        event_type="complete",
        ip_address="5.6.7.8",
        user_agent="Mozilla/5.0",
        view_time_ms=28000,
    )

    assert result["ok"] is True
    assert result.get("blocked", False) is False
    assert _revenue_cents(ddb_tables, "v_clean") > 0
    assert len(_billing_ledger_entries(ddb_tables)) >= 1


def test_fraud_service_outage_fails_open(ddb_tables, monkeypatch):
    """A fraud-service exception must not block a legitimate impression."""
    _seed_video(ddb_tables, "v_open")

    def _boom(**kw):
        raise RuntimeError("fraud service down")

    monkeypatch.setattr(
        "app.services.ad_fraud_prevention.check_fraud", _boom
    )

    from app.services.ad_placement import record_ad_impression

    result = record_ad_impression(
        video_id="v_open",
        user_id="u_real",
        slot_type="pre_roll",
        slot_index=0,
        event_type="complete",
    )

    assert result["ok"] is True
    assert result.get("blocked", False) is False
    assert _revenue_cents(ddb_tables, "v_open") > 0
