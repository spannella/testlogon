"""GAP-0068 + GAP-0069 regression tests (offline, moto in-memory DynamoDB).

GAP-0068: A platform-wide ad kill switch must exist. When enabled, serve_ad
must serve NO paid ad (returns filled=False, fill_reason="platform_kill_switch_active").

GAP-0069: Suspending an advertiser account via moderate_account(action="suspend")
must cascade and pause all of that account's ACTIVE campaigns.

Before the fix:
  * admin_ad_platform had no is_kill_switch_active/toggle_kill_switch, and
    serve_ad had no kill-switch gate → kill-switch test fails (paid ad served).
  * moderate_account never touched campaigns → suspended account's campaigns
    stay status="active" → cascade test fails.

No real AWS: moto in-memory DynamoDB + in-process moto S3/etc. are never reached.
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


def _pk_sk_table(ddb, name, *, extra_attrs=None, gsis=None):
    attr_defs = [
        {"AttributeName": "pk", "AttributeType": "S"},
        {"AttributeName": "sk", "AttributeType": "S"},
    ]
    if extra_attrs:
        attr_defs.extend(extra_attrs)
    kwargs = dict(
        TableName=name,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=attr_defs,
        BillingMode="PAY_PER_REQUEST",
    )
    if gsis:
        kwargs["GlobalSecondaryIndexes"] = gsis
    return ddb.create_table(**kwargs)


@pytest.fixture
def ddb_tables():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        _pk_sk_table(
            ddb, "ad_campaigns",
            extra_attrs=[
                {"AttributeName": "status", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "N"},
            ],
            gsis=[{
                "IndexName": "ByStatusCreatedAt",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }],
        )
        _pk_sk_table(ddb, "billing")
        _pk_sk_table(ddb, "ad_creatives")
        _pk_sk_table(ddb, "ad_targeting")
        _pk_sk_table(ddb, "ad_frequency_caps")
        _pk_sk_table(ddb, "ad_accounts")
        _pk_sk_table(ddb, "ad_moderation_log")

        import app.core.tables as tables_mod
        names = [
            "billing", "ad_campaigns", "ad_creatives", "ad_targeting",
            "ad_frequency_caps", "ad_accounts", "ad_moderation_log",
        ]
        originals = {attr: getattr(tables_mod.T, attr) for attr in names}
        for attr in names:
            object.__setattr__(tables_mod.T, attr, ddb.Table(attr))

        # Reset the kill-switch in-process cache between tests.
        from app.services import admin_ad_platform as svc
        svc._KS_CACHE.clear()

        yield ddb

        svc._KS_CACHE.clear()
        for attr, orig in originals.items():
            object.__setattr__(tables_mod.T, attr, orig)


def _seed_account(ddb, *, account_id="acct_001", status="active"):
    ddb.Table("ad_accounts").put_item(Item={
        "pk": f"ACCT#{account_id}",
        "sk": "META",
        "account_id": account_id,
        "owner_sub": "owner_1",
        "company_name": "Acme",
        "status": status,
        "created_at": 1700000000,
    })


def _seed_campaign(ddb, *, campaign_id, account_id="acct_001",
                   status="active", created_at=1700000000):
    ddb.Table("ad_campaigns").put_item(Item={
        "pk": f"ACCT#{account_id}",
        "sk": f"CAMPAIGN#{campaign_id}",
        "campaign_id": campaign_id,
        "account_id": account_id,
        "status": status,
        "bid_cpm_cents": 500,
        "created_at": created_at,
    })


# ── GAP-0068: kill switch halts paid serving ────────────────────────────────

def test_kill_switch_inactive_by_default(ddb_tables):
    from app.services import admin_ad_platform as svc
    svc._KS_CACHE.clear()
    assert svc.is_kill_switch_active() is False
    state = svc.get_kill_switch_state()
    assert state["active"] is False


def test_kill_switch_active_serves_no_paid_ad(ddb_tables):
    """With kill switch ON, serve_ad returns no-fill (not a paid ad)."""
    from app.services import admin_ad_platform as svc
    from app.services.ad_serving import serve_ad

    # Enable the kill switch through the real service path (writes DDB).
    result = svc.toggle_kill_switch(
        enabled=True, admin_sub="root_sub", reason="emergency",
    )
    assert result["active"] is True
    # Cache must have been invalidated so the gate sees the new state.
    assert svc._KS_CACHE == {}

    served = serve_ad(
        surface="feed", content_type="post", creator_id="c1",
        content_id="p1", slot_type="inline", user_id="u1",
    )
    assert served["filled"] is False
    assert served.get("is_house_ad") is False
    assert served["fill_reason"] == "platform_kill_switch_active"


def test_kill_switch_disable_resumes_serving(ddb_tables):
    """After disabling, serve_ad no longer returns the kill-switch response."""
    from app.services import admin_ad_platform as svc
    from app.services.ad_serving import serve_ad

    svc.toggle_kill_switch(enabled=True, admin_sub="root_sub", reason="x")
    svc.toggle_kill_switch(enabled=False, admin_sub="root_sub", reason="")

    assert svc.get_kill_switch_state()["active"] is False

    served = serve_ad(
        surface="feed", content_type="post", creator_id="c1",
        content_id="p1", slot_type="inline", user_id="u1",
    )
    # No campaigns seeded → house ad, NOT the kill-switch no-fill.
    assert served["fill_reason"] != "platform_kill_switch_active"


# ── GAP-0069: suspension cascades to pause active campaigns ──────────────────

def test_suspend_pauses_active_campaigns(ddb_tables):
    from app.services import admin_ad_platform as svc

    _seed_account(ddb_tables, account_id="acct_001", status="active")
    _seed_campaign(ddb_tables, campaign_id="camp_001", status="active",
                   created_at=1700000001)
    _seed_campaign(ddb_tables, campaign_id="camp_002", status="active",
                   created_at=1700000002)
    _seed_campaign(ddb_tables, campaign_id="camp_003", status="paused",
                   created_at=1700000003)

    result = svc.moderate_account(
        account_id="acct_001", action="suspend",
        admin_sub="root_sub", reason="policy violation",
    )

    assert result is not None
    # review_ad_account stores the raw decision as the status ("suspend").
    assert result["status"] == "suspend"
    assert set(result["paused_campaign_ids"]) == {"camp_001", "camp_002"}

    # Verify the campaign rows were actually mutated in DynamoDB.
    active_after = svc.list_all_campaigns(account_id="acct_001", status="active")
    assert active_after == []
    paused_after = {
        c["campaign_id"]
        for c in svc.list_all_campaigns(account_id="acct_001", status="paused")
    }
    assert paused_after == {"camp_001", "camp_002", "camp_003"}


def test_approve_does_not_pause_campaigns(ddb_tables):
    from app.services import admin_ad_platform as svc

    _seed_account(ddb_tables, account_id="acct_002", status="pending_review")
    _seed_campaign(ddb_tables, campaign_id="camp_a", account_id="acct_002",
                   status="active")

    result = svc.moderate_account(
        account_id="acct_002", action="approve", admin_sub="root_sub",
    )

    assert result["status"] == "active"
    assert result.get("paused_campaign_ids", []) == []
    # Campaign untouched.
    still_active = svc.list_all_campaigns(account_id="acct_002", status="active")
    assert {c["campaign_id"] for c in still_active} == {"camp_a"}
