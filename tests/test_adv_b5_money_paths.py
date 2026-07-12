"""ADV-504: money-path test suite for the ad system (ADV-B5).

Offline, moto in-memory DynamoDB (no real AWS, no sleeping). Asserts:

  * 2nd-price auction clears at runner-up + 1c (capped at own bid; lone bidder
    at the reserve floor)                                    -- clear_second_price
  * impression / click / conversion charges debit the correct amount, are
    funds-guarded (balance can never go negative, no ledger row on a rejected
    debit) and idempotent (a repeated idempotency_key never double-charges)
  * placement split: a creator-owned placement (video pre-roll) pays the poster
    ~70% + platform ~30%; a standalone newsfeed unit (no owner) books the
    platform the FULL charge, no creator row
  * budget / balance cannot overspend
  * ADV-502 reversal returns the money to the advertiser + claws the creator
    credit back WITHOUT inflating earnings (reversal entry_type != "credit"),
    is idempotent + double-reversal guarded
  * ADV-501 roas_report aggregates spend / impressions / clicks / CTR /
    conversions / CPA / ROAS from the ledger
"""
from __future__ import annotations

import os
from unittest.mock import patch

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


ACCOUNT_ID = "acct-b5"
OWNER_SUB = "owner-b5"
CAMPAIGN_ID = "camp_b5"
CREATOR_SUB = "poster-b5"


def _pk_sk_table(ddb, name):
    return ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                   {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                              {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )


def _ad_clicks_table(ddb):
    return ddb.create_table(
        TableName="ad_clicks",
        KeySchema=[{"AttributeName": "ad_click_id", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "ad_click_id", "AttributeType": "S"},
            {"AttributeName": "viewer_sub", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "ByViewer",
            "KeySchema": [{"AttributeName": "viewer_sub", "KeyType": "HASH"},
                          {"AttributeName": "created_at", "KeyType": "RANGE"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
    )


@pytest.fixture
def tables():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        ad_billing = _pk_sk_table(ddb, "ad_billing")
        ad_accounts = _pk_sk_table(ddb, "ad_accounts")
        ad_campaigns = _pk_sk_table(ddb, "ad_campaigns")
        billing = _pk_sk_table(ddb, "billing")
        ad_clicks = _ad_clicks_table(ddb)

        import app.core.tables as tm
        originals = {}
        for attr, tbl in (
            ("ad_billing", ad_billing), ("ad_accounts", ad_accounts),
            ("ad_campaigns", ad_campaigns), ("billing", billing),
            ("ad_clicks", ad_clicks),
        ):
            originals[attr] = getattr(tm.T, attr)
            object.__setattr__(tm.T, attr, tbl)
        try:
            yield {"ad_billing": ad_billing, "ad_accounts": ad_accounts,
                   "ad_campaigns": ad_campaigns, "billing": billing,
                   "ad_clicks": ad_clicks}
        finally:
            for attr, orig in originals.items():
                object.__setattr__(tm.T, attr, orig)


def _seed_account(t, balance_cents):
    t["ad_accounts"].put_item(Item={
        "pk": f"ACCT#{ACCOUNT_ID}", "sk": "META", "account_id": ACCOUNT_ID,
        "owner_sub": OWNER_SUB, "balance_cents": balance_cents,
    })


def _seed_campaign(t, budget_cents=1_000_000):
    t["ad_campaigns"].put_item(Item={
        "pk": f"ACCT#{ACCOUNT_ID}", "sk": f"CAMPAIGN#{CAMPAIGN_ID}",
        "campaign_id": CAMPAIGN_ID, "account_id": ACCOUNT_ID,
        "budget_cents": budget_cents, "status": "active",
        "bid_cpm_cents": 500, "bid_cpc_cents": 50, "bid_cpa_cents": 500,
    })


def _balance(t):
    it = t["ad_accounts"].get_item(Key={"pk": f"ACCT#{ACCOUNT_ID}", "sk": "META"}).get("Item")
    return int(it.get("balance_cents", 0))


def _ledger_rows(t):
    from boto3.dynamodb.conditions import Key
    return t["ad_billing"].query(
        KeyConditionExpression=Key("pk").eq(f"ACCT#{ACCOUNT_ID}") & Key("sk").begins_with("LEDGER#")
    ).get("Items", [])


def _creator_credits(creator_sub):
    from app.services import creator_earnings
    return creator_earnings._query_credit_entries(user_id=creator_sub)


# ---------------------------------------------------------------------------
# 2nd-price auction
# ---------------------------------------------------------------------------
class TestSecondPriceAuction:
    def test_winner_clears_at_runner_up_plus_one(self):
        from app.services.ad_serving import clear_second_price
        assert clear_second_price(20000, 15000) == 15001

    def test_capped_at_own_bid(self):
        from app.services.ad_serving import clear_second_price
        # runner-up basically tied -> never pay above own bid
        assert clear_second_price(15000, 15000) == 15000
        assert clear_second_price(15000, 20000) == 15000

    def test_lone_bidder_clears_at_floor(self):
        from app.services.ad_serving import clear_second_price
        assert clear_second_price(20000, None) == 50

    def test_never_below_one_cent(self):
        from app.services.ad_serving import clear_second_price
        assert clear_second_price(1, 0) == 1


# ---------------------------------------------------------------------------
# charge correctness + funds-guard + idempotency
# ---------------------------------------------------------------------------
class TestCharges:
    def test_impression_charge_amount_and_debit(self, tables):
        _seed_account(tables, 10000)
        _seed_campaign(tables)
        from app.services import ad_billing
        r = ad_billing.charge_impression(
            account_id=ACCOUNT_ID, campaign_id=CAMPAIGN_ID, creative_id="cr1",
            creator_id="", content_id="c1", bid_cpm_cents=5000)
        assert r["ok"] and r["charge_cents"] == 5  # 5000 // 1000
        assert _balance(tables) == 10000 - 5

    def test_click_charge_amount(self, tables):
        _seed_account(tables, 10000)
        _seed_campaign(tables)
        from app.services import ad_billing
        r = ad_billing.charge_click(
            account_id=ACCOUNT_ID, campaign_id=CAMPAIGN_ID, creative_id="cr1",
            creator_id="", content_id="c1", bid_cpc_cents=50)
        assert r["ok"] and r["charge_cents"] == 50
        assert _balance(tables) == 10000 - 50

    def test_insufficient_funds_no_debit_no_ledger(self, tables):
        _seed_account(tables, 30)
        _seed_campaign(tables)
        from app.services import ad_billing
        r = ad_billing.charge_click(
            account_id=ACCOUNT_ID, campaign_id=CAMPAIGN_ID, creative_id="cr1",
            creator_id="", content_id="c1", bid_cpc_cents=50)
        assert r["ok"] is False and r["reason"] == "insufficient_funds"
        assert _balance(tables) == 30  # unchanged, never negative
        assert _ledger_rows(tables) == []  # no charge row written

    def test_idempotent_click_never_double_charges(self, tables):
        _seed_account(tables, 10000)
        _seed_campaign(tables)
        from app.services import ad_billing
        key = "click#abc"
        r1 = ad_billing.charge_click(
            account_id=ACCOUNT_ID, campaign_id=CAMPAIGN_ID, creative_id="cr1",
            creator_id="", content_id="c1", bid_cpc_cents=50, idempotency_key=key)
        r2 = ad_billing.charge_click(
            account_id=ACCOUNT_ID, campaign_id=CAMPAIGN_ID, creative_id="cr1",
            creator_id="", content_id="c1", bid_cpc_cents=50, idempotency_key=key)
        assert r1["charge_cents"] == 50
        assert r2["reason"] == "duplicate" and r2["charge_cents"] == 0
        assert _balance(tables) == 10000 - 50  # debited exactly once

    def test_budget_cannot_overspend_balance(self, tables):
        # balance covers exactly two 50c clicks; the third is rejected.
        _seed_account(tables, 100)
        _seed_campaign(tables)
        from app.services import ad_billing
        ok1 = ad_billing.charge_click(account_id=ACCOUNT_ID, campaign_id=CAMPAIGN_ID,
                                      creative_id="cr1", creator_id="", content_id="c1",
                                      bid_cpc_cents=50)
        ok2 = ad_billing.charge_click(account_id=ACCOUNT_ID, campaign_id=CAMPAIGN_ID,
                                      creative_id="cr1", creator_id="", content_id="c1",
                                      bid_cpc_cents=50)
        rej = ad_billing.charge_click(account_id=ACCOUNT_ID, campaign_id=CAMPAIGN_ID,
                                      creative_id="cr1", creator_id="", content_id="c1",
                                      bid_cpc_cents=50)
        assert ok1["ok"] and ok2["ok"]
        assert rej["ok"] is False and rej["reason"] == "insufficient_funds"
        assert _balance(tables) == 0  # spent to zero, never below


# ---------------------------------------------------------------------------
# placement-aware revenue split
# ---------------------------------------------------------------------------
class TestPlacementSplit:
    def test_video_placement_pays_poster_70_platform_30(self, tables):
        _seed_account(tables, 100000)
        _seed_campaign(tables)
        from app.services import ad_billing
        ad_billing.charge_conversion(
            account_id=ACCOUNT_ID, campaign_id=CAMPAIGN_ID, creative_id="cr1",
            creator_id=CREATOR_SUB, content_id="vid1", bid_cpa_cents=500,
            conversion_value_cents=1999)
        credits = _creator_credits(CREATOR_SUB)
        assert len(credits) == 1
        assert credits[0]["amount_cents"] == 350  # 500 * 7000 // 10000
        assert credits[0]["type"] == "credit"
        # platform booked the remainder (30%)
        from boto3.dynamodb.conditions import Key
        plat = tables["ad_billing"].query(
            KeyConditionExpression=Key("pk").eq("PLATFORM#revenue") & Key("sk").begins_with("LEDGER#")
        ).get("Items", [])
        assert len(plat) == 1 and plat[0]["amount_cents"] == 150

    def test_standalone_placement_platform_full_no_creator_row(self, tables):
        _seed_account(tables, 100000)
        _seed_campaign(tables)
        from app.services import ad_billing
        ad_billing.charge_conversion(
            account_id=ACCOUNT_ID, campaign_id=CAMPAIGN_ID, creative_id="cr1",
            creator_id="", content_id="feed1", bid_cpa_cents=500,
            conversion_value_cents=1999)
        # no creator row anywhere
        assert _creator_credits(CREATOR_SUB) == []
        from boto3.dynamodb.conditions import Key
        plat = tables["ad_billing"].query(
            KeyConditionExpression=Key("pk").eq("PLATFORM#revenue") & Key("sk").begins_with("LEDGER#")
        ).get("Items", [])
        assert len(plat) == 1 and plat[0]["amount_cents"] == 500  # FULL charge, no 70% drop


# ---------------------------------------------------------------------------
# ADV-502 reversal
# ---------------------------------------------------------------------------
class TestReversal:
    def _charge_conv(self, tables, creator_id):
        from app.services import ad_billing
        ad_billing.charge_conversion(
            account_id=ACCOUNT_ID, campaign_id=CAMPAIGN_ID, creative_id="cr1",
            creator_id=creator_id, content_id="vid1", bid_cpa_cents=500,
            conversion_value_cents=1999)
        row = [r for r in _ledger_rows(tables) if r["entry_type"] == "conversion_charge"][0]
        return row["entry_id"]

    def test_reversal_refunds_advertiser_net_zero(self, tables):
        _seed_account(tables, 100000)
        _seed_campaign(tables)
        from app.services import ad_billing
        eid = self._charge_conv(tables, CREATOR_SUB)
        assert _balance(tables) == 100000 - 500
        rec = ad_billing.reverse_ad_charge(account_id=ACCOUNT_ID, entry_id=eid,
                                           reason="fraud", actor="admin1")
        assert rec["reversed"] and rec["refunded_cents"] == 500
        assert _balance(tables) == 100000  # net zero -- money returned

    def test_reversal_claws_creator_without_inflating_earnings(self, tables):
        _seed_account(tables, 100000)
        _seed_campaign(tables)
        from app.services import ad_billing
        eid = self._charge_conv(tables, CREATOR_SUB)
        # after the charge: exactly one credit of 350
        credits = _creator_credits(CREATOR_SUB)
        assert len(credits) == 1 and credits[0]["amount_cents"] == 350
        ad_billing.reverse_ad_charge(account_id=ACCOUNT_ID, entry_id=eid, reason="fraud")
        # earnings query (type=="credit") STILL returns only the original credit;
        # the reversal is entry_type != "credit" so it never inflates earnings.
        credits_after = _creator_credits(CREATOR_SUB)
        assert len(credits_after) == 1
        assert all(c["type"] == "credit" for c in credits_after)
        # the reversal clawback row exists but is NOT a credit
        from boto3.dynamodb.conditions import Key
        all_rows = tables["billing"].query(
            KeyConditionExpression=Key("pk").eq(f"USER#{CREATOR_SUB}") & Key("sk").begins_with("LEDGER#")
        ).get("Items", [])
        claw = [r for r in all_rows if r["type"] == "ad_revenue_reversal"]
        assert len(claw) == 1 and claw[0]["amount_cents"] == 350
        # original credit flipped to reversed (drops from spendable balance)
        orig = [r for r in all_rows if r["type"] == "credit"][0]
        assert orig["state"] == "reversed"

    def test_reversal_idempotent_double_guard(self, tables):
        _seed_account(tables, 100000)
        _seed_campaign(tables)
        from app.services import ad_billing
        eid = self._charge_conv(tables, CREATOR_SUB)
        r1 = ad_billing.reverse_ad_charge(account_id=ACCOUNT_ID, entry_id=eid)
        bal_after_first = _balance(tables)
        r2 = ad_billing.reverse_ad_charge(account_id=ACCOUNT_ID, entry_id=eid)
        assert r1["idempotent_replay"] is False
        assert r2["idempotent_replay"] is True
        assert r2["refunded_cents"] == 500
        assert _balance(tables) == bal_after_first  # no second refund


# ---------------------------------------------------------------------------
# ADV-501 ROAS report
# ---------------------------------------------------------------------------
class TestRoasReport:
    def test_roas_report_aggregates_money_path(self, tables):
        _seed_account(tables, 1_000_000)
        _seed_campaign(tables)
        from app.services import ad_billing, ad_roas
        # 4 impressions @ 5c, 2 clicks @ 50c, 1 conversion @ 500c value 4000c
        for _ in range(4):
            ad_billing.charge_impression(account_id=ACCOUNT_ID, campaign_id=CAMPAIGN_ID,
                                         creative_id="cr1", creator_id="", content_id="c",
                                         bid_cpm_cents=5000)
        for _ in range(2):
            ad_billing.charge_click(account_id=ACCOUNT_ID, campaign_id=CAMPAIGN_ID,
                                    creative_id="cr1", creator_id="", content_id="c",
                                    bid_cpc_cents=50)
        ad_billing.charge_conversion(account_id=ACCOUNT_ID, campaign_id=CAMPAIGN_ID,
                                     creative_id="cr1", creator_id="", content_id="c",
                                     bid_cpa_cents=500, conversion_value_cents=4000)
        rep = ad_roas.roas_report(ACCOUNT_ID, days=30)
        tot = rep["totals"]
        spend = 4 * 5 + 2 * 50 + 500  # 620
        assert tot["impressions"] == 4
        assert tot["clicks"] == 2
        assert tot["conversions"] == 1
        assert tot["spend_cents"] == spend
        assert tot["conversion_value_cents"] == 4000
        assert tot["ctr_pct"] == round(2 / 4 * 100, 2)  # 50.0
        assert tot["cpa_cents"] == round(spend / 1, 2)   # 620.0
        assert tot["roas"] == round(4000 / spend, 4)
        # per-campaign breakdown present + scoped
        assert len(rep["campaigns"]) == 1
        assert rep["campaigns"][0]["campaign_id"] == CAMPAIGN_ID
        scoped = ad_roas.roas_report(ACCOUNT_ID, campaign_id=CAMPAIGN_ID, days=30)
        assert scoped["totals"]["spend_cents"] == spend

    def test_roas_zero_spend_no_divide_error(self, tables):
        _seed_account(tables, 100000)
        _seed_campaign(tables)
        from app.services import ad_roas
        rep = ad_roas.roas_report(ACCOUNT_ID, days=30)
        assert rep["totals"]["roas"] == 0.0
        assert rep["totals"]["spend_cents"] == 0
