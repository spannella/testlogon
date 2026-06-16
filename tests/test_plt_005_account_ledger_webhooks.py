"""PLT-005 hermetic unit tests: account/ledger webhook events."""
from __future__ import annotations

import asyncio
import json
import pytest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException


@pytest.fixture(autouse=True, scope="module")
def _setup_tables():
    """Create moto billing/webhook tables, bind T.*, set S flags."""
    import boto3
    from moto import mock_aws

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        billing_tbl = ddb.create_table(
            TableName="billing_plt005",
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
        wh_endpoints_tbl = ddb.create_table(
            TableName="webhook_endpoints_plt005",
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
        wh_deliveries_tbl = ddb.create_table(
            TableName="webhook_deliveries_plt005",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "status", "AttributeType": "S"},
                {"AttributeName": "next_retry_at", "AttributeType": "N"},
                {"AttributeName": "user_sub", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "N"},
            ],
            BillingMode="PAY_PER_REQUEST",
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "ByStatus",
                    "KeySchema": [
                        {"AttributeName": "status", "KeyType": "HASH"},
                        {"AttributeName": "next_retry_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "ByUser",
                    "KeySchema": [
                        {"AttributeName": "user_sub", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
        )

        for t in [billing_tbl, wh_endpoints_tbl, wh_deliveries_tbl]:
            t.meta.client.get_waiter("table_exists").wait(TableName=t.name)

        from app.core.tables import T
        from app.core.settings import S

        orig_billing = T.billing
        orig_wh_ep = T.webhook_endpoints
        orig_wh_dl = T.webhook_deliveries
        orig_obp = S.open_bank_project_enabled
        orig_alw = S.account_ledger_webhooks_enabled
        orig_we = S.webhooks_enabled
        orig_wv2 = S.webhooks_v2_enabled
        orig_admin = getattr(S, "filemgr_admin_users", "")

        object.__setattr__(T, "billing", billing_tbl)
        object.__setattr__(T, "webhook_endpoints", wh_endpoints_tbl)
        object.__setattr__(T, "webhook_deliveries", wh_deliveries_tbl)
        object.__setattr__(S, "open_bank_project_enabled", True)
        object.__setattr__(S, "account_ledger_webhooks_enabled", True)
        object.__setattr__(S, "webhooks_enabled", True)
        object.__setattr__(S, "webhooks_v2_enabled", True)
        object.__setattr__(S, "filemgr_admin_users", "admin_plt005")

        # Seed a webhook endpoint subscribed to transaction.created
        wh_endpoints_tbl.put_item(Item={
            "pk": "EVENT#transaction.created",
            "sk": "ENDPOINT#ep_test001",
            "endpoint_id": "ep_test001",
            "user_sub": "test_user",
            "url": "https://example.com/webhook",
            "enabled": True,
            "status": "active",
        })
        # Seed endpoints for threshold events
        for evt in ["balance.threshold", "account.balance_low"]:
            wh_endpoints_tbl.put_item(Item={
                "pk": f"EVENT#{evt}",
                "sk": "ENDPOINT#ep_thresh001",
                "endpoint_id": "ep_thresh001",
                "user_sub": "test_user",
                "url": "https://example.com/webhook",
                "enabled": True,
                "status": "active",
            })

        yield {
            "billing": billing_tbl,
            "wh_endpoints": wh_endpoints_tbl,
            "wh_deliveries": wh_deliveries_tbl,
        }

        object.__setattr__(T, "billing", orig_billing)
        object.__setattr__(T, "webhook_endpoints", orig_wh_ep)
        object.__setattr__(T, "webhook_deliveries", orig_wh_dl)
        object.__setattr__(S, "open_bank_project_enabled", orig_obp)
        object.__setattr__(S, "account_ledger_webhooks_enabled", orig_alw)
        object.__setattr__(S, "webhooks_enabled", orig_we)
        object.__setattr__(S, "webhooks_v2_enabled", orig_wv2)
        object.__setattr__(S, "filemgr_admin_users", orig_admin)


def _count_deliveries(tbls, event_type: str) -> int:
    resp = tbls["wh_deliveries"].scan()
    return sum(
        1 for it in resp.get("Items", [])
        if it.get("event_type") == event_type
    )


def _clear_deliveries(tbls):
    resp = tbls["wh_deliveries"].scan()
    with tbls["wh_deliveries"].batch_writer() as batch:
        for item in resp.get("Items", []):
            batch.delete_item(Key={"pk": item["pk"], "sk": item["sk"]})


# Test 1: New event types in taxonomy
def test_taxonomy_membership(_setup_tables):
    from app.services.webhook_service import is_valid_event_type

    assert is_valid_event_type("transaction.created")
    assert is_valid_event_type("balance.threshold")
    assert is_valid_event_type("account.balance_low")


# Test 2: Flag off → no delivery rows for emit_ledger_webhook
def test_flag_off_no_delivery_for_ledger_webhook(_setup_tables):
    tbls = _setup_tables
    _clear_deliveries(tbls)

    from app.core.settings import S
    from app.services.billing_shared import emit_ledger_webhook

    object.__setattr__(S, "account_ledger_webhooks_enabled", False)
    try:
        sample_item = {"entry_id": "tx001", "type": "credit", "amount_cents": 100, "reason": "test", "state": "settled", "ledger_date": "2026-06-01"}
        emit_ledger_webhook("user_test", sample_item)
        assert _count_deliveries(tbls, "transaction.created") == 0
    finally:
        object.__setattr__(S, "account_ledger_webhooks_enabled", True)


# Test 3: emit_ledger_webhook creates delivery row when enabled
def test_emit_ledger_webhook_creates_delivery(_setup_tables):
    tbls = _setup_tables
    _clear_deliveries(tbls)

    from app.services.billing_shared import emit_ledger_webhook, new_ledger_entry

    _sk, item = new_ledger_entry(
        key_name="pk",
        key_value="USER#test_user",
        entry_type="credit",
        amount_cents=2500,
        state="settled",
        reason="wallet_deposit",
    )
    emit_ledger_webhook("test_user", item)

    count = _count_deliveries(tbls, "transaction.created")
    assert count >= 1
    # Verify payload
    resp = tbls["wh_deliveries"].scan()
    tx_deliveries = [it for it in resp.get("Items", []) if it.get("event_type") == "transaction.created"]
    assert len(tx_deliveries) >= 1
    payload = json.loads(tx_deliveries[0].get("payload") or "{}")
    data = payload.get("data") or {}
    assert data["amount_cents"] == 2500


# Test 4: Threshold downward crossing fires events
def test_threshold_downward_crossing(_setup_tables):
    tbls = _setup_tables
    _clear_deliveries(tbls)

    from app.services.billing_shared import WALLET_SK, apply_wallet_delta

    pk = "USER#thresh_test"
    # Seed wallet with balance above threshold
    tbls["billing"].put_item(Item={
        "pk": pk,
        "sk": WALLET_SK,
        "wallet_balance_cents": 1500,
        "currency": "usd",
        "balance_threshold_cents": 1000,
        "last_threshold_crossed": False,
    })

    apply_wallet_delta(tbls["billing"], pk, -600)  # new balance 900 < 1000

    thresh_count = _count_deliveries(tbls, "balance.threshold")
    low_count = _count_deliveries(tbls, "account.balance_low")
    assert thresh_count >= 1
    assert low_count >= 1

    # Verify state flag set
    wallet = tbls["billing"].get_item(Key={"pk": pk, "sk": WALLET_SK}).get("Item", {})
    assert wallet.get("last_threshold_crossed") is True


# Test 5: No re-fire while already below threshold
def test_no_refire_while_below(_setup_tables):
    tbls = _setup_tables

    from app.services.billing_shared import WALLET_SK, apply_wallet_delta

    pk = "USER#thresh_below"
    tbls["billing"].put_item(Item={
        "pk": pk,
        "sk": WALLET_SK,
        "wallet_balance_cents": 800,
        "currency": "usd",
        "balance_threshold_cents": 1000,
        "last_threshold_crossed": True,  # already crossed
    })

    _clear_deliveries(tbls)
    apply_wallet_delta(tbls["billing"], pk, -100)  # still below

    thresh_count = _count_deliveries(tbls, "balance.threshold")
    assert thresh_count == 0


# Test 6: Recovery resets state without firing event
def test_recovery_resets_state(_setup_tables):
    tbls = _setup_tables

    from app.services.billing_shared import WALLET_SK, apply_wallet_delta

    pk = "USER#thresh_recover"
    tbls["billing"].put_item(Item={
        "pk": pk,
        "sk": WALLET_SK,
        "wallet_balance_cents": 800,
        "currency": "usd",
        "balance_threshold_cents": 1000,
        "last_threshold_crossed": True,
    })

    _clear_deliveries(tbls)
    apply_wallet_delta(tbls["billing"], pk, 500)  # new balance 1300 >= 1000

    assert _count_deliveries(tbls, "balance.threshold") == 0
    wallet = tbls["billing"].get_item(Key={"pk": pk, "sk": WALLET_SK}).get("Item", {})
    assert wallet.get("last_threshold_crossed") is False


# Test 7: Re-arm after recovery
def test_rearm_after_recovery(_setup_tables):
    tbls = _setup_tables

    from app.services.billing_shared import WALLET_SK, apply_wallet_delta

    pk = "USER#thresh_rearm"
    tbls["billing"].put_item(Item={
        "pk": pk,
        "sk": WALLET_SK,
        "wallet_balance_cents": 1200,
        "currency": "usd",
        "balance_threshold_cents": 1000,
        "last_threshold_crossed": False,
    })

    _clear_deliveries(tbls)
    apply_wallet_delta(tbls["billing"], pk, -500)  # new balance 700 < 1000

    assert _count_deliveries(tbls, "balance.threshold") >= 1


# Test 8: WEBHOOKS_ENABLED=0 suppresses dispatch
def test_webhooks_disabled_suppresses(_setup_tables):
    tbls = _setup_tables
    _clear_deliveries(tbls)

    from app.core.settings import S
    from app.services.billing_shared import emit_ledger_webhook

    object.__setattr__(S, "webhooks_enabled", False)
    try:
        sample = {"entry_id": "tx999", "type": "credit", "amount_cents": 100, "reason": "test", "state": "settled", "ledger_date": "2026-06-01"}
        emit_ledger_webhook("test_user", sample)
        assert _count_deliveries(tbls, "transaction.created") == 0
    finally:
        object.__setattr__(S, "webhooks_enabled", True)


# Test 9: set_wallet_threshold endpoint sets threshold and clears edge state
def test_set_wallet_threshold_endpoint(_setup_tables):
    tbls = _setup_tables

    from app.routers.billing import set_wallet_threshold
    from app.models import SetWalletThresholdReq

    # Pre-seed wallet with a stale threshold_crossed state
    tbls["billing"].put_item(Item={
        "pk": "USER#thresh_endpoint_test",
        "sk": "WALLET",
        "wallet_balance_cents": 1000,
        "currency": "usd",
        "balance_threshold_cents": 5000,
        "last_threshold_crossed": True,
    })

    req = MagicMock()
    ctx = {"user_sub": "thresh_endpoint_test"}

    with patch("app.routers.billing.audit_event"):
        result = set_wallet_threshold(body=SetWalletThresholdReq(threshold_cents=500), req=req, ctx=ctx)

    assert result["ok"] is True
    assert result["threshold_cents"] == 500

    # Verify DDB updated
    wallet = tbls["billing"].get_item(Key={"pk": "USER#thresh_endpoint_test", "sk": "WALLET"}).get("Item", {})
    assert int(wallet["balance_threshold_cents"]) == 500

    # Test clearing (threshold=0)
    with patch("app.routers.billing.audit_event"):
        result2 = set_wallet_threshold(body=SetWalletThresholdReq(threshold_cents=0), req=req, ctx=ctx)

    assert result2["threshold_cents"] == 0
    wallet2 = tbls["billing"].get_item(Key={"pk": "USER#thresh_endpoint_test", "sk": "WALLET"}).get("Item", {})
    assert int(wallet2["balance_threshold_cents"]) == 0
    assert wallet2.get("last_threshold_crossed") is False
