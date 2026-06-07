"""GAP-0075 regression: affiliate commission withdrawal endpoint.

Earnings were computed and surfaced on the dashboard
(``available_for_withdrawal_cents``) but there was no way to redeem them — no
``withdraw`` service function and no ``POST /ui/referrals/withdraw`` route.

This test exercises the new ``withdraw()`` service function:

* Withdrawing available commission credits the user's wallet and zeroes out the
  available balance (commission rows flipped ``pending`` -> ``paid``).
* Withdrawing more than is available is rejected with ``ValueError``.

FAILS before the fix (``ImportError``: no ``withdraw`` symbol).
PASSES after the fix.

Offline only: in-memory boto3 + moto, no real AWS.
"""

from __future__ import annotations

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


@pytest.fixture(autouse=True)
def _mock_env(monkeypatch):
    monkeypatch.setenv("DEV_MODE", "1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("APP_TABLE", "app_single_table")
    # Lower the minimum so a modest seeded balance can be withdrawn in full.
    monkeypatch.setenv("REFERRAL_MIN_WITHDRAWAL_CENTS", "100")
    # Force the referrals service to talk to in-process moto, not :8001.
    monkeypatch.delenv("DDB_ENDPOINT_URL", raising=False)
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)


@pytest.fixture()
def tables(monkeypatch):
    """Create app_single_table + a moto-backed billing table.

    Yields ``(app_table, billing_table)``. Rebinds the referrals service cache
    and ``T.billing`` to the moto resources so the withdrawal credit lands in
    the in-process billing table.
    """
    import boto3
    from moto import mock_aws

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        app_table = ddb.create_table(
            TableName="app_single_table",
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
        billing_table = ddb.create_table(
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

        # Rebind lazily-cached handles to the moto resources. ``T`` is a frozen
        # dataclass, so swap the whole singleton for a tiny stand-in exposing
        # ``.billing`` (the only attribute ``withdraw`` touches).
        import types

        import app.services.referrals as referrals_svc
        import app.core.tables as tables_mod

        monkeypatch.setattr(referrals_svc, "_TABLE", None)
        monkeypatch.setattr(
            tables_mod, "T", types.SimpleNamespace(billing=billing_table)
        )

        # Seed two pending commissions for alice (3000 + 2000 = 5000 available).
        for idx, cents in enumerate((3000, 2000)):
            app_table.put_item(Item={
                "pk": "AFFILIATE#alice",
                "sk": f"COMMISSION#txn_{idx}",
                "Entity": "AffiliateCommission",
                "referrer_user_id": "alice",
                "commission_cents": cents,
                "status": "pending",
                "created_at": f"2026-01-0{idx + 1}T00:00:00Z",
            })

        yield app_table, billing_table


def _available(app_table, user_id: str) -> int:
    """Available = pending/confirmed commission minus already-paid (mirrors dashboard)."""
    from boto3.dynamodb.conditions import Key

    items = app_table.query(
        KeyConditionExpression=Key("pk").eq(f"AFFILIATE#{user_id}"),
    ).get("Items", [])
    comms = [i for i in items if str(i.get("sk", "")).startswith("COMMISSION#")]
    earned = sum(int(c["commission_cents"]) for c in comms if c.get("status") in ("pending", "confirmed"))
    paid = sum(int(c["commission_cents"]) for c in comms if c.get("status") == "paid")
    return max(0, earned - paid)


def _wallet_balance(billing_table, user_id: str) -> int:
    from app.services.billing_shared import get_wallet_balance, user_pk

    return get_wallet_balance(billing_table, user_pk(user_id))["wallet_balance_cents"]


def test_withdraw_credits_wallet_and_zeroes_available(tables):
    """Withdrawing the full available balance credits the wallet and zeroes available.

    FAILS before fix (no withdraw symbol), PASSES after.
    """
    from app.services.referrals import withdraw

    app_table, billing_table = tables

    assert _available(app_table, "alice") == 5000
    assert _wallet_balance(billing_table, "alice") == 0

    result = withdraw("alice", 5000)

    assert result["status"] == "completed"
    assert result["amount_cents"] == 5000

    # Wallet credited.
    assert _wallet_balance(billing_table, "alice") == 5000
    # Available zeroed (commissions now paid).
    assert _available(app_table, "alice") == 0

    # A settled ledger entry exists.
    from app.services.billing_shared import ddb_query_pk, user_pk

    rows = ddb_query_pk(billing_table, user_pk("alice"))
    ledger = [r for r in rows if r.get("type") == "affiliate_withdrawal_credit"]
    assert len(ledger) == 1
    assert int(ledger[0]["amount_cents"]) == 5000
    assert ledger[0]["state"] == "settled"


def test_withdraw_more_than_available_is_rejected(tables):
    """Withdrawing above the available balance raises ValueError and credits nothing."""
    from app.services.referrals import withdraw

    app_table, billing_table = tables

    with pytest.raises(ValueError, match="exceeds available"):
        withdraw("alice", 9999)

    # No wallet credit, balance untouched.
    assert _wallet_balance(billing_table, "alice") == 0
    assert _available(app_table, "alice") == 5000
