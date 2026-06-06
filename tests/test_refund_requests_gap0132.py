"""GAP-0132 regression: marketplace refund approval must debit the seller.

When an admin approves a refund for a tip/unlock transaction, the buyer is
credited AND the seller (original tip recipient) is debited, so the bilateral
ledger nets to zero. Before the fix only the buyer credit was written, leaving
the seller's earned credit in place (double-enrichment).

Offline: in-memory moto-mocked DynamoDB. No real AWS.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import boto3
import pytest
from moto import mock_aws

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

sys.modules.setdefault("prometheus_client", MagicMock())

from app.core.tables import T  # noqa: E402
from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger  # noqa: E402
from app.services import refund_requests as rr_svc  # noqa: E402


def _create_billing_table(ddb):
    return ddb.create_table(
        TableName="Billing",
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


def _create_refund_requests_table(ddb):
    return ddb.create_table(
        TableName="RefundRequests",
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


def _install_tables(billing, refunds):
    """Swap real moto tables into the frozen global registry; return a
    restore callable."""
    orig_billing = T.billing
    orig_refunds = T.refund_requests
    object.__setattr__(T, "billing", billing)
    object.__setattr__(T, "refund_requests", refunds)

    def restore():
        object.__setattr__(T, "billing", orig_billing)
        object.__setattr__(T, "refund_requests", orig_refunds)

    return restore


def _ledger_entries(billing_table, user_id):
    return billing_table.query(
        KeyConditionExpression="pk = :pk",
        ExpressionAttributeValues={":pk": f"USER#{user_id}"},
    )["Items"]


@mock_aws
def test_marketplace_refund_debits_seller(monkeypatch):
    ddb = boto3.resource("dynamodb", region_name="us-east-1")
    billing = _create_billing_table(ddb)
    refunds = _create_refund_requests_table(ddb)

    # Swap real moto tables into the global table registry for the duration.
    restore = _install_tables(billing, refunds)
    # Side-effect helpers touch other tables; stub them out.
    monkeypatch.setattr(rr_svc, "write_alert", lambda *a, **k: None)
    monkeypatch.setattr(rr_svc, "audit_event", lambda *a, **k: None)
    try:
        buyer_id = "buyer_001"
        seller_id = "seller_001"
        amount = 500  # $5.00

        # 1. Buyer tips the seller -> paired debit (buyer) + credit (seller).
        ids = write_tip_ledger(TipLedgerEntry(
            tipper_user_id=buyer_id,
            recipient_user_id=seller_id,
            amount_cents=amount,
            content_type="message",
            content_id="msg_001",
        ))
        buyer_debit_id = ids["debit_entry_id"]

        # 2. Buyer submits a refund request for that debit.
        request = rr_svc.create_refund_request(
            user_id=buyer_id,
            transaction_entry_id=buyer_debit_id,
            reason="I regret this tip",
        )
        request_id = request["refund_request_id"]

        # 3. Admin approves.
        rr_svc.approve_request(request_id=request_id, admin_id="admin_001")

        # 4. Buyer received a refund credit.
        buyer_entries = _ledger_entries(billing, buyer_id)
        refund_credits = [e for e in buyer_entries if e.get("type") == "refund_credit"]
        assert len(refund_credits) == 1
        assert int(refund_credits[0]["amount_cents"]) == amount

        # 5. Seller was debited (the GAP-0132 fix). Fails before fix.
        seller_entries = _ledger_entries(billing, seller_id)
        refund_debits = [e for e in seller_entries if e.get("type") == "refund_debit"]
        assert len(refund_debits) == 1, "Seller debit entry must be written on refund approval"
        assert int(refund_debits[0]["amount_cents"]) == amount

        # 6. Net effect for the seller is zero: +amount credit, -amount debit.
        seller_credits = sum(
            int(e["amount_cents"]) for e in seller_entries if e.get("type") == "credit"
        )
        seller_debits = sum(
            int(e["amount_cents"]) for e in seller_entries if e.get("type") == "refund_debit"
        )
        assert seller_credits - seller_debits == 0, "Seller ledger must net to zero after refund"
    finally:
        restore()


@mock_aws
def test_non_marketplace_refund_skips_seller_debit(monkeypatch):
    """A refund for a self/non-peer ledger entry credits the buyer only and
    does not invent a seller debit."""
    ddb = boto3.resource("dynamodb", region_name="us-east-1")
    billing = _create_billing_table(ddb)
    refunds = _create_refund_requests_table(ddb)

    restore = _install_tables(billing, refunds)
    monkeypatch.setattr(rr_svc, "write_alert", lambda *a, **k: None)
    monkeypatch.setattr(rr_svc, "audit_event", lambda *a, **k: None)
    try:
        buyer_id = "buyer_002"
        amount = 1000

        # A deposit-style debit with no peer recipient.
        from app.core.time import now_ts
        ts = now_ts()
        billing.put_item(Item={
            "pk": f"USER#{buyer_id}",
            "sk": f"LEDGER#{ts}#dep1",
            "entry_id": "dep1",
            "ts": ts,
            "type": "debit",
            "amount_cents": amount,
            "currency": "USD",
            "state": "settled",
            "reason": "Wallet deposit",
            "meta": {},
        })

        request = rr_svc.create_refund_request(
            user_id=buyer_id,
            transaction_entry_id="dep1",
            reason="changed my mind",
        )
        rr_svc.approve_request(request_id=request["refund_request_id"], admin_id="admin_001")

        buyer_entries = _ledger_entries(billing, buyer_id)
        assert any(e.get("type") == "refund_credit" for e in buyer_entries)
        assert not any(e.get("type") == "refund_debit" for e in buyer_entries)
    finally:
        restore()
