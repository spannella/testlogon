"""Regression test for GAP-0019 (FIN-004).

Consumer tax documents must aggregate consumer SPENDING (billing ledger
``type="debit"`` entries) — money the user *spent* — NOT creator EARNINGS
(``type="credit"`` entries). Before the fix, ``compute_*_summary`` filtered
``type="credit"`` and reused the creator-earnings classifier, so a pure
consumer's summary was empty and a creator's summary showed income instead of
spending.

Offline: in-memory moto DynamoDB, no real AWS.
"""
from __future__ import annotations

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

        original_billing = tables_mod.T.billing
        object.__setattr__(tables_mod.T, "billing", ddb.Table("billing"))
        yield ddb.Table("billing")
        object.__setattr__(tables_mod.T, "billing", original_billing)


def _seed(table, items):
    for it in items:
        table.put_item(Item=it)


# A debit (money Alice SPENT) and a credit (money Alice RECEIVED as creator).
_ALICE_DEBIT_TIP = {
    "pk": "USER#alice",
    "sk": "LEDGER#1700000001#e2",
    "type": "debit",
    "amount_cents": 1000,
    "reason": "Tip sent to Bob",
    "currency": "usd",
}
_ALICE_CREDIT_TIP = {
    "pk": "USER#alice",
    "sk": "LEDGER#1700000000#e1",
    "type": "credit",
    "amount_cents": 5000,
    "reason": "Tip received",
    "currency": "usd",
}


def test_spending_summary_counts_debits_only(billing_table):
    """A user's spending summary reflects DEBIT entries (money spent)."""
    from app.services.consumer_tax_documents import compute_spending_summary

    _seed(billing_table, [_ALICE_CREDIT_TIP, _ALICE_DEBIT_TIP])

    summary = compute_spending_summary(
        user_sub="alice", date_from=0, date_to=9_999_999_999
    )

    # Only the $10 debit counts; the $50 credit (creator earnings) does not.
    assert summary["grand_total_cents"] == 1000
    assert summary["transaction_count"] == 1
    tip_cat = next(c for c in summary["categories"] if c["category"] == "tips")
    assert tip_cat["total_cents"] == 1000
    assert tip_cat["transaction_count"] == 1


def test_credit_entries_are_excluded_from_spending(billing_table):
    """Credit (earnings) entries must NOT be counted as consumer spending."""
    from app.services.consumer_tax_documents import compute_spending_summary

    _seed(
        billing_table,
        [
            {
                "pk": "USER#alice",
                "sk": "LEDGER#1700000000#c1",
                "type": "credit",
                "amount_cents": 9999,
                "reason": "Subscription income",
                "currency": "usd",
            }
        ],
    )

    summary = compute_spending_summary(
        user_sub="alice", date_from=0, date_to=9_999_999_999
    )

    assert summary["grand_total_cents"] == 0
    assert summary["transaction_count"] == 0


def test_spending_categories_aggregate_correctly(billing_table):
    """Debits across multiple categories aggregate into consumer categories."""
    from app.services.consumer_tax_documents import compute_spending_summary

    _seed(
        billing_table,
        [
            {
                "pk": "USER#alice",
                "sk": "LEDGER#1700000001#d1",
                "type": "debit",
                "amount_cents": 1500,
                "reason": "Subscription to creator Bob",
                "currency": "usd",
            },
            {
                "pk": "USER#alice",
                "sk": "LEDGER#1700000002#d2",
                "type": "debit",
                "amount_cents": 700,
                "reason": "Unlock post #456",
                "currency": "usd",
            },
            {
                "pk": "USER#alice",
                "sk": "LEDGER#1700000003#d3",
                "type": "debit",
                "amount_cents": 2500,
                "reason": "Purchase - catalog item",
                "currency": "usd",
            },
            # Credit must be ignored.
            {
                "pk": "USER#alice",
                "sk": "LEDGER#1700000004#c1",
                "type": "credit",
                "amount_cents": 99999,
                "reason": "Tip received",
                "currency": "usd",
            },
        ],
    )

    summary = compute_spending_summary(
        user_sub="alice", date_from=0, date_to=9_999_999_999
    )

    assert summary["grand_total_cents"] == 1500 + 700 + 2500
    assert summary["transaction_count"] == 3
    by_cat = {c["category"]: c for c in summary["categories"]}
    assert by_cat["subscriptions"]["total_cents"] == 1500
    assert by_cat["unlocks"]["total_cents"] == 700
    assert by_cat["purchases"]["total_cents"] == 2500


def test_classify_category_maps_spec_categories():
    """classify_category maps FIN-004 consumer categories; credits -> other."""
    from app.services.consumer_tax_documents import classify_category

    assert classify_category({"type": "debit", "reason": "Subscription to Bob"}) == "subscriptions"
    assert classify_category({"type": "debit", "reason": "Plan upgrade - pro"}) == "subscriptions"
    assert classify_category({"type": "debit", "reason": "Tip sent to Alice"}) == "tips"
    assert classify_category({"type": "debit", "reason": "Purchase - catalog item"}) == "purchases"
    assert classify_category({"type": "debit", "reason": "Cart checkout order#123"}) == "purchases"
    assert classify_category({"type": "debit", "reason": "Unlock post #456"}) == "unlocks"
    assert classify_category({"type": "debit", "reason": "Deposit to wallet"}) == "deposits"
    assert classify_category({"type": "debit", "reason": "Unknown reason"}) == "other"
    # Credit entries are excluded from spending categorization.
    assert classify_category({"type": "credit", "reason": "Tip received"}) == "other"


def test_pdf_title_is_spending_not_earnings(billing_table, monkeypatch):
    """The consumer PDF must be titled a SPENDING summary, not EARNINGS."""
    import app.services.consumer_tax_documents as ctd
    from app.services.consumer_tax_documents import (
        compute_spending_summary,
        generate_tax_summary_pdf,
    )

    monkeypatch.setattr(
        ctd, "get_profile", lambda _sub: {"display_name": "Alice", "displayed_email": ""}
    )
    _seed(billing_table, [_ALICE_DEBIT_TIP])
    summary = compute_spending_summary(
        user_sub="alice", date_from=0, date_to=9_999_999_999
    )
    pdf_bytes = generate_tax_summary_pdf(user_sub="alice", summary=summary, year=2025)

    assert b"ANNUAL SPENDING SUMMARY" in pdf_bytes
    assert b"ANNUAL EARNINGS TAX SUMMARY" not in pdf_bytes


def test_creator_earnings_path_still_uses_credits(billing_table):
    """The retained creator-earnings helper (1099 path) still counts credits."""
    from app.services.consumer_tax_documents import compute_earnings_summary

    _seed(billing_table, [_ALICE_CREDIT_TIP, _ALICE_DEBIT_TIP])
    summary = compute_earnings_summary(
        user_sub="alice", date_from=0, date_to=9_999_999_999
    )

    # Creator earnings = the $50 credit, NOT the $10 debit.
    assert summary["grand_total_cents"] == 5000
    assert summary["transaction_count"] == 1
