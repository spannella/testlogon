"""Regression tests for GAP-0032 (SYND-004): syndicate treasury self-disbursement.

A syndicate admin must NOT be able to disburse treasury funds to their own
wallet (the admin is always a member, so the existing `_require_admin` +
`_require_is_member` guards both pass for the admin).

Offline: DynamoDB tables are mocked via moto; the ``T`` table registry is
patched in the service modules under test. No real AWS.
"""

from __future__ import annotations

import os
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

ADMIN = "alice"
MEMBER = "bob"


@pytest.fixture(autouse=True)
def _mock_env(monkeypatch):
    monkeypatch.setenv("DEV_MODE", "1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("UI_ACCESS_TOKEN_SECRET", "test-secret")
    monkeypatch.setenv("API_KEY_PEPPER", "test-pepper")


def _make_pksk_table(ddb, name):
    return ddb.create_table(
        TableName=name,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    ) or ddb.Table(name)


@pytest.fixture()
def treasury_env():
    import boto3
    from moto import mock_aws

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        _make_pksk_table(ddb, "syndicates")
        _make_pksk_table(ddb, "syndicate_treasury")
        _make_pksk_table(ddb, "billing")
        syndicates = ddb.Table("syndicates")
        treasury_tbl = ddb.Table("syndicate_treasury")
        billing = ddb.Table("billing")

        from app.services import syndicates as syndicate_svc
        from app.services import syndicate_treasury as treasury_svc

        synd_T = SimpleNamespace(syndicates=syndicates)
        treasury_T = SimpleNamespace(
            syndicate_treasury=treasury_tbl, billing=billing
        )
        with patch.object(syndicate_svc, "T", synd_T), \
             patch.object(treasury_svc, "T", treasury_T):
            # Create a syndicate: Alice is admin (also a member), Bob is a member.
            synd = syndicate_svc.create_syndicate(creator_sub=ADMIN, name="S")
            sid = synd["syndicate_id"]
            syndicate_svc._add_member(sid, MEMBER, role="member")
            syndicate_svc._increment_member_count(sid, 1)

            # Seed the treasury balance with 1000 cents (Bob deposits).
            from app.services.billing_shared import apply_wallet_delta, user_pk
            apply_wallet_delta(billing, user_pk(MEMBER), 1000)
            treasury_svc.deposit(syndicate_id=sid, user_id=MEMBER, amount_cents=1000)

            yield {
                "sid": sid,
                "treasury_svc": treasury_svc,
                "billing": billing,
            }


def test_admin_cannot_disburse_to_self(treasury_env):
    """Admin disbursing to their own wallet is rejected with 400."""
    from fastapi import HTTPException

    svc = treasury_env["treasury_svc"]
    sid = treasury_env["sid"]
    with pytest.raises(HTTPException) as exc:
        svc.disburse(
            syndicate_id=sid,
            admin_sub=ADMIN,
            recipient_user_id=ADMIN,
            amount_cents=500,
        )
    assert exc.value.status_code == 400
    assert exc.value.detail == "Admin cannot disburse treasury funds to themselves"


def test_self_disburse_does_not_move_funds(treasury_env):
    """A rejected self-disbursement must not touch the treasury balance."""
    from fastapi import HTTPException

    svc = treasury_env["treasury_svc"]
    sid = treasury_env["sid"]
    before = svc.get_treasury_balance(sid)["balance_cents"]
    with pytest.raises(HTTPException):
        svc.disburse(
            syndicate_id=sid,
            admin_sub=ADMIN,
            recipient_user_id=ADMIN,
            amount_cents=before,
        )
    after = svc.get_treasury_balance(sid)["balance_cents"]
    assert after == before == 1000


def test_admin_can_disburse_to_member(treasury_env):
    """Legitimate disbursement to a different member still succeeds."""
    svc = treasury_env["treasury_svc"]
    sid = treasury_env["sid"]

    result = svc.disburse(
        syndicate_id=sid,
        admin_sub=ADMIN,
        recipient_user_id=MEMBER,
        amount_cents=200,
    )
    assert result["ok"] is True
    assert result["amount_cents"] == 200
    assert result["recipient_user_id"] == MEMBER
    assert result["new_treasury_balance_cents"] == 800
    # Bob's wallet was credited (started at 0 after depositing his 1000).
    assert result["new_recipient_balance_cents"] == 200
