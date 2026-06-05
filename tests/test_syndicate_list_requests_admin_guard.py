"""Regression test for GAP-0061: syndicate pending join-requests listing must
be admin-guarded.

Before the fix, ``list_pending_requests(syndicate_id)`` had no caller check, so
any authenticated user (including non-member outsiders) could enumerate every
pending join request for an arbitrary syndicate. The fix threads ``caller_sub``
from the router and enforces ``_require_admin`` in the service.

Offline: DynamoDB tables are mocked via moto; the ``T`` table registry is
patched in the service module under test. No real AWS.
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
OUTSIDER = "carol"
REQUESTER = "dave"


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
def synd_env():
    import boto3
    from moto import mock_aws

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        _make_pksk_table(ddb, "syndicates")
        syndicates = ddb.Table("syndicates")

        from app.services import syndicates as syndicate_svc

        synd_T = SimpleNamespace(syndicates=syndicates)
        with patch.object(syndicate_svc, "T", synd_T):
            # Alice is admin (and a member); Bob is an ordinary member.
            synd = syndicate_svc.create_syndicate(creator_sub=ADMIN, name="S")
            sid = synd["syndicate_id"]
            syndicate_svc._add_member(sid, MEMBER, role="member")
            syndicate_svc._increment_member_count(sid, 1)

            # Dave requests to join -> one pending request exists.
            syndicate_svc.request_to_join(syndicate_id=sid, user_id=REQUESTER)

            yield {"sid": sid, "svc": syndicate_svc}


def test_non_admin_member_cannot_list_pending_requests(synd_env):
    """An ordinary member must be rejected with 403."""
    from fastapi import HTTPException

    svc = synd_env["svc"]
    sid = synd_env["sid"]
    with pytest.raises(HTTPException) as exc:
        svc.list_pending_requests(sid, MEMBER)
    assert exc.value.status_code == 403


def test_outsider_cannot_list_pending_requests(synd_env):
    """A non-member outsider must be rejected with 403."""
    from fastapi import HTTPException

    svc = synd_env["svc"]
    sid = synd_env["sid"]
    with pytest.raises(HTTPException) as exc:
        svc.list_pending_requests(sid, OUTSIDER)
    assert exc.value.status_code == 403


def test_admin_can_list_pending_requests(synd_env):
    """The syndicate admin can list pending requests."""
    svc = synd_env["svc"]
    sid = synd_env["sid"]
    items = svc.list_pending_requests(sid, ADMIN)
    assert len(items) == 1
    assert items[0]["user_id"] == REQUESTER
    assert items[0]["status"] == "pending"
