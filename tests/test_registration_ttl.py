"""Regression test for GAP-0013 — abandoned registration permanently blocks email re-use.

Verifies that unverified (pending) registration records are written WITH a
DynamoDB TTL attribute so abandoned registrations self-clean, while verified
records carry NO TTL (or have it cleared) so a verified account never expires.

Offline: uses in-memory fake DynamoDB tables via monkeypatch (no real AWS),
matching the style of tests/test_registration_service.py.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.core.settings import S
from app.core.time import now_ts
from app.services import account_state as account_state_mod
from app.services import registration


class _FakeKeyValueTable:
    """Minimal in-memory DynamoDB table keyed by user_sub."""

    def __init__(self):
        self.items = {}

    def get_item(self, Key, **kwargs):
        item = self.items.get(Key["user_sub"])
        return {"Item": dict(item)} if item else {}

    def put_item(self, Item, ConditionExpression=None, **kwargs):
        if ConditionExpression and "attribute_not_exists" in ConditionExpression:
            if Item["user_sub"] in self.items:
                raise Exception("ConditionalCheckFailed")
        self.items[Item["user_sub"]] = dict(Item)
        return {}

    def update_item(self, Key, UpdateExpression="", ExpressionAttributeValues=None, **kwargs):
        item = self.items.get(Key["user_sub"])
        if item is None:
            return {}
        expr = (UpdateExpression or "").strip()
        if expr.upper().startswith("REMOVE"):
            attr = expr[len("REMOVE"):].strip()
            item.pop(attr, None)
        self.items[Key["user_sub"]] = item
        return {}

    def delete_item(self, Key, **kwargs):
        self.items.pop(Key["user_sub"], None)
        return {}


@pytest.fixture
def fake_tables(monkeypatch):
    users = _FakeKeyValueTable()
    account_state = _FakeKeyValueTable()

    # registration.py uses T.users (and T.* via set_account_state -> account_state.T)
    monkeypatch.setattr(registration, "T", SimpleNamespace(users=users))
    monkeypatch.setattr(account_state_mod, "T", SimpleNamespace(account_state=account_state))
    # save_profile touches T.profile; not relevant to this test.
    monkeypatch.setattr(registration, "save_profile", lambda *a, **k: None)

    return SimpleNamespace(users=users, account_state=account_state)


def test_pending_user_record_has_ttl_attribute(fake_tables):
    registration.create_user_record(
        email="ttl_test@example.com",
        full_name="TTL Test",
        password="secret123",
        verification_required=True,
    )
    item = fake_tables.users.get_item(Key={"user_sub": "ttl_test@example.com"}).get("Item", {})

    assert S.ddb_ttl_attr in item
    assert isinstance(item[S.ddb_ttl_attr], int)
    assert item[S.ddb_ttl_attr] > now_ts()


def test_pending_account_state_has_ttl_attribute(fake_tables):
    registration.create_user_record(
        email="ttl_state@example.com",
        full_name="TTL State Test",
        password="secret123",
        verification_required=True,
    )
    item = fake_tables.account_state.get_item(Key={"user_sub": "ttl_state@example.com"}).get("Item", {})

    assert S.ddb_ttl_attr in item
    assert item[S.ddb_ttl_attr] > now_ts()


def test_no_ttl_on_verified_registration(fake_tables):
    registration.create_user_record(
        email="no_ttl@example.com",
        full_name="No TTL",
        password="secret123",
        verification_required=False,
    )
    users_item = fake_tables.users.get_item(Key={"user_sub": "no_ttl@example.com"}).get("Item", {})
    state_item = fake_tables.account_state.get_item(Key={"user_sub": "no_ttl@example.com"}).get("Item", {})

    assert S.ddb_ttl_attr not in users_item
    assert S.ddb_ttl_attr not in state_item


def test_ttl_cleared_on_verification(fake_tables):
    registration.create_user_record(
        email="verify_me@example.com",
        full_name="Verify Me",
        password="secret123",
        verification_required=True,
    )
    # Sanity: TTL present before verification.
    assert S.ddb_ttl_attr in fake_tables.users.get_item(
        Key={"user_sub": "verify_me@example.com"}
    ).get("Item", {})

    registration.mark_user_verified("verify_me@example.com")

    users_item = fake_tables.users.get_item(Key={"user_sub": "verify_me@example.com"}).get("Item", {})
    state_item = fake_tables.account_state.get_item(Key={"user_sub": "verify_me@example.com"}).get("Item", {})

    assert S.ddb_ttl_attr not in users_item
    assert S.ddb_ttl_attr not in state_item


def test_email_reusable_after_record_deleted(fake_tables):
    """Once the (TTL-expired) record is removed, the email becomes available again.

    Simulates DynamoDB TTL expiry, which doesn't fire in local/in-memory tables.
    """
    registration.create_user_record(
        email="reuse@example.com",
        full_name="Reuse Test",
        password="secret123",
        verification_required=True,
    )
    assert registration.is_email_available("reuse@example.com") is False

    fake_tables.users.delete_item(Key={"user_sub": "reuse@example.com"})
    assert registration.is_email_available("reuse@example.com") is True
