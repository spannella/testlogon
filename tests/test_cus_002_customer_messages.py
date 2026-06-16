"""CUS-002: Hermetic tests for user-customer link + bidirectional message thread."""
from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import boto3
import pytest
from fastapi import HTTPException
from moto import mock_aws


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _moto_tables():
    """Create customers + alerts tables with moto; patch T and S."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        customers_table = ddb.create_table(
            TableName="cus002_customers",
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

        alerts_table = ddb.create_table(
            TableName="cus002_alerts",
            KeySchema=[
                {"AttributeName": "user_sub", "KeyType": "HASH"},
                {"AttributeName": "alert_id", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "user_sub", "AttributeType": "S"},
                {"AttributeName": "alert_id", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        alert_prefs_table = ddb.create_table(
            TableName="cus002_alert_prefs",
            KeySchema=[{"AttributeName": "user_sub", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "user_sub", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )

        import app.core.tables as _tables_mod
        import app.core.settings as _settings_mod

        orig_customers = _tables_mod.T.customers
        orig_alerts = _tables_mod.T.alerts
        orig_alert_prefs = _tables_mod.T.alert_prefs
        orig_obp = _settings_mod.S.open_bank_project_enabled
        orig_cus = _settings_mod.S.customer_entity_enabled

        object.__setattr__(_tables_mod.T, "customers", customers_table)
        object.__setattr__(_tables_mod.T, "alerts", alerts_table)
        object.__setattr__(_tables_mod.T, "alert_prefs", alert_prefs_table)
        object.__setattr__(_settings_mod.S, "open_bank_project_enabled", True)
        object.__setattr__(_settings_mod.S, "customer_entity_enabled", True)

        # Remove cached modules
        for mod in ["app.services.customers", "app.services.customer_messages"]:
            sys.modules.pop(mod, None)

        from app.services.customers import CustomerStore
        from app.services.customer_messages import CustomerMessageStore

        cust_store = CustomerStore(_table=customers_table)
        msg_store = CustomerMessageStore(_table=customers_table)

        yield cust_store, msg_store, customers_table

        object.__setattr__(_tables_mod.T, "customers", orig_customers)
        object.__setattr__(_tables_mod.T, "alerts", orig_alerts)
        object.__setattr__(_tables_mod.T, "alert_prefs", orig_alert_prefs)
        object.__setattr__(_settings_mod.S, "open_bank_project_enabled", orig_obp)
        object.__setattr__(_settings_mod.S, "customer_entity_enabled", orig_cus)


def _make_customer(cust_store):
    return cust_store.create_customer(legal_name="TestCustomer", actor_sub="admin")


# ---------------------------------------------------------------------------
# Link tests
# ---------------------------------------------------------------------------

class TestLink:
    def test_link_creates_forward_and_reverse(self, _moto_tables):
        cust_store, msg_store, tbl = _moto_tables
        cust = _make_customer(cust_store)
        cid = cust["customer_id"]
        user_sub = "user-link-001"

        link = cust_store.link_user(cid, user_sub, "admin")
        assert link["customer_id"] == cid
        assert link["user_sub"] == user_sub

        # Forward
        fwd = cust_store.get_link(cid, user_sub)
        assert fwd is not None
        assert fwd["user_sub"] == user_sub

        # Reverse
        rev = cust_store.resolve_customer_for_user(user_sub)
        assert rev is not None
        assert rev["customer_id"] == cid

    def test_link_idempotent(self, _moto_tables):
        cust_store, msg_store, tbl = _moto_tables
        cust = _make_customer(cust_store)
        cid = cust["customer_id"]
        user_sub = "user-idempotent-link"
        # Link twice
        link1 = cust_store.link_user(cid, user_sub, "admin")
        link2 = cust_store.link_user(cid, user_sub, "admin")
        assert link1["customer_id"] == link2["customer_id"]

    def test_link_conflict_different_customer(self, _moto_tables):
        from app.services.customers import CustomerLinkConflictError
        cust_store, msg_store, tbl = _moto_tables
        c1 = _make_customer(cust_store)
        c2 = _make_customer(cust_store)
        user_sub = "user-conflict-link"
        cust_store.link_user(c1["customer_id"], user_sub, "admin")
        with pytest.raises(CustomerLinkConflictError) as exc_info:
            cust_store.link_user(c2["customer_id"], user_sub, "admin")
        assert exc_info.value.existing_customer_id == c1["customer_id"]

    def test_resolve_unlinked_returns_none(self, _moto_tables):
        cust_store, msg_store, tbl = _moto_tables
        result = cust_store.resolve_customer_for_user("never-linked-user")
        assert result is None


# ---------------------------------------------------------------------------
# Message thread tests
# ---------------------------------------------------------------------------

class TestMessages:
    def test_post_staff_message(self, _moto_tables):
        cust_store, msg_store, tbl = _moto_tables
        cust = _make_customer(cust_store)
        cid = cust["customer_id"]
        msg = msg_store.post_message(cid, author_sub="admin-sub", author_role="STAFF", body="Hello customer!")
        assert msg["message_id"].startswith("cmsg_")
        assert msg["author_role"] == "STAFF"
        assert msg["body"] == "Hello customer!"

    def test_post_customer_message(self, _moto_tables):
        cust_store, msg_store, tbl = _moto_tables
        cust = _make_customer(cust_store)
        cid = cust["customer_id"]
        msg = msg_store.post_message(cid, author_sub="user-abc", author_role="CUSTOMER", body="Hi support!")
        assert msg["author_role"] == "CUSTOMER"

    def test_list_messages_oldest_first(self, _moto_tables):
        from app.core.time import now_ts
        cust_store, msg_store, tbl = _moto_tables
        cust = _make_customer(cust_store)
        cid = cust["customer_id"]
        # Post 3 messages
        msg_store.post_message(cid, author_sub="a1", author_role="STAFF", body="msg1")
        msg_store.post_message(cid, author_sub="a2", author_role="CUSTOMER", body="msg2")
        msg_store.post_message(cid, author_sub="a3", author_role="STAFF", body="msg3")

        result = msg_store.list_messages(cid, newest_first=False)
        msgs = result["messages"]
        assert len(msgs) >= 3
        # Verify chronological: created_at should be non-decreasing
        timestamps = [int(m["created_at"]) for m in msgs]
        assert timestamps == sorted(timestamps)

    def test_list_messages_newest_first(self, _moto_tables):
        cust_store, msg_store, tbl = _moto_tables
        cust = _make_customer(cust_store)
        cid = cust["customer_id"]
        msg_store.post_message(cid, author_sub="b1", author_role="STAFF", body="first")
        msg_store.post_message(cid, author_sub="b2", author_role="CUSTOMER", body="second")
        result = msg_store.list_messages(cid, newest_first=True)
        msgs = result["messages"]
        assert len(msgs) >= 2
        timestamps = [int(m["created_at"]) for m in msgs]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_list_messages_pagination(self, _moto_tables):
        cust_store, msg_store, tbl = _moto_tables
        cust = _make_customer(cust_store)
        cid = cust["customer_id"]
        for i in range(5):
            msg_store.post_message(cid, author_sub="pager", author_role="STAFF", body=f"page msg {i}")

        result1 = msg_store.list_messages(cid, limit=2)
        assert len(result1["messages"]) == 2
        assert result1["cursor"] is not None

        result2 = msg_store.list_messages(cid, cursor=result1["cursor"], limit=2)
        assert len(result2["messages"]) == 2

        # Ensure no duplicates
        ids1 = {m["message_id"] for m in result1["messages"]}
        ids2 = {m["message_id"] for m in result2["messages"]}
        assert ids1.isdisjoint(ids2)

    def test_staff_message_triggers_write_alert(self, _moto_tables):
        cust_store, msg_store, tbl = _moto_tables
        cust = _make_customer(cust_store)
        cid = cust["customer_id"]
        user_sub = "user-for-notify"
        cust_store.link_user(cid, user_sub, "admin")

        with patch("app.services.alerts.write_alert") as mock_alert:
            msg_store.post_message(cid, author_sub="admin-sub", author_role="STAFF", body="Staff msg")
            mock_alert.assert_called_once()
            call_kwargs = mock_alert.call_args[1]
            assert call_kwargs["user_sub"] == user_sub

    def test_notification_failure_does_not_block_message(self, _moto_tables):
        cust_store, msg_store, tbl = _moto_tables
        cust = _make_customer(cust_store)
        cid = cust["customer_id"]
        user_sub = "user-notify-fail"
        cust_store.link_user(cid, user_sub, "admin")

        with patch("app.services.alerts.write_alert", side_effect=Exception("Network error")):
            # Should NOT raise
            msg = msg_store.post_message(cid, author_sub="admin-sub", author_role="STAFF", body="Notification will fail")
            assert msg["message_id"].startswith("cmsg_")


# ---------------------------------------------------------------------------
# Router handler tests (direct call)
# ---------------------------------------------------------------------------

class TestRouterHandlers:
    def test_get_my_customer_returns_404_when_unlinked(self, _moto_tables):
        import asyncio
        cust_store, msg_store, tbl = _moto_tables
        from app.routers.customers import get_my_customer
        ctx = {"user_sub": "unlinked-user-xyz", "role": "user"}
        with pytest.raises(HTTPException) as exc_info:
            get_my_customer(ctx=ctx)
        assert exc_info.value.status_code == 404

    def test_flag_off_raises_404(self, _moto_tables):
        import app.core.settings as _s
        orig_obp = _s.S.open_bank_project_enabled
        orig_cus = _s.S.customer_entity_enabled
        object.__setattr__(_s.S, "open_bank_project_enabled", False)
        object.__setattr__(_s.S, "customer_entity_enabled", False)
        try:
            from app.routers.customers import _require_flag
            with pytest.raises(HTTPException) as exc_info:
                _require_flag()
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(_s.S, "open_bank_project_enabled", orig_obp)
            object.__setattr__(_s.S, "customer_entity_enabled", orig_cus)
