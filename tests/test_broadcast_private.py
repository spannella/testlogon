"""Unit tests for broadcast private session service (BCAST-011)."""
from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.services import broadcast_private


class _FakeTable:
    """Minimal in-memory DynamoDB table stub supporting pk/sk composite keys."""

    def __init__(self):
        self.items: dict[str, dict] = {}

    @staticmethod
    def _key(item_or_key: dict) -> str:
        # Support both pk/sk composite keys and simple single-key tables
        if "pk" in item_or_key and "sk" in item_or_key:
            return f"{item_or_key['pk']}|{item_or_key['sk']}"
        # Fallback: use any single-key field (session_id, profile_id, etc.)
        for field in ("session_id", "profile_id", "call_id", "transition_id"):
            if field in item_or_key:
                return item_or_key[field]
        # Last resort: use pk alone or first value
        if "pk" in item_or_key:
            return item_or_key["pk"]
        vals = list(item_or_key.values())
        return str(vals[0]) if vals else ""

    def put_item(self, *, Item, **kwargs):
        self.items[self._key(Item)] = dict(Item)

    def get_item(self, *, Key: dict, **kwargs):
        k = self._key(Key)
        item = self.items.get(k)
        return {"Item": dict(item)} if item else {}

    def update_item(self, *, Key: dict, UpdateExpression: str, ExpressionAttributeValues: dict | None = None, ExpressionAttributeNames: dict | None = None, **kwargs):
        k = self._key(Key)
        item = self.items.get(k)
        if not item:
            return
        names = ExpressionAttributeNames or {}
        vals = ExpressionAttributeValues or {}
        # Simple SET parser: "SET #st = :status, foo = :bar, ..."
        set_part = UpdateExpression
        if set_part.upper().startswith("SET "):
            set_part = set_part[4:]
        for assignment in set_part.split(","):
            assignment = assignment.strip()
            if "=" not in assignment:
                continue
            lhs, rhs = [x.strip() for x in assignment.split("=", 1)]
            field = names.get(lhs, lhs)
            value = vals.get(rhs, rhs)
            item[field] = value

    def query(self, *, KeyConditionExpression, FilterExpression=None, **kwargs):
        # Naive: return all items whose pk matches and sk starts with prefix
        all_items = list(self.items.values())
        result = []
        for item in all_items:
            # Check pk and sk match
            pk_val = KeyConditionExpression._values[1] if hasattr(KeyConditionExpression, "_values") else None
            if pk_val and item.get("pk") != pk_val:
                # Try to extract from compound condition
                pass
            # Simplified: just return items that match the pk prefix
            result.append(item)

        # Apply filter
        if FilterExpression:
            filtered = []
            for item in result:
                # Handle eq filter
                if hasattr(FilterExpression, "_values"):
                    filter_val = FilterExpression._values[1]
                    filter_path = FilterExpression._values[0]
                    if hasattr(filter_path, "name"):
                        if item.get(filter_path.name) == filter_val:
                            filtered.append(item)
                    elif isinstance(filter_val, list):
                        # is_in filter
                        for path in FilterExpression._values:
                            if hasattr(path, "name"):
                                if item.get(path.name) in filter_val:
                                    filtered.append(item)
                                break
                        else:
                            filtered.append(item)
                    else:
                        filtered.append(item)
                else:
                    filtered.append(item)
            result = filtered

        return {"Items": result}

    def scan(self, **kwargs):
        return {"Items": list(self.items.values())}


class _FakeQueryTable(_FakeTable):
    """DDB table fake with better query support for pk/sk pattern."""

    def query(self, *, KeyConditionExpression, FilterExpression=None, **kwargs):
        all_items = list(self.items.values())
        result = []

        # Extract the pk value from the key condition
        # The KeyConditionExpression is typically Key("pk").eq(val) & Key("sk").begins_with(prefix)
        pk_target = None
        sk_prefix = None

        # Try to parse the compound expression
        if hasattr(KeyConditionExpression, "_expression"):
            # Compound (AND)
            for expr in [KeyConditionExpression._expression.get("values", [])]:
                pass
        # Fallback: check all items
        for item in all_items:
            result.append(item)

        # Apply FilterExpression for status matching
        if FilterExpression:
            filtered = []
            for item in result:
                status = item.get("status", "")
                # Handle is_in and eq
                try:
                    if hasattr(FilterExpression, "_values"):
                        vals = FilterExpression._values
                        if len(vals) >= 2 and isinstance(vals[1], list):
                            if status in vals[1]:
                                filtered.append(item)
                        elif len(vals) >= 2 and isinstance(vals[1], str):
                            if status == vals[1]:
                                filtered.append(item)
                        else:
                            filtered.append(item)
                    else:
                        filtered.append(item)
                except Exception:
                    filtered.append(item)
            result = filtered

        return {"Items": result}


def _make_tables(private_table=None, billing_table=None, sessions_table=None):
    """Build a fake T namespace with the required tables."""
    return SimpleNamespace(
        broadcast_private_sessions=private_table or _FakeQueryTable(),
        billing=billing_table or _FakeTable(),
        broadcast_sessions=sessions_table or _FakeTable(),
        broadcast_outputs=_FakeTable(),
        broadcast_session_transitions=_FakeTable(),
    )


def _make_session_table_with_session(session_id: str, created_by: str, status: str = "live"):
    """Create a sessions table with a pre-populated session."""
    table = _FakeTable()
    table.put_item(Item={
        "session_id": session_id,
        "pk": f"SESSION#{session_id}",
        "profile_id": "prof_1",
        "status": status,
        "created_by": created_by,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "stream_key_rotation_interval_seconds": 86400,
    })
    return table


class TestCreatePrivateRequest:
    def test_creates_item_with_requested_status(self):
        tables = _make_tables()
        with patch.object(broadcast_private, "T", tables):
            result = broadcast_private.create_private_request(
                session_id="sess_1",
                viewer_id="alice",
                viewer_display_name="Alice",
                rate_per_minute_cents=500,
                payment_method_id="pm_123",
            )
        assert result["status"] == "requested"
        assert result["rate_per_minute_cents"] == 500
        assert result["viewer_id"] == "alice"
        assert result["session_id"] == "sess_1"
        assert result["private_session_id"].startswith("priv_")

    def test_rejects_rate_below_minimum(self):
        tables = _make_tables()
        with patch.object(broadcast_private, "T", tables):
            with pytest.raises(HTTPException) as exc_info:
                broadcast_private.create_private_request(
                    session_id="sess_1",
                    viewer_id="alice",
                    viewer_display_name="Alice",
                    rate_per_minute_cents=50,
                    payment_method_id="pm_123",
                    min_rate_cents=100,
                )
        assert exc_info.value.status_code == 400
        assert "at least 100" in str(exc_info.value.detail)

    def test_rejects_duplicate_pending(self):
        tables = _make_tables()
        with patch.object(broadcast_private, "T", tables):
            broadcast_private.create_private_request(
                session_id="sess_1",
                viewer_id="alice",
                viewer_display_name="Alice",
                rate_per_minute_cents=500,
                payment_method_id="pm_123",
            )
            with pytest.raises(HTTPException) as exc_info:
                broadcast_private.create_private_request(
                    session_id="sess_1",
                    viewer_id="bob",
                    viewer_display_name="Bob",
                    rate_per_minute_cents=600,
                    payment_method_id="pm_456",
                )
        assert exc_info.value.status_code == 409

    def test_default_max_duration(self):
        tables = _make_tables()
        with patch.object(broadcast_private, "T", tables):
            result = broadcast_private.create_private_request(
                session_id="sess_1",
                viewer_id="alice",
                viewer_display_name="Alice",
                rate_per_minute_cents=500,
                payment_method_id="pm_123",
            )
        assert result["max_duration_minutes"] == 60


class TestListPendingRequests:
    def test_returns_only_requested(self):
        tables = _make_tables()
        with patch.object(broadcast_private, "T", tables):
            broadcast_private.create_private_request(
                session_id="sess_1",
                viewer_id="alice",
                viewer_display_name="Alice",
                rate_per_minute_cents=500,
                payment_method_id="pm_123",
            )
            requests = broadcast_private.list_pending_requests("sess_1")
        assert len(requests) == 1
        assert requests[0]["status"] == "requested"

    def test_empty_when_no_requests(self):
        tables = _make_tables()
        with patch.object(broadcast_private, "T", tables):
            requests = broadcast_private.list_pending_requests("sess_1")
        assert len(requests) == 0


class TestAcceptPrivateRequest:
    def test_transitions_to_accepted(self):
        tables = _make_tables()
        with patch.object(broadcast_private, "T", tables):
            req = broadcast_private.create_private_request(
                session_id="sess_1",
                viewer_id="alice",
                viewer_display_name="Alice",
                rate_per_minute_cents=500,
                payment_method_id="pm_123",
            )
            result = broadcast_private.accept_private_request(
                "sess_1", req["private_session_id"], "pause", "call_1"
            )
        assert result["status"] == "accepted"
        assert result["behavior"] == "pause"
        assert result["call_id"] == "call_1"

    def test_accept_not_found_raises_404(self):
        tables = _make_tables()
        with patch.object(broadcast_private, "T", tables):
            with pytest.raises(HTTPException) as exc_info:
                broadcast_private.accept_private_request(
                    "sess_1", "nonexistent", "pause", "call_1"
                )
        assert exc_info.value.status_code == 404


class TestDeclinePrivateRequest:
    def test_transitions_to_declined(self):
        tables = _make_tables()
        with patch.object(broadcast_private, "T", tables):
            req = broadcast_private.create_private_request(
                session_id="sess_1",
                viewer_id="alice",
                viewer_display_name="Alice",
                rate_per_minute_cents=500,
                payment_method_id="pm_123",
            )
            assert broadcast_private.decline_private_request("sess_1", req["private_session_id"]) is True
            # Verify no longer pending
            requests = broadcast_private.list_pending_requests("sess_1")
            assert len(requests) == 0

    def test_decline_nonexistent_returns_false(self):
        tables = _make_tables()
        with patch.object(broadcast_private, "T", tables):
            assert broadcast_private.decline_private_request("sess_1", "nonexistent") is False


class TestCancelPrivateRequest:
    def test_cancel_by_requester_succeeds(self):
        tables = _make_tables()
        with patch.object(broadcast_private, "T", tables):
            req = broadcast_private.create_private_request(
                session_id="sess_1",
                viewer_id="alice",
                viewer_display_name="Alice",
                rate_per_minute_cents=500,
                payment_method_id="pm_123",
            )
            assert broadcast_private.cancel_private_request("sess_1", req["private_session_id"], "alice") is True

    def test_cancel_by_wrong_user_fails(self):
        tables = _make_tables()
        with patch.object(broadcast_private, "T", tables):
            req = broadcast_private.create_private_request(
                session_id="sess_1",
                viewer_id="alice",
                viewer_display_name="Alice",
                rate_per_minute_cents=500,
                payment_method_id="pm_123",
            )
            assert broadcast_private.cancel_private_request("sess_1", req["private_session_id"], "bob") is False


class TestEndPrivateSession:
    def test_calculates_billing(self):
        sessions_table = _make_session_table_with_session("sess_1", "creator_1")
        billing_table = _FakeTable()
        tables = _make_tables(billing_table=billing_table, sessions_table=sessions_table)

        with patch.object(broadcast_private, "T", tables):
            # Also patch the get_session call used by _get_session_creator
            from app.services import broadcast_store
            with patch.object(broadcast_store, "T", SimpleNamespace(
                broadcast_sessions=sessions_table,
                broadcast_outputs=_FakeTable(),
                broadcast_session_transitions=_FakeTable(),
                broadcast_profiles=_FakeTable(),
            )):
                req = broadcast_private.create_private_request(
                    session_id="sess_1",
                    viewer_id="alice",
                    viewer_display_name="Alice",
                    rate_per_minute_cents=500,
                    payment_method_id="pm_123",
                )
                broadcast_private.accept_private_request(
                    "sess_1", req["private_session_id"], "pause", "call_1"
                )
                broadcast_private.activate_private_session(
                    "sess_1", req["private_session_id"]
                )
                result = broadcast_private.end_private_session(
                    "sess_1", req["private_session_id"], "viewer"
                )

        assert result["status"] == "ended"
        assert result["total_billed_cents"] >= 500  # At least 1 minute billed
        assert result["ended_by"] == "viewer"

    def test_end_not_active_raises_409(self):
        tables = _make_tables()
        with patch.object(broadcast_private, "T", tables):
            req = broadcast_private.create_private_request(
                session_id="sess_1",
                viewer_id="alice",
                viewer_display_name="Alice",
                rate_per_minute_cents=500,
                payment_method_id="pm_123",
            )
            # Try to end without activating first
            broadcast_private.accept_private_request(
                "sess_1", req["private_session_id"], "pause", "call_1"
            )
            with pytest.raises(HTTPException) as exc_info:
                broadcast_private.end_private_session(
                    "sess_1", req["private_session_id"], "viewer"
                )
        assert exc_info.value.status_code == 409

    def test_end_not_found_raises_404(self):
        tables = _make_tables()
        with patch.object(broadcast_private, "T", tables):
            with pytest.raises(HTTPException) as exc_info:
                broadcast_private.end_private_session(
                    "sess_1", "nonexistent", "viewer"
                )
        assert exc_info.value.status_code == 404

    def test_writes_billing_ledger_entries(self):
        sessions_table = _make_session_table_with_session("sess_1", "creator_1")
        billing_table = _FakeTable()
        tables = _make_tables(billing_table=billing_table, sessions_table=sessions_table)

        with patch.object(broadcast_private, "T", tables):
            from app.services import broadcast_store
            with patch.object(broadcast_store, "T", SimpleNamespace(
                broadcast_sessions=sessions_table,
                broadcast_outputs=_FakeTable(),
                broadcast_session_transitions=_FakeTable(),
                broadcast_profiles=_FakeTable(),
            )):
                req = broadcast_private.create_private_request(
                    session_id="sess_1",
                    viewer_id="alice",
                    viewer_display_name="Alice",
                    rate_per_minute_cents=500,
                    payment_method_id="pm_123",
                )
                broadcast_private.accept_private_request(
                    "sess_1", req["private_session_id"], "pause", "call_1"
                )
                broadcast_private.activate_private_session(
                    "sess_1", req["private_session_id"]
                )
                broadcast_private.end_private_session(
                    "sess_1", req["private_session_id"], "creator"
                )

        # Check billing table has debit and credit entries
        billing_items = list(billing_table.items.values())
        debits = [i for i in billing_items if i.get("type") == "debit"]
        credits = [i for i in billing_items if i.get("type") == "credit"]
        assert len(debits) >= 1
        assert len(credits) >= 1
        assert debits[0]["pk"] == "USER#alice"
        assert credits[0]["pk"] == "USER#creator_1"
        assert debits[0]["reason"] == "Private session"
        assert credits[0]["meta"]["content_type"] == "private_call"


class TestGetPrivateStatus:
    def test_returns_empty_when_no_session(self):
        tables = _make_tables()
        with patch.object(broadcast_private, "T", tables):
            result = broadcast_private.get_private_status("sess_1")
        assert result == {}

    def test_returns_active_session(self):
        tables = _make_tables()
        with patch.object(broadcast_private, "T", tables):
            req = broadcast_private.create_private_request(
                session_id="sess_1",
                viewer_id="alice",
                viewer_display_name="Alice",
                rate_per_minute_cents=500,
                payment_method_id="pm_123",
            )
            result = broadcast_private.get_private_status("sess_1")
        assert result["status"] == "requested"
        assert result["viewer_id"] == "alice"
