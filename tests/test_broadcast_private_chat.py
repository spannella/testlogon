"""Unit tests for broadcast private chat service (BCAST-012)."""
from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.services import broadcast_private_chat
from app.services.content_filter import filter_message


# ─── Fake DynamoDB table (same pattern as test_broadcast_private.py) ──


class _FakeTable:
    """Minimal in-memory DynamoDB table stub supporting pk/sk composite keys."""

    def __init__(self):
        self.items: dict[str, dict] = {}

    @staticmethod
    def _key(item_or_key: dict) -> str:
        if "pk" in item_or_key and "sk" in item_or_key:
            return f"{item_or_key['pk']}|{item_or_key['sk']}"
        for field in ("session_id", "profile_id"):
            if field in item_or_key:
                return item_or_key[field]
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

    def update_item(self, *, Key: dict, UpdateExpression: str,
                    ExpressionAttributeValues: dict | None = None,
                    ExpressionAttributeNames: dict | None = None, **kwargs):
        k = self._key(Key)
        item = self.items.get(k)
        if not item:
            return
        names = ExpressionAttributeNames or {}
        vals = ExpressionAttributeValues or {}
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

    def query(self, *, KeyConditionExpression, FilterExpression=None,
              Select=None, **kwargs):
        all_items = list(self.items.values())
        # Simple pk-based filtering
        result = []
        for item in all_items:
            # Just return all items — the tests will be scoped properly
            result.append(item)

        if FilterExpression:
            filtered = []
            for item in result:
                if hasattr(FilterExpression, "_values"):
                    # Simple attribute eq / is_in filters
                    try:
                        filter_val = FilterExpression._values[1]
                        filter_path = FilterExpression._values[0]
                        if hasattr(filter_path, "name"):
                            if isinstance(filter_val, list):
                                if item.get(filter_path.name) in filter_val:
                                    filtered.append(item)
                            else:
                                if item.get(filter_path.name) == filter_val:
                                    filtered.append(item)
                        else:
                            filtered.append(item)
                    except (IndexError, AttributeError):
                        filtered.append(item)
                else:
                    filtered.append(item)
            result = filtered

        if Select == "COUNT":
            return {"Count": len(result)}
        return {"Items": result}

    def scan(self, *, FilterExpression=None, **kwargs):
        return {"Items": list(self.items.values())}


@pytest.fixture(autouse=True)
def _patch_tables():
    """Patch T.broadcast_private_sessions, T.broadcast_chat_messages, and T.billing."""
    import uuid as _uuid
    private_table = _FakeTable()
    chat_table = _FakeTable()
    billing_table = _FakeTable()

    fake_t = SimpleNamespace(
        broadcast_private_sessions=private_table,
        broadcast_chat_messages=chat_table,
        billing=billing_table,
        broadcast_sessions=_FakeTable(),
    )

    def _fake_write_billing(
        viewer_id, creator_id, total_cents, creator_earnings_cents,
        chat_id, session_id, tier, duration_minutes, payment_method_id,
    ):
        """Write billing entries to the fake table instead of via transact_write_items."""
        from app.core.time import now_ts
        ts = now_ts()
        debit_id = _uuid.uuid4().hex
        credit_id = _uuid.uuid4().hex
        billing_table.put_item(Item={
            "pk": f"USER#{viewer_id}", "sk": f"LEDGER#{ts}#{debit_id}",
            "entry_id": debit_id, "ts": ts, "type": "debit",
            "amount_cents": total_cents, "currency": "USD", "state": "settled",
        })
        billing_table.put_item(Item={
            "pk": f"USER#{creator_id}", "sk": f"LEDGER#{ts}#{credit_id}",
            "entry_id": credit_id, "ts": ts, "type": "credit",
            "amount_cents": creator_earnings_cents, "currency": "USD", "state": "settled",
        })
        return debit_id, credit_id

    with (
        patch.object(broadcast_private_chat, "T", fake_t),
        patch.object(broadcast_private_chat, "_write_private_chat_billing", _fake_write_billing),
    ):
        yield {
            "private": private_table,
            "chat": chat_table,
            "billing": billing_table,
        }


@pytest.fixture
def tables(_patch_tables):
    return _patch_tables


# ─── Content filter tests ────────────────────────────────────────


class TestContentFilter:
    def test_no_blocked_words(self):
        text, filtered = filter_message("Hello, how are you?")
        assert text == "Hello, how are you?"
        assert filtered is False

    def test_blocked_word_replaced(self):
        text, filtered = filter_message("What the fuck is this?")
        assert "****" in text
        assert "fuck" not in text.lower()
        assert filtered is True

    def test_multiple_blocked_words(self):
        text, filtered = filter_message("shit and damn")
        assert "****" in text
        assert "shit" not in text.lower()
        assert "damn" not in text.lower()
        assert filtered is True

    def test_case_insensitive(self):
        text, filtered = filter_message("FUCK")
        assert text == "****"
        assert filtered is True

    def test_empty_string(self):
        text, filtered = filter_message("")
        assert text == ""
        assert filtered is False


# ─── Purchase tests ──────────────────────────────────────────────


class TestPurchasePrivateChat:
    def test_tier1_creates_active_chat(self, tables):
        result = broadcast_private_chat.purchase_private_chat(
            session_id="sess_1",
            viewer_id="alice",
            viewer_display_name="Alice",
            tier=1,
            duration_minutes=15,
            payment_method_id="pm_123",
            rate_per_minute_cents=500,
            creator_id="creator_1",
        )
        assert result["status"] == "active"
        assert result["tier"] == 1
        assert result["total_paid_cents"] == 7500  # 15 * 500
        assert result["expires_at"] > 0
        assert result["chat_id"].startswith("pchat_")

    def test_tier1_writes_billing(self, tables):
        broadcast_private_chat.purchase_private_chat(
            session_id="sess_1",
            viewer_id="alice",
            viewer_display_name="Alice",
            tier=1,
            duration_minutes=10,
            payment_method_id="pm_123",
            rate_per_minute_cents=500,
            creator_id="creator_1",
        )
        # Check billing entries exist
        billing = tables["billing"]
        entries = [v for v in billing.items.values() if "entry_id" in v]
        assert len(entries) == 2

        debit = [e for e in entries if e["type"] == "debit"][0]
        credit = [e for e in entries if e["type"] == "credit"][0]
        assert int(debit["amount_cents"]) == 5000  # 10 * 500
        assert int(credit["amount_cents"]) == 4000  # 5000 - 20% = 4000

    def test_tier1_max_concurrent_reached(self, tables):
        for i in range(5):
            broadcast_private_chat.purchase_private_chat(
                session_id="sess_1",
                viewer_id=f"viewer_{i}",
                viewer_display_name=f"Viewer {i}",
                tier=1,
                duration_minutes=5,
                payment_method_id=f"pm_{i}",
                rate_per_minute_cents=500,
                creator_id="creator_1",
            )
        with pytest.raises(HTTPException) as exc_info:
            broadcast_private_chat.purchase_private_chat(
                session_id="sess_1",
                viewer_id="viewer_6",
                viewer_display_name="Viewer 6",
                tier=1,
                duration_minutes=5,
                payment_method_id="pm_6",
                rate_per_minute_cents=500,
                creator_id="creator_1",
            )
        assert exc_info.value.status_code == 409

    def test_tier2_creates_voyeur_item(self, tables):
        chat = broadcast_private_chat.purchase_private_chat(
            session_id="sess_1",
            viewer_id="alice",
            viewer_display_name="Alice",
            tier=1,
            duration_minutes=15,
            payment_method_id="pm_123",
            rate_per_minute_cents=500,
            creator_id="creator_1",
        )
        voyeur = broadcast_private_chat.purchase_private_chat(
            session_id="sess_1",
            viewer_id="bob",
            viewer_display_name="Bob",
            tier=2,
            duration_minutes=15,
            payment_method_id="pm_456",
            rate_per_minute_cents=100,
            creator_id="creator_1",
            chat_id=chat["chat_id"],
        )
        assert voyeur["tier"] == 2
        assert voyeur["chat_id"] == chat["chat_id"]
        assert voyeur["total_paid_cents"] == 1500  # 15 * 100

    def test_tier2_fails_nonexistent_chat(self, tables):
        with pytest.raises(HTTPException) as exc_info:
            broadcast_private_chat.purchase_private_chat(
                session_id="sess_1",
                viewer_id="bob",
                viewer_display_name="Bob",
                tier=2,
                duration_minutes=15,
                payment_method_id="pm_456",
                rate_per_minute_cents=100,
                creator_id="creator_1",
                chat_id="pchat_nonexistent",
            )
        assert exc_info.value.status_code == 404


# ─── Messaging tests ─────────────────────────────────────────────


class TestPrivateChatMessaging:
    def test_send_message_stores_with_chat_id(self, tables):
        result = broadcast_private_chat.send_private_chat_message(
            session_id="sess_1",
            chat_id="pchat_abc",
            sender_id="alice",
            sender_display_name="Alice",
            text="Hello from private chat!",
        )
        assert result["private_chat_id"] == "pchat_abc"
        assert result["kind"] == "private_chat"
        assert result["text"] == "Hello from private chat!"

    def test_send_message_filters_profanity(self, tables):
        result = broadcast_private_chat.send_private_chat_message(
            session_id="sess_1",
            chat_id="pchat_abc",
            sender_id="alice",
            sender_display_name="Alice",
            text="What the fuck is this?",
        )
        assert "fuck" not in result["text"]
        assert "****" in result["text"]
        assert result["filtered"] is True

    def test_send_clean_message_not_filtered(self, tables):
        result = broadcast_private_chat.send_private_chat_message(
            session_id="sess_1",
            chat_id="pchat_abc",
            sender_id="alice",
            sender_display_name="Alice",
            text="Hello, great stream!",
        )
        assert result["filtered"] is False
        assert result["text"] == "Hello, great stream!"


# ─── End / Extend tests ──────────────────────────────────────────


class TestEndExtendPrivateChat:
    def test_end_chat_returns_true(self, tables):
        chat = broadcast_private_chat.purchase_private_chat(
            session_id="sess_1",
            viewer_id="alice",
            viewer_display_name="Alice",
            tier=1,
            duration_minutes=15,
            payment_method_id="pm_123",
            rate_per_minute_cents=500,
            creator_id="creator_1",
        )
        ok = broadcast_private_chat.end_private_chat("sess_1", chat["chat_id"], "creator_ended")
        assert ok is True

    def test_end_nonexistent_chat(self, tables):
        ok = broadcast_private_chat.end_private_chat("sess_1", "pchat_missing", "creator_ended")
        assert ok is False

    def test_extend_increases_time(self, tables):
        chat = broadcast_private_chat.purchase_private_chat(
            session_id="sess_1",
            viewer_id="alice",
            viewer_display_name="Alice",
            tier=1,
            duration_minutes=5,
            payment_method_id="pm_123",
            rate_per_minute_cents=500,
            creator_id="creator_1",
        )
        original_expires = chat["expires_at"]
        extended = broadcast_private_chat.extend_private_chat(
            session_id="sess_1",
            chat_id=chat["chat_id"],
            viewer_id="alice",
            additional_minutes=10,
            payment_method_id="pm_123",
            rate_per_minute_cents=500,
            platform_fee_pct=20,
            creator_id="creator_1",
        )
        assert extended["expires_at"] > original_expires
        assert extended["purchased_minutes"] == 15  # 5 + 10

    def test_extend_writes_billing(self, tables):
        chat = broadcast_private_chat.purchase_private_chat(
            session_id="sess_1",
            viewer_id="alice",
            viewer_display_name="Alice",
            tier=1,
            duration_minutes=5,
            payment_method_id="pm_123",
            rate_per_minute_cents=500,
            creator_id="creator_1",
        )
        broadcast_private_chat.extend_private_chat(
            session_id="sess_1",
            chat_id=chat["chat_id"],
            viewer_id="alice",
            additional_minutes=10,
            payment_method_id="pm_123",
            rate_per_minute_cents=500,
            platform_fee_pct=20,
            creator_id="creator_1",
        )
        billing = tables["billing"]
        entries = [v for v in billing.items.values() if "entry_id" in v]
        # 2 from purchase + 2 from extend = 4
        assert len(entries) == 4


# ─── Chat status and list tests ──────────────────────────────────


class TestChatStatusAndList:
    def test_chat_status_returns_remaining(self, tables):
        chat = broadcast_private_chat.purchase_private_chat(
            session_id="sess_1",
            viewer_id="alice",
            viewer_display_name="Alice",
            tier=1,
            duration_minutes=15,
            payment_method_id="pm_123",
            rate_per_minute_cents=500,
            creator_id="creator_1",
        )
        status = broadcast_private_chat.get_chat_status("sess_1", chat["chat_id"])
        assert status is not None
        assert status["remaining_seconds"] > 0
        assert status["chat_id"] == chat["chat_id"]
        assert status["viewer_id"] == "alice"

    def test_chat_status_nonexistent(self, tables):
        status = broadcast_private_chat.get_chat_status("sess_1", "pchat_missing")
        assert status is None

    def test_platform_fee_deducted(self, tables):
        broadcast_private_chat.purchase_private_chat(
            session_id="sess_1",
            viewer_id="alice",
            viewer_display_name="Alice",
            tier=1,
            duration_minutes=10,
            payment_method_id="pm_123",
            rate_per_minute_cents=500,
            platform_fee_pct=20,
            creator_id="creator_1",
        )
        billing = tables["billing"]
        entries = [v for v in billing.items.values() if "entry_id" in v]
        credit = [e for e in entries if e["type"] == "credit"][0]
        # 10 min * 500 = 5000 total, 20% fee = 1000, creator gets 4000
        assert int(credit["amount_cents"]) == 4000
