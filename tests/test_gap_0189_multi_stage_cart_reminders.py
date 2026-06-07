"""Regression test for GAP-0189 (FIN-003): multi-stage cart reminder schedule.

Before the fix, abandoned carts received a single hardcoded reminder
("You left items in your cart") gated only by a flat ``max_reminders`` cap and
a single global cooldown — there was no concept of numbered stages, per-stage
delays, or per-stage copy, and ``app/services/cart_reminders.py`` did not exist.

After the fix, ``process_abandoned_carts`` reads a stage sequence (falling back
to the built-in three-stage default), advances each cart through it via the
``current_reminder_stage`` field, and sends the per-stage subject/body once the
stage's ``delay_hours`` have elapsed.

Fully offline: in-memory fake DynamoDB tables replace ``T.shopping_cart`` and
``T.cart_reminder_config``; ``send_alert_email`` / ``write_alert`` /
``get_profile`` are monkeypatched. No real AWS access.

``S`` is a frozen dataclass — flags are flipped via ``object.__setattr__``.
"""
from __future__ import annotations

from typing import Any, Dict, List

import pytest

from app.core.settings import S
from app.services import cart_reminders


HOUR = 3600
T0 = 1_700_000_000
USER_PK = "USER#alice"
CART_SK = "CART#cart1#META"
CART_ID = "cart1"


class _FakeCartTable:
    """Minimal in-memory shopping_cart table.

    Supports the three access patterns the reminder code uses:
      * GSI query (IndexName=ByStatusActivity) → returns cart META records
      * COUNT query (Select=COUNT) → number of seeded line items
      * get_item / update_item on a META record key
    """

    def __init__(self) -> None:
        # key (PK, SK) -> attribute dict
        self.records: Dict[tuple, Dict[str, Any]] = {}
        self.item_count = 1  # line items per cart (overridden per test)

    def seed_cart(self, **attrs: Any) -> None:
        rec = {"PK": USER_PK, "SK": CART_SK, "cart_id": CART_ID, "status": "OPEN"}
        rec.update(attrs)
        self.records[(USER_PK, CART_SK)] = rec

    def query(self, **kwargs: Any) -> Dict[str, Any]:
        if kwargs.get("Select") == "COUNT":
            return {"Count": self.item_count}
        if kwargs.get("IndexName") == "ByStatusActivity":
            # Return all OPEN cart META records.
            items = [
                dict(r)
                for r in self.records.values()
                if r.get("status") == "OPEN" and r["SK"].endswith("#META")
            ]
            return {"Items": items}
        return {"Items": []}

    def get_item(self, *, Key: Dict[str, Any]) -> Dict[str, Any]:
        rec = self.records.get((Key["PK"], Key["SK"]))
        return {"Item": dict(rec)} if rec else {}

    def update_item(self, *, Key, UpdateExpression, ExpressionAttributeValues) -> None:
        rec = self.records.setdefault((Key["PK"], Key["SK"]), {"PK": Key["PK"], "SK": Key["SK"]})
        vals = ExpressionAttributeValues
        rec["last_reminder_at"] = vals[":ts"]
        rec["current_reminder_stage"] = vals[":stage"]
        rec.setdefault("abandoned_at", vals[":ts"])
        rec["reminder_count"] = int(rec.get("reminder_count", 0) or 0) + int(vals[":one"])


class _EmptyConfigTable:
    """cart_reminder_config table that is empty → defaults are used."""

    def query(self, **kwargs: Any) -> Dict[str, Any]:
        return {"Items": []}

    def get_item(self, *, Key: Dict[str, Any]) -> Dict[str, Any]:
        return {}


@pytest.fixture()
def env(monkeypatch):
    cart_table = _FakeCartTable()
    config_table = _EmptyConfigTable()

    # Patch table handles. T (Tables) is a frozen dataclass shared across
    # modules, so patch its fields via object.__setattr__ and restore manually.
    from app.core.tables import T

    saved = {
        "shopping_cart": T.shopping_cart,
        "cart_reminder_config": getattr(T, "cart_reminder_config", None),
    }
    object.__setattr__(T, "shopping_cart", cart_table)
    object.__setattr__(T, "cart_reminder_config", config_table)

    # Record emails sent (kwargs).
    emails: List[Dict[str, Any]] = []

    def fake_send_email(to_emails, subject, body_text):
        emails.append({"to": to_emails, "subject": subject, "body_text": body_text})

    monkeypatch.setattr(cart_reminders, "send_alert_email", fake_send_email)
    monkeypatch.setattr(cart_reminders, "write_alert", lambda *a, **k: None)
    monkeypatch.setattr(
        cart_reminders, "get_profile", lambda sub: {"email": "alice@test.local"}
    )

    # Enable the multi-stage path (frozen dataclass → object.__setattr__).
    object.__setattr__(S, "cart_reminders_enabled", True)
    object.__setattr__(S, "cart_abandonment_enabled", True)

    yield cart_table, emails

    # Restore frozen table handles.
    object.__setattr__(T, "shopping_cart", saved["shopping_cart"])
    if saved["cart_reminder_config"] is not None:
        object.__setattr__(T, "cart_reminder_config", saved["cart_reminder_config"])


def test_stages_progress_with_per_stage_delays_and_copy(env):
    """Stage 1 fires at 24h, Stage 2 only after its 72h delay, with new copy."""
    cart_table, emails = env
    cart_table.seed_cart(
        abandoned_at=T0, last_activity_at=T0, current_reminder_stage=0, reminder_count=0
    )

    # t = 25h → Stage 1 fires.
    result = cart_reminders.process_abandoned_carts(now=T0 + 25 * HOUR)
    assert result["reminded"] == 1
    assert len(emails) == 1
    # FAILS-BEFORE: process_abandoned_carts did not exist (ImportError); the old
    # single-blast path had no notion of "Stage 1".
    assert emails[0]["subject"] == "You left items in your cart"
    assert cart_table.records[(USER_PK, CART_SK)]["current_reminder_stage"] == 1

    # t = 49h → only 24h since Stage 1; Stage 2 delay (72h) not elapsed → nothing.
    emails.clear()
    result = cart_reminders.process_abandoned_carts(now=T0 + 49 * HOUR)
    assert result["reminded"] == 0
    assert emails == []

    # t = 97h → 72h since Stage 1 reminder → Stage 2 fires with different copy.
    emails.clear()
    result = cart_reminders.process_abandoned_carts(now=T0 + 97 * HOUR)
    assert result["reminded"] == 1
    assert len(emails) == 1
    # FAILS-BEFORE: the legacy function sent the SAME hardcoded subject again.
    assert emails[0]["subject"] == "Still thinking it over?"
    assert cart_table.records[(USER_PK, CART_SK)]["current_reminder_stage"] == 2


def test_cart_at_max_stage_is_skipped(env):
    """A cart that already reached the final stage receives no further reminders."""
    cart_table, emails = env
    cart_table.seed_cart(
        abandoned_at=T0,
        last_activity_at=T0,
        current_reminder_stage=3,  # all 3 default stages already sent
        reminder_count=3,
        last_reminder_at=T0 + 168 * HOUR,
    )

    result = cart_reminders.process_abandoned_carts(now=T0 + 400 * HOUR)
    assert result["reminded"] == 0
    assert result["skipped"] == 1
    assert emails == []


def test_disabled_flag_short_circuits(env):
    """With CART_REMINDERS_ENABLED off, the service is a no-op."""
    cart_table, emails = env
    cart_table.seed_cart(abandoned_at=T0, last_activity_at=T0, current_reminder_stage=0)
    object.__setattr__(S, "cart_reminders_enabled", False)
    try:
        result = cart_reminders.process_abandoned_carts(now=T0 + 999 * HOUR)
    finally:
        object.__setattr__(S, "cart_reminders_enabled", True)
    assert result == {"scanned": 0, "reminded": 0, "skipped": 0}
    assert emails == []
