"""Regression tests for GAP-0190 + GAP-0191 (FIN-003).

GAP-0190 — signed one-time cart recovery links:
  Before the fix ``generate_recovery_link`` returned a bare relative path
  (``/cart?cartId=...``) with no token, there was no ``recover_cart`` function,
  and no recovery endpoint. After the fix it returns a signed, time-limited,
  one-time-use URL; ``recover_cart`` validates + consumes the token (a second
  use is rejected); and the reminder email body embeds the recovery URL.

GAP-0191 — per-user opt-out preference:
  Before the fix the legacy ``send_cart_reminder`` had no opt-out check and
  there were no preference get/set helpers. After the fix an opted-out user is
  skipped (no alert/email) and ``get/set_reminder_preference`` round-trip.

Fully offline: in-memory fake DynamoDB tables replace ``T.shopping_cart`` and
``T.cart_reminder_config``; ``send_alert_email`` / ``write_alert`` /
``get_profile`` are monkeypatched. No real AWS access.

``S`` is a frozen dataclass — flags are flipped via ``object.__setattr__``.
"""
from __future__ import annotations

from typing import Any, Dict, List

import pytest
from fastapi import HTTPException

from app.core.settings import S
from app.services import cart_reminders
from app.services import shoppingcart as shoppingcart_svc


T0 = 1_700_000_000
USER_SUB = "alice"
USER_PK = "USER#alice"
CART_SK = "CART#cart1#META"
CART_ID = "cart1"


class _FakeCartTable:
    """Minimal in-memory shopping_cart table for send_cart_reminder."""

    def __init__(self) -> None:
        self.records: Dict[tuple, Dict[str, Any]] = {}
        self.item_count = 2

    def seed_cart(self, **attrs: Any) -> None:
        rec = {"PK": USER_PK, "SK": CART_SK, "cart_id": CART_ID, "status": "OPEN"}
        rec.update(attrs)
        self.records[(USER_PK, CART_SK)] = rec

    def query(self, **kwargs: Any) -> Dict[str, Any]:
        if kwargs.get("Select") == "COUNT":
            return {"Count": self.item_count}
        return {"Items": []}

    def get_item(self, *, Key: Dict[str, Any]) -> Dict[str, Any]:
        rec = self.records.get((Key["PK"], Key["SK"]))
        return {"Item": dict(rec)} if rec else {}

    def update_item(self, *, Key, UpdateExpression, ExpressionAttributeValues) -> None:
        rec = self.records.setdefault(
            (Key["PK"], Key["SK"]), {"PK": Key["PK"], "SK": Key["SK"]}
        )
        vals = ExpressionAttributeValues
        rec["last_reminder_at"] = vals.get(":ts")
        rec.setdefault("abandoned_at", vals.get(":ts"))
        rec["reminder_count"] = int(rec.get("reminder_count", 0) or 0) + int(
            vals.get(":one", 0)
        )


class _FakeConfigTable:
    """In-memory cart_reminder_config table with conditional put support."""

    def __init__(self) -> None:
        self.records: Dict[tuple, Dict[str, Any]] = {}

    def query(self, **kwargs: Any) -> Dict[str, Any]:
        return {"Items": []}

    def get_item(self, *, Key: Dict[str, Any]) -> Dict[str, Any]:
        rec = self.records.get((Key["pk"], Key["sk"]))
        return {"Item": dict(rec)} if rec else {}

    def put_item(self, *, Item, ConditionExpression=None) -> None:
        key = (Item["pk"], Item["sk"])
        if ConditionExpression == "attribute_not_exists(pk)" and key in self.records:
            from botocore.exceptions import ClientError

            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException"}}, "PutItem"
            )
        self.records[key] = dict(Item)


@pytest.fixture()
def env(monkeypatch):
    cart_table = _FakeCartTable()
    config_table = _FakeConfigTable()

    from app.core.tables import T

    saved = {
        "shopping_cart": T.shopping_cart,
        "cart_reminder_config": getattr(T, "cart_reminder_config", None),
    }
    object.__setattr__(T, "shopping_cart", cart_table)
    object.__setattr__(T, "cart_reminder_config", config_table)

    emails: List[Dict[str, Any]] = []
    alerts: List[Dict[str, Any]] = []

    def fake_send_email(to_emails, subject, body_text):
        emails.append({"to": to_emails, "subject": subject, "body_text": body_text})

    def fake_write_alert(user_sub, **kwargs):
        alerts.append({"user_sub": user_sub, **kwargs})

    # send_cart_reminder imports write_alert/send_alert_email locally inside the
    # function from app.services.alerts, so patch them at the source module.
    import app.services.alerts as alerts_mod

    monkeypatch.setattr(alerts_mod, "send_alert_email", fake_send_email)
    monkeypatch.setattr(alerts_mod, "write_alert", fake_write_alert)
    monkeypatch.setattr(
        shoppingcart_svc, "get_profile", lambda sub: {"email": "alice@test.local"}
    )

    object.__setattr__(S, "cart_recovery_link_secret", "test-secret-key")
    object.__setattr__(S, "cart_recovery_link_ttl_days", 7)
    object.__setattr__(S, "public_base_url", "http://localhost:8000")

    yield cart_table, config_table, emails, alerts

    object.__setattr__(T, "shopping_cart", saved["shopping_cart"])
    if saved["cart_reminder_config"] is not None:
        object.__setattr__(T, "cart_reminder_config", saved["cart_reminder_config"])


# ─── GAP-0190 ────────────────────────────────────────────────────────────────


def test_generate_recovery_link_is_signed_url(env, monkeypatch):
    monkeypatch.setattr(cart_reminders, "now_ts", lambda: T0)
    url = cart_reminders.generate_recovery_link(USER_SUB, CART_ID)
    # FAILS-BEFORE: stub returned bare "/cart?cartId=cart1" with no token.
    assert url.startswith("http://localhost:8000/ui/shoppingcart/recover/")
    token = url.rsplit("/recover/", 1)[1]
    assert "." in token  # payload.signature
    payload = cart_reminders._verify_recovery_token(token)
    assert payload is not None
    assert payload["user_sub"] == USER_SUB
    assert payload["cart_id"] == CART_ID


def test_recover_cart_valid_then_one_time_use(env, monkeypatch):
    monkeypatch.setattr(cart_reminders, "now_ts", lambda: T0)
    url = cart_reminders.generate_recovery_link(USER_SUB, CART_ID)
    token = url.rsplit("/recover/", 1)[1]

    # First use succeeds.
    result = cart_reminders.recover_cart(token)
    assert result == {"user_sub": USER_SUB, "cart_id": CART_ID}

    # FAILS-BEFORE: recover_cart did not exist. Second use must be rejected.
    with pytest.raises(HTTPException) as exc:
        cart_reminders.recover_cart(token)
    assert exc.value.status_code == 400


def test_recover_cart_rejects_tampered_and_expired(env, monkeypatch):
    monkeypatch.setattr(cart_reminders, "now_ts", lambda: T0)
    url = cart_reminders.generate_recovery_link(USER_SUB, CART_ID)
    token = url.rsplit("/recover/", 1)[1]

    # Tampered signature → invalid.
    bad = token[:-2] + ("AA" if not token.endswith("AA") else "BB")
    with pytest.raises(HTTPException):
        cart_reminders.recover_cart(bad)

    # Expired (clock advanced past TTL) → invalid.
    monkeypatch.setattr(cart_reminders, "now_ts", lambda: T0 + 8 * 86400)
    with pytest.raises(HTTPException):
        cart_reminders.recover_cart(token)


def test_reminder_email_embeds_recovery_url(env, monkeypatch):
    cart_table, _config, emails, alerts = env
    monkeypatch.setattr(cart_reminders, "now_ts", lambda: T0)
    cart_table.seed_cart(abandoned_at=T0, last_activity_at=T0)

    shoppingcart_svc.send_cart_reminder(cart_table.records[(USER_PK, CART_SK)], now=T0)

    assert len(emails) == 1
    # FAILS-BEFORE: body had bare "/cart?cartId=cart1" (no signed token).
    assert "/ui/shoppingcart/recover/" in emails[0]["body_text"]
    # Alert link is also the signed recovery URL.
    assert alerts and "/ui/shoppingcart/recover/" in alerts[0]["details"]["link"]


# ─── GAP-0191 ────────────────────────────────────────────────────────────────


def test_preference_get_put_roundtrip(env):
    # Default: opted in (no row).
    assert cart_reminders.get_reminder_preference(USER_SUB) == {
        "opted_out": False,
        "updated_at": None,
    }
    assert cart_reminders.is_user_opted_out(USER_SUB) is False

    cart_reminders.set_reminder_preference(USER_SUB, True)
    assert cart_reminders.is_user_opted_out(USER_SUB) is True
    pref = cart_reminders.get_reminder_preference(USER_SUB)
    assert pref["opted_out"] is True
    assert pref["updated_at"] is not None

    cart_reminders.set_reminder_preference(USER_SUB, False)
    assert cart_reminders.is_user_opted_out(USER_SUB) is False


def test_opted_out_user_skips_reminder(env, monkeypatch):
    cart_table, _config, emails, alerts = env
    monkeypatch.setattr(cart_reminders, "now_ts", lambda: T0)
    cart_table.seed_cart(abandoned_at=T0, last_activity_at=T0)
    cart_reminders.set_reminder_preference(USER_SUB, True)

    shoppingcart_svc.send_cart_reminder(cart_table.records[(USER_PK, CART_SK)], now=T0)

    # FAILS-BEFORE: legacy send_cart_reminder had no opt-out check → email sent.
    assert emails == []
    assert alerts == []


def test_opted_in_user_receives_reminder(env, monkeypatch):
    cart_table, _config, emails, alerts = env
    monkeypatch.setattr(cart_reminders, "now_ts", lambda: T0)
    cart_table.seed_cart(abandoned_at=T0, last_activity_at=T0)

    shoppingcart_svc.send_cart_reminder(cart_table.records[(USER_PK, CART_SK)], now=T0)

    assert len(emails) == 1
    assert len(alerts) == 1
