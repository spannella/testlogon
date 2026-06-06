"""Multi-stage cart abandonment reminder service (GAP-0189 / FIN-003).

Reads per-stage reminder configuration from the ``cart_reminder_config`` DDB
table and advances each eligible abandoned cart through a numbered sequence of
reminder stages. Each stage has its own ``delay_hours``, ``subject`` and
``body_template`` so the marketing team can run staged campaigns (e.g. Stage 1
at 24 h, Stage 2 at 72 h with different copy, Stage 3 at 168 h "last chance")
without a code change.

If the config table is empty the service falls back to ``_default_stages()`` so
a fresh local environment works without seeding (dev/prod parity, SECOPS-007).

The previous single-blast ``send_cart_reminder`` (in ``shoppingcart.py``) is
retained as a fallback and is gated by ``S.cart_reminders_enabled``: when the
flag is ``0`` the background loop returns to the old behaviour.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.crypto import b64url, b64url_decode
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import write_alert, send_alert_email
from app.services.profile import get_profile

# Config-table partition keys
_STAGE_CONFIG_PK = "STAGE#CONFIG"
_OPTOUT_PK_PREFIX = "OPTOUT#USER#"
# Recovery-token consumption markers live in the same config table so GAP-0190
# needs no new table. The signed token is stateless; this row only records that
# a given token id (jti) has been consumed, enforcing one-time use.
_RECOVERY_CONSUMED_PK_PREFIX = "RECOVERY#CONSUMED#"


def _default_stages() -> List[Dict[str, Any]]:
    """Built-in three-stage sequence used when the config table is empty."""
    return [
        {
            "stage_number": 1,
            "delay_hours": 24,
            "subject": "You left items in your cart",
            "body_template": (
                "You have {items_count} item(s) waiting. "
                "Complete your purchase: {recovery_url}"
            ),
        },
        {
            "stage_number": 2,
            "delay_hours": 72,
            "subject": "Still thinking it over?",
            "body_template": (
                "Your cart is waiting — don't miss out. "
                "{items_count} item(s) ready: {recovery_url}"
            ),
        },
        {
            "stage_number": 3,
            "delay_hours": 168,
            "subject": "Last chance — your cart expires soon",
            "body_template": (
                "This is your final reminder. "
                "{items_count} item(s) in your cart: {recovery_url}"
            ),
        },
    ]


def _get_stages() -> List[Dict[str, Any]]:
    """Load stage configs from DDB, sorted by ``stage_number`` ascending.

    Falls back to the built-in defaults if the table is unavailable or empty.
    """
    try:
        resp = T.cart_reminder_config.query(
            KeyConditionExpression=Key("pk").eq(_STAGE_CONFIG_PK)
            & Key("sk").begins_with("STAGE#"),
        )
        stages = resp.get("Items", []) or []
    except Exception:
        stages = []
    if not stages:
        stages = _default_stages()
    return sorted(stages, key=lambda s: int(s.get("stage_number", 0)))


def is_user_opted_out(user_sub: str) -> bool:
    """Return True if the user has opted out of cart abandonment reminders.

    Opt-out state lives in the ``cart_reminder_config`` table under the
    ``OPTOUT#USER#{sub}`` partition (GAP-0191).
    """
    try:
        item = T.cart_reminder_config.get_item(
            Key={"pk": f"{_OPTOUT_PK_PREFIX}{user_sub}", "sk": "META"}
        ).get("Item")
    except Exception:
        return False
    return bool(item and item.get("opted_out"))


# Backwards-compatible private alias (used by process_abandoned_carts above).
_is_opted_out = is_user_opted_out


def get_reminder_preference(user_sub: str) -> Dict[str, Any]:
    """Return the user's cart-reminder preference; defaults to opted-in."""
    try:
        item = T.cart_reminder_config.get_item(
            Key={"pk": f"{_OPTOUT_PK_PREFIX}{user_sub}", "sk": "META"}
        ).get("Item")
    except Exception:
        item = None
    if not item:
        return {"opted_out": False, "updated_at": None}
    updated_at = int(item.get("updated_at", 0) or 0) or None
    return {"opted_out": bool(item.get("opted_out")), "updated_at": updated_at}


def set_reminder_preference(user_sub: str, opted_out: bool) -> Dict[str, Any]:
    """Write or update the user's cart-reminder opt-out preference."""
    ts = now_ts()
    T.cart_reminder_config.put_item(
        Item={
            "pk": f"{_OPTOUT_PK_PREFIX}{user_sub}",
            "sk": "META",
            "opted_out": bool(opted_out),
            "updated_at": ts,
        }
    )
    return {"opted_out": bool(opted_out), "updated_at": ts}


# ─── GAP-0190: signed one-time cart-recovery tokens ──────────────────────────

def _recovery_secret() -> bytes:
    """Signing key for recovery tokens (dev/prod parity, SECOPS-007)."""
    secret = S.cart_recovery_link_secret or "dev-cart-recovery-secret"
    return secret.encode("utf-8")


def _sign_recovery_token(user_sub: str, cart_id: str) -> str:
    """Mint a signed, time-limited, one-time-use recovery token.

    Format mirrors ``app.core.crypto.mint_ws_token``: ``b64url(payload).b64url(sig)``
    with an HMAC-SHA256 signature. ``jti`` lets us mark the token consumed in DDB.
    """
    now = now_ts()
    payload = {
        "user_sub": user_sub,
        "cart_id": cart_id,
        "jti": uuid.uuid4().hex,
        "exp": now + S.cart_recovery_link_ttl_days * 86400,
        "iat": now,
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(_recovery_secret(), raw, hashlib.sha256).digest()
    return f"{b64url(raw)}.{b64url(sig)}"


def _verify_recovery_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify signature + expiry. Returns the payload dict or ``None``."""
    try:
        raw_b64, sig_b64 = token.split(".", 1)
        raw = b64url_decode(raw_b64)
        sig = b64url_decode(sig_b64)
        expected = hmac.new(_recovery_secret(), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None
        obj = json.loads(raw.decode("utf-8"))
        if not isinstance(obj, dict):
            return None
        if int(obj.get("exp", 0)) < now_ts():
            return None
        return obj
    except Exception:
        return None


def _is_token_consumed(jti: str) -> bool:
    try:
        item = T.cart_reminder_config.get_item(
            Key={"pk": f"{_RECOVERY_CONSUMED_PK_PREFIX}{jti}", "sk": "META"}
        ).get("Item")
    except Exception:
        return False
    return bool(item)


def _mark_token_consumed(jti: str) -> bool:
    """Atomically mark a token id consumed. Returns False if already consumed."""
    try:
        T.cart_reminder_config.put_item(
            Item={
                "pk": f"{_RECOVERY_CONSUMED_PK_PREFIX}{jti}",
                "sk": "META",
                "consumed_at": now_ts(),
            },
            ConditionExpression="attribute_not_exists(pk)",
        )
        return True
    except Exception:
        return False


def generate_recovery_link(user_sub: str, cart_id: str) -> str:
    """Return a signed, one-time-use cart recovery URL (GAP-0190).

    The token carries the owning user and cart, is signed with an HMAC secret,
    and is consumed on first use. The base URL comes from ``S.public_base_url``
    (localhost in dev, the public HTTPS domain in prod) so the same code path
    works in both environments (SECOPS-007).
    """
    token = _sign_recovery_token(user_sub, cart_id)
    base = S.public_base_url.rstrip("/")
    return f"{base}/ui/shoppingcart/recover/{token}"


def recover_cart(token: str) -> Dict[str, Any]:
    """Validate and consume a recovery token.

    Returns ``{user_sub, cart_id}``. Raises ``HTTPException(400)`` for an
    invalid/expired token or one that has already been used (one-time-use).
    """
    payload = _verify_recovery_token(token)
    if not payload:
        raise HTTPException(status_code=400, detail="Invalid or expired recovery link")
    jti = str(payload.get("jti") or "")
    if not jti or _is_token_consumed(jti):
        raise HTTPException(status_code=400, detail="Recovery link already used")
    # Atomically consume — guards against concurrent double-use.
    if not _mark_token_consumed(jti):
        raise HTTPException(status_code=400, detail="Recovery link already used")
    return {
        "user_sub": str(payload.get("user_sub") or ""),
        "cart_id": str(payload.get("cart_id") or ""),
    }


def _count_cart_items(user_pk: str, cart_id: str) -> int:
    """Count line items in a cart (inline; mirrors send_cart_reminder)."""
    prefix = f"CART#{cart_id}#ITEM#"
    resp = T.shopping_cart.query(
        KeyConditionExpression=Key("PK").eq(user_pk) & Key("SK").begins_with(prefix),
        Select="COUNT",
    )
    return int(resp.get("Count", 0) or 0)


def process_abandoned_carts(*, now: Optional[int] = None) -> Dict[str, int]:
    """Advance all eligible carts through their reminder stage pipeline.

    Each cart records ``current_reminder_stage`` (the stage number last sent, 0
    if none). The next stage in the configured sequence fires once its
    ``delay_hours`` have elapsed — measured from the cart's abandonment time for
    the first stage, and from ``last_reminder_at`` for subsequent stages.

    Returns counts: ``{scanned, reminded, skipped}``.
    """
    if not S.cart_reminders_enabled:
        return {"scanned": 0, "reminded": 0, "skipped": 0}

    # Imported lazily to avoid a circular import (shoppingcart imports nothing
    # from this module, but the background loop imports both).
    from app.services.shoppingcart import scan_abandoned_carts

    now = now if now is not None else now_ts()
    stages = _get_stages()
    if not stages:
        return {"scanned": 0, "reminded": 0, "skipped": 0}

    max_stage = len(stages)
    # Scan broadly using the smallest (Stage 1) delay as the threshold so carts
    # become candidates as soon as they could qualify for any stage.
    min_delay = int(stages[0].get("delay_hours", 24))
    carts = scan_abandoned_carts(
        threshold_hours=min_delay, now=now, apply_reminder_gate=False
    )

    reminded = skipped = 0

    for cart in carts:
        current_stage_idx = int(cart.get("current_reminder_stage", 0) or 0)
        if current_stage_idx >= max_stage:
            skipped += 1
            continue

        stage = stages[current_stage_idx]
        stage_delay_sec = int(stage.get("delay_hours", 24)) * 3600

        abandoned_at = int(cart.get("abandoned_at", 0) or 0) or int(
            cart.get("last_activity_at", 0) or 0
        )
        last_reminder_at = int(cart.get("last_reminder_at", 0) or 0)

        # Stage 1 (idx 0): delay measured from abandonment.
        # Later stages: delay measured from the previous reminder.
        reference_ts = abandoned_at if current_stage_idx == 0 else last_reminder_at
        if now < reference_ts + stage_delay_sec:
            skipped += 1
            continue

        user_sub = cart["PK"].replace("USER#", "")
        if _is_opted_out(user_sub):
            skipped += 1
            continue

        sent = _send_stage_reminder(cart, stage, now=now)
        if sent:
            reminded += 1
        else:
            skipped += 1

    return {"scanned": len(carts), "reminded": reminded, "skipped": skipped}


def _send_stage_reminder(
    cart: Dict[str, Any], stage: Dict[str, Any], *, now: int
) -> bool:
    """Send one stage reminder and advance the cart's stage counter.

    Returns ``True`` if a reminder was sent, ``False`` if it was skipped (e.g.
    the cart was purchased between scan and send, or is empty).
    """
    user_pk = cart["PK"]
    user_sub = user_pk.replace("USER#", "")
    cart_id = cart.get("cart_id", "")
    stage_number = int(stage.get("stage_number", 1))

    # Race guard: cart may have been purchased between scan and send.
    latest = T.shopping_cart.get_item(
        Key={"PK": user_pk, "SK": cart["SK"]}
    ).get("Item")
    if not latest or latest.get("status") != "OPEN":
        return False

    items_count = _count_cart_items(user_pk, cart_id)
    if items_count == 0:
        return False  # Don't remind for empty carts

    recovery_url = generate_recovery_link(user_sub, cart_id)
    subject = stage.get("subject", "You left items in your cart")
    body_tpl = stage.get(
        "body_template",
        "You have {items_count} item(s) waiting: {recovery_url}",
    )
    body_text = body_tpl.format(items_count=items_count, recovery_url=recovery_url)

    write_alert(
        user_sub,
        event="cart.abandoned",
        outcome=f"reminder_stage_{stage_number}",
        title=subject,
        details={
            "cart_id": cart_id,
            "alert_type": "cart.abandoned",
            "link": recovery_url,
            "items_count": str(items_count),
            "stage": str(stage_number),
        },
    )

    profile = get_profile(user_sub) or {}
    email = profile.get("email") or profile.get("displayed_email")
    if email:
        send_alert_email([email], subject=subject, body_text=body_text)

    # Record the stage just sent. On the next scan, current_reminder_stage ==
    # stage_number, which indexes the *next* stage dict (stages are 1-based but
    # the list is 0-indexed, so stage N sent → idx N selects stage N+1).
    T.shopping_cart.update_item(
        Key={"PK": user_pk, "SK": cart["SK"]},
        UpdateExpression=(
            "SET last_reminder_at = :ts, "
            "current_reminder_stage = :stage, "
            "abandoned_at = if_not_exists(abandoned_at, :ts) "
            "ADD reminder_count :one"
        ),
        ExpressionAttributeValues={
            ":ts": now,
            ":stage": stage_number,
            ":one": 1,
        },
    )
    return True
