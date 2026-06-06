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

from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import write_alert, send_alert_email
from app.services.profile import get_profile

# Config-table partition keys
_STAGE_CONFIG_PK = "STAGE#CONFIG"
_OPTOUT_PK_PREFIX = "OPTOUT#USER#"


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


def _is_opted_out(user_sub: str) -> bool:
    try:
        item = T.cart_reminder_config.get_item(
            Key={"pk": f"{_OPTOUT_PK_PREFIX}{user_sub}", "sk": "META"}
        ).get("Item")
    except Exception:
        return False
    return bool(item and item.get("opted_out"))


def generate_recovery_link(user_sub: str, cart_id: str) -> str:
    """Return a cart recovery URL.

    GAP-0190 covers signing this link with an authentication token; until then
    this returns the plain deep-link used by the legacy reminder so behaviour is
    unchanged. Kept as a single seam so GAP-0190 can swap the implementation.
    """
    return f"/cart?cartId={cart_id}"


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
