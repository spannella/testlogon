"""Subscription tier management for the admin Subscription Tier Manager UI (ADMIN-001).

CRUD + lifecycle (create / edit / archive / unarchive / delete / reorder) and
analytics (subscriber count, revenue per tier) for subscription tiers.

Tiers are scoped to the authenticated operator's ``creator_id`` (the admin's
``sub``).  Records are stored in a dedicated table (``admin_subscription_tiers``)
using a single-table pattern:

    pk = CREATOR#{creator_id}
    sk = TIER#{tier_id}

Subscriber counts and revenue are computed against the existing ``subscriptions``
table (where active subscriptions are stored as ``pk=SUBSCRIBER#{id}`` /
``sk=SUB#{id}`` with ``creator_id``, ``status``, ``plan_id`` and ``price_cents``).
A tier may optionally link to a subscription plan via ``plan_id`` so analytics
can attribute live subscribers to it; otherwise the denormalised
``subscriber_count`` on the tier record is used.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger("app.admin_subscription_tiers")

_VALID_BILLING_CYCLES = {"monthly", "quarterly", "yearly"}
_VALID_ACCESS_LEVELS = {"basic", "premium", "vip"}
_ACTIVE_SUB_STATUSES = {"active", "past_due", "trialing"}


def _pk_creator(creator_id: str) -> str:
    return f"CREATOR#{creator_id}"


def _sk_tier(tier_id: str) -> str:
    return f"TIER#{tier_id}"


def _new_tier_id() -> str:
    return f"tier_{uuid.uuid4().hex[:12]}"


def _to_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _item_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a raw DynamoDB tier item into the TierOut shape."""
    archived_at = item.get("archived_at")
    return {
        "tier_id": str(item.get("tier_id") or ""),
        "name": str(item.get("name") or ""),
        "price_cents": _to_int(item.get("price_cents")),
        "billing_cycle": str(item.get("billing_cycle") or "monthly"),
        "description": str(item.get("description") or ""),
        "benefits": [str(b) for b in (item.get("benefits") or [])],
        "access_level": str(item.get("access_level") or "basic"),
        "display_order": _to_int(item.get("display_order")),
        "status": str(item.get("status") or "active"),
        "subscriber_count": _to_int(item.get("subscriber_count")),
        "plan_id": (str(item["plan_id"]) if item.get("plan_id") else None),
        "created_at": _to_int(item.get("created_at")),
        "updated_at": _to_int(item.get("updated_at")),
        "archived_at": (_to_int(archived_at) if archived_at else None),
    }


def _get_tier_item(creator_id: str, tier_id: str) -> Dict[str, Any]:
    try:
        item = T.admin_subscription_tiers.get_item(
            Key={"pk": _pk_creator(creator_id), "sk": _sk_tier(tier_id)}
        ).get("Item")
    except Exception:
        item = None
    if not item:
        raise HTTPException(status_code=404, detail="Tier not found")
    return item


def _query_tier_items(creator_id: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    last_key: Optional[Dict[str, Any]] = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(_pk_creator(creator_id))
            & Key("sk").begins_with("TIER#"),
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        try:
            resp = T.admin_subscription_tiers.query(**kwargs)
        except Exception:
            break
        items.extend(resp.get("Items", []) or [])
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return items


# ─── CRUD ──────────────────────────────────────────────────────────────────


def create_tier(
    *,
    creator_id: str,
    name: str,
    price_cents: int,
    billing_cycle: str = "monthly",
    description: str = "",
    benefits: Optional[List[str]] = None,
    access_level: str = "basic",
    plan_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a new subscription tier with the next display_order value."""
    existing = _query_tier_items(creator_id)
    next_order = 0
    if existing:
        next_order = max((_to_int(i.get("display_order")) for i in existing), default=-1) + 1

    ts = now_ts()
    tier_id = _new_tier_id()
    item: Dict[str, Any] = {
        "pk": _pk_creator(creator_id),
        "sk": _sk_tier(tier_id),
        "creator_id": creator_id,
        "tier_id": tier_id,
        "name": name,
        "price_cents": int(price_cents),
        "billing_cycle": billing_cycle,
        "description": description or "",
        "benefits": list(benefits or []),
        "access_level": access_level,
        "display_order": int(next_order),
        "status": "active",
        "subscriber_count": 0,
        "created_at": ts,
        "updated_at": ts,
    }
    if plan_id:
        item["plan_id"] = plan_id
    T.admin_subscription_tiers.put_item(Item=item)
    logger.info(
        "tier.created",
        extra={
            "tier_id": tier_id,
            "creator_id": creator_id,
            "name": name,
            "price_cents": int(price_cents),
            "billing_cycle": billing_cycle,
        },
    )
    return _item_to_out(item)


def get_tier(creator_id: str, tier_id: str) -> Dict[str, Any]:
    return _item_to_out(_get_tier_item(creator_id, tier_id))


def update_tier(*, creator_id: str, tier_id: str, **updates: Any) -> Dict[str, Any]:
    """Update tier details. Price changes only apply to new subscribers."""
    item = _get_tier_item(creator_id, tier_id)

    allowed = {
        "name",
        "price_cents",
        "billing_cycle",
        "description",
        "benefits",
        "access_level",
        "plan_id",
    }
    changed: List[str] = []
    for key, value in updates.items():
        if key not in allowed or value is None:
            continue
        if key == "price_cents":
            item[key] = int(value)
        elif key == "benefits":
            item[key] = list(value)
        else:
            item[key] = value
        changed.append(key)

    if not changed:
        return _item_to_out(item)

    item["updated_at"] = now_ts()
    T.admin_subscription_tiers.put_item(Item=item)
    logger.info(
        "tier.updated",
        extra={"tier_id": tier_id, "creator_id": creator_id, "changed_fields": changed},
    )
    return _item_to_out(item)


def archive_tier(*, creator_id: str, tier_id: str) -> Dict[str, Any]:
    """Archive a tier (stop new signups, keep existing subscribers)."""
    item = _get_tier_item(creator_id, tier_id)
    if str(item.get("status")) == "archived":
        raise HTTPException(status_code=400, detail="Tier is already archived")
    item["status"] = "archived"
    item["archived_at"] = now_ts()
    item["updated_at"] = now_ts()
    T.admin_subscription_tiers.put_item(Item=item)
    logger.info(
        "tier.archived",
        extra={
            "tier_id": tier_id,
            "creator_id": creator_id,
            "subscriber_count": _to_int(item.get("subscriber_count")),
        },
    )
    return _item_to_out(item)


def unarchive_tier(*, creator_id: str, tier_id: str) -> Dict[str, Any]:
    """Re-activate an archived tier."""
    item = _get_tier_item(creator_id, tier_id)
    if str(item.get("status")) != "archived":
        raise HTTPException(status_code=400, detail="Tier is already active")
    item["status"] = "active"
    item.pop("archived_at", None)
    item["updated_at"] = now_ts()
    T.admin_subscription_tiers.put_item(Item=item)
    logger.info("tier.unarchived", extra={"tier_id": tier_id, "creator_id": creator_id})
    return _item_to_out(item)


def delete_tier(*, creator_id: str, tier_id: str) -> Dict[str, Any]:
    """Delete a tier (only if subscriber_count == 0)."""
    item = _get_tier_item(creator_id, tier_id)
    sub_count = _to_int(item.get("subscriber_count"))
    if sub_count > 0:
        logger.info(
            "tier.delete_blocked",
            extra={"tier_id": tier_id, "creator_id": creator_id, "subscriber_count": sub_count},
        )
        raise HTTPException(
            status_code=409,
            detail=f"Cannot delete tier with {sub_count} active subscribers. Archive instead.",
        )
    try:
        T.admin_subscription_tiers.delete_item(
            Key={"pk": _pk_creator(creator_id), "sk": _sk_tier(tier_id)},
            ConditionExpression="attribute_not_exists(subscriber_count) OR subscriber_count = :zero",
            ExpressionAttributeValues={":zero": 0},
        )
    except Exception as exc:
        raise HTTPException(
            status_code=409,
            detail="Cannot delete tier — subscriber count changed. Archive instead.",
        ) from exc
    logger.info("tier.deleted", extra={"tier_id": tier_id, "creator_id": creator_id})
    return {"ok": True, "tier_id": tier_id, "deleted": True}


def list_tiers(creator_id: str, *, include_archived: bool = False) -> List[Dict[str, Any]]:
    """List all tiers for a creator, sorted by display_order (then created_at)."""
    items = _query_tier_items(creator_id)
    out = [_item_to_out(i) for i in items]
    if not include_archived:
        out = [t for t in out if t["status"] != "archived"]
    out.sort(key=lambda t: (t["display_order"], t["created_at"]))
    return out


def reorder_tiers(*, creator_id: str, tier_ids: List[str]) -> List[Dict[str, Any]]:
    """Reorder tiers. tier_ids is the new order (first = display_order 0)."""
    if len(tier_ids) != len(set(tier_ids)):
        raise HTTPException(status_code=422, detail="tier_ids must contain unique values")

    existing = {str(i.get("tier_id")): i for i in _query_tier_items(creator_id)}
    for tid in tier_ids:
        if tid not in existing:
            raise HTTPException(status_code=400, detail=f"tier_ids contains unknown tier ID: {tid}")

    ts = now_ts()
    results: List[Dict[str, Any]] = []
    for order, tid in enumerate(tier_ids):
        item = existing[tid]
        item["display_order"] = int(order)
        item["updated_at"] = ts
        T.admin_subscription_tiers.put_item(Item=item)
        results.append({"tier_id": tid, "display_order": int(order)})
    logger.info(
        "tier.reordered", extra={"creator_id": creator_id, "new_order": list(tier_ids)}
    )
    return results


# ─── Analytics & preview ─────────────────────────────────────────────────────


def _active_subscriptions_for_creator(creator_id: str) -> List[Dict[str, Any]]:
    """Scan the subscriptions table for active subscriptions to this creator.

    Uses a GSI-less Scan with a filter — subscription volume per creator in the
    dev/test environment is small. Loops via LastEvaluatedKey for safety.
    """
    from boto3.dynamodb.conditions import Attr

    items: List[Dict[str, Any]] = []
    last_key: Optional[Dict[str, Any]] = None
    while True:
        scan_kwargs: Dict[str, Any] = {
            "FilterExpression": Attr("creator_id").eq(creator_id)
            & Attr("sk").begins_with("SUB#"),
        }
        if last_key:
            scan_kwargs["ExclusiveStartKey"] = last_key
        try:
            resp = T.subscriptions.scan(**scan_kwargs)
        except Exception:
            break
        for it in resp.get("Items", []) or []:
            status = str(it.get("status") or "").lower()
            if status in _ACTIVE_SUB_STATUSES:
                items.append(it)
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return items


def get_tier_subscriber_count(creator_id: str, tier_id: str) -> int:
    """Get current subscriber count for a specific tier (denormalised value)."""
    item = _get_tier_item(creator_id, tier_id)
    return _to_int(item.get("subscriber_count"))


def get_tier_analytics(
    creator_id: str, *, start_date: Optional[str] = None, end_date: Optional[str] = None
) -> Dict[str, Any]:
    """Aggregate subscriber count and revenue per tier for a creator."""
    tiers = list_tiers(creator_id, include_archived=True)
    subs = _active_subscriptions_for_creator(creator_id)

    # Build per-plan live subscriber/revenue maps from active subscriptions.
    by_plan_count: Dict[str, int] = {}
    by_plan_revenue: Dict[str, int] = {}
    for s in subs:
        pid = str(s.get("plan_id") or "")
        by_plan_count[pid] = by_plan_count.get(pid, 0) + 1
        by_plan_revenue[pid] = by_plan_revenue.get(pid, 0) + _to_int(s.get("price_cents"))

    tier_rows: List[Dict[str, Any]] = []
    total_subscribers = 0
    total_revenue_cents = 0
    for t in tiers:
        plan_id = t.get("plan_id") or ""
        live_count = by_plan_count.get(plan_id, 0) if plan_id else 0
        sub_count = live_count or t["subscriber_count"]
        if plan_id and plan_id in by_plan_revenue:
            revenue = by_plan_revenue[plan_id]
        else:
            revenue = sub_count * t["price_cents"]
        churn = 0.0
        tier_rows.append(
            {
                "tier_id": t["tier_id"],
                "name": t["name"],
                "subscriber_count": int(sub_count),
                "revenue_cents": int(revenue),
                "churn_rate": churn,
            }
        )
        total_subscribers += int(sub_count)
        total_revenue_cents += int(revenue)

    return {
        "tiers": tier_rows,
        "total_subscribers": int(total_subscribers),
        "total_revenue_cents": int(total_revenue_cents),
        "growth_series": [],
    }


def preview_tiers(creator_id: str) -> Dict[str, Any]:
    """Subscriber-facing preview: active tiers only, in display order."""
    active = list_tiers(creator_id, include_archived=False)
    tiers = [
        {
            "tier_id": t["tier_id"],
            "name": t["name"],
            "price_cents": t["price_cents"],
            "billing_cycle": t["billing_cycle"],
            "description": t["description"],
            "benefits": t["benefits"],
            "access_level": t["access_level"],
            "display_order": t["display_order"],
        }
        for t in active
    ]
    return {"tiers": tiers, "creator_id": creator_id}
