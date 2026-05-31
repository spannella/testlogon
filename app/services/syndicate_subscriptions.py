"""Syndicate bundled subscription management (SYND-002)."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services import syndicates as syndicate_svc

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create_bundle_plan(
    *,
    syndicate_id: str,
    admin_sub: str,
    name: str,
    description: str = "",
    price_cents: int,
    interval: str = "month",
) -> Dict[str, Any]:
    """Create a bundled subscription plan for a syndicate."""
    syndicate_svc._require_admin(syndicate_id, admin_sub)
    syndicate = syndicate_svc.get_syndicate(syndicate_id)
    if not syndicate:
        raise HTTPException(status_code=404, detail="Syndicate not found")
    members = syndicate_svc.list_members(syndicate_id)

    plan_id = f"plan_{uuid4().hex}"
    ts = now_ts()

    plan: Dict[str, Any] = {
        "pk": f"PLAN#{plan_id}",
        "sk": "META",
        "plan_id": plan_id,
        "plan_type": "syndicate_bundle",
        "syndicate_id": syndicate_id,
        "name": name,
        "description": description,
        "price_cents": price_cents,
        "interval": interval,
        "status": "active",
        "included_creator_ids": [m["user_id"] for m in members],
        "owner_id": syndicate_id,
        "created_at": ts,
        "updated_at": ts,
    }
    T.subscriptions.put_item(Item=plan)

    # Index for syndicate plan listing
    T.subscriptions.put_item(Item={
        "pk": f"SYNDICATE_PLANS#{syndicate_id}",
        "sk": f"PLAN#{plan_id}",
        "plan_id": plan_id,
        "name": name,
        "price_cents": price_cents,
        "status": "active",
    })

    logger.info("bundle_plan.created syndicate_id=%s plan_id=%s price_cents=%d", syndicate_id, plan_id, price_cents)
    return plan


def update_bundle_plan(
    *,
    syndicate_id: str,
    plan_id: str,
    admin_sub: str,
    name: Optional[str] = None,
    description: Optional[str] = None,
    price_cents: Optional[int] = None,
) -> Dict[str, Any]:
    """Update a bundle plan (admin only)."""
    syndicate_svc._require_admin(syndicate_id, admin_sub)
    plan = _get_plan(plan_id)
    if plan.get("syndicate_id") != syndicate_id:
        raise HTTPException(status_code=404, detail="Plan not found in this syndicate")

    ts = now_ts()
    updates: Dict[str, Any] = {"updated_at": ts}
    if name is not None:
        updates["name"] = name
    if description is not None:
        updates["description"] = description
    if price_cents is not None:
        updates["price_cents"] = price_cents

    expr_parts = []
    expr_values: Dict[str, Any] = {}
    expr_names: Dict[str, str] = {}
    for i, (k, v) in enumerate(updates.items()):
        alias = f"#k{i}"
        val_alias = f":v{i}"
        expr_parts.append(f"{alias} = {val_alias}")
        expr_names[alias] = k
        expr_values[val_alias] = v

    T.subscriptions.update_item(
        Key={"pk": f"PLAN#{plan_id}", "sk": "META"},
        UpdateExpression="SET " + ", ".join(expr_parts),
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_values,
    )

    # Update the index entry too
    index_updates: Dict[str, Any] = {}
    if name is not None:
        index_updates["name"] = name
    if price_cents is not None:
        index_updates["price_cents"] = price_cents
    if index_updates:
        idx_parts = []
        idx_values: Dict[str, Any] = {}
        idx_names: Dict[str, str] = {}
        for i, (k, v) in enumerate(index_updates.items()):
            a = f"#ik{i}"
            va = f":iv{i}"
            idx_parts.append(f"{a} = {va}")
            idx_names[a] = k
            idx_values[va] = v
        T.subscriptions.update_item(
            Key={"pk": f"SYNDICATE_PLANS#{syndicate_id}", "sk": f"PLAN#{plan_id}"},
            UpdateExpression="SET " + ", ".join(idx_parts),
            ExpressionAttributeNames=idx_names,
            ExpressionAttributeValues=idx_values,
        )

    plan.update(updates)
    logger.info("bundle_plan.updated syndicate_id=%s plan_id=%s", syndicate_id, plan_id)
    return plan


def archive_bundle_plan(
    *,
    syndicate_id: str,
    plan_id: str,
    admin_sub: str,
) -> Dict[str, Any]:
    """Archive a bundle plan (admin only). Existing subscribers unaffected."""
    syndicate_svc._require_admin(syndicate_id, admin_sub)
    plan = _get_plan(plan_id)
    if plan.get("syndicate_id") != syndicate_id:
        raise HTTPException(status_code=404, detail="Plan not found in this syndicate")

    ts = now_ts()
    T.subscriptions.update_item(
        Key={"pk": f"PLAN#{plan_id}", "sk": "META"},
        UpdateExpression="SET #s = :s, updated_at = :ts",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "archived", ":ts": ts},
    )
    T.subscriptions.update_item(
        Key={"pk": f"SYNDICATE_PLANS#{syndicate_id}", "sk": f"PLAN#{plan_id}"},
        UpdateExpression="SET #s = :s",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "archived"},
    )

    logger.info("bundle_plan.archived syndicate_id=%s plan_id=%s", syndicate_id, plan_id)
    return {"ok": True, "plan_id": plan_id, "status": "archived"}


def subscribe_to_bundle(
    *,
    subscriber_id: str,
    plan_id: str,
    payment_method_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Subscribe a user to a syndicate bundle plan."""
    plan = _get_plan(plan_id)
    if plan.get("plan_type") != "syndicate_bundle":
        raise HTTPException(status_code=400, detail="Plan is not a syndicate bundle")
    if plan.get("status") == "archived":
        raise HTTPException(status_code=400, detail="This plan is no longer available")

    syndicate_id = plan["syndicate_id"]

    # Check for existing active bundle subscription to this syndicate
    existing = _get_active_bundle_sub(subscriber_id, syndicate_id)
    if existing:
        raise HTTPException(status_code=409, detail="You already have an active subscription to this bundle")

    subscription_id = f"sub_{uuid4().hex}"
    ts = now_ts()
    period_end = ts + _interval_seconds(plan.get("interval", "month"))

    # Create subscription record
    sub: Dict[str, Any] = {
        "pk": f"SUBSCRIPTION#{subscription_id}",
        "sk": "META",
        "subscription_id": subscription_id,
        "subscriber_id": subscriber_id,
        "plan_id": plan_id,
        "plan_type": "syndicate_bundle",
        "syndicate_id": syndicate_id,
        "status": "active",
        "price_cents": int(plan.get("price_cents", 0)),
        "interval": plan.get("interval", "month"),
        "created_at": ts,
        "current_period_start": ts,
        "current_period_end": period_end,
    }
    T.subscriptions.put_item(Item=sub)

    # Subscriber index
    T.subscriptions.put_item(Item={
        "pk": f"SUBSCRIBER#{subscriber_id}",
        "sk": f"SUB#{subscription_id}",
        "subscription_id": subscription_id,
        "plan_id": plan_id,
        "plan_type": "syndicate_bundle",
        "syndicate_id": syndicate_id,
        "status": "active",
    })

    # Bundle entitlement index (for fast access checks)
    T.syndicates.put_item(Item={
        "pk": f"BUNDLE_SUB#{subscriber_id}",
        "sk": f"SYND#{syndicate_id}",
        "syndicate_id": syndicate_id,
        "subscription_id": subscription_id,
        "status": "active",
        "created_at": ts,
    })

    logger.info(
        "bundle.subscribed subscriber_id=%s syndicate_id=%s plan_id=%s",
        subscriber_id, syndicate_id, plan_id,
    )

    # SYND-003: attribute the bundle payment across syndicate members.
    # Best-effort: a split failure must never break subscription creation.
    price_cents = int(plan.get("price_cents", 0))
    if price_cents > 0:
        try:
            from app.services import syndicate_revenue_split as split_svc

            split_svc.execute_split(
                syndicate_id=syndicate_id,
                source_type="subscription",
                subscription_id=subscription_id,
                invoice_id=subscription_id,
                gross_amount_cents=price_cents,
            )
        except Exception:
            logger.warning(
                "bundle.split_failed subscriber_id=%s syndicate_id=%s",
                subscriber_id, syndicate_id,
            )
    return sub


def cancel_bundle_subscription(
    *,
    subscriber_id: str,
    subscription_id: str,
) -> Dict[str, Any]:
    """Cancel a bundle subscription (access continues until period end)."""
    sub = _get_subscription(subscription_id)
    if sub.get("subscriber_id") != subscriber_id:
        raise HTTPException(status_code=403, detail="You can only cancel your own subscriptions")
    if sub.get("status") == "cancelled":
        raise HTTPException(status_code=409, detail="Subscription is already cancelled")

    ts = now_ts()
    T.subscriptions.update_item(
        Key={"pk": f"SUBSCRIPTION#{subscription_id}", "sk": "META"},
        UpdateExpression="SET #s = :s, cancelled_at = :cat",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "cancelled", ":cat": ts},
    )

    # Update subscriber index
    T.subscriptions.update_item(
        Key={"pk": f"SUBSCRIBER#{subscriber_id}", "sk": f"SUB#{subscription_id}"},
        UpdateExpression="SET #s = :s",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "cancelled"},
    )

    # Update bundle entitlement index -- mark cancelled but keep until period end
    syndicate_id = sub.get("syndicate_id", "")
    if syndicate_id:
        T.syndicates.update_item(
            Key={"pk": f"BUNDLE_SUB#{subscriber_id}", "sk": f"SYND#{syndicate_id}"},
            UpdateExpression="SET #s = :s, cancelled_at = :cat",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "cancelled", ":cat": ts},
        )

    logger.info(
        "bundle.cancelled subscriber_id=%s subscription_id=%s",
        subscriber_id, subscription_id,
    )
    return {
        "subscription_id": subscription_id,
        "status": "cancelled",
        "current_period_end": int(sub.get("current_period_end", 0)),
        "cancelled_at": ts,
    }


def has_bundle_access(subscriber_id: str, creator_id: str) -> bool:
    """Check if subscriber has access to creator via any syndicate bundle."""
    # 1. Get creator's syndicates
    creator_syndicates = syndicate_svc.list_user_syndicates(creator_id)

    # 2. For each syndicate, check if subscriber has active bundle
    for synd in creator_syndicates:
        syndicate_id = synd.get("syndicate_id", "")
        if not syndicate_id:
            continue
        resp = T.syndicates.get_item(Key={
            "pk": f"BUNDLE_SUB#{subscriber_id}",
            "sk": f"SYND#{syndicate_id}",
        })
        item = resp.get("Item")
        if not item:
            continue
        status = (item.get("status") or "").lower()
        if status == "active":
            logger.debug(
                "bundle_access.granted_via_syndicate subscriber_id=%s creator_id=%s syndicate_id=%s",
                subscriber_id, creator_id, syndicate_id,
            )
            return True
        # Cancelled but still within period -- check period end
        if status == "cancelled":
            sub_id = item.get("subscription_id", "")
            if sub_id:
                sub_resp = T.subscriptions.get_item(Key={
                    "pk": f"SUBSCRIPTION#{sub_id}",
                    "sk": "META",
                })
                sub_item = sub_resp.get("Item")
                if sub_item:
                    period_end = int(sub_item.get("current_period_end", 0))
                    if now_ts() < period_end:
                        return True
    return False


def list_bundle_plans(syndicate_id: str) -> List[Dict[str, Any]]:
    """List all bundle plans for a syndicate."""
    resp = T.subscriptions.query(
        KeyConditionExpression=(
            Key("pk").eq(f"SYNDICATE_PLANS#{syndicate_id}")
            & Key("sk").begins_with("PLAN#")
        ),
    )
    return resp.get("Items", [])


def get_bundle_details(plan_id: str) -> Dict[str, Any]:
    """Get bundle plan details including current member list."""
    plan = _get_plan(plan_id)
    syndicate_id = plan.get("syndicate_id", "")
    members = syndicate_svc.list_members(syndicate_id) if syndicate_id else []
    plan["current_members"] = members
    return plan


def list_subscriber_bundles(subscriber_id: str) -> List[Dict[str, Any]]:
    """List all bundle subscriptions for a subscriber."""
    resp = T.subscriptions.query(
        KeyConditionExpression=(
            Key("pk").eq(f"SUBSCRIBER#{subscriber_id}")
            & Key("sk").begins_with("SUB#")
        ),
    )
    items = resp.get("Items", [])
    # Filter to bundle subscriptions only
    bundles = [i for i in items if i.get("plan_type") == "syndicate_bundle"]

    # Enrich with syndicate name and full subscription details
    for b in bundles:
        syndicate_id = b.get("syndicate_id", "")
        if syndicate_id:
            meta = syndicate_svc.get_syndicate(syndicate_id)
            b["syndicate_name"] = meta.get("name", "") if meta else ""
            # Get the full subscription record for period info
            sub_id = b.get("subscription_id", "")
            if sub_id:
                sub_resp = T.subscriptions.get_item(Key={
                    "pk": f"SUBSCRIPTION#{sub_id}",
                    "sk": "META",
                })
                sub_item = sub_resp.get("Item")
                if sub_item:
                    b["price_cents"] = int(sub_item.get("price_cents", 0))
                    b["interval"] = sub_item.get("interval", "month")
                    b["current_period_start"] = int(sub_item.get("current_period_start", 0))
                    b["current_period_end"] = int(sub_item.get("current_period_end", 0))
                    b["created_at"] = int(sub_item.get("created_at", 0))
                    b["cancelled_at"] = sub_item.get("cancelled_at")
                    b["status"] = sub_item.get("status", b.get("status", "active"))
    return bundles


def on_member_joined_syndicate(syndicate_id: str, creator_id: str) -> int:
    """Called when a creator joins a syndicate. No DDB changes needed --
    has_bundle_access checks live membership."""
    logger.info("bundle.member_joined syndicate_id=%s creator_id=%s", syndicate_id, creator_id)
    return 0


def on_member_left_syndicate(syndicate_id: str, creator_id: str) -> int:
    """Called when a creator leaves a syndicate. No DDB changes needed --
    has_bundle_access checks live membership."""
    logger.info("bundle.member_left syndicate_id=%s creator_id=%s", syndicate_id, creator_id)
    return 0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_plan(plan_id: str) -> Dict[str, Any]:
    """Get plan or raise 404."""
    resp = T.subscriptions.get_item(Key={"pk": f"PLAN#{plan_id}", "sk": "META"})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Bundle plan not found")
    return item


def _get_subscription(subscription_id: str) -> Dict[str, Any]:
    """Get subscription or raise 404."""
    resp = T.subscriptions.get_item(Key={"pk": f"SUBSCRIPTION#{subscription_id}", "sk": "META"})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Subscription not found")
    return item


def _get_active_bundle_sub(subscriber_id: str, syndicate_id: str) -> Optional[Dict[str, Any]]:
    """Check if subscriber already has an active bundle for this syndicate."""
    resp = T.syndicates.get_item(Key={
        "pk": f"BUNDLE_SUB#{subscriber_id}",
        "sk": f"SYND#{syndicate_id}",
    })
    item = resp.get("Item")
    if item and item.get("status") == "active":
        return item
    return None


def _interval_seconds(interval: str) -> int:
    return {"month": 30 * 86400, "year": 365 * 86400}.get(interval, 30 * 86400)
