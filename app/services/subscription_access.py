from __future__ import annotations

from typing import Any, Dict, List

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts


def _pk_creator(creator_id: str) -> str:
    return f"CREATOR#{creator_id}"


def _pk_subscriber(subscriber_id: str) -> str:
    return f"SUBSCRIBER#{subscriber_id}"


def get_subscription_settings(creator_id: str) -> Dict[str, Any]:
    try:
        item = T.subscriptions.get_item(Key={"pk": _pk_creator(creator_id), "sk": "SETTINGS"}).get("Item")
    except Exception:
        item = None
    if not item:
        return {"require_subscription": False, "disable_auto_renew": False, "updated_at": 0}
    return {
        "require_subscription": bool(item.get("require_subscription", False)),
        "disable_auto_renew": bool(item.get("disable_auto_renew", False)),
        "updated_at": int(item.get("updated_at") or 0),
    }


def set_subscription_settings(
    creator_id: str,
    *,
    require_subscription: bool,
    disable_auto_renew: bool = False,
) -> Dict[str, Any]:
    item = {
        "pk": _pk_creator(creator_id),
        "sk": "SETTINGS",
        "require_subscription": bool(require_subscription),
        "disable_auto_renew": bool(disable_auto_renew),
        "updated_at": now_ts(),
    }
    T.subscriptions.put_item(Item=item)
    return get_subscription_settings(creator_id)


def creator_requires_subscription(creator_id: str) -> bool:
    return bool(get_subscription_settings(creator_id).get("require_subscription"))


def has_active_subscription(subscriber_id: str, creator_id: str) -> bool:
    try:
        resp = T.subscriptions.query(
            KeyConditionExpression=Key("pk").eq(_pk_subscriber(subscriber_id)) & Key("sk").begins_with("SUB#"),
        )
    except Exception:
        return False
    items: List[Dict[str, Any]] = resp.get("Items", [])
    now = now_ts()
    for item in items:
        if item.get("creator_id") != creator_id:
            continue
        status = (item.get("status") or "").lower()
        # SUB-E1: expired/canceled subs never grant access.
        if status not in {"active", "past_due", "trialing"}:
            continue
        # SUB-E1 expiry enforcement: access is bounded by the paid period
        # (grace-extended). A lapsed sub (period elapsed with no successful
        # renewal) or a past_due sub beyond grace LOSES access. A record
        # with no period info (legacy/grandfathered) is left un-enforced.
        period_end = int(item.get("current_period_end") or 0)
        grace_until = int(item.get("grace_until") or 0)
        effective_end = max(period_end, grace_until)
        if effective_end and effective_end <= now:
            continue
        return True
    return False


def list_active_subscriber_ids(creator_id: str) -> List[str]:
    """ADV2 R4: enumerate the user_ids of users with an ACTIVE subscription to
    ``creator_id``. Reads the creator-index partition (``CREATOR#{creator_id}``,
    ``SUB#`` items) written by ``subscription_server.save_subscription`` -- the
    same index ``count_active_subscribers`` trusts -- so NO GSI/backfill is
    required. Deduped, active/trialing/past_due only. Best-effort (returns what
    it has on error)."""
    subs: List[str] = []
    seen: set = set()
    last = None
    try:
        while True:
            kwargs: Dict[str, Any] = {
                "KeyConditionExpression": Key("pk").eq(_pk_creator(creator_id))
                & Key("sk").begins_with("SUB#"),
            }
            if last:
                kwargs["ExclusiveStartKey"] = last
            resp = T.subscriptions.query(**kwargs)
            for it in resp.get("Items", []):
                status = (it.get("status") or "").lower()
                if status not in {"active", "trialing", "past_due"}:
                    continue
                sub = str(it.get("subscriber_id") or "")
                if sub and sub not in seen:
                    seen.add(sub)
                    subs.append(sub)
            last = resp.get("LastEvaluatedKey")
            if not last:
                break
    except Exception:
        return subs
    return subs


def can_access_creator(subscriber_id: str, creator_id: str) -> bool:
    if subscriber_id == creator_id:
        return True
    if not creator_requires_subscription(creator_id):
        return True
    if has_active_subscription(subscriber_id, creator_id):
        return True
    # Check syndicate bundle access (SYND-002)
    try:
        from app.services.syndicate_subscriptions import has_bundle_access
        if has_bundle_access(subscriber_id, creator_id):
            return True
    except Exception:
        pass
    return False


def require_subscription_access(subscriber_id: str, creator_id: str) -> None:
    if not can_access_creator(subscriber_id, creator_id):
        raise HTTPException(status_code=403, detail="Subscription required to access this creator")
