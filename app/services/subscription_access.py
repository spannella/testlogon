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
    item = T.subscriptions.get_item(Key={"pk": _pk_creator(creator_id), "sk": "SETTINGS"}).get("Item")
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
    for item in items:
        if item.get("creator_id") != creator_id:
            continue
        status = (item.get("status") or "").lower()
        if status in {"active", "past_due", "trialing"}:
            return True
    return False


def can_access_creator(subscriber_id: str, creator_id: str) -> bool:
    if subscriber_id == creator_id:
        return True
    if not creator_requires_subscription(creator_id):
        return True
    return has_active_subscription(subscriber_id, creator_id)


def require_subscription_access(subscriber_id: str, creator_id: str) -> None:
    if not can_access_creator(subscriber_id, creator_id):
        raise HTTPException(status_code=403, detail="Subscription required to access this creator")
