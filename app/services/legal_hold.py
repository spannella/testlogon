"""Legal-hold model + service (LEX-006).

A legal hold is a standalone marker that suspends deletion/retention for a
specific user (and optionally a matter/case). Holds live in their own
``legal_holds`` table keyed ``HOLD#{hold_id}`` / ``META`` with a ``ByUser`` GSI
(``gsi1pk="USER#{user_sub}"``) so :func:`is_user_on_hold` is an O(1) query
rather than a table scan.

Everything here is additive and only consulted by the deletion/retention paths
when the master flag ``S.legal_export_enabled`` is ON (see LEX-007). With the
flag off the table is never read and existing behavior is byte-for-byte
unchanged.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def _hold_pk(hold_id: str) -> str:
    return f"HOLD#{hold_id}"


def _user_gsi_pk(user_sub: str) -> str:
    return f"USER#{user_sub}"


def _new_hold_id() -> str:
    return f"lh_{uuid.uuid4().hex}"


def place_hold(
    *,
    user_sub: str,
    reason: str,
    created_by: str,
    case_id: Optional[str] = None,
    matter_ref: Optional[str] = None,
    expires_at: Optional[int] = None,
) -> Dict[str, Any]:
    """Create an active legal hold scoped to ``user_sub``.

    Writes a single META row carrying the user-index GSI keys so the same item
    is selectable both by hold_id and by user_sub (no second row to keep in
    sync).
    """
    if not user_sub:
        raise ValueError("user_sub is required")
    if not reason:
        raise ValueError("reason is required")

    hold_id = _new_hold_id()
    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": _hold_pk(hold_id),
        "sk": "META",
        "hold_id": hold_id,
        "user_sub": user_sub,
        "case_id": case_id or "",
        "matter_ref": matter_ref or "",
        "reason": reason,
        "status": "active",
        "created_by": created_by,
        "created_at": ts,
        # ByUser GSI keys — only present on ACTIVE holds so released holds drop
        # out of the index (sparse) and is_user_on_hold ignores them for free.
        "gsi1pk": _user_gsi_pk(user_sub),
        "gsi1sk": _hold_pk(hold_id),
    }
    if expires_at:
        item["expires_at"] = int(expires_at)
    T.legal_holds.put_item(Item=item)
    return item


def get_hold(hold_id: str) -> Optional[Dict[str, Any]]:
    resp = T.legal_holds.get_item(Key={"pk": _hold_pk(hold_id), "sk": "META"})
    return resp.get("Item")


def release_hold(hold_id: str, *, released_by: str) -> Optional[Dict[str, Any]]:
    """Release a hold: status->released and drop the user-index GSI keys.

    Removing ``gsi1pk``/``gsi1sk`` makes the row vanish from the ByUser index so
    :func:`is_user_on_hold` stops returning it, while the META row (audit trail)
    is preserved — never deleted.
    """
    existing = get_hold(hold_id)
    if not existing:
        return None
    if existing.get("status") == "released":
        return existing
    ts = now_ts()
    resp = T.legal_holds.update_item(
        Key={"pk": _hold_pk(hold_id), "sk": "META"},
        UpdateExpression=(
            "SET #st = :rel, released_by = :rb, released_at = :ra "
            "REMOVE gsi1pk, gsi1sk"
        ),
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":rel": "released",
            ":rb": released_by,
            ":ra": ts,
        },
        ReturnValues="ALL_NEW",
    )
    return resp.get("Attributes", existing)


def _hold_is_live(item: Dict[str, Any]) -> bool:
    """True if the hold is active and not expired."""
    if item.get("status") != "active":
        return False
    exp = item.get("expires_at")
    if exp:
        try:
            if now_ts() > int(exp):
                return False
        except (TypeError, ValueError):
            pass
    return True


def is_user_on_hold(user_sub: str) -> bool:
    """O(1) check: does ``user_sub`` have any live legal hold?

    Queries the ByUser GSI (only active holds carry the GSI keys). Returns
    False on any error so a lookup failure never blocks an unrelated operation.
    """
    if not user_sub:
        return False
    try:
        resp = T.legal_holds.query(
            IndexName="ByUser",
            KeyConditionExpression=Key("gsi1pk").eq(_user_gsi_pk(user_sub)),
            Limit=50,
        )
    except Exception:
        logger.exception("legal_hold.is_user_on_hold query failed for %s", user_sub)
        return False
    for item in resp.get("Items", []):
        if _hold_is_live(item):
            return True
    return False


def list_active_holds(limit: int = 200) -> List[Dict[str, Any]]:
    """List active (non-released, non-expired) holds. Uses a scan with a
    filter — acceptable for an admin/legal listing of a small table."""
    items: List[Dict[str, Any]] = []
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {"Limit": 200}
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.legal_holds.scan(**kwargs)
        for item in resp.get("Items", []):
            if item.get("sk") == "META" and _hold_is_live(item):
                items.append(item)
                if len(items) >= limit:
                    return items
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return items


def list_holds_for_user(user_sub: str) -> List[Dict[str, Any]]:
    """All holds (any status) for a user, via the ByUser GSI for active ones
    plus a fallback scan is avoided — released holds drop the GSI keys, so this
    returns only currently-active holds. Callers wanting full history should
    read by hold_id."""
    try:
        resp = T.legal_holds.query(
            IndexName="ByUser",
            KeyConditionExpression=Key("gsi1pk").eq(_user_gsi_pk(user_sub)),
        )
    except Exception:
        return []
    return [i for i in resp.get("Items", []) if i.get("sk") == "META"]
