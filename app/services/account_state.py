from __future__ import annotations

from typing import Any, Dict

from app.core.tables import T
from app.core.time import now_ts

DEFAULT_STATE = {
    "status": "active",
    "updated_at": 0,
    "reason": "",
    "requested_by": "",
}


def get_account_state(user_sub: str) -> Dict[str, Any]:
    it = T.account_state.get_item(Key={"user_sub": user_sub}).get("Item")
    if not it:
        return dict(DEFAULT_STATE)
    return {
        "status": it.get("status", "active"),
        "updated_at": int(it.get("updated_at") or 0),
        "reason": it.get("reason", ""),
        "requested_by": it.get("requested_by", ""),
    }


def set_account_state(user_sub: str, status: str, *, reason: str = "", requested_by: str = "") -> Dict[str, Any]:
    ts = now_ts()
    item = {
        "user_sub": user_sub,
        "status": status,
        "updated_at": ts,
        "reason": reason,
        "requested_by": requested_by,
    }
    T.account_state.put_item(Item=item)
    return get_account_state(user_sub)
