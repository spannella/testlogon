from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Mapping

from app.core.tables import T
from app.core.time import now_ts


class DiscoverabilityState(str, Enum):
    ACTIVE = "active"
    HIDDEN = "hidden"
    DEACTIVATED = "deactivated"
    DELETED = "deleted"


DISCOVERABILITY_FIELD = "discoverability_status"
DEFAULT_DISCOVERABILITY_STATE = DiscoverabilityState.ACTIVE

LEGACY_ACCOUNT_STATUS_TO_DISCOVERABILITY: Dict[str, DiscoverabilityState] = {
    "active": DiscoverabilityState.ACTIVE,
    "deactivated": DiscoverabilityState.DEACTIVATED,
    "deleted": DiscoverabilityState.DELETED,
}


def normalize_discoverability_state(value: Any) -> DiscoverabilityState:
    raw = str(value or "").strip().lower()
    for state in DiscoverabilityState:
        if state.value == raw:
            return state
    return DEFAULT_DISCOVERABILITY_STATE


def resolve_discoverability_state(account_state_item: Mapping[str, Any] | None) -> DiscoverabilityState:
    if not account_state_item:
        return DEFAULT_DISCOVERABILITY_STATE

    if DISCOVERABILITY_FIELD in account_state_item:
        return normalize_discoverability_state(account_state_item.get(DISCOVERABILITY_FIELD))

    legacy_status = str(account_state_item.get("status") or "").strip().lower()
    return LEGACY_ACCOUNT_STATUS_TO_DISCOVERABILITY.get(legacy_status, DEFAULT_DISCOVERABILITY_STATE)


def get_profile_discoverability_state(user_sub: str) -> Dict[str, Any]:
    item = T.account_state.get_item(Key={"user_sub": user_sub}).get("Item") or {}
    resolved = resolve_discoverability_state(item)
    if DISCOVERABILITY_FIELD in item:
        source = DISCOVERABILITY_FIELD
    elif item:
        source = "status"
    else:
        source = "default"
    return {
        "user_sub": user_sub,
        DISCOVERABILITY_FIELD: resolved.value,
        "source": source,
    }


def set_profile_discoverability_state(user_sub: str, state: DiscoverabilityState | str, *, requested_by: str = "") -> Dict[str, Any]:
    normalized = normalize_discoverability_state(state)
    ts = now_ts()
    T.account_state.update_item(
        Key={"user_sub": user_sub},
        UpdateExpression="SET #discoverability=:discoverability, updated_at=:updated_at, requested_by=:requested_by",
        ExpressionAttributeNames={"#discoverability": DISCOVERABILITY_FIELD},
        ExpressionAttributeValues={
            ":discoverability": normalized.value,
            ":updated_at": ts,
            ":requested_by": requested_by,
        },
    )
    return {
        "user_sub": user_sub,
        DISCOVERABILITY_FIELD: normalized.value,
        "updated_at": ts,
        "requested_by": requested_by,
    }
