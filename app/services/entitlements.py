from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, FrozenSet, Literal, Optional

EntitlementStatus = Literal["pending_payment", "active", "expired", "revoked", "consumed"]

ALLOWED_TRANSITIONS: Dict[EntitlementStatus, FrozenSet[EntitlementStatus]] = {
    "pending_payment": frozenset({"active", "revoked"}),
    "active": frozenset({"expired", "revoked", "consumed"}),
    "expired": frozenset(),
    "revoked": frozenset(),
    "consumed": frozenset(),
}


@dataclass(frozen=True)
class EntitlementState:
    status: EntitlementStatus
    starts_at: datetime
    ends_at: Optional[datetime] = None


def _to_utc(value: datetime) -> datetime:
    dt = value
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def can_transition(from_status: EntitlementStatus, to_status: EntitlementStatus) -> bool:
    return to_status in ALLOWED_TRANSITIONS[from_status]


def assert_transition_allowed(from_status: EntitlementStatus, to_status: EntitlementStatus) -> None:
    if not can_transition(from_status, to_status):
        raise ValueError(f"forbidden entitlement transition: {from_status} -> {to_status}")


def resolve_effective_status(state: EntitlementState, *, now: Optional[datetime] = None) -> EntitlementStatus:
    now_utc = _to_utc(now or datetime.now(timezone.utc))
    starts_at_utc = _to_utc(state.starts_at)
    ends_at_utc = _to_utc(state.ends_at) if state.ends_at else None

    if state.status == "active":
        if starts_at_utc > now_utc:
            return "pending_payment"
        if ends_at_utc and now_utc >= ends_at_utc:
            return "expired"
    return state.status


def transition_state(state: EntitlementState, *, to_status: EntitlementStatus, now: Optional[datetime] = None) -> EntitlementState:
    current = resolve_effective_status(state, now=now)
    assert_transition_allowed(current, to_status)
    return EntitlementState(status=to_status, starts_at=_to_utc(state.starts_at), ends_at=_to_utc(state.ends_at) if state.ends_at else None)
