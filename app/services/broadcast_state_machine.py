from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Set

from app.models_broadcast import BroadcastSessionStatus, BroadcastSessionTransitionAuditModel

INVALID_TRANSITION_ERROR_CODE = "BROADCAST_INVALID_STATE_TRANSITION"

_ALLOWED_TRANSITIONS: Dict[BroadcastSessionStatus, Set[BroadcastSessionStatus]] = {
    "draft": {"provisioning", "scheduled", "error"},
    "scheduled": {"provisioning", "cancelled", "error"},
    "provisioning": {"ready", "error"},
    "ready": {"live", "stopping", "error"},
    "live": {"stopping", "private", "error"},
    "private": {"live", "stopping", "error"},
    "stopping": {"stopped", "error"},
    "stopped": set(),
    "cancelled": set(),
    "error": {"provisioning", "stopped"},
}


@dataclass(frozen=True)
class TransitionValidationResult:
    legal: bool
    error_code: str | None = None


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_transition(from_status: BroadcastSessionStatus, to_status: BroadcastSessionStatus) -> TransitionValidationResult:
    if to_status in _ALLOWED_TRANSITIONS.get(from_status, set()):
        return TransitionValidationResult(legal=True)
    return TransitionValidationResult(legal=False, error_code=INVALID_TRANSITION_ERROR_CODE)


def build_transition_audit(
    *,
    transition_id: str,
    session_id: str,
    from_status: BroadcastSessionStatus,
    to_status: BroadcastSessionStatus,
    reason: str,
    actor: str,
    created_at: str | None = None,
) -> BroadcastSessionTransitionAuditModel:
    ts = created_at or now_iso()
    return BroadcastSessionTransitionAuditModel(
        transition_id=transition_id,
        session_id=session_id,
        from_status=from_status,
        to_status=to_status,
        reason=reason,
        actor=actor,
        created_at=ts,
        error_code=INVALID_TRANSITION_ERROR_CODE,
    )
