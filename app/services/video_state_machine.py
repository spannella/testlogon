from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Set

from app.models_video import VideoStatus

INVALID_TRANSITION_ERROR_CODE = "VIDEO_INVALID_STATE_TRANSITION"

_ALLOWED_TRANSITIONS: Dict[VideoStatus, Set[VideoStatus]] = {
    "created": {"probing", "deleted"},
    "probing": {"pending_encoding", "probe_failed", "deleted"},
    "probe_failed": {"probing", "deleted"},
    "pending_encoding": {"encoding", "deleted"},
    "encoding": {"pending_review", "encoding_failed", "deleted"},
    "encoding_failed": {"pending_encoding", "deleted"},
    "pending_review": {"approved", "rejected", "deleted"},
    "approved": {"published", "archived", "deleted"},
    "rejected": {"pending_review", "deleted"},
    "published": {"archived", "approved", "deleted"},
    "archived": {"published", "deleted"},
    "deleted": set(),
}


@dataclass(frozen=True)
class TransitionValidationResult:
    legal: bool
    error_code: str | None = None


def validate_transition(
    from_status: VideoStatus, to_status: VideoStatus
) -> TransitionValidationResult:
    if to_status in _ALLOWED_TRANSITIONS.get(from_status, set()):
        return TransitionValidationResult(legal=True)
    return TransitionValidationResult(
        legal=False, error_code=INVALID_TRANSITION_ERROR_CODE
    )
