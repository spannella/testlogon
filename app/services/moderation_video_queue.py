"""MOD-001: Video Review Queue service layer.

Queues uploaded / flagged videos for human moderator review and implements
the review workflow (claim / approve / reject / escalate) with priority and
status. Backed by the dedicated ``moderation_video_queue`` DynamoDB table and
queried via the ``ByStatusCreatedAt`` / ``ByStatusPriority`` GSIs.

This is a parallel workflow to the existing content-moderation ticket system
(``app/services/moderation_tickets_store.py``) -- it does NOT reuse that table.
Moderation actions are written to the shared moderation audit log when natural.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import write_alert
from app.services.moderation_audit_log import write_moderation_audit_event

logger = logging.getLogger(__name__)

# --- Enumerations ----------------------------------------------------------

# Queue lifecycle statuses.
STATUS_PENDING = "pending"
STATUS_IN_REVIEW = "in_review"
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"
STATUS_ESCALATED = "escalated"

_TERMINAL_STATUSES = {STATUS_APPROVED, STATUS_REJECTED}
_OPEN_STATUSES = {STATUS_PENDING, STATUS_IN_REVIEW, STATUS_ESCALATED}
_VALID_STATUSES = _OPEN_STATUSES | _TERMINAL_STATUSES

# Priority ordering. Lower rank == higher urgency, so a ScanIndexForward=True
# query on the numeric ``priority_rank`` sort key surfaces urgent items first.
PRIORITY_RANKS = {
    "urgent": 0,
    "high": 1,
    "normal": 2,
    "low": 3,
}
_DEFAULT_PRIORITY = "normal"


def _priority_rank(priority: str) -> int:
    return PRIORITY_RANKS.get(priority, PRIORITY_RANKS[_DEFAULT_PRIORITY])


def _normalize_priority(priority: Optional[str]) -> str:
    p = (priority or "").strip().lower()
    return p if p in PRIORITY_RANKS else _DEFAULT_PRIORITY


def _conflict(*, entry_id: str, from_status: str, action: str) -> HTTPException:
    return HTTPException(
        status_code=409,
        detail={
            "code": "VIDEO_QUEUE_INVALID_STATE_TRANSITION",
            "entry_id": entry_id,
            "from_status": from_status,
            "action": action,
        },
    )


# --- Enqueue ---------------------------------------------------------------


def enqueue_video(
    *,
    video_id: str,
    owner_user_id: str,
    title: str = "",
    description: str = "",
    priority: str = _DEFAULT_PRIORITY,
    source: str = "manual",
    thumbnail_url: Optional[str] = None,
    hls_manifest_url: Optional[str] = None,
    duration_seconds: Optional[float] = None,
    flag_reason: Optional[str] = None,
    enqueued_by: str = "",
) -> dict[str, Any]:
    """Create a new review-queue entry for a video.

    ``source`` is one of ``manual`` (a moderator/admin added it), ``flagged``
    (a user/automated flag routed it here), or ``upload`` (auto-enqueued on
    upload). Idempotent on the open queue: if an OPEN entry already exists for
    the same ``video_id`` it is returned unchanged rather than duplicated.
    """
    existing = get_open_entry_for_video(video_id)
    if existing is not None:
        return existing

    ts = now_ts()
    priority = _normalize_priority(priority)
    entry_id = f"vq_{uuid.uuid4().hex[:24]}"
    item: dict[str, Any] = {
        "entry_id": entry_id,
        "video_id": video_id,
        "owner_user_id": owner_user_id,
        "title": title or "",
        "description": description or "",
        "status": STATUS_PENDING,
        "priority": priority,
        "priority_rank": _priority_rank(priority),
        "source": source,
        "created_at": ts,
        "updated_at": ts,
        "claimed_by": "",
        "claimed_at": 0,
        "reviewed_by": "",
        "reviewed_at": 0,
        "review_notes": "",
        "decision": "",
        "escalated": False,
    }
    if thumbnail_url:
        item["thumbnail_url"] = thumbnail_url
    if hls_manifest_url:
        item["hls_manifest_url"] = hls_manifest_url
    if duration_seconds is not None:
        item["duration_seconds"] = str(duration_seconds)
    if flag_reason:
        item["flag_reason"] = flag_reason

    T.moderation_video_queue.put_item(Item=item)

    write_moderation_audit_event(
        action="video_queue_enqueued",
        actor_user_id=enqueued_by or "system",
        content_type="video",
        content_id=video_id,
        target_user_id=owner_user_id,
        metadata={
            "entry_id": entry_id,
            "source": source,
            "priority": priority,
            "flag_reason": flag_reason or "",
        },
    )
    return item


def get_open_entry_for_video(video_id: str) -> Optional[dict[str, Any]]:
    """Return the most recent OPEN (non-terminal) queue entry for a video."""
    resp = T.moderation_video_queue.query(
        IndexName="ByVideo",
        KeyConditionExpression=Key("video_id").eq(video_id),
    )
    open_items = [
        it for it in resp.get("Items", []) if it.get("status") in _OPEN_STATUSES
    ]
    open_items.sort(key=lambda it: int(it.get("created_at", 0)), reverse=True)
    return open_items[0] if open_items else None


def get_entry(entry_id: str) -> Optional[dict[str, Any]]:
    return T.moderation_video_queue.get_item(Key={"entry_id": entry_id}).get("Item")


# --- Listing ---------------------------------------------------------------


def list_queue(
    *,
    status: str = STATUS_PENDING,
    order_by: str = "priority",
    limit: int = 25,
    cursor: dict | None = None,
    owner_filter: str | None = None,
) -> dict[str, Any]:
    """List queue entries filtered by ``status``.

    ``order_by`` selects the GSI: ``priority`` uses ``ByStatusPriority``
    (most-urgent first) and ``created_at`` uses ``ByStatusCreatedAt``
    (oldest-waiting first). Paginates up to 10 DDB pages, applying an optional
    ``owner_filter`` via FilterExpression (which does not reduce page size, so
    we over-fetch with ``Limit = limit * 3``).
    """
    if status not in _VALID_STATUSES:
        raise HTTPException(status_code=422, detail="invalid status filter")
    limit = max(1, min(int(limit), 100))

    index_name = "ByStatusPriority" if order_by == "priority" else "ByStatusCreatedAt"
    collected: list[dict[str, Any]] = []
    current_cursor = cursor
    max_pages = 10

    for _ in range(max_pages):
        kwargs: dict[str, Any] = {
            "IndexName": index_name,
            "KeyConditionExpression": Key("status").eq(status),
            "Limit": limit * 3,
            "ScanIndexForward": True,  # urgent / oldest first
        }
        if current_cursor:
            kwargs["ExclusiveStartKey"] = current_cursor
        if owner_filter:
            kwargs["FilterExpression"] = Attr("owner_user_id").eq(owner_filter)

        resp = T.moderation_video_queue.query(**kwargs)
        for it in resp.get("Items", []):
            collected.append(it)
            if len(collected) >= limit:
                break

        current_cursor = resp.get("LastEvaluatedKey")
        if len(collected) >= limit or not current_cursor:
            break

    return {
        "items": collected[:limit],
        "cursor": current_cursor,
        "total": count_by_status(status),
    }


def count_by_status(status: str) -> int:
    """Count queue entries in a given status (for queue-depth badges)."""
    total = 0
    last_key: Optional[dict] = None
    for _ in range(10):
        kwargs: dict[str, Any] = {
            "IndexName": "ByStatusCreatedAt",
            "KeyConditionExpression": Key("status").eq(status),
            "Select": "COUNT",
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.moderation_video_queue.query(**kwargs)
        total += resp.get("Count", 0)
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return total


def queue_stats() -> dict[str, int]:
    """Return counts across all statuses for the dashboard summary."""
    return {s: count_by_status(s) for s in sorted(_VALID_STATUSES)}


# --- Review actions --------------------------------------------------------


def _put(entry: dict[str, Any]) -> None:
    entry["updated_at"] = now_ts()
    T.moderation_video_queue.put_item(Item=entry)


def claim_entry(*, entry_id: str, moderator_user_id: str) -> dict[str, Any]:
    """Claim a pending entry for review (pending -> in_review).

    Idempotent for the claiming moderator; raises 409 if another moderator
    already holds the claim or the entry is terminal.
    """
    entry = get_entry(entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="queue entry not found")
    status = entry.get("status")
    if status == STATUS_IN_REVIEW and entry.get("claimed_by") == moderator_user_id:
        return entry
    if status != STATUS_PENDING:
        raise _conflict(entry_id=entry_id, from_status=status, action="claim")

    ts = now_ts()
    entry["status"] = STATUS_IN_REVIEW
    entry["claimed_by"] = moderator_user_id
    entry["claimed_at"] = ts
    _put(entry)

    write_moderation_audit_event(
        action="video_queue_claimed",
        actor_user_id=moderator_user_id,
        content_type="video",
        content_id=entry.get("video_id", ""),
        target_user_id=entry.get("owner_user_id", ""),
        metadata={"entry_id": entry_id},
    )
    return entry


def release_entry(*, entry_id: str, moderator_user_id: str) -> dict[str, Any]:
    """Release a claimed entry back to pending (in_review -> pending)."""
    entry = get_entry(entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="queue entry not found")
    if entry.get("status") != STATUS_IN_REVIEW:
        raise _conflict(
            entry_id=entry_id, from_status=entry.get("status"), action="release"
        )
    entry["status"] = STATUS_PENDING
    entry["claimed_by"] = ""
    entry["claimed_at"] = 0
    _put(entry)
    return entry


def _decide(
    *,
    entry_id: str,
    moderator_user_id: str,
    decision: str,
    new_status: str,
    review_notes: str,
    audit_action: str,
    notify_creator: bool,
    alert_event: str,
    alert_outcome: str,
    alert_title: str,
) -> dict[str, Any]:
    entry = get_entry(entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="queue entry not found")
    if entry.get("status") not in _OPEN_STATUSES:
        raise _conflict(
            entry_id=entry_id, from_status=entry.get("status"), action=decision
        )

    ts = now_ts()
    entry["status"] = new_status
    entry["decision"] = decision
    entry["reviewed_by"] = moderator_user_id
    entry["reviewed_at"] = ts
    entry["review_notes"] = review_notes or ""
    if new_status == STATUS_ESCALATED:
        entry["escalated"] = True
    _put(entry)

    audit_id = write_moderation_audit_event(
        action=audit_action,
        actor_user_id=moderator_user_id,
        content_type="video",
        content_id=entry.get("video_id", ""),
        target_user_id=entry.get("owner_user_id", ""),
        metadata={
            "entry_id": entry_id,
            "decision": decision,
            "review_notes": review_notes or "",
            "new_status": new_status,
        },
    )

    if notify_creator and entry.get("owner_user_id"):
        write_alert(
            entry["owner_user_id"],
            event=alert_event,
            outcome=alert_outcome,
            title=alert_title,
            details={
                "video_id": entry.get("video_id", ""),
                "title": entry.get("title", ""),
                "review_notes": review_notes or "",
            },
        )

    return {"entry": entry, "audit_id": audit_id}


def approve_entry(
    *,
    entry_id: str,
    moderator_user_id: str,
    review_notes: str = "",
    notify_creator: bool = True,
) -> dict[str, Any]:
    """Approve a queued video (open -> approved)."""
    return _decide(
        entry_id=entry_id,
        moderator_user_id=moderator_user_id,
        decision="approve",
        new_status=STATUS_APPROVED,
        review_notes=review_notes,
        audit_action="video_queue_approved",
        notify_creator=notify_creator,
        alert_event="video_review_approved",
        alert_outcome="success",
        alert_title="Video approved",
    )


def reject_entry(
    *,
    entry_id: str,
    moderator_user_id: str,
    rejection_reason: str,
    notify_creator: bool = True,
) -> dict[str, Any]:
    """Reject a queued video (open -> rejected). Reason is required."""
    return _decide(
        entry_id=entry_id,
        moderator_user_id=moderator_user_id,
        decision="reject",
        new_status=STATUS_REJECTED,
        review_notes=rejection_reason,
        audit_action="video_queue_rejected",
        notify_creator=notify_creator,
        alert_event="video_review_rejected",
        alert_outcome="warning",
        alert_title="Video not approved",
    )


def escalate_entry(
    *,
    entry_id: str,
    moderator_user_id: str,
    escalation_reason: str,
    notify_creator: bool = False,
) -> dict[str, Any]:
    """Escalate a queued video to a senior moderator (open -> escalated)."""
    return _decide(
        entry_id=entry_id,
        moderator_user_id=moderator_user_id,
        decision="escalate",
        new_status=STATUS_ESCALATED,
        review_notes=escalation_reason,
        audit_action="video_queue_escalated",
        notify_creator=notify_creator,
        alert_event="video_review_escalated",
        alert_outcome="info",
        alert_title="Video escalated for review",
    )


# --- Owner review history --------------------------------------------------


def get_owner_review_history(owner_user_id: str) -> dict[str, Any]:
    """Aggregate prior approve/reject decisions for an owner from the audit log."""
    events: list[dict] = []
    approvals = 0
    rejections = 0
    for action_type in ("video_queue_approved", "video_queue_rejected"):
        resp = T.moderation_audit_log.query(
            IndexName="ByActionCreatedAt",
            KeyConditionExpression=Key("action").eq(action_type),
            FilterExpression=Attr("target_user_id").eq(owner_user_id),
            Limit=50,
            ScanIndexForward=False,
        )
        for item in resp.get("Items", []):
            events.append(item)
            if action_type == "video_queue_approved":
                approvals += 1
            else:
                rejections += 1
    events.sort(key=lambda e: int(str(e.get("created_at", "0"))), reverse=True)
    return {
        "events": events[:20],
        "approvals_count": approvals,
        "rejections_count": rejections,
    }
