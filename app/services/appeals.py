"""Appeals service layer (MOD-003).

Manages the full lifecycle of user appeals against enforcement actions:
filing, withdrawing, admin claiming, decision-making, and queue stats.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Attr, Key

from app.core.cursor import decode_cursor, encode_cursor
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import write_alert
from app.services.moderation_audit_log import write_moderation_audit_event

logger = logging.getLogger(__name__)


def _coerce_int(val: Any, default: int = 0) -> int:
    try:
        return int(str(val))
    except (TypeError, ValueError):
        return default


def _appeal_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a raw DDB item to a public appeal dict."""
    return {
        "appeal_id": item.get("appeal_id", ""),
        "user_id": item.get("user_id", ""),
        "enforcement_id": item.get("enforcement_id", ""),
        "enforcement_type": item.get("enforcement_type", ""),
        "source_ticket_id": item.get("source_ticket_id", ""),
        "appeal_text": item.get("appeal_text", ""),
        "status": item.get("status", ""),
        "created_at": _coerce_int(item.get("created_at")),
        "updated_at": _coerce_int(item.get("updated_at")),
        "decided_at": _coerce_int(item.get("decided_at")) or None,
        "decision_note": item.get("decision_note") or None,
        "modified_enforcement_type": item.get("modified_enforcement_type") or None,
        "modified_duration_days": _coerce_int(item.get("modified_duration_days")) or None,
    }


# ---------------------------------------------------------------------------
# Enforcement helpers
# ---------------------------------------------------------------------------

def _get_enforcement_record(user_id: str, enforcement_id: str) -> Optional[Dict[str, Any]]:
    """Fetch an enforcement record from UserEnforcementHistory table."""
    try:
        resp = T.user_enforcement_history.get_item(
            Key={"user_id": user_id, "enforcement_id": enforcement_id},
        )
        return resp.get("Item")
    except Exception:
        logger.exception("Failed to fetch enforcement record %s for user %s", enforcement_id, user_id)
        return None


def _get_enforcement_for_any_user(enforcement_id: str) -> Optional[Dict[str, Any]]:
    """Try to look up enforcement by scanning — used when user_id isn't known yet."""
    # We can't efficiently scan the table, so we rely on the appeal containing user_id.
    return None


def _list_user_enforcements(user_id: str, limit: int = 10) -> List[Dict[str, Any]]:
    """List recent enforcement records for a user."""
    try:
        resp = T.user_enforcement_history.query(
            KeyConditionExpression=Key("user_id").eq(user_id),
            ScanIndexForward=False,
            Limit=limit,
        )
        return resp.get("Items", [])
    except Exception:
        logger.exception("Failed to list enforcements for user %s", user_id)
        return []


def _reverse_enforcement(user_id: str, enforcement_id: str, enforcement_record: Dict[str, Any]) -> bool:
    """Reverse an enforcement action (lift ban, clear warning)."""
    ts = now_ts()
    enf_type = str(enforcement_record.get("enforcement_type", "")).lower()

    # Update enforcement record status
    try:
        T.user_enforcement_history.update_item(
            Key={"user_id": user_id, "enforcement_id": enforcement_id},
            UpdateExpression="SET #s = :s, updated_at = :ts, reversed_at = :ts, reversal_reason = :reason",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":s": "reversed",
                ":ts": ts,
                ":reason": "appeal_reversed",
            },
        )
    except Exception:
        logger.exception("Failed to update enforcement record %s", enforcement_id)
        return False

    # If it was a ban, lift the ban via account_state
    if enf_type in ("ban", "temporary_ban", "permanent_ban"):
        try:
            T.account_state.update_item(
                Key={"user_sub": user_id},
                UpdateExpression="SET #s = :s, updated_at = :ts, reversal_reason = :reason",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":s": "unbanned_via_appeal",
                    ":ts": ts,
                    ":reason": "appeal_reversed",
                },
                ConditionExpression=Attr("status").eq("banned"),
            )
        except Exception:
            # account_state may not exist or may already be unbanned
            logger.warning("Could not update account_state for %s (may already be unbanned)", user_id)

    return True


def _modify_enforcement(
    user_id: str,
    enforcement_id: str,
    enforcement_record: Dict[str, Any],
    *,
    new_enforcement_type: Optional[str] = None,
    new_duration_days: Optional[int] = None,
) -> bool:
    """Modify an enforcement action (change type or duration)."""
    ts = now_ts()
    old_type = str(enforcement_record.get("enforcement_type", "")).lower()
    update_parts = ["updated_at = :ts", "modified_at = :ts", "#s = :s"]
    attr_names: Dict[str, str] = {"#s": "status"}
    attr_values: Dict[str, Any] = {":ts": ts, ":s": "modified"}

    if new_enforcement_type:
        update_parts.append("enforcement_type = :new_type")
        attr_values[":new_type"] = new_enforcement_type

    if new_duration_days is not None:
        update_parts.append("ban_duration_days = :dur")
        attr_values[":dur"] = new_duration_days
        new_until = ts + new_duration_days * 86400
        update_parts.append("ban_until = :until")
        attr_values[":until"] = new_until

    try:
        T.user_enforcement_history.update_item(
            Key={"user_id": user_id, "enforcement_id": enforcement_id},
            UpdateExpression="SET " + ", ".join(update_parts),
            ExpressionAttributeNames=attr_names,
            ExpressionAttributeValues=attr_values,
        )
    except Exception:
        logger.exception("Failed to modify enforcement record %s", enforcement_id)
        return False

    # If changing from ban to warning, lift the ban
    if new_enforcement_type and old_type in ("ban", "temporary_ban", "permanent_ban") and new_enforcement_type in ("warning", "warn"):
        try:
            T.account_state.update_item(
                Key={"user_sub": user_id},
                UpdateExpression="SET #s = :s, updated_at = :ts, reversal_reason = :reason",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":s": "unbanned_via_appeal",
                    ":ts": ts,
                    ":reason": "appeal_modified_to_warning",
                },
                ConditionExpression=Attr("status").eq("banned"),
            )
        except Exception:
            logger.warning("Could not update account_state for %s during modification", user_id)

    # If changing duration on a ban, update ban_until in account_state
    if new_duration_days is not None and (not new_enforcement_type or new_enforcement_type in ("ban", "temporary_ban")):
        new_until = ts + new_duration_days * 86400
        try:
            T.account_state.update_item(
                Key={"user_sub": user_id},
                UpdateExpression="SET ban_until = :until, ban_duration_days = :dur, updated_at = :ts",
                ExpressionAttributeValues={
                    ":until": new_until,
                    ":dur": new_duration_days,
                    ":ts": ts,
                },
                ConditionExpression=Attr("status").eq("banned"),
            )
        except Exception:
            logger.warning("Could not update ban_until in account_state for %s", user_id)

    return True


# ---------------------------------------------------------------------------
# Core operations
# ---------------------------------------------------------------------------

def file_appeal(user_id: str, enforcement_id: str, appeal_text: str) -> Dict[str, Any]:
    """File a new appeal against an enforcement action.

    Validates:
    1. The enforcement record exists and belongs to the user.
    2. No existing non-withdrawn appeal exists for this enforcement.
    3. No other pending (submitted/under_review) appeal exists for this user.
    """
    # 1. Verify enforcement exists and belongs to user
    enforcement = _get_enforcement_record(user_id, enforcement_id)
    if not enforcement:
        raise ValueError("enforcement_not_found")

    # 2. Check for existing appeal on this enforcement
    try:
        resp = T.appeals.query(
            IndexName="ByEnforcementId",
            KeyConditionExpression=Key("enforcement_id").eq(enforcement_id),
            Limit=10,
        )
        existing = resp.get("Items", [])
        for item in existing:
            if item.get("status") not in ("withdrawn",):
                raise ValueError("appeal_already_exists")
    except ValueError:
        raise
    except Exception:
        logger.exception("Failed to check existing appeals for enforcement %s", enforcement_id)

    # 3. Check for pending appeal by this user
    try:
        resp = T.appeals.query(
            IndexName="ByUserCreatedAt",
            KeyConditionExpression=Key("user_id").eq(user_id),
            ScanIndexForward=False,
            Limit=50,
        )
        for item in resp.get("Items", []):
            if item.get("status") in ("submitted", "under_review"):
                raise ValueError("pending_appeal_exists")
    except ValueError:
        raise
    except Exception:
        logger.exception("Failed to check pending appeals for user %s", user_id)

    ts = now_ts()
    appeal_id = f"appeal_{uuid4().hex}"

    item: Dict[str, Any] = {
        "appeal_id": appeal_id,
        "entity_type": "appeal",
        "user_id": user_id,
        "enforcement_id": enforcement_id,
        "enforcement_type": str(enforcement.get("enforcement_type", "")),
        "source_ticket_id": str(enforcement.get("source_ticket_id", "")),
        "appeal_text": appeal_text,
        "status": "submitted",
        "created_at": ts,
        "updated_at": ts,
    }
    T.appeals.put_item(Item=item)

    write_moderation_audit_event(
        action="appeal_filed",
        actor_user_id=user_id,
        target_user_id=user_id,
        metadata={
            "appeal_id": appeal_id,
            "enforcement_id": enforcement_id,
        },
    )

    write_alert(
        user_id,
        event="appeal_filed",
        outcome="info",
        title="Appeal submitted",
        details={
            "appeal_id": appeal_id,
            "enforcement_id": enforcement_id,
        },
    )

    return {
        "ok": True,
        "appeal_id": appeal_id,
        "status": "submitted",
        "created_at": ts,
    }


def list_user_appeals(
    user_id: str,
    *,
    status: Optional[str] = None,
    limit: int = 25,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List appeals for a specific user."""
    kwargs: Dict[str, Any] = {
        "IndexName": "ByUserCreatedAt",
        "KeyConditionExpression": Key("user_id").eq(user_id),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if status:
        kwargs["FilterExpression"] = Attr("status").eq(status)

    exclusive_start_key = decode_cursor(cursor)
    if exclusive_start_key:
        kwargs["ExclusiveStartKey"] = exclusive_start_key

    resp = T.appeals.query(**kwargs)
    items = [_appeal_out(i) for i in resp.get("Items", [])]
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))

    return {"items": items, "next_cursor": next_cursor}


def get_appeal(appeal_id: str) -> Optional[Dict[str, Any]]:
    """Get a single appeal by ID."""
    resp = T.appeals.get_item(Key={"appeal_id": appeal_id})
    item = resp.get("Item")
    if not item:
        return None
    return _appeal_out(item)


def withdraw_appeal(appeal_id: str, user_id: str) -> Dict[str, Any]:
    """Withdraw an appeal. Only the appeal owner can withdraw, and only if submitted or under_review."""
    resp = T.appeals.get_item(Key={"appeal_id": appeal_id})
    item = resp.get("Item")
    if not item:
        raise ValueError("appeal_not_found")
    if item.get("user_id") != user_id:
        raise ValueError("not_owner")
    if item.get("status") not in ("submitted", "under_review"):
        raise ValueError("invalid_status")

    ts = now_ts()
    T.appeals.update_item(
        Key={"appeal_id": appeal_id},
        UpdateExpression="SET #s = :s, updated_at = :ts",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "withdrawn", ":ts": ts},
    )

    write_moderation_audit_event(
        action="appeal_withdrawn",
        actor_user_id=user_id,
        target_user_id=user_id,
        metadata={"appeal_id": appeal_id},
    )

    return {
        "ok": True,
        "appeal_id": appeal_id,
        "status": "withdrawn",
    }


# ---------------------------------------------------------------------------
# Admin operations
# ---------------------------------------------------------------------------

def list_appeals_admin(
    *,
    status: Optional[str] = None,
    assigned_admin: Optional[str] = None,
    limit: int = 25,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List appeals for admin review queue."""
    kwargs: Dict[str, Any] = {
        "ScanIndexForward": False,
        "Limit": limit,
    }

    exclusive_start_key = decode_cursor(cursor)
    if exclusive_start_key:
        kwargs["ExclusiveStartKey"] = exclusive_start_key

    if assigned_admin:
        kwargs["IndexName"] = "ByAssignedAdminCreatedAt"
        kwargs["KeyConditionExpression"] = Key("assigned_admin_user_id").eq(assigned_admin)
        if status:
            kwargs["FilterExpression"] = Attr("status").eq(status)
    elif status:
        kwargs["IndexName"] = "ByStatusCreatedAt"
        kwargs["KeyConditionExpression"] = Key("status").eq(status)
    else:
        # Default: show submitted appeals
        kwargs["IndexName"] = "ByStatusCreatedAt"
        kwargs["KeyConditionExpression"] = Key("status").eq("submitted")

    resp = T.appeals.query(**kwargs)
    items = [_appeal_out(i) for i in resp.get("Items", [])]
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))

    return {"items": items, "next_cursor": next_cursor}


def claim_appeal(appeal_id: str, admin_user_id: str) -> Dict[str, Any]:
    """Claim an appeal for review. Atomic update: only succeeds if status is 'submitted'."""
    ts = now_ts()
    try:
        T.appeals.update_item(
            Key={"appeal_id": appeal_id},
            UpdateExpression="SET #s = :s, assigned_admin_user_id = :admin, updated_at = :ts",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":s": "under_review",
                ":admin": admin_user_id,
                ":ts": ts,
            },
            ConditionExpression=Attr("status").eq("submitted"),
            ReturnValues="ALL_NEW",
        )
    except T.appeals.meta.client.exceptions.ConditionalCheckFailedException:
        raise ValueError("claim_failed")
    except Exception:
        # boto3 may raise ClientError with ConditionalCheckFailedException code
        import botocore.exceptions
        raise

    write_moderation_audit_event(
        action="appeal_claimed",
        actor_user_id=admin_user_id,
        metadata={"appeal_id": appeal_id},
    )

    return {
        "ok": True,
        "appeal_id": appeal_id,
        "assigned_admin_user_id": admin_user_id,
    }


def decide_appeal(
    appeal_id: str,
    decision: str,
    decision_note: str,
    admin_user_id: str,
    *,
    modified_enforcement_type: Optional[str] = None,
    modified_duration_days: Optional[int] = None,
) -> Dict[str, Any]:
    """Record a decision on an appeal."""
    resp = T.appeals.get_item(Key={"appeal_id": appeal_id})
    item = resp.get("Item")
    if not item:
        raise ValueError("appeal_not_found")
    if item.get("status") != "under_review":
        raise ValueError("invalid_status")

    ts = now_ts()
    user_id = item.get("user_id", "")
    enforcement_id = item.get("enforcement_id", "")

    enforcement_reversed = False
    enforcement_modified = False

    # Apply decision to enforcement
    if decision in ("reversed", "modified"):
        enforcement = _get_enforcement_record(user_id, enforcement_id)
        if enforcement:
            if decision == "reversed":
                enforcement_reversed = _reverse_enforcement(user_id, enforcement_id, enforcement)
            elif decision == "modified":
                enforcement_modified = _modify_enforcement(
                    user_id,
                    enforcement_id,
                    enforcement,
                    new_enforcement_type=modified_enforcement_type,
                    new_duration_days=modified_duration_days,
                )

    # Determine final status
    final_status = f"decided_{decision}"  # decided_upheld, decided_modified, decided_reversed

    update_expr = "SET #s = :s, decided_at = :ts, decision_note = :note, updated_at = :ts, decision = :dec"
    attr_names: Dict[str, str] = {"#s": "status"}
    attr_values: Dict[str, Any] = {
        ":s": final_status,
        ":ts": ts,
        ":note": decision_note,
        ":dec": decision,
    }

    if modified_enforcement_type:
        update_expr += ", modified_enforcement_type = :met"
        attr_values[":met"] = modified_enforcement_type
    if modified_duration_days is not None:
        update_expr += ", modified_duration_days = :mdd"
        attr_values[":mdd"] = modified_duration_days

    T.appeals.update_item(
        Key={"appeal_id": appeal_id},
        UpdateExpression=update_expr,
        ExpressionAttributeNames=attr_names,
        ExpressionAttributeValues=attr_values,
    )

    write_moderation_audit_event(
        action=f"appeal_decided_{decision}",
        actor_user_id=admin_user_id,
        target_user_id=user_id,
        metadata={
            "appeal_id": appeal_id,
            "enforcement_id": enforcement_id,
            "decision": decision,
            "enforcement_reversed": enforcement_reversed,
            "enforcement_modified": enforcement_modified,
        },
    )

    # Notify the user
    write_alert(
        user_id,
        event="appeal_decided",
        outcome="info",
        title="Appeal decision rendered",
        details={
            "appeal_id": appeal_id,
            "decision": decision,
            "enforcement_reversed": enforcement_reversed,
            "enforcement_modified": enforcement_modified,
        },
    )

    return {
        "ok": True,
        "appeal_id": appeal_id,
        "status": final_status,
        "decision": decision,
        "decided_at": ts,
        "enforcement_reversed": enforcement_reversed,
        "enforcement_modified": enforcement_modified,
    }


def get_appeal_detail(appeal_id: str) -> Optional[Dict[str, Any]]:
    """Assemble full appeal detail including enforcement record, ticket, and history."""
    resp = T.appeals.get_item(Key={"appeal_id": appeal_id})
    item = resp.get("Item")
    if not item:
        return None

    appeal = _appeal_out(item)
    user_id = item.get("user_id", "")
    enforcement_id = item.get("enforcement_id", "")
    source_ticket_id = item.get("source_ticket_id", "")

    # Fetch enforcement record
    enforcement_record: Dict[str, Any] = {}
    if user_id and enforcement_id:
        enf = _get_enforcement_record(user_id, enforcement_id)
        if enf:
            enforcement_record = {
                k: (int(str(v)) if isinstance(v, (int, float)) and k.endswith("_at") else v)
                for k, v in enf.items()
                if k != "entity_type"
            }

    # Fetch moderation ticket if available
    moderation_ticket: Dict[str, Any] = {}
    if source_ticket_id:
        try:
            ticket_resp = T.moderation_tickets.get_item(Key={"ticket_id": source_ticket_id})
            ticket_item = ticket_resp.get("Item")
            if ticket_item:
                moderation_ticket = {
                    k: v for k, v in ticket_item.items() if k != "entity_type"
                }
        except Exception:
            logger.warning("Failed to fetch moderation ticket %s", source_ticket_id)

    # Fetch user enforcement history
    user_enforcement_history = _list_user_enforcements(user_id)
    enforcement_history_out = []
    for enf in user_enforcement_history:
        enforcement_history_out.append({
            k: v for k, v in enf.items() if k != "entity_type"
        })

    # Fetch user appeal history
    user_appeals_result = list_user_appeals(user_id, limit=10)
    user_appeal_history = user_appeals_result.get("items", [])

    return {
        "appeal": appeal,
        "enforcement_record": enforcement_record,
        "moderation_ticket": moderation_ticket,
        "user_enforcement_history": enforcement_history_out,
        "user_appeal_history": user_appeal_history,
    }


def get_appeal_queue_stats() -> Dict[str, Any]:
    """Compute queue statistics for the appeals dashboard."""
    ts = now_ts()

    total_submitted = 0
    oldest_submitted_ts: Optional[int] = None
    total_under_review = 0

    # Count submitted
    try:
        submitted_kwargs: Dict[str, Any] = {
            "IndexName": "ByStatusCreatedAt",
            "KeyConditionExpression": Key("status").eq("submitted"),
            "Select": "COUNT",
        }
        last_key = None
        while True:
            if last_key:
                submitted_kwargs["ExclusiveStartKey"] = last_key
            resp = T.appeals.query(**submitted_kwargs)
            total_submitted += resp.get("Count", 0)
            # Track oldest by querying with ascending order
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
    except Exception:
        logger.exception("Failed to count submitted appeals")

    # Get oldest submitted
    try:
        oldest_resp = T.appeals.query(
            IndexName="ByStatusCreatedAt",
            KeyConditionExpression=Key("status").eq("submitted"),
            ScanIndexForward=True,
            Limit=1,
        )
        oldest_items = oldest_resp.get("Items", [])
        if oldest_items:
            oldest_submitted_ts = _coerce_int(oldest_items[0].get("created_at"))
    except Exception:
        logger.exception("Failed to get oldest submitted appeal")

    # Count under_review
    try:
        review_kwargs: Dict[str, Any] = {
            "IndexName": "ByStatusCreatedAt",
            "KeyConditionExpression": Key("status").eq("under_review"),
            "Select": "COUNT",
        }
        last_key = None
        while True:
            if last_key:
                review_kwargs["ExclusiveStartKey"] = last_key
            resp = T.appeals.query(**review_kwargs)
            total_under_review += resp.get("Count", 0)
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
    except Exception:
        logger.exception("Failed to count under_review appeals")

    oldest_age_minutes = 0
    if oldest_submitted_ts and oldest_submitted_ts > 0:
        oldest_age_minutes = max(0, (ts - oldest_submitted_ts) // 60)

    return {
        "total_submitted": total_submitted,
        "total_under_review": total_under_review,
        "oldest_submitted_age_minutes": oldest_age_minutes,
    }
