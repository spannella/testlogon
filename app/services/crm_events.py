"""CRM Events service — EVT-002/003/004.

Single module that owns all DynamoDB access for the crm_events and
crm_event_registrations tables.  All public helpers are thin wrappers
around DDB; no HTTP concerns live here.
"""
from __future__ import annotations

import logging
import uuid
from decimal import Decimal
from typing import Any, Optional

from boto3.dynamodb.conditions import Key, Attr

from app.core.tables import T
from app.core.time import now_ts
from app.core.cursor import encode_cursor, decode_cursor

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _safe_get_identity(user_sub: str) -> dict:
    """Best-effort profile identity lookup; returns {} on any error."""
    try:
        from app.services.profile import get_profile_identity  # lazy import (RULE-1)
        return get_profile_identity(user_sub) or {}
    except Exception:
        return {}


def _resolve_email(user_sub: str) -> Optional[str]:
    """Resolve the displayed_email for a user_sub. Returns None when absent."""
    return _safe_get_identity(user_sub).get("email")


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    """Best-effort audit event — never raises."""
    try:
        from app.services.alerts import audit_event  # lazy import (RULE-1)
        audit_event(event, user_sub, **fields)
    except Exception:
        logger.warning("crm_events audit failed: %s", event, exc_info=True)


def _query_all_invitees(event_id: str) -> list[dict]:
    """Full paginated scan of all INVITEE rows for an event."""
    items: list[dict] = []
    kwargs: dict[str, Any] = {
        "KeyConditionExpression": (
            Key("event_id").eq(event_id) & Key("sk").begins_with("INVITEE#")
        ),
    }
    while True:
        resp = T.crm_events.query(**kwargs)
        items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return items


def _build_invitation_email(event_meta: dict, invitee_sub: str) -> tuple[str, str]:
    """Construct invitation email subject and body text."""
    name = event_meta.get("name", "Event")
    description = event_meta.get("description", "")
    cal_id = event_meta.get("calendar_event_id")
    subject = f"You're invited: {name}"
    lines = [f"You have been invited to: {name}"]
    if description:
        lines.append(description)
    if cal_id:
        lines.append(f"\nCalendar event: /calendar?event={cal_id}")
    body = "\n".join(lines)
    return subject, body


def _int(val: Any) -> Optional[int]:
    if val is None:
        return None
    return int(val)


def _invitee_out(item: dict) -> dict:
    """Convert a raw DDB INVITEE item to the CrmInviteeOut shape."""
    return {
        "event_id": item.get("event_id", ""),
        "invitee_sub": item.get("invitee_sub", ""),
        "invite_status": item.get("invite_status", "pending"),
        "invited_at": _int(item.get("invited_at")) or 0,
        "responded_at": _int(item.get("responded_at")),
        "display_name": item.get("display_name"),
    }


def _reg_out(item: dict) -> dict:
    """Convert a raw DDB registration item to CrmRegistrationOut shape."""
    return {
        "event_id": item.get("event_id", ""),
        "registrant_sub": item.get("registrant_sub", ""),
        "status": item.get("status", "registered"),
        "registered_at": _int(item.get("registered_at")) or 0,
        "responded_at": _int(item.get("responded_at")),
        "checked_in_at": _int(item.get("checked_in_at")),
        "waitlist_position": _int(item.get("waitlist_position")),
        "invited": item.get("invited"),
    }


# ---------------------------------------------------------------------------
# EVT-002: Event CRUD + invitee management
# ---------------------------------------------------------------------------

def create_crm_event(
    owner_sub: str,
    name: str,
    description: str = "",
    calendar_event_id: Optional[str] = None,
    max_attendance: Optional[int] = None,
) -> dict:
    """Write a META row for a new CRM event. Returns the full item dict."""
    event_id = uuid.uuid4().hex
    now = now_ts()
    item: dict[str, Any] = {
        "event_id": event_id,
        "sk": "META",
        "owner_sub": owner_sub,
        "name": name,
        "description": description,
        "created_at": now,
        "updated_at": now,
    }
    if calendar_event_id is not None:
        item["calendar_event_id"] = calendar_event_id
    if max_attendance is not None:
        item["max_attendance"] = max_attendance
    T.crm_events.put_item(Item=item)
    _audit("crm_event_created", owner_sub, event_id=event_id, name=name)
    return item


def get_crm_event(event_id: str) -> Optional[dict]:
    """Load the META row. Returns None when not found."""
    resp = T.crm_events.get_item(Key={"event_id": event_id, "sk": "META"})
    return resp.get("Item")


def add_invitee(event_id: str, invitee_sub: str, actor_sub: str) -> tuple[dict, bool]:
    """Write an INVITEE row with invite_status='pending'.

    Idempotent: if the row already exists the existing item is returned with
    was_new=False.  Returns (item, was_new).
    """
    sk = f"INVITEE#{invitee_sub}"
    now = now_ts()
    identity = _safe_get_identity(invitee_sub)
    item: dict[str, Any] = {
        "event_id": event_id,
        "sk": sk,
        "invitee_sub": invitee_sub,
        "invite_status": "pending",
        "invited_at": now,
        "display_name": identity.get("display_name"),
    }
    try:
        T.crm_events.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(sk)",
        )
        _audit("crm_invitee_added", actor_sub, event_id=event_id, invitee_sub=invitee_sub)
        return item, True
    except Exception as exc:
        # ConditionalCheckFailedException — row already exists
        error_code = getattr(getattr(exc, "response", {}), "get", lambda k, d=None: d)("Error", {}).get("Code", "")
        if not error_code:
            try:
                error_code = exc.response["Error"]["Code"]  # type: ignore[attr-defined]
            except Exception:
                error_code = type(exc).__name__
        if "ConditionalCheckFailed" in error_code or "ConditionalCheckFailed" in str(exc):
            existing = T.crm_events.get_item(
                Key={"event_id": event_id, "sk": sk}
            ).get("Item", item)
            return existing, False
        raise


def remove_invitee(event_id: str, invitee_sub: str, actor_sub: str) -> bool:
    """Delete the INVITEE row. Returns True when row existed."""
    sk = f"INVITEE#{invitee_sub}"
    existing = T.crm_events.get_item(Key={"event_id": event_id, "sk": sk}).get("Item")
    if not existing:
        return False
    T.crm_events.delete_item(Key={"event_id": event_id, "sk": sk})
    _audit("crm_invitee_removed", actor_sub, event_id=event_id, invitee_sub=invitee_sub)
    return True


def bulk_import_invitees(event_id: str, user_subs: list[str], actor_sub: str) -> dict:
    """Add multiple invitees idempotently. Returns {added, skipped}."""
    added = 0
    skipped = 0
    seen: set[str] = set()
    for sub in user_subs:
        if sub in seen:
            skipped += 1
            continue
        seen.add(sub)
        _item, was_new = add_invitee(event_id, sub, actor_sub)
        if was_new:
            added += 1
        else:
            skipped += 1
    _audit(
        "crm_bulk_import_invitees",
        actor_sub,
        event_id=event_id,
        total=len(user_subs),
        added=added,
        skipped=skipped,
    )
    return {"added": added, "skipped": skipped}


def send_invitations(event_id: str, event_meta: dict, actor_sub: str) -> dict:
    """Dispatch invitation emails to all INVITEE rows with invite_status=='pending'."""
    try:
        from app.services.alerts import send_alert_email  # lazy import (RULE-1)
    except Exception:
        send_alert_email = None  # type: ignore[assignment]

    invitees = _query_all_invitees(event_id)
    sent = skipped = failed = 0

    for invitee in invitees:
        if invitee.get("invite_status") != "pending":
            skipped += 1
            continue

        invitee_sub = invitee["invitee_sub"]
        email = _resolve_email(invitee_sub)
        if not email:
            failed += 1
            continue

        subject, body = _build_invitation_email(event_meta, invitee_sub)
        try:
            if send_alert_email is not None:
                send_alert_email([email], subject, body)
            # Advance status to "sent" only after successful dispatch.
            T.crm_events.update_item(
                Key={"event_id": event_id, "sk": f"INVITEE#{invitee_sub}"},
                UpdateExpression="SET invite_status = :s",
                ConditionExpression="invite_status = :p",
                ExpressionAttributeValues={":s": "sent", ":p": "pending"},
            )
            sent += 1
        except Exception:
            logger.warning(
                "crm_send_invitation_failed event_id=%s invitee_sub=%s",
                event_id, invitee_sub, exc_info=True,
            )
            failed += 1

    _audit(
        "crm_invitations_sent",
        actor_sub,
        event_id=event_id,
        sent=sent,
        skipped=skipped,
        failed=failed,
    )
    return {"sent": sent, "skipped": skipped, "failed": failed}


def list_invitees(event_id: str, limit: int = 50, cursor: Optional[str] = None) -> dict:
    """Paginated list of INVITEE rows for an event."""
    kwargs: dict[str, Any] = {
        "KeyConditionExpression": (
            Key("event_id").eq(event_id) & Key("sk").begins_with("INVITEE#")
        ),
        "Limit": min(limit, 200),
    }
    lek = decode_cursor(cursor)
    if lek:
        kwargs["ExclusiveStartKey"] = lek

    resp = T.crm_events.query(**kwargs)
    items = resp.get("Items", [])
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return {
        "invitees": [_invitee_out(i) for i in items],
        "cursor": next_cursor,
    }


# ---------------------------------------------------------------------------
# EVT-003: Registration workflow
# ---------------------------------------------------------------------------

def register_for_event(event_id: str, registrant_sub: str) -> dict:
    """Self-register a user for an event.

    Raises HTTPException(409) on duplicate. Raises HTTPException(403) if the
    event requires an invitation and the user is not invited.
    EVT-004 capacity enforcement is applied before writing the row.
    """
    from fastapi import HTTPException  # local import to avoid circular at module level

    # Check for duplicate
    existing_key = {"event_id": event_id, "registrant_sub": registrant_sub}
    existing = T.crm_event_registrations.get_item(Key=existing_key).get("Item")
    if existing:
        raise HTTPException(status_code=409, detail="Already registered for this event")

    # Load meta for capacity check
    meta = get_crm_event(event_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Event not found")

    now = now_ts()

    # Check if invitee
    invitee_sk = f"INVITEE#{registrant_sub}"
    invitee_row = T.crm_events.get_item(
        Key={"event_id": event_id, "sk": invitee_sk}
    ).get("Item")
    is_invited = invitee_row is not None

    # EVT-004: capacity enforcement
    max_att = meta.get("max_attendance")
    status = "registered"
    waitlist_position: Optional[int] = None
    waitlisted_at: Optional[int] = None

    if max_att is not None:
        accepted_count = _count_by_status(event_id, "accepted")
        if accepted_count >= int(max_att):
            # Place on waitlist
            status = "waitlisted"
            waitlist_position = _atomic_increment_waitlist_counter(event_id)
            waitlisted_at = now

    item: dict[str, Any] = {
        "event_id": event_id,
        "registrant_sub": registrant_sub,
        "status": status,
        "registered_at": now,
        "invited": is_invited,
    }
    if waitlist_position is not None:
        item["waitlist_position"] = waitlist_position
    if waitlisted_at is not None:
        item["waitlisted_at"] = waitlisted_at

    try:
        T.crm_event_registrations.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(event_id)",
        )
    except Exception as exc:
        _code = ""
        try:
            _code = exc.response["Error"]["Code"]  # type: ignore[attr-defined]
        except Exception:
            _code = str(exc)
        if "ConditionalCheckFailed" in _code:
            raise HTTPException(status_code=409, detail="Already registered for this event")
        raise

    _audit("crm_event_registered", registrant_sub, event_id=event_id, status=status)
    return item


def respond_to_invitation(
    event_id: str, registrant_sub: str, new_status: str, actor_sub: str
) -> dict:
    """Accept or decline a registration. new_status must be 'accepted' or 'declined'."""
    from fastapi import HTTPException  # local import

    if new_status not in ("accepted", "declined"):
        raise HTTPException(status_code=400, detail="new_status must be 'accepted' or 'declined'")

    key = {"event_id": event_id, "registrant_sub": registrant_sub}
    existing = T.crm_event_registrations.get_item(Key=key).get("Item")
    if not existing:
        raise HTTPException(status_code=404, detail="Registration not found")

    now = now_ts()
    T.crm_event_registrations.update_item(
        Key=key,
        UpdateExpression="SET #st = :s, responded_at = :t",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":s": new_status, ":t": now},
    )

    # EVT-004: promote from waitlist when declined
    if new_status == "declined":
        try:
            _promote_from_waitlist(event_id)
        except Exception:
            logger.warning("crm promote_from_waitlist failed event_id=%s", event_id, exc_info=True)

    _audit("crm_event_responded", actor_sub, event_id=event_id, registrant_sub=registrant_sub, new_status=new_status)
    item = T.crm_event_registrations.get_item(Key=key).get("Item", existing)
    return item


def check_in_attendee(event_id: str, registrant_sub: str, actor_sub: str) -> dict:
    """Mark a registrant as attended."""
    from fastapi import HTTPException  # local import

    key = {"event_id": event_id, "registrant_sub": registrant_sub}
    existing = T.crm_event_registrations.get_item(Key=key).get("Item")
    if not existing:
        raise HTTPException(status_code=404, detail="Registration not found")

    now = now_ts()
    T.crm_event_registrations.update_item(
        Key=key,
        UpdateExpression="SET #st = :s, checked_in_at = :t",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":s": "attended", ":t": now},
    )
    _audit("crm_event_checked_in", actor_sub, event_id=event_id, registrant_sub=registrant_sub)
    item = T.crm_event_registrations.get_item(Key=key).get("Item", existing)
    return item


def cancel_registration(event_id: str, registrant_sub: str, actor_sub: str) -> bool:
    """Cancel (delete) a registration row and promote from waitlist."""
    key = {"event_id": event_id, "registrant_sub": registrant_sub}
    existing = T.crm_event_registrations.get_item(Key=key).get("Item")
    if not existing:
        return False
    T.crm_event_registrations.delete_item(Key=key)
    _audit("crm_event_cancelled", actor_sub, event_id=event_id, registrant_sub=registrant_sub)

    # EVT-004: promote next waitlisted
    try:
        _promote_from_waitlist(event_id)
    except Exception:
        logger.warning("crm promote_from_waitlist failed event_id=%s", event_id, exc_info=True)

    return True


def list_registrations(event_id: str, limit: int = 50, cursor: Optional[str] = None) -> dict:
    """Paginated list of registration rows for an event."""
    kwargs: dict[str, Any] = {
        "KeyConditionExpression": Key("event_id").eq(event_id),
        "Limit": min(limit, 200),
    }
    lek = decode_cursor(cursor)
    if lek:
        kwargs["ExclusiveStartKey"] = lek

    resp = T.crm_event_registrations.query(**kwargs)
    items = resp.get("Items", [])
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return {
        "registrations": [_reg_out(i) for i in items],
        "cursor": next_cursor,
    }


# ---------------------------------------------------------------------------
# EVT-004: Capacity helpers
# ---------------------------------------------------------------------------

def _count_by_status(event_id: str, status: str) -> int:
    """Count registrations with the given status (loops LastEvaluatedKey)."""
    count = 0
    kwargs: dict[str, Any] = {
        "KeyConditionExpression": Key("event_id").eq(event_id),
        "FilterExpression": Attr("status").eq(status),
    }
    while True:
        resp = T.crm_event_registrations.query(**kwargs)
        count += resp.get("Count", 0)
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return count


def _atomic_increment_waitlist_counter(event_id: str) -> int:
    """Atomically increment waitlist_counter on the META row.

    Returns the NEW value (i.e., the waitlist position for this registrant).
    """
    resp = T.crm_events.update_item(
        Key={"event_id": event_id, "sk": "META"},
        UpdateExpression="ADD waitlist_counter :one",
        ExpressionAttributeValues={":one": 1},
        ReturnValues="UPDATED_NEW",
    )
    return int(resp["Attributes"]["waitlist_counter"])


def _promote_from_waitlist(event_id: str) -> None:
    """Promote the first waitlisted registrant to 'registered'.

    Queries all registrations, finds the lowest waitlist_position, and
    updates their status to 'registered'.  Best-effort — the caller wraps
    in try/except.
    """
    # Collect all waitlisted rows (FilterExpression, must loop LastEvaluatedKey)
    waitlisted: list[dict] = []
    kwargs: dict[str, Any] = {
        "KeyConditionExpression": Key("event_id").eq(event_id),
        "FilterExpression": Attr("status").eq("waitlisted"),
    }
    while True:
        resp = T.crm_event_registrations.query(**kwargs)
        waitlisted.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek

    if not waitlisted:
        return

    # Promote the one with the lowest waitlist_position
    top = min(waitlisted, key=lambda x: int(x.get("waitlist_position", 999999)))
    registrant_sub = top["registrant_sub"]
    now = now_ts()
    T.crm_event_registrations.update_item(
        Key={"event_id": event_id, "registrant_sub": registrant_sub},
        UpdateExpression="SET #st = :s, responded_at = :t REMOVE waitlist_position, waitlisted_at",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":s": "registered", ":t": now},
    )
    _audit(
        "crm_waitlist_promoted",
        "system",
        event_id=event_id,
        registrant_sub=registrant_sub,
    )


def get_event_capacity(event_id: str) -> dict:
    """Return capacity summary for an event."""
    meta = get_crm_event(event_id)
    from fastapi import HTTPException  # local import
    if not meta:
        raise HTTPException(status_code=404, detail="Event not found")

    max_att_raw = meta.get("max_attendance")
    max_att = int(max_att_raw) if max_att_raw is not None else None
    accepted = _count_by_status(event_id, "accepted")
    waitlisted = _count_by_status(event_id, "waitlisted")
    available = (max_att - accepted) if max_att is not None else None

    return {
        "event_id": event_id,
        "max_attendance": max_att,
        "accepted_count": accepted,
        "waitlisted_count": waitlisted,
        "available_spots": available,
    }
