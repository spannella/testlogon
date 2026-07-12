"""CRM Contact SMS service — EVT-014.

Thin adapter that resolves a contact's phone via the profile service and
delegates to the existing sms_delivery pipeline.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

_SMS_HISTORY_TTL_SECONDS = 365 * 86400


def send_contact_sms(
    *,
    sender_sub: str,
    contact_id: str,
    body: str,
) -> dict:
    """Validate + resolve + dispatch a single outbound SMS to a contact.

    Steps:
    1. Resolve contact record from T.contacts.
    2. Resolve phone via get_profile_identity(contact_id).
    3. Normalise phone.
    4. Call sms_delivery.send_sms.
    5. Write CRM-layer send log row to T.crm_contact_sms_log.
    """
    from fastapi import HTTPException  # local import
    from app.core.normalize import normalize_phone  # lazy import (RULE-1)

    # 1. Confirm contact exists and is owned by sender
    key = {"owner_id": sender_sub, "contact_id": contact_id}
    contact_item = T.contacts.get_item(Key=key).get("Item")
    if not contact_item:
        raise HTTPException(status_code=404, detail="Contact not found")

    # 2. Resolve phone number
    phone: str | None = None
    try:
        from app.services.profile import get_profile_identity  # lazy import (RULE-1)
        identity = get_profile_identity(contact_id) or {}
        phone = identity.get("phone")
    except Exception:
        phone = None

    if not phone:
        raise HTTPException(status_code=404, detail="Contact has no phone number")

    # 3. Normalise phone
    try:
        phone = normalize_phone(phone)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid phone number for this contact")

    # 4. Send via sms_delivery
    from app.services.sms_delivery import send_sms  # lazy import (RULE-1)
    result = send_sms(phone, body)

    # 5. Write CRM log row
    sms_id = uuid.uuid4().hex
    now = now_ts()
    segments = max(1, (len(body) + 159) // 160)
    log_item: dict[str, Any] = {
        "sender_sub": sender_sub,
        "sk": f"LOG#{now:010d}#{sms_id}",
        "sms_id": sms_id,
        "contact_id": contact_id,
        "contact_phone": phone,
        "body_preview": body[:160],
        "segments": segments,
        "status": result.get("status", "unknown"),
        "message_id": result.get("message_id", ""),
        "sent_at_ts": now,
        "ttl_epoch": now + _SMS_HISTORY_TTL_SECONDS,
    }
    try:
        T.crm_contact_sms_log.put_item(Item=log_item)
    except Exception:
        logger.warning("crm_contact_sms: failed to write log row", exc_info=True)

    try:
        from app.services.alerts import audit_event  # lazy import (RULE-1)
        audit_event(
            "crm_contact_sms_sent",
            sender_sub,
            contact_id=contact_id,
            status=result.get("status"),
        )
    except Exception:
        pass

    return {
        "sms_id": sms_id,
        "contact_id": contact_id,
        "contact_phone": phone,
        "status": result.get("status", "unknown"),
        "message_id": result.get("message_id", ""),
        "sent_at_ts": now,
    }


def list_contact_sms_log(
    sender_sub: str,
    *,
    limit: int = 50,
    cursor: str | None = None,
) -> dict:
    """List the CRM-layer SMS send history for a sender."""
    from app.core.cursor import encode_cursor, decode_cursor  # lazy import (RULE-1)
    from boto3.dynamodb.conditions import Key  # lazy import

    kwargs: dict[str, Any] = {
        "KeyConditionExpression": Key("sender_sub").eq(sender_sub),
        "Limit": min(limit, 200),
        "ScanIndexForward": False,
    }
    lek = decode_cursor(cursor)
    if lek:
        kwargs["ExclusiveStartKey"] = lek

    resp = T.crm_contact_sms_log.query(**kwargs)
    items = resp.get("Items", [])
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return {
        "items": [
            {
                "sms_id": it.get("sms_id", ""),
                "contact_id": it.get("contact_id", ""),
                "contact_phone": it.get("contact_phone", ""),
                "status": it.get("status", ""),
                "message_id": it.get("message_id", ""),
                "sent_at_ts": int(it.get("sent_at_ts", 0)),
            }
            for it in items
        ],
        "cursor": next_cursor,
    }
