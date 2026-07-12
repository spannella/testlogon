"""Email archiving — relate email to CRM record (EML-007).

Archives a synced email message (from ``user_email_messages``) to a CRM
entity (ticket or contact).  All endpoints are gated by
``S.email_archiving_enabled`` (default OFF).

Table: email_archive
  PK: ENTITY#{entity_type}#{entity_id}
  SK: EMAIL#{date_ts:010d}#{message_id_hash}

GSI ByUser:
  PK: gsi_user_pk (USER#{user_sub})
  SK: archived_at (N)
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

_SUPPORTED_ENTITY_TYPES = {"contact", "ticket"}


def _require_enabled() -> None:
    if not S.email_archiving_enabled:
        raise HTTPException(
            status_code=503,
            detail={"code": "feature_disabled", "feature": "email_archiving"},
        )


def _require_entity_type_supported(entity_type: str) -> None:
    if entity_type not in _SUPPORTED_ENTITY_TYPES:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "entity_type_not_supported",
                "detail": f"entity_type '{entity_type}' not supported",
            },
        )


def archive_email(
    user_sub: str,
    account_id: str,
    uid: int,
    entity_type: str,
    entity_id: str,
    *,
    is_admin: bool = False,
) -> Dict[str, Any]:
    """Archive a synced email to a CRM record.

    Raises 400 for unsupported entity_type, 404 for missing message/entity,
    403 for access denied.
    """
    _require_enabled()
    _require_entity_type_supported(entity_type)

    from app.services.alerts import audit_event

    # Resolve source message
    pk_msg = f"USER#{user_sub}#ACCT#{account_id}"
    try:
        resp = T.user_email_messages.get_item(Key={"pk": pk_msg, "sk": f"MSG#{uid:010d}"})
        message = resp.get("Item")
    except Exception:
        logger.exception("Failed to read source message uid %d", uid)
        message = None

    if not message:
        raise HTTPException(status_code=404, detail={"code": "message_not_found"})

    # Validate entity ownership
    if entity_type == "ticket":
        try:
            from app.services.tickets import STORE as ticket_store
            ticket = ticket_store.get_ticket(entity_id)
        except ImportError:
            ticket = None
        except Exception:
            ticket = None
        if not ticket:
            raise HTTPException(status_code=404, detail={"code": "ticket_not_found"})
        if not is_admin and ticket.get("owner_sub") != user_sub:
            raise HTTPException(status_code=403, detail={"code": "access_forbidden"})

    elif entity_type == "contact":
        try:
            resp = T.contacts.get_item(Key={"owner_id": user_sub, "contact_id": entity_id})
            contact = resp.get("Item")
        except Exception:
            contact = None
        if not contact:
            raise HTTPException(status_code=404, detail={"code": "contact_not_found"})

    # Build archive row
    message_id = str(message.get("message_id", ""))
    message_id_hash = hashlib.sha256(message_id.encode("utf-8")).hexdigest()[:16]
    date_ts = int(message.get("date_ts", now_ts()))

    pk = f"ENTITY#{entity_type}#{entity_id}"
    sk = f"EMAIL#{date_ts:010d}#{message_id_hash}"

    item: Dict[str, Any] = {
        "pk": pk,
        "sk": sk,
        "gsi_user_pk": f"USER#{user_sub}",
        "entity_type": entity_type,
        "entity_id": entity_id,
        "user_sub": user_sub,
        "account_id": account_id,
        "uid": uid,
        "message_id": message_id,
        "message_id_hash": message_id_hash,
        "subject": str(message.get("subject", ""))[:500],
        "from_addr": str(message.get("from_addr", ""))[:320],
        "snippet": str(message.get("snippet", ""))[:200],
        "date_ts": date_ts,
        "archived_at": now_ts(),
    }

    T.email_archive.put_item(Item=item)

    try:
        audit_event(
            "email_archived",
            user_sub,
            request=None,
            entity_type=entity_type,
            entity_id=entity_id,
            message_id=message_id,
            account_id=account_id,
        )
    except Exception:
        logger.exception("Failed to audit email_archived")

    return item


def list_archived_emails(
    entity_type: str,
    entity_id: str,
    *,
    limit: int = 25,
    cursor: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """List archived emails for an entity, chronological order."""
    _require_enabled()

    limit = min(max(1, limit), 100)
    pk = f"ENTITY#{entity_type}#{entity_id}"
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(pk),
        "ScanIndexForward": True,
        "Limit": limit,
    }
    if cursor:
        try:
            kwargs["ExclusiveStartKey"] = decode_cursor(cursor)
        except Exception:
            pass

    try:
        resp = T.email_archive.query(**kwargs)
    except Exception:
        logger.exception("Failed to list archived emails for %s/%s", entity_type, entity_id)
        return [], None

    items = resp.get("Items", [])
    next_cursor = encode_cursor(resp["LastEvaluatedKey"]) if resp.get("LastEvaluatedKey") else None
    return items, next_cursor


def unarchive_email(
    user_sub: str,
    entity_type: str,
    entity_id: str,
    message_id_hash: str,
    *,
    is_admin: bool = False,
) -> None:
    """Remove an archive entry.  Raises 404 if not found, 403 if not authorised."""
    _require_enabled()

    from app.services.alerts import audit_event

    pk = f"ENTITY#{entity_type}#{entity_id}"

    # Find the item by querying for SK begins_with the hash suffix
    item = None
    sk_found = None
    try:
        resp = T.email_archive.query(
            KeyConditionExpression=Key("pk").eq(pk),
            FilterExpression=Key("sk").begins_with(f"EMAIL#"),
        )
        for it in resp.get("Items", []):
            if it.get("message_id_hash") == message_id_hash or it.get("sk", "").endswith(message_id_hash):
                item = it
                sk_found = it["sk"]
                break
    except Exception:
        logger.exception("Failed to find archive entry for unarchive")

    if not item or not sk_found:
        raise HTTPException(status_code=404, detail={"code": "archive_entry_not_found"})

    if not is_admin and item.get("user_sub") != user_sub:
        raise HTTPException(status_code=403, detail={"code": "unarchive_forbidden"})

    T.email_archive.delete_item(Key={"pk": pk, "sk": sk_found})

    try:
        audit_event(
            "email_unarchived",
            user_sub,
            entity_type=entity_type,
            entity_id=entity_id,
            message_id_hash=message_id_hash,
        )
    except Exception:
        logger.exception("Failed to audit email_unarchived")
