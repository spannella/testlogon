"""
ACT-010 — CRM Notes service.

Table: crm_notes
  PK = user_sub
  SK = NOTE#{inverted_ts:013d}#{note_id}
  GSI ByEntity: GSI1PK=ENTITY#{linked_entity_type}#{linked_entity_id},
                GSI1SK=created_at (N)

S3 key: crm-notes/{user_sub}/{note_id}/{safe_filename}
Bucket: S.crm_notes_s3_bucket
"""
from __future__ import annotations

import logging
import re
import uuid
from typing import Any, Dict, Optional

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.core.cursor import encode_cursor, decode_cursor

logger = logging.getLogger(__name__)

_INVERTED_MAX = 9_999_999_999_999


def _make_note_sk(created_at: int, note_id: str) -> str:
    inverted = _INVERTED_MAX - created_at
    return f"NOTE#{inverted:013d}#{note_id}"


def _safe_filename(filename: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", filename)
    return safe or "attachment"


def _item_to_out(item: Dict[str, Any], attachment_url: Optional[str] = None) -> Dict[str, Any]:
    return {
        "note_id": item["note_id"],
        "user_sub": item["user_sub"],
        "body": item.get("body", ""),
        "linked_entity_type": item.get("linked_entity_type"),
        "linked_entity_id": item.get("linked_entity_id"),
        "attachment_s3_key": item.get("attachment_s3_key"),
        "attachment_filename": item.get("attachment_filename"),
        "attachment_content_type": item.get("attachment_content_type"),
        "attachment_url": attachment_url,
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
    }


def _resolve_attachment_url(item: Dict[str, Any]) -> Optional[str]:
    s3_key = item.get("attachment_s3_key")
    if not s3_key:
        return None
    if S.dev_mode:
        bucket = S.crm_notes_s3_bucket
        return f"/mock/s3/{bucket}/{s3_key}"
    try:
        from app.core.aws_clients import s3_client
        url = s3_client().generate_presigned_url(
            "get_object",
            Params={"Bucket": S.crm_notes_s3_bucket, "Key": s3_key},
            ExpiresIn=300,
        )
        return url
    except Exception:
        return None


def create_note(
    user_sub: str,
    body: str = "",
    linked_entity_type: Optional[str] = None,
    linked_entity_id: Optional[str] = None,
    attachment_bytes: Optional[bytes] = None,
    attachment_filename: Optional[str] = None,
    attachment_content_type: Optional[str] = None,
) -> Dict[str, Any]:
    ts = now_ts()
    note_id = f"note_{uuid.uuid4().hex}"
    sk = _make_note_sk(ts, note_id)
    item: Dict[str, Any] = {
        "user_sub": user_sub,
        "sk": sk,
        "note_id": note_id,
        "body": body or "",
        "created_at": ts,
        "updated_at": ts,
    }
    if linked_entity_type:
        item["linked_entity_type"] = linked_entity_type
        if linked_entity_id:
            item["linked_entity_id"] = linked_entity_id
            item["GSI1PK"] = f"ENTITY#{linked_entity_type}#{linked_entity_id}"
            item["GSI1SK"] = ts
    # Upload attachment if provided
    attachment_url = None
    if attachment_bytes and attachment_filename:
        safe = _safe_filename(attachment_filename)
        s3_key = f"crm-notes/{user_sub}/{note_id}/{safe}"
        try:
            from app.core.aws_clients import s3_client
            s3_client().put_object(
                Bucket=S.crm_notes_s3_bucket,
                Key=s3_key,
                Body=attachment_bytes,
                ContentType=attachment_content_type or "application/octet-stream",
            )
            item["attachment_s3_key"] = s3_key
            item["attachment_filename"] = safe
            item["attachment_content_type"] = attachment_content_type or "application/octet-stream"
            if S.dev_mode:
                attachment_url = f"/mock/s3/{S.crm_notes_s3_bucket}/{s3_key}"
            else:
                attachment_url = _resolve_attachment_url(item)
        except Exception:
            logger.warning("Failed to upload note attachment", exc_info=True)
    T.crm_notes.put_item(Item=item)
    # Fire-and-forget timeline write (ACT-009)
    if linked_entity_type and linked_entity_id:
        try:
            from app.services.crm_activity_timeline import record_crm_activity
            record_crm_activity(
                entity_type=linked_entity_type,
                entity_id=linked_entity_id,
                activity_type="note",
                activity_id=note_id,
                user_sub=user_sub,
                summary=body[:100] if body else "Note added",
                metadata={"has_attachment": attachment_filename is not None},
            )
        except Exception:
            logger.warning("crm_activity_timeline unavailable; skipping", exc_info=True)
    try:
        from app.services.alerts import audit_event
        audit_event("crm_note_create", user_sub, None, note_id=note_id)
    except Exception:
        pass
    return _item_to_out(item, attachment_url=attachment_url)


def list_notes(
    user_sub: str,
    limit: int = 20,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    kw: Dict[str, Any] = dict(
        KeyConditionExpression=Key("user_sub").eq(user_sub) & Key("sk").begins_with("NOTE#"),
        ScanIndexForward=True,
        Limit=limit,
    )
    if cursor:
        kw["ExclusiveStartKey"] = decode_cursor(cursor)
    resp = T.crm_notes.query(**kw)
    items = resp.get("Items", [])
    lek = resp.get("LastEvaluatedKey")
    return {
        "notes": [_item_to_out(i, _resolve_attachment_url(i)) for i in items],
        "next_cursor": encode_cursor(lek) if lek else None,
    }


def list_notes_by_entity(
    entity_type: str,
    entity_id: str,
    limit: int = 20,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    from boto3.dynamodb.conditions import Key as _Key
    gsi1pk = f"ENTITY#{entity_type}#{entity_id}"
    kw: Dict[str, Any] = dict(
        IndexName="ByEntity",
        KeyConditionExpression=_Key("GSI1PK").eq(gsi1pk),
        ScanIndexForward=False,  # newest first on GSI1SK=created_at
        Limit=limit,
    )
    if cursor:
        kw["ExclusiveStartKey"] = decode_cursor(cursor)
    resp = T.crm_notes.query(**kw)
    items = resp.get("Items", [])
    lek = resp.get("LastEvaluatedKey")
    return {
        "notes": [_item_to_out(i, _resolve_attachment_url(i)) for i in items],
        "next_cursor": encode_cursor(lek) if lek else None,
    }


def _get_raw(user_sub: str, note_id: str) -> Optional[Dict[str, Any]]:
    from boto3.dynamodb.conditions import Attr
    resp = T.crm_notes.query(
        KeyConditionExpression=Key("user_sub").eq(user_sub) & Key("sk").begins_with("NOTE#"),
        FilterExpression=Attr("note_id").eq(note_id),
    )
    items = resp.get("Items", [])
    return items[0] if items else None


def get_note(user_sub: str, note_id: str) -> Optional[Dict[str, Any]]:
    item = _get_raw(user_sub, note_id)
    if not item:
        return None
    return _item_to_out(item, _resolve_attachment_url(item))


def update_note(user_sub: str, note_id: str, body: str) -> Optional[Dict[str, Any]]:
    existing = _get_raw(user_sub, note_id)
    if not existing:
        return None
    ts = now_ts()
    updated = {**existing, "body": body, "updated_at": ts}
    T.crm_notes.put_item(Item=updated)
    return _item_to_out(updated, _resolve_attachment_url(updated))


def delete_note(user_sub: str, note_id: str) -> bool:
    existing = _get_raw(user_sub, note_id)
    if not existing:
        return False
    T.crm_notes.delete_item(Key={"user_sub": user_sub, "sk": existing["sk"]})
    return True
