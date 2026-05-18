from __future__ import annotations

import json
import os
import time
import uuid
from decimal import Decimal
from typing import Any

DDB_MESSAGE_DRAFTS = os.getenv("DDB_MESSAGE_DRAFTS", "MessageDrafts")
DRAFTS_TTL_ATTR = os.getenv("DRAFTS_TTL_ATTR", "ttl_epoch")
DRAFTS_RETENTION_DAYS = max(1, int(os.getenv("DRAFTS_RETENTION_DAYS", "30")))
MAX_TEXT_CHARS = 4000
MAX_ROW_BYTES = 16 * 1024


class DraftError(Exception):
    pass


class DraftValidationError(DraftError):
    pass


class DraftNotFoundError(DraftError):
    pass


def _get_table(table: Any | None = None) -> Any:
    if table is not None:
        return table
    from app.core.aws import ddb  # lazy import for test environments without boto3

    return ddb.Table(DDB_MESSAGE_DRAFTS)


def _now_epoch(now: int | None = None) -> int:
    return int(now if now is not None else time.time())


def _draft_ttl_epoch(ts: int) -> int:
    return int(ts + (DRAFTS_RETENTION_DAYS * 86_400))


def _normalize_text(text: str) -> str:
    trimmed = text.strip()
    if not trimmed:
        raise DraftValidationError("text must not be empty")
    if len(trimmed) > MAX_TEXT_CHARS:
        raise DraftValidationError(f"text must be <= {MAX_TEXT_CHARS} characters")
    return trimmed


def _build_conversation_owner_key(owner_user_id: str, conversation_id: str) -> str:
    if not owner_user_id or not conversation_id:
        raise DraftValidationError("owner_user_id and conversation_id are required")
    return f"{owner_user_id}#{conversation_id}"


def _row_size_bytes(item: dict[str, Any]) -> int:
    return len(json.dumps(item, default=str, separators=(",", ":")).encode("utf-8"))


def _as_int(v: Any) -> int:
    if isinstance(v, Decimal):
        return int(v)
    if isinstance(v, (int, float)):
        return int(v)
    if isinstance(v, str) and v.isdigit():
        return int(v)
    raise ValueError("value is not an integer")


def _normalize_item(item: dict[str, Any] | None) -> dict[str, Any] | None:
    if not item:
        return None
    try:
        draft_id = str(item["draft_id"])
        owner_user_id = str(item["owner_user_id"])
        conversation_id = str(item["conversation_id"])
        text = str(item["text"])
        version = _as_int(item.get("version", 1))
        created_at = _as_int(item["created_at"])
        updated_at = _as_int(item["updated_at"])
    except (KeyError, TypeError, ValueError):
        return None

    out = {
        "draft_id": draft_id,
        "owner_user_id": owner_user_id,
        "conversation_id": conversation_id,
        "text": text,
        "version": version,
        "created_at": created_at,
        "updated_at": updated_at,
    }
    if item.get("client_updated_at") is not None:
        try:
            out["client_updated_at"] = _as_int(item["client_updated_at"])
        except Exception:
            pass
    if item.get("tenant_id") is not None:
        out["tenant_id"] = str(item["tenant_id"])
    return out


def create_draft(
    *,
    owner_user_id: str,
    conversation_id: str,
    text: str,
    client_updated_at: int | None = None,
    tenant_id: str = "default",
    draft_id: str | None = None,
    now: int | None = None,
    table: Any | None = None,
) -> dict[str, Any]:
    tbl = _get_table(table)
    ts = _now_epoch(now)
    did = draft_id or f"drf_{uuid.uuid4().hex}"
    clean_text = _normalize_text(text)
    conversation_owner_key = _build_conversation_owner_key(owner_user_id, conversation_id)

    item: dict[str, Any] = {
        "owner_user_id": owner_user_id,
        "draft_id": did,
        "conversation_id": conversation_id,
        "conversation_owner_key": conversation_owner_key,
        "text": clean_text,
        "version": 1,
        "created_at": ts,
        "updated_at": ts,
        DRAFTS_TTL_ATTR: _draft_ttl_epoch(ts),
        "tenant_id": tenant_id,
    }
    if client_updated_at is not None:
        item["client_updated_at"] = int(client_updated_at)

    if _row_size_bytes(item) > MAX_ROW_BYTES:
        raise DraftValidationError("draft exceeds maximum row size")

    tbl.put_item(
        Item=item,
        ConditionExpression="attribute_not_exists(owner_user_id) AND attribute_not_exists(draft_id)",
    )
    normalized = _normalize_item(item)
    if not normalized:
        raise DraftValidationError("failed to normalize created draft")
    return normalized


def get_draft(
    *,
    owner_user_id: str,
    conversation_id: str,
    draft_id: str,
    table: Any | None = None,
) -> dict[str, Any]:
    tbl = _get_table(table)
    item = tbl.get_item(Key={"owner_user_id": owner_user_id, "draft_id": draft_id}).get("Item")
    normalized = _normalize_item(item)
    if not normalized or normalized["conversation_id"] != conversation_id:
        raise DraftNotFoundError("draft not found")
    return normalized


def update_draft(
    *,
    owner_user_id: str,
    conversation_id: str,
    draft_id: str,
    text: str,
    client_updated_at: int | None = None,
    now: int | None = None,
    table: Any | None = None,
) -> dict[str, Any]:
    existing = get_draft(
        owner_user_id=owner_user_id,
        conversation_id=conversation_id,
        draft_id=draft_id,
        table=table,
    )
    tbl = _get_table(table)
    clean_text = _normalize_text(text)
    ts = _now_epoch(now)

    names = {"#text": "text", "#updated_at": "updated_at", "#version": "version"}
    names["#ttl_attr"] = DRAFTS_TTL_ATTR
    values: dict[str, Any] = {
        ":text": clean_text,
        ":updated_at": ts,
        ":inc": 1,
        ":ttl_attr": _draft_ttl_epoch(ts),
    }
    set_expr = "#text = :text, #updated_at = :updated_at, #version = #version + :inc, #ttl_attr = :ttl_attr"

    if client_updated_at is not None:
        names["#client_updated_at"] = "client_updated_at"
        values[":client_updated_at"] = int(client_updated_at)
        set_expr += ", #client_updated_at = :client_updated_at"

    updated = tbl.update_item(
        Key={"owner_user_id": owner_user_id, "draft_id": draft_id},
        UpdateExpression=f"SET {set_expr}",
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
        ConditionExpression="attribute_exists(owner_user_id) AND attribute_exists(draft_id)",
        ReturnValues="ALL_NEW",
    ).get("Attributes")

    normalized = _normalize_item(updated)
    if not normalized or normalized["conversation_id"] != existing["conversation_id"]:
        raise DraftNotFoundError("draft not found")

    if _row_size_bytes(updated or {}) > MAX_ROW_BYTES:
        raise DraftValidationError("draft exceeds maximum row size")
    return normalized


def delete_draft(
    *,
    owner_user_id: str,
    conversation_id: str,
    draft_id: str,
    table: Any | None = None,
) -> None:
    # strict ownership + conversation check before delete
    get_draft(
        owner_user_id=owner_user_id,
        conversation_id=conversation_id,
        draft_id=draft_id,
        table=table,
    )
    tbl = _get_table(table)
    tbl.delete_item(Key={"owner_user_id": owner_user_id, "draft_id": draft_id})


def list_drafts(
    *,
    owner_user_id: str,
    conversation_id: str,
    limit: int = 20,
    cursor: dict[str, Any] | None = None,
    table: Any | None = None,
) -> dict[str, Any]:
    if limit < 1 or limit > 100:
        raise DraftValidationError("limit must be between 1 and 100")

    tbl = _get_table(table)
    cok = _build_conversation_owner_key(owner_user_id, conversation_id)
    query_kwargs: dict[str, Any] = {
        "IndexName": "ByConversationUpdatedAt",
        "KeyConditionExpression": "conversation_owner_key = :cok",
        "ExpressionAttributeValues": {":cok": cok},
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        query_kwargs["ExclusiveStartKey"] = cursor

    resp = tbl.query(**query_kwargs)
    items = resp.get("Items", [])
    normalized: list[dict[str, Any]] = []
    for raw in items:
        item = _normalize_item(raw)
        if not item:
            # malformed legacy rows are skipped safely
            continue
        if item["owner_user_id"] != owner_user_id or item["conversation_id"] != conversation_id:
            # defensive ownership/conversation guard
            continue
        normalized.append(item)

    return {
        "items": normalized,
        "next_cursor": resp.get("LastEvaluatedKey"),
    }
