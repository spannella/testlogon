from __future__ import annotations

from typing import Any, Iterable, Optional, Tuple

from boto3.dynamodb.conditions import Key


GALLERY_INDEX_TYPES = ("image", "video", "file", "link")


def gallery_index_partition_key(conversation_id: str, gallery_type: str) -> str:
    return f"{conversation_id}#{gallery_type}"


def gallery_index_sort_key(created_at: int, message_id: str) -> str:
    return f"{int(created_at):013d}#{message_id}"


def sync_gallery_index_entries(
    *,
    table: Any,
    conversation_id: str,
    message_id: str,
    created_at: int,
    entries: Iterable[dict[str, Any]],
) -> None:
    """Replace all gallery index projections for a message (idempotent)."""
    if table is None:
        return

    sort_key = gallery_index_sort_key(created_at, message_id)
    with table.batch_writer() as batch:
        for gallery_type in GALLERY_INDEX_TYPES:
            batch.delete_item(
                Key={
                    "gallery_partition": gallery_index_partition_key(conversation_id, gallery_type),
                    "gallery_sort": sort_key,
                }
            )

        for entry in entries:
            item = dict(entry)
            item.setdefault("gallery_partition", gallery_index_partition_key(conversation_id, str(item.get("type") or "")))
            item.setdefault("gallery_sort", sort_key)
            item.setdefault("conversation_id", conversation_id)
            item.setdefault("message_id", message_id)
            item.setdefault("created_at", int(created_at))
            batch.put_item(Item=item)


def fetch_gallery_index_page(
    *,
    table: Any,
    conversation_id: str,
    gallery_type: str,
    limit: int,
    cursor_sort_key: Optional[str],
) -> Tuple[list[dict[str, Any]], Optional[str]]:
    """Fetch reverse-chronological gallery rows from materialized index."""
    if table is None:
        return [], None

    kwargs: dict[str, Any] = {
        "KeyConditionExpression": Key("gallery_partition").eq(
            gallery_index_partition_key(conversation_id, gallery_type)
        ),
        "ScanIndexForward": False,
        "Limit": max(1, int(limit)),
    }
    if cursor_sort_key:
        kwargs["ExclusiveStartKey"] = {
            "gallery_partition": gallery_index_partition_key(conversation_id, gallery_type),
            "gallery_sort": cursor_sort_key,
        }

    resp = table.query(**kwargs)
    items = resp.get("Items") or []
    next_key = resp.get("LastEvaluatedKey") or {}
    next_sort = str(next_key.get("gallery_sort") or "").strip() or None
    return items, next_sort


def backfill_conversation_gallery_index(
    *,
    messages_table: Any,
    index_table: Any,
    conversation_id: str,
    project_entries: Any,
    page_size: int = 200,
) -> dict[str, int]:
    """Backfill one conversation from source messages into gallery index."""
    scanned = 0
    upserted = 0
    start_key = None
    while True:
        kwargs: dict[str, Any] = {
            "KeyConditionExpression": Key("conversation_id").eq(conversation_id),
            "ScanIndexForward": False,
            "Limit": max(1, int(page_size)),
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = messages_table.query(**kwargs)
        items = resp.get("Items") or []
        for message in items:
            scanned += 1
            message_id = str(message.get("message_id") or "").strip()
            created_at = int(message.get("created_at") or 0)
            if not message_id or not created_at:
                continue
            entries = project_entries(message)
            sync_gallery_index_entries(
                table=index_table,
                conversation_id=conversation_id,
                message_id=message_id,
                created_at=created_at,
                entries=entries,
            )
            upserted += len(entries)
        start_key = resp.get("LastEvaluatedKey")
        if not isinstance(start_key, dict):
            break
    return {"messages_scanned": scanned, "entries_upserted": upserted}


def check_gallery_index_consistency(
    *,
    messages: Iterable[dict[str, Any]],
    index_items: Iterable[dict[str, Any]],
    project_entries: Any,
) -> dict[str, Any]:
    """Compare expected projected entries against index rows."""
    expected = set()
    for message in messages:
        conversation_id = str(message.get("conversation_id") or "").strip()
        message_id = str(message.get("message_id") or "").strip()
        created_at = int(message.get("created_at") or 0)
        if not conversation_id or not message_id or not created_at:
            continue
        sort_key = gallery_index_sort_key(created_at, message_id)
        for entry in project_entries(message):
            gallery_type = str(entry.get("type") or "").strip()
            if not gallery_type:
                continue
            expected.add((gallery_index_partition_key(conversation_id, gallery_type), sort_key))

    actual = set()
    for row in index_items:
        actual.add((str(row.get("gallery_partition") or ""), str(row.get("gallery_sort") or "")))

    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    return {
        "expected_count": len(expected),
        "actual_count": len(actual),
        "missing_count": len(missing),
        "unexpected_count": len(unexpected),
        "ok": not missing and not unexpected,
    }
