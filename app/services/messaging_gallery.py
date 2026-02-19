from __future__ import annotations

from typing import Any, Callable, Optional, Tuple

from boto3.dynamodb.conditions import Key


GalleryMapper = Callable[[dict[str, Any], str], Optional[Any]]
GalleryVisibility = Callable[[dict[str, Any]], bool]


def fetch_gallery_page(
    *,
    table: Any,
    conversation_id: str,
    gallery_type: str,
    limit: int,
    cursor_message_id: Optional[str],
    is_visible: GalleryVisibility,
    map_item: GalleryMapper,
) -> Tuple[list[Any], Optional[str]]:
    """Fetch a reverse-chronological gallery page from the message backing store.

    Pagination is stable and deterministic: `next_cursor` always encodes the last scanned
    message id that contributed to pagination progress.
    """
    out: list[Any] = []
    query_limit = max(50, min(200, limit * 4))
    start_key = {"conversation_id": conversation_id, "message_id": cursor_message_id} if cursor_message_id else None

    while True:
        kwargs: dict[str, Any] = {
            "KeyConditionExpression": Key("conversation_id").eq(conversation_id),
            "ScanIndexForward": False,
            "Limit": query_limit,
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key

        resp = table.query(**kwargs)
        items = resp.get("Items", [])
        last_evaluated_key = resp.get("LastEvaluatedKey")

        last_scanned_message_id: Optional[str] = None
        reached_limit = False

        for idx, item in enumerate(items):
            message_id = str(item.get("message_id") or "").strip()
            if message_id:
                last_scanned_message_id = message_id

            if not is_visible(item):
                continue

            gallery_item = map_item(item, gallery_type)
            if gallery_item is None:
                continue

            out.append(gallery_item)
            if len(out) >= limit:
                reached_limit = True
                has_more_in_batch = idx < (len(items) - 1)
                if has_more_in_batch or isinstance(last_evaluated_key, dict):
                    return out, last_scanned_message_id
                return out, None

        if not isinstance(last_evaluated_key, dict):
            return out, None

        next_start_message_id = str(last_evaluated_key.get("message_id") or "").strip()
        if not next_start_message_id:
            return out, None

        start_key = {"conversation_id": conversation_id, "message_id": next_start_message_id}

        if reached_limit:
            return out, last_scanned_message_id
