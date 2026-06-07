"""Sticker collection service for MSG-008.

Single-table design in the ``sticker_collections`` DynamoDB table:
  - PK ``collection_id`` ("sc_<hex>"), SK ``META`` -> collection metadata
  - PK ``collection_id``, SK ``STICKER#{sticker_id}`` -> individual sticker

User favorites live in the ``billing`` table (shared user-preferences table):
  - PK ``USER#{user_sub}``, SK ``FAV_STICKER#{collection_id}``

Sticker images are uploaded to S3 (moto mock in dev) and served via the
``/mock/s3/`` prefix.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key

from app.core.aws_clients import s3_client
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

S3_BUCKET_IMAGES = "my-chat-images"

# Allowed MIME types (validated against magic bytes, not just the declared header).
# image/svg+xml removed: SVG is text-based, has no reliable magic bytes, and can
# carry executable JavaScript (XSS). PNG + WebP only. (GAP-0315)
_ALLOWED_MIME = {
    "image/png": "png",
    "image/webp": "webp",
}

# Magic-byte signatures.
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_WEBP_RIFF = b"RIFF"
_WEBP_MARKER = b"WEBP"


def _detect_content_type(data: bytes) -> Optional[str]:
    """Sniff the real content type from magic bytes.

    Mirrors ``app/services/custom_emojis.py:_detect_content_type``: the declared
    header is ignored entirely and the actual bytes determine the MIME. Returns
    the detected MIME string, or ``None`` if unrecognised. SVG is text-based and
    intentionally not detectable here.
    """
    if data[:8] == _PNG_MAGIC:
        return "image/png"
    # WebP: "RIFF" at offset 0, "WEBP" at offset 8.
    if len(data) >= 12 and data[:4] == _WEBP_RIFF and data[8:12] == _WEBP_MARKER:
        return "image/webp"
    return None


def _new_collection_id() -> str:
    return "sc_" + uuid.uuid4().hex


def _new_sticker_id() -> str:
    return "stk_" + uuid.uuid4().hex


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _meta_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "collection_id": item["collection_id"],
        "name": item.get("name", ""),
        "description": item.get("description", ""),
        "thumbnail_url": item.get("thumbnail_url"),
        "sticker_count": _coerce_int(item.get("sticker_count"), 0),
        "is_active": str(item.get("is_active", "1")) == "1",
        "created_at": _coerce_int(item.get("created_at"), 0),
    }


def _sticker_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "sticker_id": item["sticker_id"],
        "image_url": item.get("image_url", ""),
        "alt_text": item.get("alt_text", ""),
        "sort_order": _coerce_int(item.get("sort_order"), 0),
        "width": _coerce_int(item.get("width"), 256),
        "height": _coerce_int(item.get("height"), 256),
    }


# ---------------------------------------------------------------------------
# Collections
# ---------------------------------------------------------------------------

def get_collection_meta(collection_id: str, *, active_only: bool = True) -> Optional[Dict[str, Any]]:
    resp = T.sticker_collections.get_item(Key={"collection_id": collection_id, "sk": "META"})
    item = resp.get("Item")
    if not item:
        return None
    if active_only and str(item.get("is_active", "1")) != "1":
        return None
    return item


def list_collections(active_only: bool = True, limit: int = 50) -> List[Dict[str, Any]]:
    """List sticker collections, newest first, via the GSI1 index."""
    out: List[Dict[str, Any]] = []
    try:
        resp = T.sticker_collections.query(
            IndexName="GSI1",
            KeyConditionExpression=Key("is_active").eq("1"),
            ScanIndexForward=False,
            Limit=limit,
        )
        for item in resp.get("Items", []):
            out.append(_meta_to_out(item))
    except Exception:
        # Fallback: scan META items (dev resilience if GSI not ready)
        resp = T.sticker_collections.scan()
        for item in resp.get("Items", []):
            if item.get("sk") != "META":
                continue
            if active_only and str(item.get("is_active", "1")) != "1":
                continue
            out.append(_meta_to_out(item))
        out.sort(key=lambda c: c.get("created_at", 0), reverse=True)
    return out


def get_collection_stickers(collection_id: str) -> List[Dict[str, Any]]:
    resp = T.sticker_collections.query(
        KeyConditionExpression=Key("collection_id").eq(collection_id)
        & Key("sk").begins_with("STICKER#"),
    )
    stickers = [_sticker_to_out(i) for i in resp.get("Items", [])]
    stickers.sort(key=lambda s: s.get("sort_order", 0))
    return stickers


def get_sticker(collection_id: str, sticker_id: str) -> Optional[Dict[str, Any]]:
    resp = T.sticker_collections.get_item(
        Key={"collection_id": collection_id, "sk": f"STICKER#{sticker_id}"}
    )
    item = resp.get("Item")
    return _sticker_to_out(item) if item else None


def create_collection(
    *,
    name: str,
    description: str,
    created_by: str,
    files: List[Tuple[bytes, str, str]],
) -> Dict[str, Any]:
    """Create a sticker collection.

    ``files`` is a list of ``(data, content_type, alt_text)`` tuples.
    Raises ``ValueError`` with a machine code for validation failures.
    """
    if not files:
        raise ValueError("no_stickers")
    if len(files) > S.sticker_max_per_collection:
        raise ValueError("collection_full")

    collection_id = _new_collection_id()
    ts = now_ts()
    s3 = s3_client()
    try:
        s3.head_bucket(Bucket=S3_BUCKET_IMAGES)
    except Exception:
        try:
            s3.create_bucket(Bucket=S3_BUCKET_IMAGES)
        except Exception:
            pass

    stickers_out: List[Dict[str, Any]] = []
    thumbnail_url: Optional[str] = None
    for idx, (data, content_type, alt_text) in enumerate(files, start=1):
        # Determine the MIME from the ACTUAL bytes, not the client-controlled
        # declared header (GAP-0315). Mirrors custom_emojis: the sniffed type is
        # authoritative; reject if it isn't an allowed image type.
        sniffed_ct = _detect_content_type(data)
        ext = _ALLOWED_MIME.get(sniffed_ct) if sniffed_ct else None
        if ext is None:
            raise ValueError("invalid_file_type")
        content_type = sniffed_ct
        if len(data) > S.sticker_max_file_size_bytes:
            raise ValueError("file_too_large")
        sticker_id = _new_sticker_id()
        key = f"stickers/{collection_id}/{sticker_id}.{ext}"
        try:
            s3.put_object(Bucket=S3_BUCKET_IMAGES, Key=key, Body=data, ContentType=content_type)
        except Exception:
            pass
        image_url = f"/mock/s3/{S3_BUCKET_IMAGES}/{key}"
        if thumbnail_url is None:
            thumbnail_url = image_url
        sticker_item = {
            "collection_id": collection_id,
            "sk": f"STICKER#{sticker_id}",
            "sticker_id": sticker_id,
            "image_url": image_url,
            "alt_text": alt_text or "",
            "sort_order": idx,
            "width": 256,
            "height": 256,
        }
        T.sticker_collections.put_item(Item=sticker_item)
        stickers_out.append(_sticker_to_out(sticker_item))

    meta_item = {
        "collection_id": collection_id,
        "sk": "META",
        "name": name,
        "description": description or "",
        "thumbnail_url": thumbnail_url,
        "sticker_count": len(stickers_out),
        "created_by": created_by,
        "created_at": ts,
        "is_active": "1",
    }
    T.sticker_collections.put_item(Item=meta_item)

    out = _meta_to_out(meta_item)
    out["stickers"] = stickers_out
    return out


def delete_collection(collection_id: str) -> bool:
    """Soft-delete a collection (set is_active="0"). Returns False if missing."""
    meta = get_collection_meta(collection_id, active_only=False)
    if not meta:
        return False
    T.sticker_collections.update_item(
        Key={"collection_id": collection_id, "sk": "META"},
        UpdateExpression="SET is_active = :z",
        ExpressionAttributeValues={":z": "0"},
    )
    return True


# ---------------------------------------------------------------------------
# Favorites (stored in billing table)
# ---------------------------------------------------------------------------

def add_favorite(user_sub: str, collection_id: str) -> None:
    T.billing.put_item(
        Item={
            "pk": f"USER#{user_sub}",
            "sk": f"FAV_STICKER#{collection_id}",
            "added_at": now_ts(),
        }
    )


def remove_favorite(user_sub: str, collection_id: str) -> None:
    T.billing.delete_item(
        Key={"pk": f"USER#{user_sub}", "sk": f"FAV_STICKER#{collection_id}"}
    )


def list_favorites(user_sub: str) -> List[str]:
    resp = T.billing.query(
        KeyConditionExpression=Key("pk").eq(f"USER#{user_sub}")
        & Key("sk").begins_with("FAV_STICKER#"),
    )
    ids: List[str] = []
    for item in resp.get("Items", []):
        sk = item.get("sk", "")
        if sk.startswith("FAV_STICKER#"):
            ids.append(sk[len("FAV_STICKER#"):])
    return ids


def list_favorites_with_stickers(user_sub: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for cid in list_favorites(user_sub):
        meta = get_collection_meta(cid, active_only=True)
        if not meta:
            continue
        col = _meta_to_out(meta)
        col["stickers"] = get_collection_stickers(cid)
        out.append(col)
    return out


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

def search_stickers(user_sub: str, query: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Search stickers by alt_text across the user's favorited collections."""
    q = (query or "").strip().lower()
    results: List[Dict[str, Any]] = []
    if not q:
        return results
    for cid in list_favorites(user_sub):
        meta = get_collection_meta(cid, active_only=True)
        if not meta:
            continue
        for sticker in get_collection_stickers(cid):
            if q in (sticker.get("alt_text", "") or "").lower():
                results.append(
                    {
                        "sticker_id": sticker["sticker_id"],
                        "collection_id": cid,
                        "image_url": sticker["image_url"],
                        "alt_text": sticker["alt_text"],
                        "collection_name": meta.get("name", ""),
                    }
                )
                if len(results) >= limit:
                    return results
    return results
