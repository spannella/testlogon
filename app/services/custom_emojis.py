"""Custom emoji service for MSG-007.

Single-table design in the ``custom_emojis`` DynamoDB table:
  - PK ``owner_scope`` (``USER#{user_sub}`` for personal, ``"GLOBAL"`` for admin)
  - SK ``emoji_sk`` (``EMOJI#{emoji_id}``)

GSIs:
  - ``GSI1``: ``owner_scope`` -> ``shortcode`` (uniqueness check / resolution)
  - ``GSI2``: ``created_by`` -> ``created_at`` (per-user emoji list / limit count)

Emoji images are uploaded to S3 (moto mock in dev) and served via the
``/mock/s3/`` prefix.
"""
from __future__ import annotations

import io
import re
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from boto3.dynamodb.conditions import Key

from app.core.aws_clients import s3_client
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

S3_BUCKET_IMAGES = "my-chat-images"

GLOBAL_SCOPE = "GLOBAL"

# Allowed MIME types (validated against magic bytes, not just header).
_ALLOWED_MIME = {
    "image/png": "png",
    "image/gif": "gif",
}

_SHORTCODE_RE = re.compile(r"^[a-z0-9_]{2,32}$")

# Magic-byte signatures.
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_GIF_MAGIC_87 = b"GIF87a"
_GIF_MAGIC_89 = b"GIF89a"


class CustomEmojiError(Exception):
    """Validation/business error with a machine-readable ``code`` and message."""

    def __init__(self, code: str, message: str, status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def user_scope(user_sub: str) -> str:
    return f"USER#{user_sub}"


def _new_emoji_id() -> str:
    return "ce_" + uuid.uuid4().hex


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _detect_content_type(data: bytes) -> Optional[str]:
    """Sniff the real content type from magic bytes."""
    if data.startswith(_PNG_MAGIC):
        return "image/png"
    if data.startswith(_GIF_MAGIC_87) or data.startswith(_GIF_MAGIC_89):
        return "image/gif"
    return None


def _emoji_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "emoji_id": item.get("emoji_id", ""),
        "shortcode": item.get("shortcode", ""),
        "name": item.get("name", ""),
        "image_url": item.get("image_url", ""),
        "alt_text": item.get("alt_text", ""),
        "category": item.get("category", "Uncategorized"),
        "owner_scope": item.get("owner_scope", ""),
        "created_by": item.get("created_by", ""),
        "created_at": _coerce_int(item.get("created_at"), 0),
        "content_type": item.get("content_type", "image/png"),
        "file_size_bytes": _coerce_int(item.get("file_size_bytes"), 0),
    }


def _ensure_bucket(s3) -> None:
    try:
        s3.head_bucket(Bucket=S3_BUCKET_IMAGES)
    except Exception:
        try:
            s3.create_bucket(Bucket=S3_BUCKET_IMAGES)
        except Exception:
            pass


def validate_shortcode(shortcode: str) -> str:
    sc = (shortcode or "").strip().lower()
    if not _SHORTCODE_RE.match(sc):
        raise CustomEmojiError(
            "validation_error",
            "Shortcode must be 2-32 alphanumeric characters or underscores.",
            status_code=422,
        )
    return sc


def _find_by_shortcode(owner_scope: str, shortcode: str) -> Optional[Dict[str, Any]]:
    resp = T.custom_emojis.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("owner_scope").eq(owner_scope) & Key("shortcode").eq(shortcode),
        Limit=1,
    )
    items = resp.get("Items", [])
    return items[0] if items else None


def _count_for_creator(created_by: str) -> int:
    """Count emojis created by a user (across scopes) via GSI2."""
    total = 0
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "GSI2",
            "KeyConditionExpression": Key("created_by").eq(created_by),
            "Select": "COUNT",
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.custom_emojis.query(**kwargs)
        total += _coerce_int(resp.get("Count"), 0)
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return total


def create_custom_emoji(
    *,
    owner_scope: str,
    shortcode: str,
    name: str,
    alt_text: str,
    category: str,
    created_by: str,
    data: bytes,
    declared_content_type: str = "",
) -> Dict[str, Any]:
    """Validate an emoji image, upload to S3, and write the DDB record.

    Raises :class:`CustomEmojiError` for validation failures.
    """
    sc = validate_shortcode(shortcode)

    # File size.
    if len(data) > S.custom_emoji_max_file_size_bytes:
        raise CustomEmojiError(
            "file_too_large",
            "File size exceeds maximum of 256KB.",
            status_code=400,
        )
    if not data:
        raise CustomEmojiError("invalid_content_type", "Only PNG and GIF images are allowed.", status_code=400)

    # MIME via magic bytes (not just declared header).
    content_type = _detect_content_type(data)
    if content_type is None or content_type not in _ALLOWED_MIME:
        raise CustomEmojiError(
            "invalid_content_type",
            "Only PNG and GIF images are allowed.",
            status_code=400,
        )
    ext = _ALLOWED_MIME[content_type]

    # Dimensions via Pillow.
    try:
        from PIL import Image

        with Image.open(io.BytesIO(data)) as img:
            width, height = img.size
    except Exception:
        raise CustomEmojiError(
            "invalid_content_type",
            "Only PNG and GIF images are allowed.",
            status_code=400,
        )
    max_dim = S.custom_emoji_max_dimension_px
    if width > max_dim or height > max_dim:
        raise CustomEmojiError(
            "image_too_large",
            f"Image dimensions must be {max_dim}x{max_dim} pixels or smaller.",
            status_code=400,
        )

    # Uniqueness within scope.
    if _find_by_shortcode(owner_scope, sc) is not None:
        raise CustomEmojiError(
            "shortcode_exists",
            "Shortcode already exists in this scope.",
            status_code=409,
        )

    # Per-user limit (personal scope only — global is admin-managed).
    if owner_scope != GLOBAL_SCOPE:
        if _count_for_creator(created_by) >= S.custom_emoji_max_per_user:
            raise CustomEmojiError(
                "emoji_limit_reached",
                f"Maximum custom emoji limit reached ({S.custom_emoji_max_per_user}).",
                status_code=400,
            )

    emoji_id = _new_emoji_id()
    ts = now_ts()

    s3 = s3_client()
    _ensure_bucket(s3)
    key = f"{S.custom_emoji_s3_prefix}/{quote(owner_scope, safe='')}/{emoji_id}.{ext}"
    try:
        s3.put_object(
            Bucket=S3_BUCKET_IMAGES,
            Key=key,
            Body=data,
            ContentType=content_type,
            ContentDisposition="inline",
        )
    except Exception:
        pass
    image_url = f"/mock/s3/{S3_BUCKET_IMAGES}/{quote(key, safe='/')}"

    item = {
        "owner_scope": owner_scope,
        "emoji_sk": f"EMOJI#{emoji_id}",
        "emoji_id": emoji_id,
        "shortcode": sc,
        "name": (name or sc).strip()[:128],
        "image_url": image_url,
        "alt_text": (alt_text or "").strip()[:256],
        "category": (category or "Uncategorized").strip()[:64] or "Uncategorized",
        "created_by": created_by,
        "created_at": ts,
        "content_type": content_type,
        "file_size_bytes": len(data),
    }
    T.custom_emojis.put_item(Item=item)
    return _emoji_to_out(item)


def _list_scope(owner_scope: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("owner_scope").eq(owner_scope)
            & Key("emoji_sk").begins_with("EMOJI#"),
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.custom_emojis.query(**kwargs)
        for item in resp.get("Items", []):
            out.append(_emoji_to_out(item))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    out.sort(key=lambda e: e.get("created_at", 0), reverse=True)
    return out


def list_personal_emojis(user_sub: str) -> List[Dict[str, Any]]:
    return _list_scope(user_scope(user_sub))


def list_global_emojis() -> List[Dict[str, Any]]:
    return _list_scope(GLOBAL_SCOPE)


def list_visible_emojis(user_sub: str) -> Dict[str, Any]:
    """List all emojis visible to a caller: personal + global merged."""
    personal = list_personal_emojis(user_sub)
    glob = list_global_emojis()
    return {
        "emojis": personal + glob,
        "personal_count": len(personal),
        "global_count": len(glob),
    }


def get_custom_emoji(owner_scope: str, emoji_id: str) -> Optional[Dict[str, Any]]:
    resp = T.custom_emojis.get_item(Key={"owner_scope": owner_scope, "emoji_sk": f"EMOJI#{emoji_id}"})
    item = resp.get("Item")
    return _emoji_to_out(item) if item else None


def delete_custom_emoji(owner_scope: str, emoji_id: str) -> bool:
    """Delete an emoji record and its S3 object. Returns False if not found."""
    existing = get_custom_emoji(owner_scope, emoji_id)
    if existing is None:
        return False
    image_url = existing.get("image_url", "")
    # Best-effort S3 delete (key derived from URL prefix).
    prefix = f"/mock/s3/{S3_BUCKET_IMAGES}/"
    if image_url.startswith(prefix):
        from urllib.parse import unquote

        key = unquote(image_url[len(prefix):])
        try:
            s3_client().delete_object(Bucket=S3_BUCKET_IMAGES, Key=key)
        except Exception:
            pass
    T.custom_emojis.delete_item(Key={"owner_scope": owner_scope, "emoji_sk": f"EMOJI#{emoji_id}"})
    return True


def resolve_custom_shortcodes(user_sub: str, shortcodes: List[str]) -> Dict[str, str]:
    """Resolve shortcodes to image URLs, checking personal then global scope."""
    resolved: Dict[str, str] = {}
    seen: set[str] = set()
    codes: List[str] = []
    for raw in shortcodes:
        sc = (raw or "").strip().lower()
        if not sc or sc in seen:
            continue
        if not _SHORTCODE_RE.match(sc):
            continue
        seen.add(sc)
        codes.append(sc)

    personal = user_scope(user_sub)
    for sc in codes:
        item = _find_by_shortcode(personal, sc)
        if item is None:
            item = _find_by_shortcode(GLOBAL_SCOPE, sc)
        if item is not None:
            resolved[sc] = item.get("image_url", "")
    return resolved
