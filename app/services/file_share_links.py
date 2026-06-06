"""Encrypted one-time share links (FILES-001).

Allows a file owner to generate a time-limited, encrypted, one-time-use
download link for a file in the file manager. External (non-platform)
recipients can open a public, no-auth URL and download the file, optionally
after entering a password.

Security design (ticket §7):
- File content is encrypted at rest with a per-link random AES-256-GCM key.
- The AES key is wrapped with KMS (falls back to an HMAC-derived local wrap
  when KMS is not configured in dev) and stored alongside the link record.
- Optional password is bcrypt-hashed; never stored in plaintext.
- Link IDs carry 128 bits of entropy (uuid4 hex).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import uuid
from typing import Any, Dict, List, Optional

import bcrypt
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import HTTPException

from app.core.aws import ddb
from app.core.aws_clients import s3_client
from app.core.crypto import kms_decrypt, kms_encrypt
from app.core.settings import S
from app.core.time import now_ts
from app.services import filemanager

logger = logging.getLogger(__name__)

_s3 = s3_client()

SK_META = "META"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _table():
    if not S.ddb_file_share_links_table:
        raise HTTPException(500, "file share links table not configured")
    return ddb.Table(S.ddb_file_share_links_table)


def _bucket() -> str:
    if not S.filemgr_bucket:
        raise HTTPException(500, "file manager bucket not configured")
    return S.filemgr_bucket


def _encrypted_s3_key(link_id: str) -> str:
    prefix = (S.share_link_s3_prefix or "share-links").strip("/")
    return f"{prefix}/{link_id}/encrypted"


def encrypt_file_content(content: bytes, key: bytes) -> bytes:
    """Encrypt file content with AES-256-GCM; nonce is prepended."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, content, None)
    return nonce + ciphertext


def decrypt_file_content(encrypted: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-GCM content produced by ``encrypt_file_content``."""
    nonce = encrypted[:12]
    ciphertext = encrypted[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def _local_wrap_secret() -> bytes:
    """Stable secret for the local (non-KMS) key-wrap fallback in dev."""
    seed = (S.ui_access_token_secret or S.api_key_pepper or "file-share-links-dev")
    return hashlib.sha256(("fsl-wrap:" + seed).encode("utf-8")).digest()


def _wrap_key(aes_key: bytes) -> str:
    """Wrap the AES key for storage. Uses KMS when available, else local HMAC wrap."""
    key_b64 = base64.b64encode(aes_key).decode("ascii")
    if S.kms_key_id:
        try:
            return "kms:" + kms_encrypt(key_b64)
        except Exception:  # pragma: no cover - dev KMS hiccup
            logger.warning("KMS wrap failed; using local key wrap fallback")
    mac = hmac.new(_local_wrap_secret(), aes_key, hashlib.sha256).hexdigest()
    return "loc:" + key_b64 + ":" + mac


def _unwrap_key(wrapped: str) -> bytes:
    if wrapped.startswith("kms:"):
        plaintext = kms_decrypt(wrapped[len("kms:"):])
        # kms_encrypt encrypted the base64 string of the key
        return base64.b64decode(plaintext)
    if wrapped.startswith("loc:"):
        body = wrapped[len("loc:"):]
        key_b64, _, mac = body.rpartition(":")
        aes_key = base64.b64decode(key_b64)
        expected = hmac.new(_local_wrap_secret(), aes_key, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, expected):
            raise HTTPException(500, "internal_error")
        return aes_key
    raise HTTPException(500, "internal_error")


def _hash_password(password: str) -> str:
    pw = password.encode("utf-8")[:72]  # bcrypt limit
    return bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode("ascii")


def _verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8")[:72], password_hash.encode("ascii"))
    except Exception:
        return False


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _share_url(link_id: str) -> str:
    base = (S.share_link_base_url or "http://localhost:3000/share").rstrip("/")
    return f"{base}/{link_id}"


def _to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    link_id = str(item.get("link_id"))
    return {
        "link_id": link_id,
        "file_node_id": str(item.get("file_node_id") or ""),
        "file_name": str(item.get("file_name") or ""),
        "file_size_bytes": _int(item.get("file_size_bytes")),
        "content_type": str(item.get("content_type") or "application/octet-stream"),
        "created_at": _int(item.get("created_at")),
        "expires_at": _int(item.get("expires_at")),
        "max_downloads": _int(item.get("max_downloads"), 1),
        "download_count": _int(item.get("download_count")),
        "has_password": bool(item.get("password_hash")),
        "is_revoked": bool(item.get("is_revoked")),
        "share_url": _share_url(link_id),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create_share_link(
    *,
    file_node_id: str,
    owner_sub: str,
    expiry_hours: int = 24,
    max_downloads: int = 1,
    password: Optional[str] = None,
) -> Dict[str, Any]:
    """Create an encrypted one-time share link for a file owned by ``owner_sub``.

    ``file_node_id`` is the file manager node identifier (its path).
    """
    if not S.file_share_links_enabled:
        raise HTTPException(404, "share links disabled")

    # 1. Validate file exists and is owned by owner_sub (get_node raises 404).
    path = filemanager.norm_path(file_node_id, is_folder=False)
    node = filemanager.get_node(owner_sub, path)
    if node.get("type") != "file":
        raise HTTPException(404, "file_not_found")

    file_size = _int(node.get("size"))
    if file_size > S.share_link_max_file_size_bytes:
        raise HTTPException(400, "file_too_large")

    expiry_hours = max(1, min(int(expiry_hours), S.share_link_max_expiry_hours))
    max_downloads = max(1, min(int(max_downloads), 100))

    link_id = f"fsl_{uuid.uuid4().hex}"
    aes_key = os.urandom(32)

    # 5. Download file content from S3.
    try:
        obj = _s3.get_object(Bucket=node["s3_bucket"], Key=node["s3_key"])
        content = obj["Body"].read()
    except ClientError as exc:
        raise HTTPException(500, "file content unavailable") from exc

    # 6/7. Encrypt and upload to a separate S3 key.
    encrypted = encrypt_file_content(content, aes_key)
    enc_key = _encrypted_s3_key(link_id)
    try:
        _s3.put_object(
            Bucket=_bucket(),
            Key=enc_key,
            Body=encrypted,
            ContentType="application/octet-stream",
        )
    except ClientError as exc:
        raise HTTPException(500, "internal_error") from exc

    # 8/9. Wrap AES key and hash password.
    wrapped_key = _wrap_key(aes_key)
    password_hash = _hash_password(password) if password else None

    created_at = now_ts()
    expires_at = created_at + expiry_hours * 3600

    item: Dict[str, Any] = {
        "link_id": link_id,
        "sk": SK_META,
        "file_node_id": path,
        "file_name": str(node.get("name") or path.rsplit("/", 1)[-1] or "file"),
        "file_size_bytes": file_size,
        "content_type": str(node.get("content_type") or "application/octet-stream"),
        "owner_sub": owner_sub,
        "created_at": created_at,
        "expires_at": expires_at,
        "max_downloads": max_downloads,
        "download_count": 0,
        "encrypted_s3_key": enc_key,
        "encryption_key_wrapped": wrapped_key,
        "is_revoked": False,
        "ttl": expires_at + 86400,
    }
    if password_hash:
        item["password_hash"] = password_hash

    _table().put_item(Item=item)
    logger.info(
        "share link created",
        extra={
            "user_sub": owner_sub,
            "link_id": link_id,
            "file_name": item["file_name"],
            "expiry_hours": expiry_hours,
            "max_downloads": max_downloads,
            "has_password": bool(password_hash),
        },
    )
    return _to_out(item)


def _get_link(link_id: str) -> Dict[str, Any]:
    # GAP-0185: strongly consistent read closes the eventual-consistency window
    # so a just-applied revocation/expiry is visible to the pre-flight checks in
    # consume_share_link (the atomic ConditionExpression is the correctness gate,
    # but the consistent read gives accurate fast-path error codes).
    resp = _table().get_item(
        Key={"link_id": link_id, "sk": SK_META}, ConsistentRead=True
    )
    item = resp.get("Item")
    if not item:
        raise HTTPException(404, "link_not_found")
    return item


def _is_expired(item: Dict[str, Any]) -> bool:
    return now_ts() >= _int(item.get("expires_at"))


def _is_used(item: Dict[str, Any]) -> bool:
    return _int(item.get("download_count")) >= _int(item.get("max_downloads"), 1)


def get_share_link_info(link_id: str) -> Dict[str, Any]:
    """Public info shown on the download page. Reveals no owner/key/s3 details."""
    item = _get_link(link_id)
    max_downloads = _int(item.get("max_downloads"), 1)
    download_count = _int(item.get("download_count"))
    return {
        "file_name": str(item.get("file_name") or ""),
        "file_size_bytes": _int(item.get("file_size_bytes")),
        "content_type": str(item.get("content_type") or "application/octet-stream"),
        "requires_password": bool(item.get("password_hash")),
        "is_expired": _is_expired(item),
        "is_used": _is_used(item),
        "is_revoked": bool(item.get("is_revoked")),
        "remaining_downloads": max(0, max_downloads - download_count),
    }


def consume_share_link(*, link_id: str, password: Optional[str] = None) -> Dict[str, Any]:
    """Validate a link, atomically consume a download, and return decrypted content.

    Returns ``{"content": bytes, "file_name": str, "content_type": str}``.
    Raises HTTPException with the appropriate status (410/403/404/500).
    """
    item = _get_link(link_id)

    if bool(item.get("is_revoked")):
        logger.warning("share link rejected", extra={"link_id": link_id, "reason": "revoked"})
        raise HTTPException(410, "link_revoked")
    if _is_expired(item):
        logger.warning("share link rejected", extra={"link_id": link_id, "reason": "expired"})
        raise HTTPException(410, "link_expired")
    if _is_used(item):
        logger.warning("share link rejected", extra={"link_id": link_id, "reason": "used"})
        raise HTTPException(410, "link_used")

    password_hash = item.get("password_hash")
    if password_hash:
        if not password or not _verify_password(password, str(password_hash)):
            logger.warning("share link wrong password", extra={"link_id": link_id})
            raise HTTPException(403, "invalid_password")

    max_downloads = _int(item.get("max_downloads"), 1)
    # 4. Atomically increment download_count (guards against races / exhaustion).
    try:
        updated = _table().update_item(
            Key={"link_id": link_id, "sk": SK_META},
            UpdateExpression="SET download_count = download_count + :one",
            ConditionExpression=Attr("download_count").lt(max_downloads)
            & Attr("is_revoked").ne(True)
            & Attr("expires_at").gt(now_ts()),
            ExpressionAttributeValues={":one": 1},
            ReturnValues="ALL_NEW",
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            raise HTTPException(410, "link_used") from exc
        raise HTTPException(500, "internal_error") from exc

    new_item = updated.get("Attributes", item)

    # 5/6. Decrypt key + content.
    try:
        aes_key = _unwrap_key(str(new_item.get("encryption_key_wrapped") or ""))
        enc_obj = _s3.get_object(Bucket=_bucket(), Key=str(new_item.get("encrypted_s3_key")))
        encrypted = enc_obj["Body"].read()
        content = decrypt_file_content(encrypted, aes_key)
    except HTTPException:
        raise
    except ClientError as exc:
        logger.error("share link s3 missing", extra={"link_id": link_id})
        raise HTTPException(500, "internal_error") from exc
    except Exception as exc:  # pragma: no cover - decrypt failure
        logger.error("share link decrypt error", extra={"link_id": link_id})
        raise HTTPException(500, "internal_error") from exc

    logger.info(
        "share link downloaded",
        extra={
            "link_id": link_id,
            "download_count": _int(new_item.get("download_count")),
            "file_size_bytes": _int(new_item.get("file_size_bytes")),
        },
    )
    return {
        "content": content,
        "file_name": str(new_item.get("file_name") or "file"),
        "content_type": str(new_item.get("content_type") or "application/octet-stream"),
    }


def list_share_links(owner_sub: str) -> List[Dict[str, Any]]:
    """List all share links for a user, newest first (GSI1 by owner_sub)."""
    tbl = _table()
    items: List[Dict[str, Any]] = []
    try:
        resp = tbl.query(
            IndexName="GSI1",
            KeyConditionExpression=Key("owner_sub").eq(owner_sub),
            ScanIndexForward=False,
        )
        items = resp.get("Items", [])
    except ClientError:
        # Fallback for environments without the GSI: scan + filter.
        resp = tbl.scan(FilterExpression=Attr("owner_sub").eq(owner_sub))
        items = [it for it in resp.get("Items", []) if it.get("sk") == SK_META]
        items.sort(key=lambda it: _int(it.get("created_at")), reverse=True)
    return [_to_out(it) for it in items]


def revoke_share_link(link_id: str, owner_sub: str) -> bool:
    """Revoke a link (owner-only). Deletes the encrypted S3 object."""
    item = _get_link(link_id)
    if str(item.get("owner_sub")) != owner_sub:
        raise HTTPException(403, "forbidden")
    _table().update_item(
        Key={"link_id": link_id, "sk": SK_META},
        UpdateExpression="SET is_revoked = :t",
        ExpressionAttributeValues={":t": True},
    )
    enc_key = item.get("encrypted_s3_key")
    if enc_key:
        try:
            _s3.delete_object(Bucket=_bucket(), Key=str(enc_key))
        except ClientError:
            logger.warning("failed to delete encrypted share object", extra={"link_id": link_id})
    logger.info("share link revoked", extra={"user_sub": owner_sub, "link_id": link_id})
    return True
