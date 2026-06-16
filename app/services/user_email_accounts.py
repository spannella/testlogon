"""Per-user IMAP/SMTP email account credential vault (EML-003).

Each user can register up to ``_MAX_ACCOUNTS_PER_USER`` external email accounts.
Passwords are KMS-encrypted at rest (``password_ct_b64``).  A lightweight
``verify_connection`` endpoint checks IMAP reachability.

Table: user_email_accounts
  PK: USER#{user_sub}
  SK: ACCT#{account_id}

GSI ByUser:
  PK: pk (USER#{user_sub})
  SK: created_at (N)
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.crypto import kms_decrypt, kms_encrypt
from app.core.cursor import decode_cursor, encode_cursor
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

_MAX_ACCOUNTS_PER_USER = 20
_PASSWORD_FIELD = "password_ct_b64"

# Fields returned to API callers (never includes password_ct_b64)
_SAFE_FIELDS = {
    "account_id",
    "label",
    "imap_host",
    "imap_port",
    "imap_use_ssl",
    "smtp_host",
    "smtp_port",
    "smtp_use_tls",
    "username",
    "is_default",
    "created_at",
    "updated_at",
    "status",
    "last_error",
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AccountNotFound(Exception):
    pass


class LimitExceeded(Exception):
    pass


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _strip_password(item: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in item.items() if k in _SAFE_FIELDS}


def _pk(user_sub: str) -> str:
    return f"USER#{user_sub}"


def _sk(account_id: str) -> str:
    return f"ACCT#{account_id}"


def _validate_host(host: str, field: str) -> str:
    """Strip whitespace and reject control characters."""
    host = host.strip()
    if not host:
        raise HTTPException(status_code=400, detail=f"{field} must not be empty")
    if any(c in host for c in ("\n", "\r", "\x00")):
        raise HTTPException(status_code=400, detail=f"{field} contains invalid characters")
    return host


def _clear_existing_defaults(user_sub: str) -> None:
    """Clear is_default flag on any existing default account."""
    try:
        resp = T.user_email_accounts.query(
            IndexName="ByUser",
            KeyConditionExpression=Key("pk").eq(_pk(user_sub)),
            FilterExpression=Attr("is_default").eq(True),
        )
        for item in resp.get("Items", []):
            if not item.get("account_id"):
                continue
            T.user_email_accounts.update_item(
                Key={"pk": _pk(user_sub), "sk": _sk(item["account_id"])},
                UpdateExpression="SET is_default = :v, updated_at = :ua",
                ExpressionAttributeValues={":v": False, ":ua": now_ts()},
            )
    except Exception:
        logger.exception("Failed to clear existing default accounts for %s", user_sub)


# ---------------------------------------------------------------------------
# IMAP connection factory (patchable in tests)
# ---------------------------------------------------------------------------


def _get_imap_client(host: str, port: int, use_ssl: bool):
    import imaplib
    if use_ssl:
        return imaplib.IMAP4_SSL(host, port)
    return imaplib.IMAP4(host, port)


# ---------------------------------------------------------------------------
# Public CRUD
# ---------------------------------------------------------------------------


def create_account(user_sub: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Create a new email account entry (credentials encrypted at rest)."""
    from app.core.normalize import normalize_email
    from app.services.alerts import audit_event

    label = str(payload.get("label", "")).strip()
    if not label or len(label) > 100:
        raise HTTPException(status_code=400, detail="label must be 1-100 characters")

    imap_host = _validate_host(str(payload.get("imap_host", "")), "imap_host")
    smtp_host = _validate_host(str(payload.get("smtp_host", "")), "smtp_host")

    username = str(payload.get("username", ""))
    try:
        username = normalize_email(username)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    imap_port = int(payload.get("imap_port", 993))
    smtp_port = int(payload.get("smtp_port", 587))

    password = str(payload.get("password", ""))
    if not password:
        raise HTTPException(status_code=400, detail="password is required")

    # Enforce per-user account cap
    try:
        resp = T.user_email_accounts.query(
            IndexName="ByUser",
            KeyConditionExpression=Key("pk").eq(_pk(user_sub)),
            Select="COUNT",
        )
        if resp.get("Count", 0) >= _MAX_ACCOUNTS_PER_USER:
            raise HTTPException(status_code=400, detail="Maximum email accounts reached")
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to count accounts for %s", user_sub)

    try:
        password_ct_b64 = kms_encrypt(password)
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail="credential encryption is not configured") from exc

    account_id = uuid.uuid4().hex
    is_default = bool(payload.get("is_default", False))
    if is_default:
        _clear_existing_defaults(user_sub)

    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": _pk(user_sub),
        "sk": _sk(account_id),
        "account_id": account_id,
        "label": label,
        "imap_host": imap_host,
        "imap_port": imap_port,
        "imap_use_ssl": bool(payload.get("imap_use_ssl", True)),
        "smtp_host": smtp_host,
        "smtp_port": smtp_port,
        "smtp_use_tls": bool(payload.get("smtp_use_tls", True)),
        "username": username,
        "password_ct_b64": password_ct_b64,
        "is_default": is_default,
        "status": "unverified",
        "last_error": None,
        "created_at": ts,
        "updated_at": ts,
    }

    T.user_email_accounts.put_item(Item=item)

    try:
        audit_event("email_account_created", user_sub, account_id=account_id, label=label)
    except Exception:
        logger.exception("Failed to audit email_account_created")

    return _strip_password(item)


def list_accounts(
    user_sub: str,
    *,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """List accounts for a user via ByUser GSI, oldest first."""
    limit = min(max(1, limit), 100)
    kwargs: Dict[str, Any] = {
        "IndexName": "ByUser",
        "KeyConditionExpression": Key("pk").eq(_pk(user_sub)),
        "ScanIndexForward": True,
        "Limit": limit,
    }
    if cursor:
        try:
            kwargs["ExclusiveStartKey"] = decode_cursor(cursor)
        except Exception:
            pass

    try:
        resp = T.user_email_accounts.query(**kwargs)
    except Exception:
        logger.exception("Failed to list accounts for %s", user_sub)
        return [], None

    items = [_strip_password(it) for it in resp.get("Items", []) if it.get("account_id")]
    next_cursor = encode_cursor(resp["LastEvaluatedKey"]) if resp.get("LastEvaluatedKey") else None
    return items, next_cursor


def get_account(user_sub: str, account_id: str) -> Optional[Dict[str, Any]]:
    """Return the raw account item (including password_ct_b64) or None."""
    try:
        resp = T.user_email_accounts.get_item(
            Key={"pk": _pk(user_sub), "sk": _sk(account_id)}
        )
        return resp.get("Item")
    except Exception:
        logger.exception("Failed to get account %s for %s", account_id, user_sub)
        return None


def update_account(
    user_sub: str,
    account_id: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """Update mutable account fields.  Raises AccountNotFound (→ 404) if absent."""
    from app.core.normalize import normalize_email
    from app.services.alerts import audit_event

    existing = get_account(user_sub, account_id)
    if not existing:
        raise AccountNotFound(account_id)

    set_parts: List[str] = ["updated_at = :ua"]
    values: Dict[str, Any] = {":ua": now_ts()}
    names: Dict[str, str] = {}
    credential_changed = False

    if "label" in payload and payload["label"] is not None:
        label = str(payload["label"]).strip()
        if not label or len(label) > 100:
            raise HTTPException(status_code=400, detail="label must be 1-100 characters")
        set_parts.append("#lbl = :lbl")
        names["#lbl"] = "label"
        values[":lbl"] = label

    for field in ("imap_host", "smtp_host"):
        if field in payload and payload[field] is not None:
            host = _validate_host(str(payload[field]), field)
            set_parts.append(f"{field} = :{field}")
            values[f":{field}"] = host
            credential_changed = True

    for field in ("imap_port", "smtp_port"):
        if field in payload and payload[field] is not None:
            set_parts.append(f"{field} = :{field}")
            values[f":{field}"] = int(payload[field])

    for field in ("imap_use_ssl", "smtp_use_tls"):
        if field in payload and payload[field] is not None:
            set_parts.append(f"{field} = :{field}")
            values[f":{field}"] = bool(payload[field])

    if "username" in payload and payload["username"] is not None:
        try:
            username = normalize_email(str(payload["username"]))
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        set_parts.append("username = :username")
        values[":username"] = username
        credential_changed = True

    if "password" in payload and payload["password"]:
        try:
            password_ct_b64 = kms_encrypt(str(payload["password"]))
        except RuntimeError as exc:
            raise HTTPException(status_code=500, detail="credential encryption is not configured") from exc
        set_parts.append("password_ct_b64 = :pct")
        values[":pct"] = password_ct_b64
        credential_changed = True

    if credential_changed:
        set_parts.append("#st = :st")
        names["#st"] = "status"
        values[":st"] = "unverified"

    is_default = payload.get("is_default")
    if is_default is True:
        _clear_existing_defaults(user_sub)
        set_parts.append("is_default = :isd")
        values[":isd"] = True
    elif is_default is False:
        set_parts.append("is_default = :isd")
        values[":isd"] = False

    kwargs: Dict[str, Any] = {
        "Key": {"pk": _pk(user_sub), "sk": _sk(account_id)},
        "UpdateExpression": "SET " + ", ".join(set_parts),
        "ExpressionAttributeValues": values,
        "ReturnValues": "ALL_NEW",
    }
    if names:
        kwargs["ExpressionAttributeNames"] = names

    try:
        resp = T.user_email_accounts.update_item(**kwargs)
        updated = resp.get("Attributes", existing)
    except Exception:
        logger.exception("Failed to update account %s", account_id)
        updated = get_account(user_sub, account_id) or existing

    try:
        audit_event("email_account_updated", user_sub, account_id=account_id)
    except Exception:
        logger.exception("Failed to audit email_account_updated")

    return _strip_password(updated)


def delete_account(user_sub: str, account_id: str) -> None:
    """Delete an account. Raises AccountNotFound if absent."""
    from app.services.alerts import audit_event

    existing = get_account(user_sub, account_id)
    if not existing:
        raise AccountNotFound(account_id)

    T.user_email_accounts.delete_item(Key={"pk": _pk(user_sub), "sk": _sk(account_id)})

    try:
        audit_event("email_account_deleted", user_sub, account_id=account_id)
    except Exception:
        logger.exception("Failed to audit email_account_deleted")


def verify_connection(user_sub: str, account_id: str) -> Dict[str, Any]:
    """Attempt an IMAP login to check credentials.  Never raises; returns ok bool."""
    from app.services.alerts import audit_event

    item = get_account(user_sub, account_id)
    if not item:
        raise HTTPException(status_code=404, detail="Account not found")

    try:
        password = kms_decrypt(item["password_ct_b64"]).decode("utf-8")
    except Exception as exc:
        logger.exception("Failed to decrypt password for account %s", account_id)
        return {"ok": False, "status": "error", "detail": "password decryption failed"}

    ts = now_ts()
    try:
        imap = _get_imap_client(item["imap_host"], int(item["imap_port"]), bool(item.get("imap_use_ssl", True)))
        imap.login(item["username"], password)
        imap.logout()
        # Update status to active
        T.user_email_accounts.update_item(
            Key={"pk": _pk(user_sub), "sk": _sk(account_id)},
            UpdateExpression="SET #st = :st, last_error = :le, updated_at = :ua",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":st": "active", ":le": None, ":ua": ts},
        )
        try:
            audit_event("email_account_verified", user_sub, account_id=account_id)
        except Exception:
            pass
        return {"ok": True, "status": "active"}
    except Exception as exc:
        detail = str(exc)[:500]
        try:
            T.user_email_accounts.update_item(
                Key={"pk": _pk(user_sub), "sk": _sk(account_id)},
                UpdateExpression="SET #st = :st, last_error = :le, updated_at = :ua",
                ExpressionAttributeNames={"#st": "status"},
                ExpressionAttributeValues={":st": "error", ":le": detail, ":ua": ts},
            )
        except Exception:
            pass
        try:
            audit_event("email_account_verify_failed", user_sub, account_id=account_id, error=detail)
        except Exception:
            pass
        return {"ok": False, "status": "error", "detail": detail}
