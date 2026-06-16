"""IMAP inbox synchronisation and email threading (EML-004).

Fetches messages from a user's registered IMAP account (EML-003) and stores
them in ``user_email_messages``.  Large HTML bodies are spilled to S3.
Thread IDs are derived from RFC-2822 ``Message-ID`` / ``References`` headers.

All public functions are synchronous (call via ``asyncio.to_thread`` from routers).
"""
from __future__ import annotations

import email as _email_lib
import email.header
import email.parser
import email.policy
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


# ---------------------------------------------------------------------------
# Mock IMAP client for dev mode
# ---------------------------------------------------------------------------

_MOCK_RAW_1 = (
    b"From: sender@example.com\r\n"
    b"To: user@example.com\r\n"
    b"Subject: Mock Message 1\r\n"
    b"Message-ID: <mock-root-001@dev.local>\r\n"
    b"Date: Thu, 01 Jan 2026 10:00:00 +0000\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"Hello from dev.\r\n"
)

_MOCK_RAW_2 = (
    b"From: user@example.com\r\n"
    b"To: sender@example.com\r\n"
    b"Subject: Re: Mock Message 1\r\n"
    b"Message-ID: <mock-reply-001@dev.local>\r\n"
    b"In-Reply-To: <mock-root-001@dev.local>\r\n"
    b"References: <mock-root-001@dev.local>\r\n"
    b"Date: Thu, 01 Jan 2026 11:00:00 +0000\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"Dev reply.\r\n"
)


class _MockImapClient:
    """Deterministic mock IMAP client for dev/test mode."""

    def select(self, folder: str = "INBOX"):
        return ("OK", [b"2"])

    def uid(self, command: str, *args):
        command = command.lower()
        if command == "search":
            return ("OK", [b"1 2"])
        if command == "fetch":
            uid_str = str(args[0]) if args else b""
            return (
                "OK",
                [
                    (b"1 (RFC822 {%d}" % len(_MOCK_RAW_1), _MOCK_RAW_1),
                    b")",
                    (b"2 (RFC822 {%d}" % len(_MOCK_RAW_2), _MOCK_RAW_2),
                    b")",
                ],
            )
        return ("OK", [b""])

    def logout(self):
        pass


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _open_imap(account: Dict[str, Any]):
    """Decrypt password and return an IMAP client (mock in dev mode)."""
    from app.core.crypto import kms_decrypt

    if S.dev_mode:
        return _MockImapClient()

    password = kms_decrypt(account["password_ct_b64"]).decode("utf-8")
    import imaplib
    import socket

    host = account["imap_host"]
    port = int(account.get("imap_port", 993))
    use_ssl = bool(account.get("imap_use_ssl", True))
    timeout = S.email_imap_timeout_seconds

    try:
        if use_ssl:
            imap = imaplib.IMAP4_SSL(host, port)
        else:
            imap = imaplib.IMAP4(host, port)
        imap.login(account["username"], password)
        return imap
    except (imaplib.IMAP4.error, socket.timeout, OSError) as exc:
        raise HTTPException(
            status_code=503,
            detail={"code": "imap_connect_failed", "message": str(exc)},
        ) from exc


def _decode_header_value(value: Optional[str]) -> str:
    if not value:
        return ""
    parts = email.header.decode_header(value)
    decoded = []
    for raw, charset in parts:
        if isinstance(raw, bytes):
            decoded.append(raw.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(str(raw))
    return "".join(decoded)


def _parse_message_id(raw: str) -> str:
    """Strip angle brackets from a Message-ID."""
    return raw.strip().strip("<>").strip()


def _extract_references(raw: str) -> List[str]:
    """Split a References header into individual Message-IDs."""
    parts = raw.strip().split()
    return [_parse_message_id(p) for p in parts if p]


def _spill_html_to_s3(user_sub: str, account_id: str, uid: int, html: str) -> str:
    """Upload HTML body to S3 and return the object key."""
    from app.core.aws_clients import s3_client
    key = f"{S.email_bodies_s3_prefix}{user_sub}/{account_id}/{uid}.html"
    try:
        s3_client().put_object(
            Bucket=S.email_bodies_s3_bucket,
            Key=key,
            Body=html.encode("utf-8"),
            ContentType="text/html; charset=utf-8",
        )
    except Exception:
        # Ensure bucket exists (dev bootstrap)
        try:
            s3_client().create_bucket(Bucket=S.email_bodies_s3_bucket)
            s3_client().put_object(
                Bucket=S.email_bodies_s3_bucket,
                Key=key,
                Body=html.encode("utf-8"),
                ContentType="text/html; charset=utf-8",
            )
        except Exception:
            logger.exception("Failed to spill HTML body to S3 for uid %d", uid)
            raise
    return key


def _parse_message(raw: bytes, uid: int, folder: str) -> Dict[str, Any]:
    """Parse a raw RFC-2822 message into a DDB-ready dict."""
    try:
        msg = email.parser.BytesParser(policy=email.policy.compat32).parsebytes(raw)
    except Exception:
        msg = None

    if msg is None:
        return {}

    # Headers
    message_id_raw = msg.get("Message-ID", f"<synthetic-{uid}@local>")
    message_id = _parse_message_id(message_id_raw)
    in_reply_to_raw = msg.get("In-Reply-To", "")
    in_reply_to = _parse_message_id(in_reply_to_raw) if in_reply_to_raw else None
    references_raw = msg.get("References", "")
    references = _extract_references(references_raw) if references_raw else []

    subject = _decode_header_value(msg.get("Subject", ""))[:500]
    from_addr = _decode_header_value(msg.get("From", ""))[:320]

    to_raw = msg.get("To", "")
    to_addrs = [_decode_header_value(a.strip()) for a in to_raw.split(",") if a.strip()] if to_raw else []

    cc_raw = msg.get("Cc", "")
    cc_addrs = [_decode_header_value(a.strip()) for a in cc_raw.split(",") if a.strip()] if cc_raw else []

    # Date parsing
    from email.utils import parsedate_to_datetime
    date_ts = now_ts()
    date_str = msg.get("Date", "")
    if date_str:
        try:
            dt = parsedate_to_datetime(date_str)
            date_ts = int(dt.timestamp())
        except Exception:
            pass

    # Body extraction
    body_text = ""
    body_html = ""
    has_attachments = False

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = part.get("Content-Disposition", "")
            if disp.startswith("attachment"):
                has_attachments = True
                continue
            charset = part.get_content_charset() or "utf-8"
            if ctype == "text/plain" and not body_text:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_text += payload.decode(charset, errors="replace")
                except Exception:
                    pass
            elif ctype == "text/html" and not body_html:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_html = payload.decode(charset, errors="replace")
                except Exception:
                    pass
    else:
        ctype = msg.get_content_type()
        charset = msg.get_content_charset() or "utf-8"
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                text = payload.decode(charset, errors="replace")
                if ctype == "text/html":
                    body_html = text
                else:
                    body_text = text
        except Exception:
            pass

    body_text = body_text[:32768]
    snippet = body_text[:200]

    result: Dict[str, Any] = {
        "uid": uid,
        "message_id": message_id,
        "in_reply_to": in_reply_to,
        "references": references[:10],
        "subject": subject,
        "from_addr": from_addr,
        "to_addrs": to_addrs,
        "cc_addrs": cc_addrs,
        "date_ts": date_ts,
        "folder": folder,
        "flags": [],
        "snippet": snippet,
        "body_text": body_text,
        "has_attachments": has_attachments,
        "synced_at": now_ts(),
    }

    # HTML spill handled by caller
    if body_html:
        result["_body_html"] = body_html  # temp key for caller

    return result


def _fetch_uids_from_mock(imap: _MockImapClient, folder: str, since_uid: int, max_fetch: int) -> List[int]:
    imap.select(folder)
    status, data = imap.uid("search", None, f"UID {since_uid}:*")
    if status != "OK" or not data or not data[0]:
        return []
    uid_strs = data[0].split()
    uids = [int(u) for u in uid_strs if int(u) > since_uid or since_uid == 0]
    return uids[:max_fetch]


def derive_thread_id(
    message_id: str,
    in_reply_to: Optional[str],
    references: List[str],
    *,
    user_sub: str,
    account_id: str,
) -> str:
    """Compute stable thread_id.

    Algorithm:
    1. Collect candidates (references + in_reply_to + message_id).
    2. For each, check if a message with that thread_id hash already exists.
    3. First match wins.  If none, return sha256(message_id)[:16].
    """
    pk = f"USER#{user_sub}#ACCT#{account_id}"
    candidates = references[:10] + ([in_reply_to] if in_reply_to else []) + [message_id]

    for cand in candidates:
        if not cand:
            continue
        candidate_hash = hashlib.sha256(cand.encode("utf-8")).hexdigest()[:16]
        # Check ByThread GSI
        try:
            resp = T.user_email_messages.query(
                IndexName="ByThread",
                KeyConditionExpression=Key("pk").eq(pk) & Key("thread_id").eq(candidate_hash),
                Limit=1,
                Select="COUNT",
            )
            if resp.get("Count", 0) > 0:
                return candidate_hash
        except Exception:
            pass

    return hashlib.sha256(message_id.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Public service functions
# ---------------------------------------------------------------------------


def sync_inbox(
    user_sub: str,
    account_id: str,
    *,
    folder: str = "INBOX",
    max_fetch: Optional[int] = None,
) -> Dict[str, Any]:
    """Fetch new messages from IMAP and upsert into user_email_messages.

    Returns {"synced": int, "folder": str, "last_uid": int}.
    Raises HTTPException 404 if account not found, 503 on IMAP failure.
    """
    from app.services.user_email_accounts import get_account
    from app.services.alerts import audit_event

    account = get_account(user_sub, account_id)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    _max = max_fetch if max_fetch else S.email_imap_max_fetch

    pk = f"USER#{user_sub}#ACCT#{account_id}"
    cursor_sk = "SYNC#CURSOR"

    # Read sync cursor
    last_uid = 0
    try:
        resp = T.user_email_messages.get_item(Key={"pk": pk, "sk": cursor_sk})
        cursor_item = resp.get("Item")
        if cursor_item:
            last_uid = int(cursor_item.get("last_uid", 0))
    except Exception:
        pass

    try:
        imap = _open_imap(account)
    except HTTPException:
        # Update account status on connect failure
        try:
            from app.services.user_email_accounts import _pk, _sk
            T.user_email_accounts.update_item(
                Key={"pk": _pk(user_sub), "sk": _sk(account_id)},
                UpdateExpression="SET #st = :st, last_error = :le, updated_at = :ua",
                ExpressionAttributeNames={"#st": "status"},
                ExpressionAttributeValues={":st": "error", ":le": "imap_connect_failed", ":ua": now_ts()},
            )
        except Exception:
            pass
        raise

    synced_count = 0
    fetched_uids: List[int] = []

    try:
        if isinstance(imap, _MockImapClient):
            uids = _fetch_uids_from_mock(imap, folder, last_uid, _max)
        else:
            imap.select(folder)
            since = last_uid + 1 if last_uid > 0 else 1
            status, data = imap.uid("search", None, f"UID {since}:*")
            if status != "OK" or not data or not data[0]:
                uids = []
            else:
                all_uids = [int(u) for u in data[0].split() if data[0]]
                uids = all_uids[:_max]

        for uid in uids:
            try:
                if isinstance(imap, _MockImapClient):
                    # Fetch specific mock messages
                    raw = _MOCK_RAW_1 if uid == 1 else _MOCK_RAW_2
                else:
                    status, msg_data = imap.uid("fetch", str(uid), "(RFC822)")
                    if status != "OK" or not msg_data:
                        continue
                    raw = None
                    for part in msg_data:
                        if isinstance(part, tuple):
                            raw = part[1]
                            break
                    if not raw:
                        continue

                parsed = _parse_message(raw, uid, folder)
                if not parsed:
                    continue

                body_html = parsed.pop("_body_html", "")
                body_html_s3_key = None
                if body_html and len(body_html) > 65536:
                    try:
                        body_html_s3_key = _spill_html_to_s3(user_sub, account_id, uid, body_html)
                        body_html = ""
                    except Exception:
                        body_html_s3_key = None

                thread_id = derive_thread_id(
                    parsed.get("message_id", f"synthetic-{uid}@local"),
                    parsed.get("in_reply_to"),
                    parsed.get("references", []),
                    user_sub=user_sub,
                    account_id=account_id,
                )

                item: Dict[str, Any] = {
                    "pk": pk,
                    "sk": f"MSG#{uid:010d}",
                    "folder_pk": f"USER#{user_sub}#ACCT#{account_id}#FOLDER#{folder}",
                    "thread_id": thread_id,
                    "ttl_epoch": now_ts() + S.email_messages_ttl_days * 86400,
                    **parsed,
                }
                if body_html:
                    item["body_html"] = body_html[:65536]
                if body_html_s3_key:
                    item["body_html_s3_key"] = body_html_s3_key

                T.user_email_messages.put_item(Item=item)
                fetched_uids.append(uid)
                synced_count += 1
            except Exception:
                logger.exception("Failed to process uid %d", uid)

        if isinstance(imap, _MockImapClient):
            imap.logout()
        else:
            imap.logout()

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("IMAP sync failed for account %s", account_id)
        raise HTTPException(status_code=503, detail={"code": "imap_sync_failed", "message": str(exc)}) from exc

    if fetched_uids:
        new_last_uid = max(fetched_uids)
        try:
            T.user_email_messages.put_item(Item={
                "pk": pk,
                "sk": cursor_sk,
                "folder": folder,
                "last_uid": new_last_uid,
                "last_synced_at": now_ts(),
            })
        except Exception:
            logger.exception("Failed to write sync cursor")
        last_uid = new_last_uid

    try:
        audit_event("email_inbox_synced", user_sub, account_id=account_id, folder=folder, synced=synced_count)
    except Exception:
        pass

    return {"synced": synced_count, "folder": folder, "last_uid": last_uid}


def list_messages(
    user_sub: str,
    account_id: str,
    folder: str,
    *,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Query ByFolder GSI newest-first."""
    limit = min(max(1, limit), 200)
    folder_pk = f"USER#{user_sub}#ACCT#{account_id}#FOLDER#{folder}"
    kwargs: Dict[str, Any] = {
        "IndexName": "ByFolder",
        "KeyConditionExpression": Key("folder_pk").eq(folder_pk),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        try:
            kwargs["ExclusiveStartKey"] = decode_cursor(cursor)
        except Exception:
            pass

    try:
        resp = T.user_email_messages.query(**kwargs)
    except Exception:
        logger.exception("Failed to list messages")
        return [], None

    items = []
    for it in resp.get("Items", []):
        if it.get("sk", "").startswith("SYNC#"):
            continue
        out = {k: v for k, v in it.items() if k not in ("pk", "sk", "folder_pk", "ttl_epoch", "_body_html")}
        # Strip body fields from list response
        out.pop("body_text", None)
        out.pop("body_html", None)
        out.pop("body_html_s3_key", None)
        items.append(out)

    next_cursor = encode_cursor(resp["LastEvaluatedKey"]) if resp.get("LastEvaluatedKey") else None
    return items, next_cursor


def get_message(user_sub: str, account_id: str, uid: int) -> Optional[Dict[str, Any]]:
    """Fetch one message by UID.  Injects body_html_url when body is spilled to S3."""
    pk = f"USER#{user_sub}#ACCT#{account_id}"
    try:
        resp = T.user_email_messages.get_item(Key={"pk": pk, "sk": f"MSG#{uid:010d}"})
        item = resp.get("Item")
    except Exception:
        logger.exception("Failed to get message uid %d", uid)
        return None

    if not item:
        return None

    out = {k: v for k, v in item.items() if k not in ("pk", "sk", "folder_pk", "ttl_epoch", "_body_html")}

    # Presigned URL for large HTML bodies
    s3_key = out.pop("body_html_s3_key", None)
    if s3_key:
        if S.dev_mode:
            out["body_html_url"] = f"/mock/s3/{S.email_bodies_s3_bucket}/{s3_key}"
        else:
            try:
                from app.core.aws_clients import s3_client
                out["body_html_url"] = s3_client().generate_presigned_url(
                    "get_object",
                    Params={"Bucket": S.email_bodies_s3_bucket, "Key": s3_key},
                    ExpiresIn=300,
                )
            except Exception:
                out["body_html_url"] = None
        out["body_html"] = None

    return out


def list_thread(user_sub: str, account_id: str, thread_id: str) -> List[Dict[str, Any]]:
    """Return all messages sharing thread_id, oldest first."""
    pk = f"USER#{user_sub}#ACCT#{account_id}"
    items: List[Dict[str, Any]] = []
    last_key = None

    for _ in range(3):
        kwargs: Dict[str, Any] = {
            "IndexName": "ByThread",
            "KeyConditionExpression": Key("pk").eq(pk) & Key("thread_id").eq(thread_id),
            "ScanIndexForward": True,
            "Limit": 100,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        try:
            resp = T.user_email_messages.query(**kwargs)
        except Exception:
            break
        for it in resp.get("Items", []):
            if it.get("sk", "").startswith("SYNC#"):
                continue
            out = {k: v for k, v in it.items() if k not in ("pk", "sk", "folder_pk", "ttl_epoch")}
            items.append(out)
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    items.sort(key=lambda x: int(x.get("date_ts", 0)))
    return items
