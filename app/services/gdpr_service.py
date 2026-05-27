"""GDPR Data Export & Account Deletion service (PRIVACY-001)."""

from __future__ import annotations

import hashlib
import io
import json
import logging
import uuid
import zipfile
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import write_alert
from app.services.billing_shared import ddb_query_pk, user_pk

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_REQUEST_TTL_DAYS = 90  # Audit / request records kept for 90 days


def _req_id() -> str:
    return f"req_{uuid.uuid4().hex[:16]}"


def _evt_id() -> str:
    return f"evt_{uuid.uuid4().hex[:8]}"


def _user_pk(user_sub: str) -> str:
    return f"USER#{user_sub}"


def _req_sk(request_id: str) -> str:
    return f"REQUEST#{request_id}"


def _audit_pk(request_id: str) -> str:
    return f"REQUEST#{request_id}"


def _write_audit(request_id: str, actor: str, action: str, details: Optional[Dict[str, Any]] = None) -> None:
    ts = now_ts()
    eid = _evt_id()
    T.data_request_audit.put_item(Item={
        "pk": _audit_pk(request_id),
        "sk": f"AUDIT#{ts}#{eid}",
        "actor": actor,
        "action": action,
        "details": details or {},
        "created_at": ts,
    })


def _item_to_out(item: Dict[str, Any], *, include_user: bool = False) -> Dict[str, Any]:
    """Convert a DDB item to the response dict matching DataRequestOut."""
    out: Dict[str, Any] = {
        "request_id": item.get("request_id", ""),
        "request_type": item.get("request_type", ""),
        "status": item.get("status", ""),
        "created_at": int(item.get("created_at", 0)),
        "updated_at": _safe_int(item.get("updated_at")),
        "completed_at": _safe_int(item.get("completed_at")),
        "grace_period_ends_at": _safe_int(item.get("grace_period_ends_at")),
        "export_size_bytes": _safe_int(item.get("export_size_bytes")),
        "export_download_url": item.get("export_download_url"),
        "deletion_reason": item.get("deletion_reason"),
        "deletion_summary": item.get("deletion_summary"),
        "retention_hold": bool(item.get("retention_hold", False)),
        "retention_hold_reason": item.get("retention_hold_reason"),
        "admin_actor": item.get("admin_actor"),
        "admin_note": item.get("admin_note"),
    }
    if include_user:
        out["user_sub"] = item.get("user_sub", "")
    return out


def _safe_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(v)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def create_export_request(user_sub: str, categories: Dict[str, bool]) -> Dict[str, Any]:
    """Create a new data export request. Returns the request dict."""
    ts = now_ts()
    request_id = _req_id()
    ttl = ts + _REQUEST_TTL_DAYS * 86400

    item: Dict[str, Any] = {
        "pk": _user_pk(user_sub),
        "sk": _req_sk(request_id),
        "request_id": request_id,
        "user_sub": user_sub,
        "request_type": "export",
        "status": "pending",
        "created_at": ts,
        "updated_at": ts,
        "export_categories": categories,
        "ttl_epoch": ttl,
    }
    T.data_requests.put_item(Item=item)
    _write_audit(request_id, user_sub, "created", {"request_type": "export"})
    return item


def create_deletion_request(user_sub: str, reason: Optional[str] = None) -> Dict[str, Any]:
    """Create an account deletion request with grace period."""
    ts = now_ts()
    request_id = _req_id()
    grace_ends = ts + S.privacy_deletion_grace_period_days * 86400
    ttl = ts + _REQUEST_TTL_DAYS * 86400

    item: Dict[str, Any] = {
        "pk": _user_pk(user_sub),
        "sk": _req_sk(request_id),
        "request_id": request_id,
        "user_sub": user_sub,
        "request_type": "deletion",
        "status": "pending",
        "created_at": ts,
        "updated_at": ts,
        "grace_period_ends_at": grace_ends,
        "ttl_epoch": ttl,
    }
    if reason:
        item["deletion_reason"] = reason
    T.data_requests.put_item(Item=item)
    _write_audit(request_id, user_sub, "created", {"request_type": "deletion", "grace_period_ends_at": grace_ends})
    return item


def get_request(user_sub: str, request_id: str) -> Optional[Dict[str, Any]]:
    resp = T.data_requests.get_item(Key={"pk": _user_pk(user_sub), "sk": _req_sk(request_id)})
    return resp.get("Item")


def get_request_by_id_admin(request_id: str) -> Optional[Dict[str, Any]]:
    """Admin lookup: scan ByType GSI or iterate. For simplicity, use ByStatus GSI scan."""
    # We'll query ByType GSI with request_type filter -- but since we need a specific request_id,
    # the most reliable way is to scan the table. For MVP, iterate status values.
    for status in ("pending", "processing", "completed", "cancelled", "failed", "rejected", "held"):
        resp = T.data_requests.query(
            IndexName="ByStatus",
            KeyConditionExpression=Key("status").eq(status),
        )
        for item in resp.get("Items", []):
            if item.get("request_id") == request_id:
                return item
    return None


def list_user_requests(user_sub: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(_user_pk(user_sub)),
            "Limit": 100,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.data_requests.query(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    # Sort newest first
    items.sort(key=lambda x: int(x.get("created_at", 0)), reverse=True)
    return items


def list_requests_by_status(status: str, limit: int = 50) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    resp = T.data_requests.query(
        IndexName="ByStatus",
        KeyConditionExpression=Key("status").eq(status),
        Limit=limit,
        ScanIndexForward=False,
    )
    items = resp.get("Items", [])
    return items, None


def list_requests_by_type(request_type: str, limit: int = 50) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    resp = T.data_requests.query(
        IndexName="ByType",
        KeyConditionExpression=Key("request_type").eq(request_type),
        Limit=limit,
        ScanIndexForward=False,
    )
    items = resp.get("Items", [])
    return items, None


def cancel_deletion(user_sub: str, request_id: str) -> Dict[str, Any]:
    """Cancel a pending deletion request if still within grace period."""
    item = get_request(user_sub, request_id)
    if not item:
        raise ValueError("not_found")
    if item.get("request_type") != "deletion":
        raise ValueError("not_deletion")
    if item.get("status") != "pending":
        raise ValueError("not_pending")
    grace_ends = int(item.get("grace_period_ends_at", 0))
    ts = now_ts()
    if ts > grace_ends:
        raise ValueError("grace_period_expired")

    T.data_requests.update_item(
        Key={"pk": _user_pk(user_sub), "sk": _req_sk(request_id)},
        UpdateExpression="SET #s = :s, updated_at = :t",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "cancelled", ":t": ts},
    )
    _write_audit(request_id, user_sub, "cancelled", {})
    item["status"] = "cancelled"
    item["updated_at"] = ts
    return item


def has_recent_export(user_sub: str) -> bool:
    """Check if the user has an export request within the rate-limit window."""
    cutoff = now_ts() - S.privacy_export_rate_limit_hours * 3600
    requests = list_user_requests(user_sub)
    for r in requests:
        if r.get("request_type") == "export" and int(r.get("created_at", 0)) > cutoff:
            if r.get("status") not in ("cancelled", "failed"):
                return True
    return False


def has_pending_deletion(user_sub: str) -> bool:
    """Check if the user already has a pending deletion request."""
    requests = list_user_requests(user_sub)
    for r in requests:
        if r.get("request_type") == "deletion" and r.get("status") == "pending":
            return True
    return False


def has_retention_hold(user_sub: str) -> bool:
    """Check if the user has any request with retention hold."""
    requests = list_user_requests(user_sub)
    for r in requests:
        if r.get("retention_hold"):
            return True
    return False


# ---------------------------------------------------------------------------
# Admin actions
# ---------------------------------------------------------------------------

def admin_approve(request_id: str, admin_sub: str, note: Optional[str] = None) -> Dict[str, Any]:
    item = get_request_by_id_admin(request_id)
    if not item:
        raise ValueError("not_found")
    if item.get("status") != "pending":
        raise ValueError("not_pending")
    ts = now_ts()
    update_expr = "SET #s = :s, updated_at = :t, admin_actor = :a"
    expr_values: Dict[str, Any] = {":s": "processing", ":t": ts, ":a": admin_sub}
    if note:
        update_expr += ", admin_note = :n"
        expr_values[":n"] = note
    T.data_requests.update_item(
        Key={"pk": item["pk"], "sk": item["sk"]},
        UpdateExpression=update_expr,
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues=expr_values,
    )
    _write_audit(request_id, admin_sub, "approved", {"note": note})
    item["status"] = "processing"
    return item


def admin_reject(request_id: str, admin_sub: str, note: Optional[str] = None) -> Dict[str, Any]:
    item = get_request_by_id_admin(request_id)
    if not item:
        raise ValueError("not_found")
    if item.get("status") not in ("pending", "processing"):
        raise ValueError("invalid_status")
    ts = now_ts()
    update_expr = "SET #s = :s, updated_at = :t, admin_actor = :a"
    expr_values: Dict[str, Any] = {":s": "rejected", ":t": ts, ":a": admin_sub}
    if note:
        update_expr += ", admin_note = :n"
        expr_values[":n"] = note
    T.data_requests.update_item(
        Key={"pk": item["pk"], "sk": item["sk"]},
        UpdateExpression=update_expr,
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues=expr_values,
    )
    _write_audit(request_id, admin_sub, "rejected", {"note": note})
    item["status"] = "rejected"
    return item


def admin_hold(request_id: str, admin_sub: str, reason: str) -> Dict[str, Any]:
    item = get_request_by_id_admin(request_id)
    if not item:
        raise ValueError("not_found")
    ts = now_ts()
    T.data_requests.update_item(
        Key={"pk": item["pk"], "sk": item["sk"]},
        UpdateExpression="SET retention_hold = :h, retention_hold_reason = :r, updated_at = :t, #s = :s",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":h": True, ":r": reason, ":t": ts, ":s": "held"},
    )
    _write_audit(request_id, admin_sub, "held", {"reason": reason})
    item["retention_hold"] = True
    item["retention_hold_reason"] = reason
    item["status"] = "held"
    return item


def admin_release_hold(request_id: str, admin_sub: str) -> Dict[str, Any]:
    item = get_request_by_id_admin(request_id)
    if not item:
        raise ValueError("not_found")
    if not item.get("retention_hold"):
        raise ValueError("no_hold")
    ts = now_ts()
    T.data_requests.update_item(
        Key={"pk": item["pk"], "sk": item["sk"]},
        UpdateExpression="SET retention_hold = :h, updated_at = :t, #s = :s REMOVE retention_hold_reason",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":h": False, ":t": ts, ":s": "pending"},
    )
    _write_audit(request_id, admin_sub, "released", {})
    item["retention_hold"] = False
    item["status"] = "pending"
    return item


def get_audit_trail(request_id: str) -> List[Dict[str, Any]]:
    resp = T.data_request_audit.query(
        KeyConditionExpression=Key("pk").eq(_audit_pk(request_id)),
    )
    return resp.get("Items", [])


# ---------------------------------------------------------------------------
# Data Export
# ---------------------------------------------------------------------------

def _query_all(table: Any, key_expr: Any, index_name: Optional[str] = None) -> List[Dict[str, Any]]:
    """Paginate through all items matching a key expression."""
    items: List[Dict[str, Any]] = []
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {"KeyConditionExpression": key_expr, "Limit": 500}
        if index_name:
            kwargs["IndexName"] = index_name
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = table.query(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return items


def _serialize_items(items: List[Dict[str, Any]], redact_keys: Optional[set] = None) -> List[Dict[str, Any]]:
    """Convert DDB items to JSON-safe dicts, optionally redacting fields."""
    import decimal
    out = []
    for item in items:
        d: Dict[str, Any] = {}
        for k, v in item.items():
            if redact_keys and k in redact_keys:
                continue
            if isinstance(v, decimal.Decimal):
                d[k] = int(v) if v == int(v) else float(v)
            elif isinstance(v, set):
                d[k] = list(v)
            else:
                d[k] = v
            # Ensure nested dicts are also cleaned
        out.append(d)
    return out


def process_export(user_sub: str, request_id: str, categories: Dict[str, bool]) -> Dict[str, Any]:
    """Compile user data into a ZIP archive and upload to S3. Returns summary dict."""
    import boto3 as _boto3

    ts = now_ts()
    buf = io.BytesIO()
    export_dir = f"export_{user_sub}_{ts}"

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Profile
        if categories.get("include_profile", True):
            try:
                prof_resp = T.profile.get_item(Key={"user_sub": user_sub})
                prof = prof_resp.get("Item", {})
                zf.writestr(f"{export_dir}/profile.json", json.dumps(_serialize_items([prof]), indent=2, default=str))
            except Exception as e:
                logger.warning("Export profile error: %s", e)

            try:
                addr_items = _query_all(T.addresses, Key("user_sub").eq(user_sub))
                zf.writestr(f"{export_dir}/account.json", json.dumps(_serialize_items(addr_items), indent=2, default=str))
            except Exception as e:
                logger.warning("Export addresses error: %s", e)

        # Billing
        if categories.get("include_billing", True):
            try:
                billing_items = _query_all(T.billing, Key("pk").eq(user_pk(user_sub)))
                safe_items = _serialize_items(billing_items, redact_keys={"card_number", "cvv"})
                zf.writestr(f"{export_dir}/billing/history.json", json.dumps(safe_items, indent=2, default=str))
            except Exception as e:
                logger.warning("Export billing error: %s", e)

        # Messages
        if categories.get("include_messages", True):
            try:
                # Get conversations via the Participants table pattern
                # Messages table uses conversation_id (pk), message_id (sk)
                # For simplicity, query conversations table for this user
                conversations: List[Dict[str, Any]] = []
                messages_out: List[Dict[str, Any]] = []
                # Query via app_single_table or Conversations/Participants tables
                # Since the messaging tables are separate (not T.*), we'll try to get them
                try:
                    from app.core.aws import ddb as _ddb
                    msg_table = _ddb.Table("Messages")
                    conv_table = _ddb.Table("Conversations")
                    part_table = _ddb.Table("Participants")
                    # Get all conversations the user participates in
                    part_items = _query_all(part_table, Key("user_id").eq(user_sub))
                    for p in part_items:
                        cid = p.get("conversation_id")
                        if cid:
                            # Get conversation metadata
                            try:
                                c_resp = conv_table.get_item(Key={"conversation_id": cid})
                                c = c_resp.get("Item")
                                if c:
                                    conversations.append(c)
                            except Exception:
                                pass
                            # Get messages (limit per conversation to avoid huge exports)
                            try:
                                msgs = _query_all(msg_table, Key("conversation_id").eq(cid))
                                messages_out.extend(msgs)
                            except Exception:
                                pass
                except Exception:
                    pass

                zf.writestr(
                    f"{export_dir}/messages/conversations.json",
                    json.dumps(_serialize_items(conversations), indent=2, default=str),
                )
                zf.writestr(
                    f"{export_dir}/messages/messages.json",
                    json.dumps(_serialize_items(messages_out, redact_keys={"session_token"}), indent=2, default=str),
                )
            except Exception as e:
                logger.warning("Export messages error: %s", e)

        # Contacts
        if categories.get("include_profile", True):
            try:
                contacts_items = _query_all(T.contacts, Key("user_sub").eq(user_sub))
                zf.writestr(f"{export_dir}/contacts/contacts.json", json.dumps(_serialize_items(contacts_items), indent=2, default=str))
            except Exception as e:
                logger.warning("Export contacts error: %s", e)

        # Calendar
        if categories.get("include_profile", True):
            try:
                cal_items = _query_all(T.calendar, Key("calendar_id").eq(f"CAL#{user_sub}"))
                zf.writestr(f"{export_dir}/calendar/events.json", json.dumps(_serialize_items(cal_items), indent=2, default=str))
            except Exception as e:
                logger.warning("Export calendar error: %s", e)

        # Subscriptions
        if categories.get("include_billing", True):
            try:
                sub_items = _query_all(T.subscriptions, Key("pk").eq(f"SUB#{user_sub}"))
                zf.writestr(f"{export_dir}/subscriptions/subscriptions.json", json.dumps(_serialize_items(sub_items), indent=2, default=str))
            except Exception as e:
                logger.warning("Export subscriptions error: %s", e)

        # Security (redacted)
        try:
            session_items = _query_all(T.sessions, Key("user_sub").eq(user_sub))
            safe_sessions = _serialize_items(session_items, redact_keys={"session_token", "csrf_token", "access_token"})
            zf.writestr(f"{export_dir}/security/sessions.json", json.dumps(safe_sessions, indent=2, default=str))
        except Exception as e:
            logger.warning("Export sessions error: %s", e)

        try:
            api_key_items = _query_all(T.api_keys, Key("user_sub").eq(user_sub), index_name=S.api_keys_user_index)
            safe_keys = _serialize_items(api_key_items, redact_keys={"key_hash", "key_secret"})
            zf.writestr(f"{export_dir}/security/api_keys.json", json.dumps(safe_keys, indent=2, default=str))
        except Exception as e:
            logger.warning("Export api_keys error: %s", e)

        # Files metadata (not actual files for MVP -- too large)
        if categories.get("include_files", True):
            try:
                from app.core.aws import ddb as _ddb
                filemgr = _ddb.Table(S.filemgr_table_name) if S.filemgr_table_name else None
                if filemgr:
                    file_items = _query_all(filemgr, Key("pk").eq(f"USER#{user_sub}"))
                    zf.writestr(
                        f"{export_dir}/files/manifest.json",
                        json.dumps(_serialize_items(file_items, redact_keys={"s3_key"}), indent=2, default=str),
                    )
            except Exception as e:
                logger.warning("Export files error: %s", e)

        # Newsfeed posts
        if categories.get("include_profile", True):
            try:
                from app.core.aws import ddb as _ddb
                single_table = _ddb.Table("app_single_table")
                post_items = _query_all(single_table, Key("pk").eq(f"POST#{user_sub}"))
                zf.writestr(f"{export_dir}/newsfeed/posts.json", json.dumps(_serialize_items(post_items), indent=2, default=str))
            except Exception as e:
                logger.warning("Export posts error: %s", e)

        # Tickets
        try:
            ticket_items = _query_all(T.tickets, Key("pk").eq(f"USER#{user_sub}"))
            zf.writestr(f"{export_dir}/tickets/tickets.json", json.dumps(_serialize_items(ticket_items), indent=2, default=str))
        except Exception as e:
            logger.warning("Export tickets error: %s", e)

    # Upload to S3
    buf.seek(0)
    zip_bytes = buf.getvalue()
    zip_size = len(zip_bytes)
    s3_key = f"data-exports/{user_sub}_{ts}.zip"

    try:
        s3_client = _boto3.client(
            "s3",
            endpoint_url=S.s3_endpoint_url or None,
            region_name=S.aws_region,
        )
        bucket = S.privacy_export_s3_bucket
        # Ensure bucket exists in dev mode
        if S.dev_mode:
            try:
                s3_client.head_bucket(Bucket=bucket)
            except Exception:
                try:
                    s3_client.create_bucket(Bucket=bucket)
                except Exception:
                    pass
        s3_client.put_object(Bucket=bucket, Key=s3_key, Body=zip_bytes)
    except Exception as e:
        logger.error("Failed to upload export ZIP to S3: %s", e)
        # Update request to failed
        T.data_requests.update_item(
            Key={"pk": _user_pk(user_sub), "sk": _req_sk(request_id)},
            UpdateExpression="SET #s = :s, updated_at = :t",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "failed", ":t": now_ts()},
        )
        _write_audit(request_id, user_sub, "failed", {"error": str(e)})
        raise

    # Update request to completed
    completed_ts = now_ts()
    export_expires = completed_ts + S.privacy_export_ttl_days * 86400
    T.data_requests.update_item(
        Key={"pk": _user_pk(user_sub), "sk": _req_sk(request_id)},
        UpdateExpression="SET #s = :s, updated_at = :t, completed_at = :c, export_s3_key = :k, export_size_bytes = :sz, export_expires_at = :ex",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": "completed",
            ":t": completed_ts,
            ":c": completed_ts,
            ":k": s3_key,
            ":sz": zip_size,
            ":ex": export_expires,
        },
    )
    _write_audit(request_id, user_sub, "completed", {"size_bytes": zip_size, "s3_key": s3_key})

    # Notify user
    try:
        write_alert(
            user_sub,
            event="privacy.export_ready",
            outcome="success",
            title="Your data export is ready for download",
            details={"request_id": request_id, "size_bytes": zip_size},
        )
    except Exception:
        pass

    return {"size_bytes": zip_size, "s3_key": s3_key}


def get_export_download_url(user_sub: str, request_id: str) -> Optional[str]:
    """Generate a presigned S3 URL for the export ZIP."""
    import boto3 as _boto3

    item = get_request(user_sub, request_id)
    if not item:
        return None
    if item.get("status") != "completed":
        return None
    s3_key = item.get("export_s3_key")
    if not s3_key:
        return None

    # Check expiry
    expires_at = _safe_int(item.get("export_expires_at"))
    if expires_at and now_ts() > expires_at:
        return None

    try:
        s3_client = _boto3.client(
            "s3",
            endpoint_url=S.s3_endpoint_url or None,
            region_name=S.aws_region,
        )
        url = s3_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": S.privacy_export_s3_bucket, "Key": s3_key},
            ExpiresIn=3600,
        )
        return url
    except Exception as e:
        logger.error("Failed to generate presigned URL: %s", e)
        return None


# ---------------------------------------------------------------------------
# Data Deletion
# ---------------------------------------------------------------------------

def process_deletion(user_sub: str, request_id: str) -> Dict[str, Any]:
    """Execute full account deletion. Returns a summary dict of items deleted."""
    from app.services.account import delete_user_data

    summary: Dict[str, Any] = {}
    ts = now_ts()

    # Update status to processing
    T.data_requests.update_item(
        Key={"pk": _user_pk(user_sub), "sk": _req_sk(request_id)},
        UpdateExpression="SET #s = :s, updated_at = :t",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "processing", ":t": ts},
    )
    _write_audit(request_id, user_sub, "processing", {})

    # Step 1: Anonymize billing records within retention window
    try:
        billing_items = _query_all(T.billing, Key("pk").eq(user_pk(user_sub)))
        anonymized = 0
        deleted_billing = 0
        anon_hash = f"DELETED#{hashlib.sha256(user_sub.encode()).hexdigest()[:16]}"
        retention_cutoff = ts - S.privacy_billing_retention_years * 365 * 86400

        for item in billing_items:
            sk = item.get("sk", "")
            created = _safe_int(item.get("created_at")) or 0
            if sk.startswith("LEDGER#") and created > retention_cutoff:
                # Anonymize: strip PII but keep amounts
                T.billing.update_item(
                    Key={"pk": user_pk(user_sub), "sk": sk},
                    UpdateExpression="SET anonymized_id = :a REMOVE email, #n, address",
                    ExpressionAttributeNames={"#n": "name"},
                    ExpressionAttributeValues={":a": anon_hash},
                )
                anonymized += 1
            elif not sk.startswith("LEDGER#"):
                # Delete non-ledger billing items (payment methods, wallet state)
                T.billing.delete_item(Key={"pk": user_pk(user_sub), "sk": sk})
                deleted_billing += 1
            else:
                # Old ledger entries beyond retention window -- delete
                T.billing.delete_item(Key={"pk": user_pk(user_sub), "sk": sk})
                deleted_billing += 1
        summary["billing_anonymized"] = anonymized
        summary["billing_deleted"] = deleted_billing
    except Exception as e:
        logger.warning("Deletion billing error: %s", e)
        summary["billing_error"] = str(e)

    # Step 2: Call existing delete_user_data for sessions, MFA, etc.
    try:
        delete_user_data(user_sub)
        summary["core_tables_deleted"] = True
    except Exception as e:
        logger.warning("delete_user_data error: %s", e)
        summary["core_tables_error"] = str(e)

    # Step 3: Delete profile
    try:
        T.profile.delete_item(Key={"user_sub": user_sub})
        summary["profile_deleted"] = True
    except Exception as e:
        logger.warning("Delete profile error: %s", e)

    # Step 4: Delete addresses
    try:
        addr_items = _query_all(T.addresses, Key("user_sub").eq(user_sub))
        for item in addr_items:
            T.addresses.delete_item(Key={"user_sub": user_sub, "address_id": item["address_id"]})
        summary["addresses_deleted"] = len(addr_items)
    except Exception as e:
        logger.warning("Delete addresses error: %s", e)

    # Step 5: Delete contacts
    try:
        contact_items = _query_all(T.contacts, Key("user_sub").eq(user_sub))
        for item in contact_items:
            sk = item.get("sk") or item.get("contact_id", "")
            if sk:
                T.contacts.delete_item(Key={"user_sub": user_sub, "sk": sk})
        summary["contacts_deleted"] = len(contact_items)
    except Exception as e:
        logger.warning("Delete contacts error: %s", e)

    # Step 6: Delete calendar events
    try:
        cal_items = _query_all(T.calendar, Key("calendar_id").eq(f"CAL#{user_sub}"))
        for item in cal_items:
            T.calendar.delete_item(Key={"calendar_id": f"CAL#{user_sub}", "sk": item["sk"]})
        summary["calendar_events_deleted"] = len(cal_items)
    except Exception as e:
        logger.warning("Delete calendar error: %s", e)

    # Step 7: Delete subscriptions
    try:
        sub_items = _query_all(T.subscriptions, Key("pk").eq(f"SUB#{user_sub}"))
        for item in sub_items:
            T.subscriptions.delete_item(Key={"pk": f"SUB#{user_sub}", "sk": item.get("sk", "")})
        summary["subscriptions_deleted"] = len(sub_items)
    except Exception as e:
        logger.warning("Delete subscriptions error: %s", e)

    # Step 8: Delete account state
    try:
        T.account_state.delete_item(Key={"user_sub": user_sub})
        summary["account_state_deleted"] = True
    except Exception as e:
        logger.warning("Delete account_state error: %s", e)

    # Step 9: Delete tickets
    try:
        ticket_items = _query_all(T.tickets, Key("pk").eq(f"USER#{user_sub}"))
        for item in ticket_items:
            T.tickets.delete_item(Key={"pk": f"USER#{user_sub}", "sk": item.get("sk", "")})
        summary["tickets_deleted"] = len(ticket_items)
    except Exception as e:
        logger.warning("Delete tickets error: %s", e)

    # Step 10: Delete video metadata
    try:
        vid_items = _query_all(T.video_metadata, Key("pk").eq(f"USER#{user_sub}"))
        for item in vid_items:
            T.video_metadata.delete_item(Key={"pk": f"USER#{user_sub}", "sk": item.get("sk", "")})
        summary["videos_deleted"] = len(vid_items)
    except Exception as e:
        logger.warning("Delete video_metadata error: %s", e)

    # Finalize: update request to completed
    completed_ts = now_ts()
    T.data_requests.update_item(
        Key={"pk": _user_pk(user_sub), "sk": _req_sk(request_id)},
        UpdateExpression="SET #s = :s, updated_at = :t, completed_at = :c, deletion_summary = :ds",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": "completed",
            ":t": completed_ts,
            ":c": completed_ts,
            ":ds": summary,
        },
    )
    _write_audit(request_id, user_sub, "completed", {"summary": summary})

    # Notify user (if they can still receive it)
    try:
        write_alert(
            user_sub,
            event="privacy.deletion_completed",
            outcome="success",
            title="Your account has been deleted",
            details={"request_id": request_id},
        )
    except Exception:
        pass

    return summary
