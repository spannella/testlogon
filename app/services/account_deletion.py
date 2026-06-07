"""Account deletion request lifecycle + data export (PLATFORM-018).

This is a self-contained subsystem stored in the ``account_deletion_requests``
DynamoDB table. It manages:

- Account-deletion requests with a grace period (scheduled deletion).
- Cancellation during the grace period.
- Admin retention holds that block deletion even after the grace period.
- An audit trail (stored in the same table under ``AUDIT#`` sort keys).
- A privacy data-export ("download my data").
- Finalization of due deletions (driven by ``deletion_scheduler``).

Destructive behaviour is gated behind ``S.account_deletion_destructive`` so
that running this in dev/test never wipes shared seed users -- by default
the finalize step performs a soft anonymize/mark-deleted only.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Keys / helpers
# ---------------------------------------------------------------------------

_REQUEST_TTL_DAYS = 90

_ACTIVE_STATUSES = ("pending", "processing")
_FINAL_STATUSES = ("completed", "cancelled", "failed")


def _req_id() -> str:
    return f"adr_{uuid.uuid4().hex[:16]}"


def _exp_id() -> str:
    return f"adx_{uuid.uuid4().hex[:16]}"


def _evt_id() -> str:
    return f"evt_{uuid.uuid4().hex[:8]}"


def _user_pk(user_sub: str) -> str:
    return f"USER#{user_sub}"


def _req_sk(request_id: str) -> str:
    return f"REQUEST#{request_id}"


def _audit_pk(request_id: str) -> str:
    return f"AUDIT#{request_id}"


def _safe_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(v)
    except (ValueError, TypeError):
        return None


def _write_audit(request_id: str, actor: str, event_type: str,
                 details: Optional[Dict[str, Any]] = None) -> None:
    ts = now_ts()
    eid = _evt_id()
    T.account_deletion_requests.put_item(Item={
        "pk": _audit_pk(request_id),
        "sk": f"AUDIT#{ts:012d}#{eid}",
        "event_id": eid,
        "event_type": event_type,
        "actor": actor,
        "timestamp": ts,
        "details": details or {},
    })


def get_audit_trail(request_id: str) -> List[Dict[str, Any]]:
    resp = T.account_deletion_requests.query(
        KeyConditionExpression=Key("pk").eq(_audit_pk(request_id))
        & Key("sk").begins_with("AUDIT#"),
        ScanIndexForward=True,
    )
    out: List[Dict[str, Any]] = []
    for item in resp.get("Items", []):
        out.append({
            "event_id": item.get("event_id", ""),
            "event_type": item.get("event_type", ""),
            "actor": item.get("actor", ""),
            "timestamp": int(item.get("timestamp", 0)),
            "details": item.get("details", {}) or {},
        })
    return out


def request_to_out(item: Dict[str, Any], *, include_user: bool = False) -> Dict[str, Any]:
    status = item.get("status", "")
    scheduled_for = _safe_int(item.get("scheduled_for"))
    grace_remaining: Optional[int] = None
    if scheduled_for is not None:
        grace_remaining = max(0, (scheduled_for - now_ts()) // 86400)
    can_cancel = (
        status == "pending"
        and not bool(item.get("retention_hold", False))
        and (scheduled_for is None or scheduled_for > now_ts())
    )
    out: Dict[str, Any] = {
        "request_id": item.get("request_id", ""),
        "status": status,
        "created_at": int(item.get("created_at", 0)),
        "scheduled_for": scheduled_for,
        "grace_days_remaining": grace_remaining,
        "can_cancel": can_cancel,
        "retention_hold": bool(item.get("retention_hold", False)),
        "retention_hold_reason": item.get("retention_hold_reason"),
        "reason": item.get("reason"),
        "completed_at": _safe_int(item.get("completed_at")),
        "deletion_summary": item.get("deletion_summary"),
    }
    if include_user:
        out["user_sub"] = item.get("user_sub", "")
    return out


# ---------------------------------------------------------------------------
# Deletion request lifecycle
# ---------------------------------------------------------------------------

def get_request(user_sub: str, request_id: str) -> Optional[Dict[str, Any]]:
    resp = T.account_deletion_requests.get_item(
        Key={"pk": _user_pk(user_sub), "sk": _req_sk(request_id)}
    )
    return resp.get("Item")


def list_user_requests(user_sub: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(_user_pk(user_sub))
            & Key("sk").begins_with("REQUEST#"),
            "Limit": 100,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.account_deletion_requests.query(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    items.sort(key=lambda x: int(x.get("created_at", 0)), reverse=True)
    return items


def has_pending_deletion(user_sub: str) -> bool:
    for r in list_user_requests(user_sub):
        if r.get("status") in _ACTIVE_STATUSES:
            return True
    return False


def create_deletion_request(user_sub: str, reason: Optional[str] = None) -> Dict[str, Any]:
    ts = now_ts()
    request_id = _req_id()
    scheduled_for = ts + S.account_deletion_grace_period_days * 86400
    ttl = scheduled_for + _REQUEST_TTL_DAYS * 86400

    item: Dict[str, Any] = {
        "pk": _user_pk(user_sub),
        "sk": _req_sk(request_id),
        "request_id": request_id,
        "user_sub": user_sub,
        "status": "pending",
        "created_at": ts,
        "updated_at": ts,
        "scheduled_for": scheduled_for,
        "retention_hold": False,
        "ttl_epoch": ttl,
    }
    if reason:
        item["reason"] = reason
    T.account_deletion_requests.put_item(Item=item)
    _write_audit(request_id, user_sub, "deletion_requested", {
        "grace_period_days": S.account_deletion_grace_period_days,
        "scheduled_for": scheduled_for,
        "reason": reason,
    })
    logger.info("privacy.deletion_requested user=%s request=%s scheduled=%s",
                user_sub, request_id, scheduled_for)
    return item


def cancel_deletion(user_sub: str, request_id: str) -> Dict[str, Any]:
    item = get_request(user_sub, request_id)
    if not item:
        raise ValueError("not_found")
    status = item.get("status")
    if status != "pending":
        raise ValueError("not_pending")
    scheduled_for = int(item.get("scheduled_for", 0))
    if scheduled_for and now_ts() > scheduled_for:
        raise ValueError("grace_expired")

    ts = now_ts()
    T.account_deletion_requests.update_item(
        Key={"pk": _user_pk(user_sub), "sk": _req_sk(request_id)},
        UpdateExpression="SET #s = :s, updated_at = :t, cancelled_at = :t",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "cancelled", ":t": ts},
    )
    _write_audit(request_id, user_sub, "deletion_cancelled", {})
    item["status"] = "cancelled"
    item["updated_at"] = ts
    item["cancelled_at"] = ts
    logger.info("privacy.deletion_cancelled user=%s request=%s", user_sub, request_id)
    return item


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------

def list_requests_by_status(status: str, limit: int = 200) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "ByStatusScheduled",
            "KeyConditionExpression": Key("status").eq(status),
            "Limit": limit,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.account_deletion_requests.query(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key or len(items) >= limit:
            break
    return items[:limit]


def get_request_by_id_admin(request_id: str) -> Optional[Dict[str, Any]]:
    for status in ("pending", "processing", "completed", "cancelled", "failed"):
        for item in list_requests_by_status(status):
            if item.get("request_id") == request_id:
                return item
    return None


def place_retention_hold(request_id: str, admin_sub: str, reason: str) -> Dict[str, Any]:
    item = get_request_by_id_admin(request_id)
    if not item:
        raise ValueError("not_found")
    if item.get("status") != "pending":
        raise ValueError("not_pending")
    ts = now_ts()
    user_sub = item["user_sub"]
    T.account_deletion_requests.update_item(
        Key={"pk": _user_pk(user_sub), "sk": _req_sk(request_id)},
        UpdateExpression=(
            "SET retention_hold = :h, retention_hold_reason = :r, "
            "held_by = :a, held_at = :t, updated_at = :t"
        ),
        ExpressionAttributeValues={":h": True, ":r": reason, ":a": admin_sub, ":t": ts},
    )
    _write_audit(request_id, admin_sub, "hold_placed", {"reason": reason})
    logger.warning("privacy.hold_placed user=%s request=%s admin=%s", user_sub, request_id, admin_sub)
    item.update({"retention_hold": True, "retention_hold_reason": reason,
                 "held_by": admin_sub, "held_at": ts})
    return item


def release_retention_hold(request_id: str, admin_sub: str) -> Dict[str, Any]:
    item = get_request_by_id_admin(request_id)
    if not item:
        raise ValueError("not_found")
    if not bool(item.get("retention_hold", False)):
        raise ValueError("no_hold")
    ts = now_ts()
    user_sub = item["user_sub"]
    T.account_deletion_requests.update_item(
        Key={"pk": _user_pk(user_sub), "sk": _req_sk(request_id)},
        UpdateExpression=(
            "SET retention_hold = :h, retention_hold_reason = :n, "
            "held_by = :n, held_at = :n, updated_at = :t"
        ),
        ExpressionAttributeValues={":h": False, ":n": None, ":t": ts},
    )
    _write_audit(request_id, admin_sub, "hold_released", {})
    logger.info("privacy.hold_released user=%s request=%s admin=%s", user_sub, request_id, admin_sub)
    item.update({"retention_hold": False, "retention_hold_reason": None,
                 "held_by": None, "held_at": None})
    return item


# ---------------------------------------------------------------------------
# Finalization (deletion cascade)
# ---------------------------------------------------------------------------

def _send_pre_deletion_notice(user_sub: str) -> None:
    try:
        from app.services.alerts import write_alert
        write_alert(
            user_sub,
            event="account_deletion_processing",
            outcome="info",
            title="Your account deletion is being processed",
            details={"message": "Your account deletion grace period has ended and "
                                 "your data is now being removed."},
        )
    except Exception:  # noqa: BLE001
        logger.exception("pre-deletion notice failed for %s", user_sub)


def _refund_wallet(user_sub: str) -> int:
    """Zero the wallet balance with a deletion_refund ledger entry. Returns cents refunded."""
    try:
        from app.services.billing_shared import get_wallet_balance, user_pk
        pk = user_pk(user_sub)
        bal = get_wallet_balance(T.billing, pk)
        cents = int(bal.get("wallet_balance_cents", 0))
        if cents <= 0:
            return 0
        ts = now_ts()
        T.billing.put_item(Item={
            "pk": pk,
            "sk": f"LEDGER#{ts:012d}#{uuid.uuid4().hex[:8]}",
            "kind": "ledger",
            "reason": "deletion_refund",
            "amount_cents": -cents,
            "currency": bal.get("currency", "usd"),
            "created_at": ts,
        })
        T.billing.update_item(
            Key={"pk": pk, "sk": "WALLET"},
            UpdateExpression="SET wallet_balance_cents = :z, updated_at = :t",
            ExpressionAttributeValues={":z": 0, ":t": ts},
        )
        logger.info("privacy.wallet_refund user=%s amount_cents=%d", user_sub, cents)
        return cents
    except Exception:  # noqa: BLE001
        logger.exception("wallet refund failed for %s", user_sub)
        return 0


_ANON_NAME = "Deleted User"
_ANON_TEXT = "[This message was deleted]"
_ANON_SENDER_ID = "deleted_user"


def _messages_table():
    """boto3 handle for the messaging Messages table (env ``DDB_MESSAGES``)."""
    import os

    from app.core.aws import ddb
    return ddb.Table(os.environ.get("DDB_MESSAGES", "Messages"))


def _participants_table():
    """boto3 handle for the messaging Participants table (env ``DDB_PARTICIPANTS``)."""
    import os

    from app.core.aws import ddb
    return ddb.Table(os.environ.get("DDB_PARTICIPANTS", "Participants"))


def _posts_table():
    """boto3 handle for the newsfeed single table (env ``APP_TABLE``)."""
    import os

    from app.core.aws import ddb
    return ddb.Table(os.environ.get("APP_TABLE", "app_single_table"))


def _anonymize_messages(user_sub: str) -> int:
    """Overwrite sender-identifying fields + body on every message authored by
    ``user_sub``.

    Gated behind ``S.account_deletion_destructive``: when that flag is off (the
    dev/test default) this is a no-op that returns ``0`` so shared seed data is
    never mutated. When on, it tombstones the user's messages so deleted-user
    identity is purged (GDPR Art. 17 erasure).

    Messages live in the ``Messages`` table (PK ``conversation_id``,
    SK ``message_id``, attr ``sender_id``). There is no GSI on ``sender_id``, so
    we enumerate the conversations the user participated in via the
    ``Participants`` table (PK ``user_id``, SK ``conversation_id``) and then,
    per conversation, query + filter the user's own messages. Every page is
    drained via ``LastEvaluatedKey``.
    """
    if not S.account_deletion_destructive:
        return 0
    from boto3.dynamodb.conditions import Attr

    parts = _participants_table()
    msgs = _messages_table()

    # Step 1: conversations the user participated in.
    conv_ids: List[str] = []
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("user_id").eq(user_sub),
            "ProjectionExpression": "conversation_id",
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = parts.query(**kwargs)
        conv_ids.extend(
            str(it["conversation_id"]) for it in resp.get("Items", [])
            if it.get("conversation_id")
        )
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    # Step 2: per conversation, overwrite this user's messages.
    anonymized = 0
    ts = now_ts()
    for conv_id in conv_ids:
        last_key = None
        while True:
            kwargs = {
                "KeyConditionExpression": Key("conversation_id").eq(conv_id),
                "FilterExpression": Attr("sender_id").eq(user_sub),
                "ProjectionExpression": "conversation_id, message_id",
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = msgs.query(**kwargs)
            for it in resp.get("Items", []):
                msgs.update_item(
                    Key={
                        "conversation_id": it["conversation_id"],
                        "message_id": it["message_id"],
                    },
                    UpdateExpression=(
                        "SET sender_id = :sid, sender_display_name = :name, "
                        "#txt = :txt, anonymized = :t, anonymized_at = :ts"
                    ),
                    ExpressionAttributeNames={"#txt": "text"},
                    ExpressionAttributeValues={
                        ":sid": _ANON_SENDER_ID,
                        ":name": _ANON_NAME,
                        ":txt": _ANON_TEXT,
                        ":t": True,
                        ":ts": ts,
                    },
                )
                anonymized += 1
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
    if anonymized:
        logger.info("privacy.anonymize_messages user=%s count=%d", user_sub, anonymized)
    return anonymized


def _anonymize_posts(user_sub: str) -> int:
    """Overwrite author identity + content on every newsfeed post by ``user_sub``.

    Gated behind ``S.account_deletion_destructive`` (no-op returning ``0`` when
    off, mirroring ``_anonymize_messages``).

    Posts live in ``app_single_table`` (env ``APP_TABLE``), PK ``POST#{post_id}``
    / SK ``META``. Author lookups go through GSI2 (``GSI2PK =
    POST_AUTHOR#{user_id}``). We query GSI2 to enumerate the user's posts and
    overwrite ``user_id`` (surfaced as ``author_id``) and the body/content
    fields. Paginated to exhaustion via ``LastEvaluatedKey``.
    """
    if not S.account_deletion_destructive:
        return 0

    posts = _posts_table()
    anonymized = 0
    ts = now_ts()
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "GSI2",
            "KeyConditionExpression": Key("GSI2PK").eq(f"POST_AUTHOR#{user_sub}"),
            "ProjectionExpression": "pk, sk",
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = posts.query(**kwargs)
        for it in resp.get("Items", []):
            posts.update_item(
                Key={"pk": it["pk"], "sk": it["sk"]},
                UpdateExpression=(
                    "SET user_id = :name, body = :txt, body_plain = :txt, "
                    "body_markdown = :n, body_markdown_html = :n, body_rich = :n, "
                    "body_format = :fmt, anonymized = :t, anonymized_at = :ts"
                ),
                ExpressionAttributeValues={
                    ":name": _ANON_NAME,
                    ":txt": _ANON_TEXT,
                    ":n": None,
                    ":fmt": "plain",
                    ":t": True,
                    ":ts": ts,
                },
            )
            anonymized += 1
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    if anonymized:
        logger.info("privacy.anonymize_posts user=%s count=%d", user_sub, anonymized)
    return anonymized


def _cancel_active_subscriptions(user_sub: str) -> int:
    """Cancel the user's active subscriptions (as subscriber *and* as creator).

    Gated behind ``S.account_deletion_destructive`` (no-op returning ``0`` when
    off, mirroring the anonymization helpers).

    Subscriptions live in ``T.subscriptions`` with a fan-out layout: per-sub
    record PK ``SUB#{subscription_id}`` / SK ``META``; subscriber index PK
    ``SUBSCRIBER#{subscriber_id}``; creator index PK ``CREATOR#{creator_id}``.
    We list the user's subscription ids from both index partitions, then set
    each active META record to ``status="canceled"`` (immediate — the account is
    gone). Paginated via ``LastEvaluatedKey``.
    """
    if not S.account_deletion_destructive:
        return 0

    active_statuses = {"active", "trialing", "past_due", "canceling"}
    cancelled = 0
    ts = now_ts()

    def _sub_ids_for_pk(pk_value: str) -> List[str]:
        ids: List[str] = []
        last_key = None
        while True:
            kwargs: Dict[str, Any] = {"KeyConditionExpression": Key("pk").eq(pk_value)}
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = T.subscriptions.query(**kwargs)
            for it in resp.get("Items", []):
                sk = str(it.get("sk", ""))
                if sk.startswith("SUB#"):
                    ids.append(sk[4:])
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
        return ids

    def _cancel_one(subscription_id: str) -> bool:
        meta = T.subscriptions.get_item(
            Key={"pk": f"SUB#{subscription_id}", "sk": "META"}
        ).get("Item")
        if not meta:
            return False
        if str(meta.get("status", "")) not in active_statuses:
            return False
        T.subscriptions.update_item(
            Key={"pk": f"SUB#{subscription_id}", "sk": "META"},
            UpdateExpression=(
                "SET #s = :canceled, auto_renew = :f, cancel_at_period_end = :f, "
                "updated_at = :t, cancelled_at = :t, cancelled_reason = :reason"
            ),
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":canceled": "canceled",
                ":f": False,
                ":t": ts,
                ":reason": "account_deleted",
            },
        )
        logger.info(
            "privacy.subscription_cancelled subscription=%s user=%s",
            subscription_id, user_sub,
        )
        return True

    seen: set[str] = set()
    for pk_value in (f"SUBSCRIBER#{user_sub}", f"CREATOR#{user_sub}"):
        for sub_id in _sub_ids_for_pk(pk_value):
            if sub_id in seen:
                continue
            seen.add(sub_id)
            if _cancel_one(sub_id):
                cancelled += 1

    if cancelled:
        logger.info(
            "privacy.subscriptions_cancelled_total user=%s count=%d", user_sub, cancelled
        )
    return cancelled


def finalize_deletion(user_sub: str, request_id: str) -> Dict[str, Any]:
    """Execute the deletion cascade for a request and mark it completed.

    In dev/test (``account_deletion_destructive`` False) the cascade is a
    safe no-op summary plus the wallet refund ledger entry -- it never wipes
    shared seed-user data destructively.
    """
    item = get_request(user_sub, request_id)
    if not item:
        raise ValueError("not_found")
    if item.get("status") not in _ACTIVE_STATUSES:
        raise ValueError("not_active")
    if bool(item.get("retention_hold", False)):
        raise ValueError("retention_hold")

    ts = now_ts()
    T.account_deletion_requests.update_item(
        Key={"pk": _user_pk(user_sub), "sk": _req_sk(request_id)},
        UpdateExpression="SET #s = :s, updated_at = :t",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "processing", ":t": ts},
    )
    _write_audit(request_id, "system", "deletion_started", {})
    logger.info("privacy.deletion_started user=%s request=%s", user_sub, request_id)

    _send_pre_deletion_notice(user_sub)

    summary: Dict[str, Any] = {
        "wallet_refunded_cents": _refund_wallet(user_sub),
        "destructive": bool(S.account_deletion_destructive),
        "profile_deleted": False,
        "messages_anonymized": _anonymize_messages(user_sub),
        "posts_anonymized": _anonymize_posts(user_sub),
        "files_deleted": 0,
        "push_devices_deleted": 0,
        "subscriptions_cancelled": _cancel_active_subscriptions(user_sub),
    }

    if S.account_deletion_destructive:
        try:
            from app.services.account import delete_user_data
            delete_user_data(user_sub)
            summary["profile_deleted"] = True
            summary["core_tables_deleted"] = True
        except Exception:  # noqa: BLE001
            logger.exception("destructive delete_user_data failed for %s", user_sub)

    ts = now_ts()
    T.account_deletion_requests.update_item(
        Key={"pk": _user_pk(user_sub), "sk": _req_sk(request_id)},
        UpdateExpression=(
            "SET #s = :s, updated_at = :t, completed_at = :t, deletion_summary = :sum"
        ),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "completed", ":t": ts, ":sum": summary},
    )
    _write_audit(request_id, "system", "deletion_completed", {"summary": summary})
    logger.info("privacy.deletion_completed user=%s request=%s", user_sub, request_id)
    item.update({"status": "completed", "completed_at": ts, "deletion_summary": summary})
    return item


def process_due_deletions(limit: int = 200) -> Tuple[int, int, List[str]]:
    """Process all pending requests whose grace period has expired.

    Returns ``(processed, skipped, processed_request_ids)``.
    """
    now = now_ts()
    processed = 0
    skipped = 0
    done: List[str] = []
    for item in list_requests_by_status("pending", limit=limit):
        scheduled_for = int(item.get("scheduled_for", 0))
        if scheduled_for == 0 or scheduled_for > now:
            continue
        if bool(item.get("retention_hold", False)):
            skipped += 1
            continue
        user_sub = item.get("user_sub")
        request_id = item.get("request_id")
        if not (user_sub and request_id):
            continue
        try:
            finalize_deletion(user_sub, request_id)
            processed += 1
            done.append(request_id)
        except ValueError:
            skipped += 1
        except Exception:  # noqa: BLE001
            logger.exception("privacy.deletion_failed user=%s request=%s", user_sub, request_id)
            try:
                T.account_deletion_requests.update_item(
                    Key={"pk": _user_pk(user_sub), "sk": _req_sk(request_id)},
                    UpdateExpression="SET #s = :s, updated_at = :t",
                    ExpressionAttributeNames={"#s": "status"},
                    ExpressionAttributeValues={":s": "failed", ":t": now_ts()},
                )
                _write_audit(request_id, "system", "deletion_failed", {})
            except Exception:  # noqa: BLE001
                pass
            skipped += 1
    return processed, skipped, done


# ---------------------------------------------------------------------------
# Data export
# ---------------------------------------------------------------------------

def has_recent_export(user_sub: str, window_hours: int = 24) -> bool:
    cutoff = now_ts() - window_hours * 3600
    for r in list_user_requests(user_sub):
        # exports are stored with sk REQUEST#adx_*; reuse same prefix lookup
        if r.get("kind") == "export" and int(r.get("created_at", 0)) > cutoff:
            if r.get("status") not in ("failed",):
                return True
    return False


def _collect_export_data(user_sub: str, categories: Dict[str, bool]) -> Dict[str, Any]:
    """Collect a lightweight per-category summary of the user's data.

    Kept intentionally minimal/safe for dev: counts + a small profile stub,
    so it never streams large blobs or PII it cannot safely read.
    """
    data: Dict[str, Any] = {}
    if categories.get("profile"):
        data["profile"] = {"user_sub": user_sub}
    for cat in ("messages", "posts", "billing", "files", "contacts",
                "calendar", "subscriptions", "push_devices", "tickets", "sessions"):
        if categories.get(cat):
            data[cat] = {"included": True}
    return data


def create_export_request(user_sub: str, categories: Dict[str, bool]) -> Dict[str, Any]:
    ts = now_ts()
    request_id = _exp_id()
    enabled = {k: bool(v) for k, v in categories.items() if v}
    download_expires_at = ts + S.account_deletion_export_ttl_days * 86400
    ttl = download_expires_at + _REQUEST_TTL_DAYS * 86400

    data = _collect_export_data(user_sub, categories)

    item: Dict[str, Any] = {
        "pk": _user_pk(user_sub),
        "sk": _req_sk(request_id),
        "request_id": request_id,
        "user_sub": user_sub,
        "kind": "export",
        "status": "completed",
        "created_at": ts,
        "updated_at": ts,
        "completed_at": ts,
        "export_categories": enabled,
        "categories_requested": len(enabled),
        "download_url": f"/ui/privacy/account-deletion/export/{request_id}/download",
        "download_expires_at": download_expires_at,
        "export_data": data,
        "ttl_epoch": ttl,
    }
    T.account_deletion_requests.put_item(Item=item)
    logger.info("privacy.export_completed user=%s request=%s categories=%d",
                user_sub, request_id, len(enabled))
    return item


def export_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "request_id": item.get("request_id", ""),
        "status": item.get("status", ""),
        "created_at": int(item.get("created_at", 0)),
        "completed_at": _safe_int(item.get("completed_at")),
        "download_url": item.get("download_url"),
        "download_expires_at": _safe_int(item.get("download_expires_at")),
        "categories_requested": int(item.get("categories_requested", 0)),
        "file_size_bytes": _safe_int(item.get("file_size_bytes")),
        "data": item.get("export_data"),
    }
