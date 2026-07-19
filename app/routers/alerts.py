from __future__ import annotations

import asyncio
import json
import re
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from app.core.crypto import sha256_str
from app.core.cursor import decode_cursor, encode_cursor
from app.core.normalize import normalize_email, normalize_phone
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.models import (
    AlertEmailBeginReq,
    AlertEmailConfirmReq,
    AlertEmailPrefsReq,
    AlertEmailRemoveReq,
    AlertPushPrefsReq,
    AlertSmsBeginReq,
    AlertSmsConfirmReq,
    AlertSmsPrefsReq,
    AlertSmsRemoveReq,
    AlertToastPrefsReq,
    AlertWebhookPrefsReq,
    AlertTypePreferenceUpdate,
    MarkReadReq,
)
from boto3.dynamodb.conditions import Attr
from app.services.alerts import (
    ALERT_EVENT_TYPES,
    DEFAULT_PUSH_EVENT_TYPES,
    ALERT_CATEGORIES,
    get_alert_category,
    audit_event,
    get_alert_prefs,
    send_alert_email,
    send_alert_sms,
    set_alert_prefs,
    sse_subscribe,
    sse_unsubscribe,
)
from app.services.mfa import gen_numeric_code
from app.services.rate_limit import can_send_alert_channel, can_send_verification
from app.services.sessions import create_action_challenge, load_challenge_or_401, require_ui_session, revoke_challenge

router = APIRouter(prefix="/ui", tags=["alerts"])


def _alert_query_tokens(query: str) -> list[str]:
    return [t for t in re.findall(r"[a-z0-9@._-]+", (query or "").lower()) if t]


def _alert_haystack(item: Dict[str, Any]) -> str:
    details = item.get("details") or {}
    detail_parts = []
    if isinstance(details, dict):
        for key, value in details.items():
            detail_parts.append(str(key))
            detail_parts.append(str(value))
    return " ".join(
        [
            str(item.get("event", "")),
            str(item.get("outcome", "")),
            str(item.get("title", "")),
            " ".join(detail_parts),
        ]
    ).lower()


def _alert_matches(query_tokens: list[str], item: Dict[str, Any]) -> bool:
    if not query_tokens:
        return False
    haystack = _alert_haystack(item)
    return all(token in haystack for token in query_tokens)


def _alert_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "alert_id": item.get("alert_id"),
        "ts": item.get("ts"),
        "event": item.get("event"),
        "outcome": item.get("outcome"),
        "title": item.get("title"),
        "details": item.get("details", {}),
        "read": item.get("read", False),
        "read_at": item.get("read_at", 0),
        "toast_delivered": item.get("toast_delivered", False),
        "priority": item.get("priority", "normal"),
        # Activity feed fields
        "action_url": item.get("action_url"),
        "category": item.get("category", "security"),
        "actors": item.get("actors", []),
        "actor_count": int(item.get("actor_count", 0)),
        "source_type": item.get("source_type"),
        "source_id": item.get("source_id"),
    }


@router.get("/alerts/types")
async def alert_types(_: Dict[str, str] = Depends(require_ui_session)):
    return {"types": ALERT_EVENT_TYPES, "event_types": ALERT_EVENT_TYPES}


@router.get("/alerts")
async def list_alerts(
    limit: int = 50,
    cursor: Optional[str] = None,
    unread_only: int = 0,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    eks = decode_cursor(cursor)
    query_kwargs = {
        "KeyConditionExpression": Key("user_sub").eq(ctx["user_sub"]),
        "ScanIndexForward": False,
        "Limit": max(1, min(int(limit), 200)),
    }
    if eks:
        query_kwargs["ExclusiveStartKey"] = eks
    r = T.alerts.query(**query_kwargs)
    items = r.get("Items", [])
    next_cursor = encode_cursor(r.get("LastEvaluatedKey"))
    out = []
    for it in items:
        if unread_only and it.get("read", False):
            continue
        out.append(_alert_out(it))
    return {"alerts": out, "next_cursor": next_cursor}


@router.get("/alerts/search")
async def search_alerts(
    q: str = Query(..., min_length=1),
    limit: int = Query(200, ge=1, le=200),
    cursor: Optional[str] = None,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    query_tokens = _alert_query_tokens(q)
    if not query_tokens:
        raise HTTPException(status_code=400, detail="Search query must include searchable text")
    start_key = decode_cursor(cursor)
    out: List[Dict[str, Any]] = []
    page_limit = max(25, min(200, limit * 4))
    while len(out) < limit:
        query_kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("user_sub").eq(ctx["user_sub"]),
            "ScanIndexForward": False,
            "Limit": page_limit,
        }
        if start_key:
            query_kwargs["ExclusiveStartKey"] = start_key
        resp = T.alerts.query(**query_kwargs)
        items = resp.get("Items", [])
        for item in items:
            if _alert_matches(query_tokens, item):
                out.append(_alert_out(item))
                if len(out) >= limit:
                    break
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break
    next_cursor = encode_cursor(start_key)
    return {"alerts": out, "next_cursor": next_cursor}


@router.post("/alerts/mark_read")
async def mark_read(body: MarkReadReq, ctx: Dict[str, str] = Depends(require_ui_session)):
    ts = now_ts()
    updated = 0
    for aid in body.alert_ids[:200]:
        try:
            # Unconditionally mark the alert read and stamp read_at. Using a
            # ConditionExpression of `read = False` previously skipped alerts that
            # had no `read` attribute at all (created via an alternate path), which
            # left read_at unset (0) even though the caller asked to mark it read.
            # We still only count alerts that were *previously* unread so the
            # `updated` total — used to decrement the unread sentinel — stays
            # accurate.
            resp = T.alerts.update_item(
                Key={"user_sub": ctx["user_sub"], "alert_id": aid},
                UpdateExpression="SET #r=:t, read_at=:ts",
                ConditionExpression="attribute_exists(alert_id)",
                ExpressionAttributeNames={"#r": "read"},
                ExpressionAttributeValues={":t": True, ":ts": ts},
                ReturnValues="ALL_OLD",
            )
            old = resp.get("Attributes", {}) or {}
            if not old.get("read", False):
                updated += 1
        except Exception:
            pass
    # Decrement sentinel count for each alert marked read
    if updated > 0 and S.notification_unread_count_enabled:
        try:
            from app.services.notification_unread import decrement_unread_count
            decrement_unread_count(ctx["user_sub"], updated)
        except Exception:
            pass
    return {"ok": True, "updated": updated}


@router.get("/alerts/email_prefs")
async def get_email_prefs(ctx: Dict[str, str] = Depends(require_ui_session)):
    return get_alert_prefs(ctx["user_sub"])


@router.post("/alerts/email_prefs")
async def set_email_prefs(body: AlertEmailPrefsReq, ctx: Dict[str, str] = Depends(require_ui_session)):
    prefs = set_alert_prefs(ctx["user_sub"], email_event_types=body.email_event_types)
    audit_event("alerts_email_prefs_set", ctx["user_sub"], None, outcome="success", enabled=len(prefs.get("email_event_types") or []))
    return prefs


@router.get("/alerts/sms_prefs")
async def get_sms_prefs(ctx: Dict[str, str] = Depends(require_ui_session)):
    prefs = get_alert_prefs(ctx["user_sub"])
    return {"sms_numbers": prefs["sms_numbers"], "sms_event_types": prefs["sms_event_types"]}


@router.post("/alerts/sms_prefs")
async def set_sms_prefs(body: AlertSmsPrefsReq, ctx: Dict[str, str] = Depends(require_ui_session)):
    prefs = set_alert_prefs(ctx["user_sub"], sms_event_types=body.sms_event_types)
    audit_event("alerts_sms_prefs_set", ctx["user_sub"], None, outcome="success", enabled=len(prefs.get("sms_event_types") or []))
    return prefs


@router.get("/alerts/toast_prefs")
async def get_toast_prefs(ctx: Dict[str, str] = Depends(require_ui_session)):
    prefs = get_alert_prefs(ctx["user_sub"])
    return {"toast_event_types": prefs["toast_event_types"]}


@router.post("/alerts/toast_prefs")
async def set_toast_prefs(body: AlertToastPrefsReq, ctx: Dict[str, str] = Depends(require_ui_session)):
    prefs = set_alert_prefs(ctx["user_sub"], toast_event_types=body.toast_event_types)
    audit_event("alerts_toast_prefs_set", ctx["user_sub"], None, outcome="success", enabled=len(prefs.get("toast_event_types") or []))
    return prefs


@router.get("/alerts/push_prefs")
async def get_push_prefs(ctx: Dict[str, str] = Depends(require_ui_session)):
    # D2: read the per-event PUSH prefs + the default-ON set so the app can render each
    # transactional event ON/OFF (default-ON minus opt-out, plus explicit opt-in).
    prefs = get_alert_prefs(ctx["user_sub"])
    return {
        "push_event_types": prefs.get("push_event_types", []),
        "push_opt_out_event_types": prefs.get("push_opt_out_event_types", []),
        "default_push_event_types": list(DEFAULT_PUSH_EVENT_TYPES),
    }


@router.post("/alerts/push_prefs")
async def set_push_prefs(body: AlertPushPrefsReq, ctx: Dict[str, str] = Depends(require_ui_session)):
    # D2: set both the opt-IN list and the opt-OUT (of default-ON) list. None leaves that list as-is.
    prefs = set_alert_prefs(
        ctx["user_sub"],
        push_event_types=body.push_event_types,
        push_opt_out_event_types=body.push_opt_out_event_types,
    )
    audit_event("alerts_push_prefs_set", ctx["user_sub"], None, outcome="success", enabled=len(prefs.get("push_event_types") or []))
    return prefs


@router.get("/alerts/webhook_prefs")
async def get_webhook_prefs(ctx: Dict[str, str] = Depends(require_ui_session)):
    prefs = get_alert_prefs(ctx["user_sub"])
    return {"webhook_urls": prefs["webhook_urls"], "event_types": prefs["webhook_event_types"]}


@router.post("/alerts/webhook_prefs")
async def set_webhook_prefs(body: AlertWebhookPrefsReq, ctx: Dict[str, str] = Depends(require_ui_session)):
    prefs = set_alert_prefs(
        ctx["user_sub"],
        webhook_urls=body.webhook_urls,
        webhook_event_types=body.webhook_event_types,
    )
    audit_event(
        "alerts_webhook_prefs_set",
        ctx["user_sub"],
        None,
        outcome="success",
        enabled=len(prefs.get("webhook_event_types") or []),
    )
    return prefs


# --------------------------------------------------------------------------- #
#  SOC-004: Unread count, mark-all-read, per-type preferences                   #
# --------------------------------------------------------------------------- #

@router.get("/alerts/unread-count")
async def get_unread_count(ctx: Dict[str, str] = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    if S.notification_unread_count_enabled:
        from app.services.notification_unread import get_unread_count as _get_count
        count = _get_count(user_sub)
    else:
        from app.services.social_alerts import get_unread_alert_count
        count = get_unread_alert_count(user_sub, cap=99)
    return {"count": count, "unread_count": count}


@router.post("/alerts/mark-all-read")
async def mark_all_read(ctx: Dict[str, str] = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    # Reset sentinel counter
    if S.notification_unread_count_enabled:
        from app.services.notification_unread import reset_unread_count
        reset_unread_count(user_sub)
    # Also mark individual alert rows as read
    from app.services.social_alerts import mark_all_alerts_read
    marked = mark_all_alerts_read(user_sub)
    return {"ok": True, "count": 0, "marked_count": marked}


@router.get("/alerts/type-preferences")
async def get_type_preferences(ctx: Dict[str, str] = Depends(require_ui_session)):
    from app.services.social_alerts import get_all_type_preferences
    user_sub = ctx["user_sub"]
    prefs = get_all_type_preferences(user_sub)
    return {"type_preferences": prefs}


@router.post("/alerts/type-preferences")
async def update_type_preferences(
    body: AlertTypePreferenceUpdate,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    from app.services.social_alerts import update_type_preference
    user_sub = ctx["user_sub"]
    updated = update_type_preference(
        user_sub,
        body.alert_type,
        enabled=body.enabled,
        email=body.email,
        push=body.push,
        in_app=body.in_app,
        sms=body.sms,
    )
    return {"alert_type": body.alert_type, **updated}


@router.post("/alerts/mark_toast_delivered")
async def mark_toast_delivered(body: Dict[str, Any], ctx: Dict[str, str] = Depends(require_ui_session)):
    updated = 0
    for aid in (body.get("alert_ids") or [])[:200]:
        try:
            T.alerts.update_item(
                Key={"user_sub": ctx["user_sub"], "alert_id": aid},
                UpdateExpression="SET toast_delivered = :t, toast_delivered_at = :now",
                ExpressionAttributeValues={":t": True, ":now": now_ts()},
            )
            updated += 1
        except Exception:
            pass
    return {"ok": True, "updated": updated}


def _check_attempt_budget(chal: Dict[str, Any], *, prefix: str, max_attempts: int, window_seconds: int) -> None:
    attempts = int(chal.get(f"{prefix}_attempts", 0))
    sent_at = int(chal.get(f"{prefix}_sent_at", 0) or chal.get("created_at", 0))
    if attempts >= max_attempts and (now_ts() - sent_at) < window_seconds:
        raise HTTPException(429, "Too many attempts; wait and retry")


def _bump_attempt(user_sub: str, challenge_id: str, prefix: str, attempts: int) -> None:
    try:
        T.sessions.update_item(
            Key={"user_sub": user_sub, "session_id": challenge_id},
            UpdateExpression=f"SET {prefix}_attempts = :n",
            ExpressionAttributeValues={":n": attempts + 1},
        )
    except Exception:
        pass


@router.post("/alerts/sms/begin")
async def alert_sms_add_begin(req: Request, body: AlertSmsBeginReq, ctx: Dict[str, str] = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    phone = normalize_phone(body.phone)
    code = gen_numeric_code(6)
    code_hash = sha256_str(code)
    challenge_id = create_action_challenge(
        req,
        user_sub=user_sub,
        purpose="alert_sms_add",
        send_to=[phone],
        payload={"sms_code_hash": code_hash, "phone": phone, "sms_code_attempts": 0, "sms_code_sent_at": now_ts()},
        ttl_seconds=600,
    )
    send_alert_sms([phone], f"Your confirmation code is: {code}")
    audit_event("alerts_sms_add_begin", user_sub, req, outcome="success", phone=phone)
    return {"challenge_id": challenge_id, "sent_to": phone}


@router.post("/alerts/sms/confirm")
async def alert_sms_add_confirm(req: Request, body: AlertSmsConfirmReq, ctx: Dict[str, str] = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if chal.get("purpose") != "alert_sms_add":
        raise HTTPException(400, "Bad challenge")
    _check_attempt_budget(chal, prefix="sms_code", max_attempts=S.sms_code_max_attempts, window_seconds=S.sms_code_attempt_window_seconds)
    if sha256_str(body.code.strip()) != chal.get("sms_code_hash"):
        _bump_attempt(user_sub, body.challenge_id, "sms_code", int(chal.get("sms_code_attempts", 0)))
        audit_event("alerts_sms_add_confirm", user_sub, req, outcome="failure", reason="bad_code")
        raise HTTPException(401, "Bad SMS code")
    phone = chal.get("phone")
    prefs = get_alert_prefs(user_sub)
    nums = prefs.get("sms_numbers") or []
    if phone and phone not in nums:
        nums.append(phone)
    prefs2 = set_alert_prefs(user_sub, sms_numbers=nums)
    revoke_challenge(user_sub, body.challenge_id)
    audit_event("alerts_sms_add_confirm", user_sub, req, outcome="success", phone=phone)
    return prefs2


@router.post("/alerts/sms/remove")
async def alert_sms_remove(req: Request, body: AlertSmsRemoveReq, ctx: Dict[str, str] = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    phone = normalize_phone(body.phone)
    prefs = get_alert_prefs(user_sub)
    nums = [n for n in (prefs.get("sms_numbers") or []) if n != phone]
    prefs2 = set_alert_prefs(user_sub, sms_numbers=nums)
    audit_event("alerts_sms_remove", user_sub, req, outcome="success", phone=phone)
    return prefs2


@router.post("/alerts/emails/begin")
async def alert_email_add_begin(req: Request, body: AlertEmailBeginReq, ctx: Dict[str, str] = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    email = normalize_email(body.email)
    if not can_send_alert_channel(user_sub, "email"):
        raise HTTPException(429, "Too many verification emails; try again later")
    code = gen_numeric_code(6)
    code_hash = sha256_str(code)
    challenge_id = create_action_challenge(
        req,
        user_sub=user_sub,
        purpose="alert_email_add",
        send_to=[email],
        payload={"email_code_hash": code_hash, "email": email, "email_code_attempts": 0, "email_code_sent_at": now_ts()},
        ttl_seconds=600,
    )
    send_alert_email([email], "Confirm alerts email", f"Your confirmation code is: {code}\n\nIf you didn't request this, ignore.")
    audit_event("alerts_email_add_begin", user_sub, req, outcome="success", email=email)
    return {"challenge_id": challenge_id, "sent_to": email}


@router.post("/alerts/emails/confirm")
async def alert_email_add_confirm(req: Request, body: AlertEmailConfirmReq, ctx: Dict[str, str] = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if chal.get("purpose") != "alert_email_add":
        raise HTTPException(400, "Bad challenge")
    _check_attempt_budget(chal, prefix="email_code", max_attempts=S.email_code_max_attempts, window_seconds=S.email_code_attempt_window_seconds)
    if sha256_str(body.code.strip()) != chal.get("email_code_hash"):
        _bump_attempt(user_sub, body.challenge_id, "email_code", int(chal.get("email_code_attempts", 0)))
        audit_event("alerts_email_add_confirm", user_sub, req, outcome="failure", reason="bad_code")
        raise HTTPException(401, "Bad email code")
    email = chal.get("email")
    prefs = get_alert_prefs(user_sub)
    emails = prefs.get("emails") or []
    if email and email not in emails:
        emails.append(email)
    prefs2 = set_alert_prefs(user_sub, emails=emails)
    revoke_challenge(user_sub, body.challenge_id)
    audit_event("alerts_email_add_confirm", user_sub, req, outcome="success", email=email)
    return prefs2


@router.post("/alerts/emails/remove")
async def alert_email_remove(req: Request, body: AlertEmailRemoveReq, ctx: Dict[str, str] = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    email = normalize_email(body.email)
    prefs = get_alert_prefs(user_sub)
    emails = [e for e in (prefs.get("emails") or []) if e != email]
    prefs2 = set_alert_prefs(user_sub, emails=emails)
    audit_event("alerts_email_remove", user_sub, req, outcome="success", email=email)
    return prefs2


# --------------------------------------------------------------------------- #
#  PLATFORM-012: Activity feed, tips summary, mark-group-read                   #
# --------------------------------------------------------------------------- #


def _format_activity_title(group: Dict[str, Any]) -> str:
    """Generate a human-readable title for a grouped activity item."""
    parts = []
    aggs = group.get("aggregations", {})

    for event_type, agg in aggs.items():
        count = agg["count"]
        total_cents = agg.get("total_cents", 0)

        if event_type == "post_liked":
            parts.append(f"{count} like{'s' if count != 1 else ''}")
        elif event_type == "post_reaction":
            parts.append(f"{count} reaction{'s' if count != 1 else ''}")
        elif event_type == "post_comment":
            parts.append(f"{count} comment{'s' if count != 1 else ''}")
        elif event_type == "post_tip":
            total_str = f" ${total_cents / 100:.2f}" if total_cents else ""
            parts.append(f"{count} tip{'s' if count != 1 else ''}{total_str}")
        elif event_type == "post_shared":
            parts.append(f"{count} share{'s' if count != 1 else ''}")
        elif event_type == "message_tip":
            total_str = f" ${total_cents / 100:.2f}" if total_cents else ""
            parts.append(f"tipped{total_str}")
        elif event_type == "new_follower":
            parts.append(f"{count} new follower{'s' if count != 1 else ''}")

    source_type = group.get("source_type", "")
    if source_type == "post":
        return f"Your post received {', '.join(parts)}" if parts else "Activity on your post"
    elif source_type == "message":
        return f"Your message was {', '.join(parts)}" if parts else "Activity on your message"
    elif source_type == "follower":
        return ", ".join(parts) if parts else "New follower"
    return ", ".join(parts) or group.get("title", "Activity")


@router.get("/alerts/activity")
async def get_activity_feed(
    limit: int = Query(default=20, ge=1, le=50),
    cursor: Optional[str] = Query(default=None),
    category: Optional[str] = Query(default=None),
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    """Get grouped activity feed for the current user."""
    user_sub = ctx["user_sub"]

    # Query alerts
    query_kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("user_sub").eq(user_sub),
        "ScanIndexForward": False,
        "Limit": limit * 5,  # Over-fetch to allow grouping
    }
    eks = decode_cursor(cursor)
    if eks:
        query_kwargs["ExclusiveStartKey"] = eks
    if category:
        query_kwargs["FilterExpression"] = Attr("category").eq(category)

    resp = T.alerts.query(**query_kwargs)
    raw_items = resp.get("Items", [])

    # Filter out internal records (UNREAD_COUNT sentinel, legacy BATCH# items without ts)
    items = []
    for it in raw_items:
        aid = it.get("alert_id", "")
        # Skip internal sentinel records
        if aid == "UNREAD_COUNT":
            continue
        # Skip legacy batch records that lack ts (they have updated_at as string)
        if aid.startswith("BATCH#") and not it.get("ts"):
            continue
        items.append(it)

    # Group by source entity
    groups: Dict[str, Dict[str, Any]] = {}
    group_order: List[str] = []

    for item in items:
        source_type = item.get("source_type")
        source_id = item.get("source_id")

        if not source_type or not source_id:
            # Non-groupable: treat as standalone
            key = f"standalone:{item['alert_id']}"
            groups[key] = {
                "source_type": item.get("event", "unknown"),
                "source_id": item.get("alert_id"),
                "action_url": item.get("action_url"),
                "aggregations": {},
                "latest_ts": int(item.get("ts", 0)),
                "title": item.get("title", ""),
                "unread": not item.get("read", False),
                "alert_ids": [item["alert_id"]],
            }
            group_order.append(key)
            continue

        key = f"{source_type}:{source_id}"
        if key not in groups:
            groups[key] = {
                "source_type": source_type,
                "source_id": source_id,
                "action_url": item.get("action_url"),
                "aggregations": {},
                "latest_ts": int(item.get("ts", 0)),
                "title": "",
                "unread": False,
                "alert_ids": [],
            }
            group_order.append(key)

        group = groups[key]
        event = item.get("event", "")
        if event not in group["aggregations"]:
            group["aggregations"][event] = {
                "count": 0,
                "latest_actor": None,
                "total_cents": 0,
            }
        agg = group["aggregations"][event]
        agg["count"] += 1
        if not agg["latest_actor"]:
            actor_name = (item.get("details") or {}).get("actor_display_name")
            if actor_name:
                agg["latest_actor"] = str(actor_name)
        if "amount_cents" in (item.get("details") or {}):
            agg["total_cents"] += int(item["details"]["amount_cents"])

        if not item.get("read", False):
            group["unread"] = True
        group["alert_ids"].append(item["alert_id"])

    # Build response with formatted titles. Order groups by their latest_ts desc
    # (group_order preserves first-seen order, which is NOT guaranteed to match
    # latest_ts once grouping collapses multiple events -> the feed could return
    # out-of-order items).
    ordered_keys = sorted(
        group_order,
        key=lambda k: int(groups[k].get("latest_ts", 0)),
        reverse=True,
    )
    result_items = []
    for key in ordered_keys[:limit]:
        group = groups[key]
        # Only format title for grouped items (not standalone)
        if not key.startswith("standalone:"):
            group["title"] = _format_activity_title(group)
        result_items.append(group)

    next_cursor = None
    if resp.get("LastEvaluatedKey"):
        next_cursor = encode_cursor(resp["LastEvaluatedKey"])

    return {"items": result_items, "next_cursor": next_cursor}


@router.get("/alerts/tips-summary")
async def get_tips_summary(
    period: str = Query(default="30d"),
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    """Ledger-backed tips-received summary for the current user (TIPX-D1).

    Retires the old alert-stream total (GROSS, post_tip+message_tip only, capped
    at the last 1000 alerts, mislabeled "Total Earned").  This now reads the
    billing LEDGER via tips_measurement so total_tips_cents is NET, covers all
    8 tip surfaces, excludes reversed tips, and RECONCILES to the earnings tips
    bucket and the leaderboard for the same creator/period.

    The response keeps the legacy keys the web TipsFeed reads
    (total_tips_cents -- now NET, tip_count, top_tippers,
    by_type.post_tip/by_type.message_tip) and adds net: true,
    source: "ledger", and a full-surface by_surface breakdown.
    """
    from app.services.tips_measurement import get_tips_received_summary

    user_sub = ctx["user_sub"]
    if period not in ("7d", "30d", "all"):
        period = "30d"

    summary = get_tips_received_summary(user_sub, period)
    by_surface = summary.get("by_type", {})

    # Legacy 2-bucket shape the current web TipsFeed renders (post/message), now NET.
    legacy_by_type = {
        "post_tip": by_surface.get("post", {"count": 0, "total_cents": 0}),
        "message_tip": by_surface.get("message", {"count": 0, "total_cents": 0}),
    }

    return {
        "total_tips_cents": summary.get("total_net_cents", 0),
        "tip_count": summary.get("tip_count", 0),
        "top_tippers": summary.get("top_tippers", []),
        "by_type": legacy_by_type,
        "by_surface": by_surface,
        "unique_tippers": summary.get("unique_tippers", 0),
        "net": True,
        "source": "ledger",
    }


@router.post("/alerts/mark-group-read")
async def mark_group_read(
    body: Dict[str, Any],
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    """Mark all alerts in a group as read."""
    alert_ids = body.get("alert_ids", [])
    if not isinstance(alert_ids, list):
        raise HTTPException(400, "alert_ids must be a list")
    alert_ids = alert_ids[:50]

    ts = now_ts()
    marked = 0
    for aid in alert_ids:
        try:
            T.alerts.update_item(
                Key={"user_sub": ctx["user_sub"], "alert_id": aid},
                UpdateExpression="SET #r=:t, read_at=:ts",
                ConditionExpression="#r = :f",
                ExpressionAttributeNames={"#r": "read"},
                ExpressionAttributeValues={":t": True, ":ts": ts, ":f": False},
            )
            marked += 1
        except Exception:
            pass

    if marked > 0 and S.notification_unread_count_enabled:
        try:
            from app.services.notification_unread import decrement_unread_count
            decrement_unread_count(ctx["user_sub"], marked)
        except Exception:
            pass

    return {"ok": True, "marked_count": marked}


@router.get("/alerts/stream")
async def alerts_stream(ctx: Dict[str, str] = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    q = sse_subscribe(user_sub)

    async def gen():
        try:
            # Send initial sync with current unread count
            try:
                if S.notification_unread_count_enabled:
                    from app.services.notification_unread import get_unread_count as _get_count
                    count = _get_count(user_sub)
                else:
                    count = 0
                yield "event: hello\ndata: " + json.dumps({"type": "sync", "unread_count": count}, separators=(",", ":")) + "\n\n"
            except Exception:
                yield "event: hello\ndata: {}\n\n"

            heartbeat_interval = 30  # seconds
            while True:
                try:
                    item = await asyncio.wait_for(q.get(), timeout=heartbeat_interval)
                    yield "event: alert\ndata: " + json.dumps(item, separators=(",", ":"), default=str) + "\n\n"
                except asyncio.TimeoutError:
                    # Send heartbeat
                    yield "event: heartbeat\ndata: " + json.dumps({"ts": now_ts()}, separators=(",", ":")) + "\n\n"
        finally:
            sse_unsubscribe(user_sub, q)

    return StreamingResponse(gen(), media_type="text/event-stream")
