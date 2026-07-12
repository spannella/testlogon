from __future__ import annotations

"""MOD-A4/A5/A6: the moderation_case LIFECYCLE operations.

Sits on top of ``moderation_case`` (state store + transitions), ``moderation_hide``
(non-destructive hide/unhide) and ``moderation_delete`` (terminal hard delete).

Operations:
  - admin_dismiss       under_review/visible -> dismissed  (UN-HIDE; content visible again)
  - admin_confirm_hold  under_review/visible -> hold       (stays HIDDEN; hold_until=now+30d; notify poster + invite)
  - admin_final_call    hold/awaiting_final  -> reinstated (restore ORIGINAL, visible) | deleted (hard delete + violation [+ ban])
  - poster_respond      hold                 -> awaiting_final (owner statement; admin must make the final call)
  - poster_close        hold/awaiting_final  -> deleted    (owner opt-out -> immediate hard delete + violation)
  - sweep_expired_holds hold past hold_until -> deleted    (no response -> auto delete + violation)

Every DELETE terminal records exactly one violation on ``user_enforcement_history``
and notifies the owner. All transitions are idempotent and cannot skip states.
"""

import logging
import time
import uuid
from typing import Any, Dict, Iterable, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.services import moderation_case as mc
from app.services import moderation_delete as mdel
from app.services import moderation_hide as mhide
from app.services.alerts import write_alert
from app.services.moderation_audit_log import write_moderation_audit_event

logger = logging.getLogger(__name__)

_CONTENT_LABEL = {
    "feed_post": "post",
    "feed_comment": "comment",
    "feed_media": "post",
    "message": "message",
    "message_media": "message",
    "video": "video",
    "video_comment": "comment",
    "profile_photo": "profile photo",
}


def _label(content_type: str) -> str:
    return _CONTENT_LABEL.get(content_type, "content")


def _categories_csv(case: Dict[str, Any]) -> str:
    cats = case.get("categories") or []
    try:
        return ",".join(sorted({mc.normalize_category(c) for c in cats}))
    except Exception:
        return ""


def _notify(owner_user_id: Optional[str], *, event: str, title: str, message: str, case_id: str, state: str, extra: Optional[Dict[str, Any]] = None) -> None:
    if not owner_user_id:
        return
    details = {"case_id": case_id, "state": state, "message": message}
    if extra:
        details.update({k: v for k, v in extra.items() if v is not None})
    try:
        try:
            write_alert(owner_user_id, event=event, outcome="warning", title=title, details=details, push_event_types=[event])
        except TypeError:
            write_alert(owner_user_id, event=event, outcome="warning", title=title, details=details)
    except Exception:
        logger.exception("moderation_lifecycle._notify failed for %s", owner_user_id)


def record_violation(*, owner_user_id: Optional[str], case_id: str, content_type: str, categories_csv: str, source_ticket_id: str, admin_user_id: str, note: str, now_ts: Optional[int] = None) -> Optional[str]:
    """Append a content-violation record to user_enforcement_history (one per terminal delete)."""
    if not owner_user_id:
        return None
    ts = int(now_ts or time.time())
    enforcement_id = f"enf_{uuid.uuid4().hex[:20]}"
    try:
        T.user_enforcement_history.put_item(
            Item={
                "user_id": str(owner_user_id),
                "enforcement_id": enforcement_id,
                "entity_type": "user_enforcement",
                "status": "recorded",
                "enforcement_type": "content_violation",
                # BySourceTicketCreatedAt GSI key cannot be empty; fall back to the case id
                # when the case was not linked to a ticket (e.g. sweep/close paths).
                "source_ticket_id": str(source_ticket_id or case_id),
                "created_at": str(ts),
                "created_by_admin_user_id": str(admin_user_id or "system"),
                "note": str(note or "")[:500],
                "content_type": str(content_type or ""),
                "moderation_case_id": case_id,
                "categories": categories_csv,
                "duration_days": 0,
            }
        )
    except Exception:
        logger.exception("moderation_lifecycle.record_violation failed for %s", owner_user_id)
        return None
    return enforcement_id


def _resolve_meta(case: Dict[str, Any], metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    md = dict(case.get("content_metadata") or {})
    for k, v in (metadata or {}).items():
        if v is not None:
            md[k] = v
    return md


def _finalize_delete(
    *,
    case: Dict[str, Any],
    metadata: Optional[Dict[str, Any]],
    admin_user_id: str,
    reason: str,
    source_ticket_id: str,
    record_violation_flag: bool = True,
    now_ts: Optional[int] = None,
) -> Dict[str, Any]:
    ts = int(now_ts or time.time())
    case_id = case["case_id"]
    content_type = str(case.get("content_type") or "")
    content_id = str(case.get("content_id") or "")
    md = _resolve_meta(case, metadata)
    owner = case.get("owner_user_id") or mhide.resolve_owner(content_type=content_type, content_id=content_id, metadata=md)

    resolved_owner = mdel.delete_content(content_type=content_type, content_id=content_id, metadata=md, case_id=case_id) or owner
    updated = mc.transition(
        case_id,
        mc.STATE_DELETED,
        extra={"hidden": True, "deleted_at": ts, "delete_reason": str(reason or "")[:64]},
        now_ts=ts,
    )
    enforcement_id = None
    if record_violation_flag:
        enforcement_id = record_violation(
            owner_user_id=resolved_owner,
            case_id=case_id,
            content_type=content_type,
            categories_csv=_categories_csv(case),
            source_ticket_id=source_ticket_id or str(case.get("ticket_id") or ""),
            admin_user_id=admin_user_id,
            note=reason,
            now_ts=ts,
        )
    _notify(
        resolved_owner,
        event="moderation_content_deleted",
        title="Your content was removed",
        message=f"After review, your {_label(content_type)} has been permanently removed.",
        case_id=case_id,
        state=mc.STATE_DELETED,
        extra={"content_type": content_type, "reason": reason, "enforcement_id": enforcement_id},
    )
    return {"state": mc.STATE_DELETED, "owner_user_id": resolved_owner, "enforcement_id": enforcement_id, "case": updated}


# ── Admin triage (MOD-A4) ────────────────────────────────────────────────────

def admin_dismiss(*, case: Dict[str, Any], metadata: Optional[Dict[str, Any]], admin_user_id: str, now_ts: Optional[int] = None) -> Dict[str, Any]:
    """No violation: un-hide the content (visible again) and close the case (dismissed)."""
    ts = int(now_ts or time.time())
    case_id = case["case_id"]
    content_type = str(case.get("content_type") or "")
    content_id = str(case.get("content_id") or "")
    md = _resolve_meta(case, metadata)
    owner = case.get("owner_user_id") or mhide.resolve_owner(content_type=content_type, content_id=content_id, metadata=md)
    # Restore visibility (pure flag clear; no-op if never hidden).
    mhide.unhide_content(content_type=content_type, content_id=content_id, metadata=md, case_id=case_id, state=mc.STATE_VISIBLE)
    updated = mc.transition(case_id, mc.STATE_DISMISSED, extra={"hidden": False, "dismissed_at": ts, "dismissed_by": admin_user_id}, now_ts=ts)
    _notify(
        owner,
        event="moderation_content_restored",
        title="Report dismissed",
        message=f"A report against your {_label(content_type)} was reviewed and dismissed. Your content is visible again.",
        case_id=case_id,
        state=mc.STATE_DISMISSED,
        extra={"content_type": content_type},
    )
    return {"state": mc.STATE_DISMISSED, "owner_user_id": owner, "case": updated}


def admin_confirm_hold(*, case: Dict[str, Any], metadata: Optional[Dict[str, Any]], admin_user_id: str, now_ts: Optional[int] = None) -> Dict[str, Any]:
    """Confirm a violation: keep content HIDDEN, start the 30-day poster-response hold."""
    ts = int(now_ts or time.time())
    case_id = case["case_id"]
    content_type = str(case.get("content_type") or "")
    content_id = str(case.get("content_id") or "")
    md = _resolve_meta(case, metadata)
    state = str(case.get("state") or mc.STATE_VISIBLE)
    # Ensure the content is hidden with the case-state mirror; owner still sees it.
    owner = mhide.hide_content(content_type=content_type, content_id=content_id, metadata=md, case_id=case_id, state=mc.STATE_HOLD) or case.get("owner_user_id")
    # Advance visible -> under_review -> hold (never skip states).
    if state == mc.STATE_VISIBLE:
        mc.mark_under_review(case_id, hide_reason="admin_confirm", now_ts=ts)
    hold_until = ts + mc.HOLD_WINDOW_SECONDS
    updated = mc.transition(
        case_id,
        mc.STATE_HOLD,
        extra={"hidden": True, "hold_until": hold_until, "confirmed_at": ts, "confirmed_by": admin_user_id},
        now_ts=ts,
    )
    _notify(
        owner,
        event="moderation_violation_confirmed",
        title="Content violation confirmed",
        message=(
            f"A violation was confirmed for your {_label(content_type)}. It stays hidden. "
            "You have 30 days to respond before a final decision; with no response it will be removed."
        ),
        case_id=case_id,
        state=mc.STATE_HOLD,
        extra={"content_type": content_type, "hold_until": hold_until, "respond_deadline": hold_until},
    )
    return {"state": mc.STATE_HOLD, "owner_user_id": owner, "hold_until": hold_until, "case": updated}


def admin_final_reinstate(*, case: Dict[str, Any], metadata: Optional[Dict[str, Any]], admin_user_id: str, now_ts: Optional[int] = None) -> Dict[str, Any]:
    """Final call: reinstate -> restore the ORIGINAL content (byte-for-byte) + visible."""
    ts = int(now_ts or time.time())
    case_id = case["case_id"]
    content_type = str(case.get("content_type") or "")
    content_id = str(case.get("content_id") or "")
    md = _resolve_meta(case, metadata)
    owner = mhide.unhide_content(content_type=content_type, content_id=content_id, metadata=md, case_id=case_id, state=mc.STATE_VISIBLE) or case.get("owner_user_id")
    updated = mc.transition(case_id, mc.STATE_REINSTATED, extra={"hidden": False, "reinstated_at": ts, "reinstated_by": admin_user_id}, now_ts=ts)
    _notify(
        owner,
        event="moderation_content_reinstated",
        title="Your content was reinstated",
        message=f"After review, your {_label(content_type)} has been restored and is visible again.",
        case_id=case_id,
        state=mc.STATE_REINSTATED,
        extra={"content_type": content_type},
    )
    return {"state": mc.STATE_REINSTATED, "owner_user_id": owner, "case": updated}


def admin_final_delete(*, case: Dict[str, Any], metadata: Optional[Dict[str, Any]], admin_user_id: str, source_ticket_id: str = "", note: str = "", now_ts: Optional[int] = None) -> Dict[str, Any]:
    """Final call: delete -> hard delete the content + record the violation."""
    return _finalize_delete(
        case=case,
        metadata=metadata,
        admin_user_id=admin_user_id,
        reason=note or "admin_final_delete",
        source_ticket_id=source_ticket_id,
        record_violation_flag=True,
        now_ts=now_ts,
    )


# ── Poster response (MOD-A5) ─────────────────────────────────────────────────

def poster_respond(*, case_id: str, owner_user_id: str, statement: str, now_ts: Optional[int] = None) -> Dict[str, Any]:
    """Owner posts one statement on a held case -> awaiting_final (admin must decide)."""
    ts = int(now_ts or time.time())
    case = mc.get_case(case_id)
    if not case:
        raise ValueError("case_not_found")
    if str(case.get("owner_user_id") or "") != str(owner_user_id):
        raise PermissionError("not_owner")
    state = str(case.get("state") or "")
    if state == mc.STATE_AWAITING_FINAL:
        return {"state": state, "case": case, "already": True}
    if state != mc.STATE_HOLD:
        raise ValueError(f"invalid_state:{state}")
    updated = mc.transition(
        case_id,
        mc.STATE_AWAITING_FINAL,
        expected_from=[mc.STATE_HOLD],
        extra={"hidden": True, "poster_response": str(statement or "")[:2000], "responded_at": ts},
        now_ts=ts,
    )
    ticket_id = str(case.get("ticket_id") or "")
    try:
        write_moderation_audit_event(
            action="content_hold_poster_responded",
            actor_user_id=str(owner_user_id),
            ticket_id=ticket_id,
            content_type=str(case.get("content_type") or ""),
            content_id=str(case.get("content_id") or ""),
            target_user_id=str(owner_user_id),
            metadata={"case_id": case_id, "response_len": len(str(statement or ""))},
        )
    except Exception:
        logger.exception("poster_respond audit failed")
    # Re-open the linked ticket so it surfaces on the admin board awaiting a final call.
    if ticket_id:
        try:
            T.moderation_tickets.update_item(
                Key={"ticket_id": ticket_id},
                UpdateExpression="SET #s = :open, moderation_case_state = :st, updated_at = :ts",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":open": "open", ":st": mc.STATE_AWAITING_FINAL, ":ts": str(ts)},
            )
        except Exception:
            logger.exception("poster_respond ticket reopen failed for %s", ticket_id)
    return {"state": mc.STATE_AWAITING_FINAL, "case": updated}


def poster_close(*, case_id: str, owner_user_id: str, now_ts: Optional[int] = None) -> Dict[str, Any]:
    """Owner withdraws/closes -> content immediately hard-deleted (+ violation)."""
    case = mc.get_case(case_id)
    if not case:
        raise ValueError("case_not_found")
    if str(case.get("owner_user_id") or "") != str(owner_user_id):
        raise PermissionError("not_owner")
    state = str(case.get("state") or "")
    if state == mc.STATE_DELETED:
        return {"state": state, "already": True}
    if state not in (mc.STATE_HOLD, mc.STATE_AWAITING_FINAL):
        raise ValueError(f"invalid_state:{state}")
    return _finalize_delete(
        case=case,
        metadata=None,
        admin_user_id="system",
        reason="poster_closed",
        source_ticket_id=str(case.get("ticket_id") or ""),
        record_violation_flag=True,
        now_ts=now_ts,
    )


# ── 30-day expiry sweep (MOD-A6) ─────────────────────────────────────────────

def sweep_expired_holds(*, now_ts: Optional[int] = None, limit: int = 200) -> Dict[str, Any]:
    """Delete every case in HOLD whose hold_until has elapsed with no response.

    A hold that got a response is in AWAITING_FINAL (a different GSI partition) and
    is therefore NEVER swept — the admin must make the final call.
    """
    ts = int(now_ts or time.time())
    processed: List[str] = []
    start_key = None
    scanned = 0
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "ByState",
            "KeyConditionExpression": Key("state").eq(mc.STATE_HOLD) & Key("hold_until").lte(ts),
            "Limit": 25,
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = T.moderation_cases.query(**kwargs)
        for item in resp.get("Items", []):
            scanned += 1
            if scanned > limit:
                break
            case_id = str(item.get("case_id") or "")
            try:
                _finalize_delete(
                    case=item,
                    metadata=None,
                    admin_user_id="system",
                    reason="hold_expired_no_response",
                    source_ticket_id=str(item.get("ticket_id") or ""),
                    record_violation_flag=True,
                    now_ts=ts,
                )
                processed.append(case_id)
            except Exception:
                logger.exception("sweep_expired_holds: failed to finalize %s", case_id)
        start_key = resp.get("LastEvaluatedKey")
        if not start_key or scanned > limit:
            break
    if processed:
        logger.info("moderation hold sweep: deleted %d expired case(s)", len(processed))
    return {"deleted": len(processed), "case_ids": processed}


async def _hold_sweep_loop() -> None:
    import asyncio
    from app.core.settings import S

    if not getattr(S, "moderation_hold_sweep_enabled", True):
        logger.info("moderation hold sweep timer disabled")
        return
    interval = max(60, int(getattr(S, "moderation_hold_sweep_interval_seconds", 900)))
    logger.info("moderation hold sweep timer started (interval=%ds)", interval)
    while True:
        try:
            sweep_expired_holds()
        except Exception:
            logger.exception("hold_sweep: unhandled error during sweep")
        await asyncio.sleep(interval)


def start_hold_sweep_task() -> None:
    import asyncio
    from app.core.settings import S

    if not getattr(S, "moderation_hold_sweep_enabled", True):
        logger.info("moderation hold sweep timer not started (disabled)")
        return
    try:
        asyncio.get_event_loop().create_task(_hold_sweep_loop())
    except RuntimeError:
        asyncio.ensure_future(_hold_sweep_loop())
