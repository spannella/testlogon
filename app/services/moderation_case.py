from __future__ import annotations

"""MOD-A1: Content moderation CASE store + state machine + guarded auto-hide.

A single case is keyed to a piece of content ``(content_type, content_id)`` and
aggregates every report filed against that content. The case drives the
non-destructive hide -> under_review -> 30d hold -> final-call lifecycle.

Non-destructive is the crux: this module NEVER nulls content bodies. Hiding is a
flag over the intact row (see ``moderation_hide``); only a terminal DELETE
removes content.
"""

import hashlib
import logging
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

from botocore.exceptions import ClientError

from app.core.tables import T

logger = logging.getLogger(__name__)

# -- States ------------------------------------------------------------------
STATE_VISIBLE = "visible"
STATE_UNDER_REVIEW = "under_review"
STATE_HOLD = "hold"
STATE_AWAITING_FINAL = "awaiting_final"
STATE_DISMISSED = "dismissed"
STATE_REINSTATED = "reinstated"
STATE_DELETED = "deleted"

TERMINAL_STATES = {STATE_DISMISSED, STATE_REINSTATED, STATE_DELETED}

# Legal forward transitions (illegal transitions rejected; same->same is a no-op).
ALLOWED_TRANSITIONS: Dict[str, set] = {
    STATE_VISIBLE: {STATE_UNDER_REVIEW},
    STATE_UNDER_REVIEW: {STATE_DISMISSED, STATE_HOLD, STATE_VISIBLE},
    STATE_HOLD: {STATE_AWAITING_FINAL, STATE_DELETED, STATE_REINSTATED},
    STATE_AWAITING_FINAL: {STATE_REINSTATED, STATE_DELETED},
    STATE_DISMISSED: set(),
    STATE_REINSTATED: set(),
    STATE_DELETED: set(),
}

# -- Categories (D-CATEGORIES: 6) + back-compat map for the legacy 5 topics --
SEVERE_CATEGORIES = {"sexual", "violence_threats", "hate"}
LOWER_CATEGORIES = {"spam", "harassment", "other"}
CATEGORIES = SEVERE_CATEGORIES | LOWER_CATEGORIES

# Legacy topic -> new category (keep old reports working end-to-end).
LEGACY_CATEGORY_MAP = {
    "extortion": "harassment",
    "criminal": "violence_threats",
    "racist": "hate",
    "sexual": "sexual",
    "spam": "spam",
}

# D-AUTOHIDE: lower-severity hides at >=3 reports OR a trusted reporter.
LOWER_HIDE_THRESHOLD = 3

HOLD_WINDOW_SECONDS = 30 * 86400  # 30 days


def normalize_category(topic: str) -> str:
    t = str(topic or "").strip().lower()
    return LEGACY_CATEGORY_MAP.get(t, t)


def normalize_categories(topics: Iterable[str]) -> List[str]:
    out: List[str] = []
    for t in topics or []:
        c = normalize_category(t)
        if c and c not in out:
            out.append(c)
    return out


def case_id_for(content_type: str, content_id: str) -> str:
    digest = hashlib.sha256(f"{content_type}:{content_id}".encode("utf-8")).hexdigest()[:20]
    return f"modcase_{digest}"


def content_ref(content_type: str, content_id: str) -> str:
    return f"{content_type}#{content_id}"


def get_case(case_id: str) -> Optional[Dict[str, Any]]:
    try:
        return T.moderation_cases.get_item(Key={"case_id": case_id}).get("Item")
    except ClientError:
        logger.exception("moderation_case.get_case failed for %s", case_id)
        return None


def get_case_for_content(content_type: str, content_id: str) -> Optional[Dict[str, Any]]:
    return get_case(case_id_for(content_type, content_id))


def is_severe(categories: Iterable[str]) -> bool:
    return any(normalize_category(c) in SEVERE_CATEGORIES for c in (categories or []))


def is_trusted_reporter(reporter_user_id: str) -> bool:
    """Simple trusted-reporter signal (D-AUTOHIDE).

    Trusted when account_state carries an explicit ``trusted_reporter`` flag, OR
    the reporter has a good reputation (``report_trust_score`` >= 1) with a low
    false-report rate (``report_false_rate`` <= 0.2). A boolean is sufficient.
    """
    if not reporter_user_id:
        return False
    try:
        st = T.account_state.get_item(Key={"user_sub": reporter_user_id}).get("Item") or {}
    except ClientError:
        return False
    if bool(st.get("trusted_reporter")):
        return True
    try:
        score = float(st.get("report_trust_score") or 0)
        false_rate = float(st.get("report_false_rate") or 0)
    except (TypeError, ValueError):
        return False
    return score >= 1 and false_rate <= 0.2


def should_auto_hide(*, categories: Iterable[str], report_count: int, trusted: bool) -> Tuple[bool, str]:
    """Guarded auto-hide decision (D-AUTOHIDE).

    - SEVERE category -> hide on the 1st report.
    - LOWER category  -> hide only at report_count>=3 OR a trusted reporter.
    """
    if is_severe(categories):
        return True, "severe_category"
    if trusted:
        return True, "trusted_reporter"
    if int(report_count or 0) >= LOWER_HIDE_THRESHOLD:
        return True, "report_threshold"
    return False, ""


def aggregate_report(
    *,
    content_type: str,
    content_id: str,
    categories: Iterable[str],
    owner_user_id: Optional[str],
    ticket_id: Optional[str],
    metadata: Optional[Dict[str, Any]] = None,
    now_ts: Optional[int] = None,
) -> Dict[str, Any]:
    """Create-or-aggregate the moderation case for a piece of content.

    One case per content ref. Atomically ADDs report_count + the category set.
    Returns the fresh case dict.
    """
    ts = int(now_ts or time.time())
    cid = case_id_for(content_type, content_id)
    cats = normalize_categories(categories) or ["other"]
    cat_set = set(cats)
    md = {k: v for k, v in (metadata or {}).items() if v is not None}

    base_item: Dict[str, Any] = {
        "case_id": cid,
        "entity_type": "moderation_case",
        "content_type": content_type,
        "content_id": content_id,
        "content_ref": content_ref(content_type, content_id),
        "state": STATE_VISIBLE,
        "report_count": 1,
        "categories": cat_set,
        "hidden": False,
        "created_at": ts,
        "updated_at": ts,
    }
    if owner_user_id:
        base_item["owner_user_id"] = owner_user_id
    if ticket_id:
        base_item["ticket_id"] = ticket_id
    if md:
        base_item["content_metadata"] = md

    try:
        T.moderation_cases.put_item(Item=base_item, ConditionExpression="attribute_not_exists(case_id)")
        return dict(base_item)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
            raise

    names = {"#rc": "report_count", "#cats": "categories", "#ua": "updated_at"}
    values: Dict[str, Any] = {":one": 1, ":cats": cat_set, ":ts": ts}
    set_parts = ["#ua = :ts"]
    if owner_user_id:
        names["#owner"] = "owner_user_id"
        set_parts.append("#owner = if_not_exists(#owner, :owner)")
        values[":owner"] = owner_user_id
    if ticket_id:
        names["#tk"] = "ticket_id"
        set_parts.append("#tk = if_not_exists(#tk, :tk)")
        values[":tk"] = ticket_id
    upd = "SET " + ", ".join(set_parts) + " ADD #rc :one, #cats :cats"
    try:
        T.moderation_cases.update_item(
            Key={"case_id": cid},
            UpdateExpression=upd,
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )
    except ClientError:
        logger.exception("moderation_case.aggregate_report update failed for %s", cid)
    return get_case(cid) or dict(base_item)


def transition(
    case_id: str,
    to_state: str,
    *,
    expected_from: Optional[Iterable[str]] = None,
    extra: Optional[Dict[str, Any]] = None,
    now_ts: Optional[int] = None,
) -> Dict[str, Any]:
    """Idempotent, guarded state transition.

    Rejects illegal transitions (a case cannot skip states). A no-op when the
    case is already in ``to_state``.
    """
    ts = int(now_ts or time.time())
    case = get_case(case_id)
    frm = str((case or {}).get("state") or STATE_VISIBLE)
    if to_state == frm:
        return case or {}
    allowed = ALLOWED_TRANSITIONS.get(frm, set())
    if to_state not in allowed:
        raise ValueError(f"illegal moderation_case transition {frm} -> {to_state}")
    if expected_from is not None and frm not in set(expected_from):
        raise ValueError(f"unexpected from-state {frm}")

    names = {"#s": "state", "#ua": "updated_at"}
    values: Dict[str, Any] = {":to": to_state, ":ts": ts, ":from": frm}
    set_parts = ["#s = :to", "#ua = :ts"]
    for i, (k, v) in enumerate((extra or {}).items()):
        nk, vk = f"#e{i}", f":e{i}"
        names[nk] = k
        values[vk] = v
        set_parts.append(f"{nk} = {vk}")
    try:
        T.moderation_cases.update_item(
            Key={"case_id": case_id},
            UpdateExpression="SET " + ", ".join(set_parts),
            ConditionExpression="#s = :from",
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return get_case(case_id) or {}
        raise
    return get_case(case_id) or {}


def mark_under_review(case_id: str, *, hide_reason: str, now_ts: Optional[int] = None) -> Dict[str, Any]:
    ts = int(now_ts or time.time())
    return transition(
        case_id,
        STATE_UNDER_REVIEW,
        extra={"hidden": True, "hidden_at": ts, "hide_reason": str(hide_reason or "")[:64]},
        now_ts=ts,
    )


# ── D-NOTIFY: notify the content owner when their content is (auto)hidden ─────
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


def _notify_owner_hidden(owner_user_id: Optional[str], *, content_type: str, case_id: str, reason: str, categories: Iterable[str]) -> None:
    if not owner_user_id:
        return
    label = _CONTENT_LABEL.get(content_type, "content")
    try:
        from app.services.alerts import write_alert
        write_alert(
            owner_user_id,
            event="moderation_content_hidden",
            outcome="warning",
            title="Your content was reported",
            details={
                "case_id": case_id,
                "action": "content_hidden",
                "content_type": content_type,
                "content_label": label,
                "hide_reason": str(reason or ""),
                "categories": ",".join(sorted({normalize_category(c) for c in (categories or [])})),
                "state": STATE_UNDER_REVIEW,
                "message": f"Your {label} was reported and is hidden pending review.",
            },
            push_event_types=["moderation_content_hidden"],
        )
    except TypeError:
        # write_alert without push_event_types kwarg (older signature): in-app only.
        from app.services.alerts import write_alert
        write_alert(
            owner_user_id,
            event="moderation_content_hidden",
            outcome="warning",
            title="Your content was reported",
            details={
                "case_id": case_id,
                "action": "content_hidden",
                "content_type": content_type,
                "content_label": label,
                "message": f"Your {label} was reported and is hidden pending review.",
            },
        )
    except Exception:
        logger.exception("moderation_case._notify_owner_hidden failed for %s", owner_user_id)


def on_report_filed(
    *,
    content_type: str,
    content_id: str,
    topics: Iterable[str],
    reporter_user_id: str,
    metadata: Optional[Dict[str, Any]] = None,
    ticket_id: Optional[str] = None,
    now_ts: Optional[int] = None,
) -> Dict[str, Any]:
    """MOD-A3: aggregate the report onto the case, apply the GUARDED auto-hide,
    and (when hidden) move the case to under_review + notify the poster.

    Idempotent + non-destructive. Never regresses a terminal/already-hidden case.
    """
    from app.services import moderation_hide as mhide

    ts = int(now_ts or time.time())
    metadata = metadata or {}
    owner = mhide.resolve_owner(content_type=content_type, content_id=content_id, metadata=metadata)

    case = aggregate_report(
        content_type=content_type,
        content_id=content_id,
        categories=topics,
        owner_user_id=owner,
        ticket_id=ticket_id,
        metadata=metadata,
        now_ts=ts,
    )
    case_id = case["case_id"]
    report_count = int(case.get("report_count") or 1)
    cats = list(case.get("categories") or normalize_categories(topics))
    state = str(case.get("state") or STATE_VISIBLE)

    result = {
        "case_id": case_id,
        "state": state,
        "report_count": report_count,
        "categories": sorted({normalize_category(c) for c in cats}),
        "auto_hidden_now": False,
        "owner_user_id": owner,
    }

    # Already hidden or terminal -> nothing new to hide (idempotent aggregation only).
    if bool(case.get("hidden")) or state in TERMINAL_STATES or state != STATE_VISIBLE:
        return result

    trusted = is_trusted_reporter(reporter_user_id)
    do_hide, reason = should_auto_hide(categories=cats, report_count=report_count, trusted=trusted)
    result["hide_decision_reason"] = reason
    result["trusted_reporter"] = trusted
    if not do_hide:
        return result

    resolved_owner = mhide.hide_content(
        content_type=content_type,
        content_id=content_id,
        metadata=metadata,
        case_id=case_id,
        state=STATE_UNDER_REVIEW,
    ) or owner
    mark_under_review(case_id, hide_reason=reason, now_ts=ts)
    _notify_owner_hidden(resolved_owner, content_type=content_type, case_id=case_id, reason=reason, categories=cats)

    result.update({"state": STATE_UNDER_REVIEW, "auto_hidden_now": True, "owner_user_id": resolved_owner})
    return result
