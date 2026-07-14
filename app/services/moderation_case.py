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
    STATE_VISIBLE: {STATE_UNDER_REVIEW, STATE_DISMISSED},  # MODAB: dismiss a not-yet-hidden report
    STATE_UNDER_REVIEW: {STATE_DISMISSED, STATE_HOLD, STATE_VISIBLE},
    STATE_HOLD: {STATE_AWAITING_FINAL, STATE_DELETED, STATE_REINSTATED},
    STATE_AWAITING_FINAL: {STATE_REINSTATED, STATE_DELETED},
    STATE_DISMISSED: set(),
    STATE_REINSTATED: set(),
    STATE_DELETED: set(),
}

# -- Categories (D-CATEGORIES: 6 + MODX-8 illegal lane) + back-compat map --
SEVERE_CATEGORIES = {"sexual", "violence_threats", "hate", "illegal"}
LOWER_CATEGORIES = {"spam", "harassment", "other"}
CATEGORIES = SEVERE_CATEGORIES | LOWER_CATEGORIES

# MODX-8: the gravest category rides a DISTINCT locked lane (see
# moderation_illegal_lane); ``csam`` normalises to ``illegal``.
ILLEGAL_CATEGORIES = {"illegal", "csam"}

# Legacy topic -> new category (keep old reports working end-to-end).
LEGACY_CATEGORY_MAP = {
    "extortion": "harassment",
    "criminal": "violence_threats",
    "racist": "hate",
    "sexual": "sexual",
    "spam": "spam",
    "csam": "illegal",
}

# D-AUTOHIDE: lower-severity hides at >=3 DISTINCT reporters OR a trusted reporter.
LOWER_HIDE_THRESHOLD = 3

# MODX-3 anti-weaponization tuning.
SEVERE_DISTINCT_FLOOR = 2          # a severe 1st-report from one account never auto-hides
VELOCITY_BURST_MIN = 3             # >=N fresh/untrusted distinct reporters in a burst => human review
NEW_ACCOUNT_AGE_SECONDS = 7 * 86400  # accounts younger than this are "fresh" (burner-shaped)
PROTECTED_ACCOUNT_AGE_SECONDS = 30 * 86400  # established targets get a corroboration tier

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


def is_illegal_category(categories: Iterable[str]) -> bool:
    """MODX-8: does any category route to the locked illegal/CSAM lane?"""
    for c in (categories or []):
        raw = str(c or "").strip().lower()
        if raw in ILLEGAL_CATEGORIES or normalize_category(c) == "illegal":
            return True
    return False


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


def _account_age_seconds(user_id: str, *, now_ts: Optional[int] = None) -> Optional[int]:
    """Best-effort account age. Prefers ``account_state``/``users`` created_at.
    Returns None when unknown (treated as fresh/uncredible by callers)."""
    if not user_id:
        return None
    ts = int(now_ts or time.time())
    for tbl, key in ((T.account_state, "user_sub"), (T.users, "user_sub")):
        try:
            it = tbl.get_item(Key={key: user_id}).get("Item") or {}
        except ClientError:
            it = {}
        for f in ("created_at", "signup_at", "account_created_at"):
            v = it.get(f)
            if v is not None:
                try:
                    return max(0, ts - int(float(v)))
                except (TypeError, ValueError):
                    continue
        if bool(it.get("established")):
            return PROTECTED_ACCOUNT_AGE_SECONDS + 1
    return None


def reporter_is_credible(reporter_user_id: str, *, now_ts: Optional[int] = None) -> bool:
    """A reporter is *credible* (not a fresh burner) when trusted OR their account
    is older than the fresh-account window. Uncredible => burner-shaped."""
    if not reporter_user_id:
        return False
    if is_trusted_reporter(reporter_user_id):
        return True
    age = _account_age_seconds(reporter_user_id, now_ts=now_ts)
    return age is not None and age >= NEW_ACCOUNT_AGE_SECONDS


def is_protected_target(owner_user_id: str, *, now_ts: Optional[int] = None) -> bool:
    """MODX-3 target-protection tier: an established/verified creator needs
    corroboration (>=2 distinct reporters) before ANY auto-hide, so a single
    actor can't darken a high-value account."""
    if not owner_user_id:
        return False
    try:
        u = T.users.get_item(Key={"user_sub": owner_user_id}).get("Item") or {}
    except ClientError:
        u = {}
    if bool(u.get("verified")) or bool(u.get("is_verified")):
        return True
    age = _account_age_seconds(owner_user_id, now_ts=now_ts)
    return age is not None and age >= PROTECTED_ACCOUNT_AGE_SECONDS


def evaluate_reporters(reporter_ids: Iterable[str], *, now_ts: Optional[int] = None) -> Dict[str, Any]:
    """Summarise a case's distinct reporter set for the auto-hide decision."""
    ids = sorted({str(r) for r in (reporter_ids or []) if r})
    credible = [r for r in ids[:25] if reporter_is_credible(r, now_ts=now_ts)]
    trusted = [r for r in ids[:25] if is_trusted_reporter(r)]
    return {
        "distinct": len(ids),
        "credible": len(credible),
        "any_trusted": bool(trusted),
        "fresh_untrusted": len(ids) - len(credible),
    }


def should_auto_hide(
    *,
    categories: Iterable[str],
    distinct_reporter_count: int,
    credible_reporter_count: int,
    any_trusted: bool,
    protected_target: bool,
    velocity_suspect: bool,
) -> Tuple[bool, str]:
    """MODX-3 guarded, anti-weaponization auto-hide decision.

    A single throwaway account (or one account's repeated reports) can NEVER
    auto-hide: the decision is driven by the DISTINCT reporter set, and severe
    content needs either a trusted reporter or >=2 distinct reporters with at
    least one CREDIBLE (non-burner). A burst of fresh/untrusted accounts is
    suppressed to human review instead of auto-hiding. Protected (established/
    verified) targets always require corroboration.
    """
    distinct = int(distinct_reporter_count or 0)
    credible = int(credible_reporter_count or 0)

    # Coordinated fresh-account brigade -> never auto-hide; route to a human.
    if velocity_suspect:
        return False, "velocity_suppressed_human_review"

    # Protected target: corroboration is mandatory before any auto-hide.
    if protected_target and distinct < SEVERE_DISTINCT_FLOOR:
        return False, "awaiting_corroboration_protected"

    if is_severe(categories):
        if any_trusted:
            return True, "trusted_reporter"
        if distinct >= SEVERE_DISTINCT_FLOOR and credible >= 1:
            return True, "severe_corroborated"
        return False, "awaiting_corroboration"

    # LOWER severity.
    if any_trusted:
        return True, "trusted_reporter"
    if distinct >= LOWER_HIDE_THRESHOLD and credible >= 1:
        return True, "report_threshold"
    return False, ""


def aggregate_report(
    *,
    content_type: str,
    content_id: str,
    categories: Iterable[str],
    owner_user_id: Optional[str],
    ticket_id: Optional[str],
    reporter_user_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    now_ts: Optional[int] = None,
) -> Dict[str, Any]:
    """Create-or-aggregate the moderation case for a piece of content.

    One case per content ref. Atomically ADDs report_count, the category set, and
    (MODX-3/MODX-5) the DISTINCT ``reporter_ids`` set — a self-report
    (reporter == owner) is dropped so it can never pad the auto-hide counts.
    Returns the fresh case dict.
    """
    ts = int(now_ts or time.time())
    cid = case_id_for(content_type, content_id)
    cats = normalize_categories(categories) or ["other"]
    cat_set = set(cats)
    md = {k: v for k, v in (metadata or {}).items() if v is not None}
    # COI (MODX-5 A13): a self-report never counts toward the distinct set.
    reporter = str(reporter_user_id or "").strip()
    if reporter and owner_user_id and reporter == str(owner_user_id):
        reporter = ""
    rid_set = {reporter} if reporter else None

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
    if rid_set:
        base_item["reporter_ids"] = set(rid_set)
        base_item["first_report_at"] = ts
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
    add_parts = ["#rc :one", "#cats :cats"]
    if owner_user_id:
        names["#owner"] = "owner_user_id"
        set_parts.append("#owner = if_not_exists(#owner, :owner)")
        values[":owner"] = owner_user_id
    if ticket_id:
        names["#tk"] = "ticket_id"
        set_parts.append("#tk = if_not_exists(#tk, :tk)")
        values[":tk"] = ticket_id
    if rid_set:
        names["#rids"] = "reporter_ids"
        values[":rids"] = set(rid_set)
        add_parts.append("#rids :rids")
        names["#fra"] = "first_report_at"
        set_parts.append("#fra = if_not_exists(#fra, :ts)")
    upd = "SET " + ", ".join(set_parts) + " ADD " + ", ".join(add_parts)
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


def transition_result(
    case_id: str,
    to_state: str,
    *,
    expected_from: Optional[Iterable[str]] = None,
    extra: Optional[Dict[str, Any]] = None,
    now_ts: Optional[int] = None,
) -> Tuple[bool, Dict[str, Any]]:
    """Idempotent, guarded state transition returning ``(changed, case)``.

    ``changed`` is True ONLY when THIS call actually moved the case into
    ``to_state`` (i.e. it won the DB conditional write). A no-op (already in
    ``to_state``) and a lost race (a concurrent writer transitioned first) BOTH
    return ``changed=False``.

    This is the act-AFTER-guard primitive (MODX-2): a caller that performs an
    irreversible side-effect (hard delete, violation strike, un-hide) must do so
    ONLY when ``changed`` is True, so concurrent finalizers/dismissers can never
    double-act, and an illegal-state delete raises BEFORE any content is touched.

    Rejects illegal transitions (a case cannot skip states).
    """
    ts = int(now_ts or time.time())
    case = get_case(case_id)
    frm = str((case or {}).get("state") or STATE_VISIBLE)
    if to_state == frm:
        return False, case or {}
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
            # Lost the race: another writer already moved the case -> NOT our change.
            return False, get_case(case_id) or {}
        raise
    return True, get_case(case_id) or {}


def transition(
    case_id: str,
    to_state: str,
    *,
    expected_from: Optional[Iterable[str]] = None,
    extra: Optional[Dict[str, Any]] = None,
    now_ts: Optional[int] = None,
) -> Dict[str, Any]:
    """Back-compat wrapper over ``transition_result`` returning just the case dict.

    Prefer ``transition_result`` when the caller must know whether it actually
    moved the case (act-AFTER-guard). Rejects illegal transitions; no-op when the
    case is already in ``to_state``.
    """
    _changed, case = transition_result(
        case_id, to_state, expected_from=expected_from, extra=extra, now_ts=now_ts
    )
    return case


def reopen_terminal_case(
    case_id: str,
    *,
    categories: Iterable[str],
    ticket_id: Optional[str] = None,
    now_ts: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """MODX-1: open a FRESH lifecycle on previously-actioned (terminal) content.

    A ``case_id`` is a deterministic hash of ``(content_type, content_id)``, so a
    re-report of ``dismissed``/``reinstated``/``deleted`` content reuses the same
    (frozen) case. This atomically resets that terminal case back to ``visible``:
    clears ``hidden``, drops the hold/terminal markers, resets ``report_count`` to
    1 and ``categories`` to THIS report's, bumps ``reopen_count``, and re-points
    ``ticket_id`` at the newly-minted open ticket.

    Conditional on the case still being terminal, so concurrent re-reports reopen
    EXACTLY ONCE (the loser is a no-op -> returns None). Returns the reopened case
    on success, else None (not terminal / lost race).
    """
    ts = int(now_ts or time.time())
    cats = set(normalize_categories(categories) or ["other"])
    names = {
        "#s": "state", "#ua": "updated_at", "#h": "hidden",
        "#rc": "report_count", "#cats": "categories",
        "#ra": "reopened_at", "#rn": "reopen_count",
    }
    values: Dict[str, Any] = {
        ":vis": STATE_VISIBLE, ":ts": ts, ":false": False,
        ":one": 1, ":zero": 0, ":cats": cats,
        ":dismissed": STATE_DISMISSED, ":reinstated": STATE_REINSTATED, ":deleted": STATE_DELETED,
    }
    set_parts = [
        "#s = :vis", "#ua = :ts", "#h = :false",
        "#rc = :one", "#cats = :cats", "#ra = :ts",
        "#rn = if_not_exists(#rn, :zero) + :one",
    ]
    if ticket_id:
        names["#tk"] = "ticket_id"
        values[":tk"] = ticket_id
        set_parts.append("#tk = :tk")
    remove_parts = [
        "hold_until", "deleted_at", "delete_reason", "reinstated_at",
        "reinstated_by", "dismissed_at", "dismissed_by", "confirmed_at",
        "confirmed_by", "poster_response", "responded_at", "hidden_at", "hide_reason",
    ]
    upd = "SET " + ", ".join(set_parts) + " REMOVE " + ", ".join(remove_parts)
    try:
        T.moderation_cases.update_item(
            Key={"case_id": case_id},
            UpdateExpression=upd,
            ConditionExpression="#s = :dismissed OR #s = :reinstated OR #s = :deleted",
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return None
        logger.exception("moderation_case.reopen_terminal_case failed for %s", case_id)
        return None
    return get_case(case_id)


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
        reporter_user_id=reporter_user_id,
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

    # MODX-1: a re-report of previously-actioned (terminal) content must open a
    # FRESH actionable case instead of hitting the frozen terminal state. Reopen
    # to `visible`, then fall through and re-evaluate the guarded auto-hide below
    # (so a severe re-report re-hides, and admin actions on the re-report ticket
    # act on a live, non-terminal case -> no 500).
    if state in TERMINAL_STATES:
        reopened = reopen_terminal_case(
            case_id, categories=normalize_categories(topics), ticket_id=ticket_id, now_ts=ts
        )
        case = reopened or get_case(case_id) or case
        state = str(case.get("state") or STATE_VISIBLE)
        report_count = int(case.get("report_count") or 1)
        cats = list(case.get("categories") or normalize_categories(topics))
        result.update({
            "state": state,
            "report_count": report_count,
            "categories": sorted({normalize_category(c) for c in cats}),
            "reopened": True,
        })

    # Persist the current distinct-reporter count for the admin detail DTO.
    reporter_ids = list(case.get("reporter_ids") or [])
    distinct_reporter_count = len({str(r) for r in reporter_ids if r})
    result["distinct_reporter_count"] = distinct_reporter_count

    # MODX-8: illegal/CSAM content takes the DISTINCT locked lane — immediate
    # restricted hide on the FIRST report (no distinct-reporter/trust gate),
    # preserve evidence, mandated-report, senior-only queue. NEVER the public hold.
    if is_illegal_category(cats):
        if bool(case.get("hidden")) or state != STATE_VISIBLE:
            result["illegal_lane"] = True
            return result
        try:
            from app.services import moderation_illegal_lane as _illegal
            esc = _illegal.escalate(
                case_id=case_id,
                content_type=content_type,
                content_id=content_id,
                owner_user_id=owner,
                categories=cats,
                reporter_user_id=reporter_user_id,
                ticket_id=ticket_id,
                metadata=metadata,
                now_ts=ts,
            )
            _notify_owner_hidden(esc.get("owner_user_id") or owner, content_type=content_type, case_id=case_id, reason="illegal_content", categories=cats)
            result.update({
                "state": STATE_UNDER_REVIEW,
                "auto_hidden_now": True,
                "illegal_lane": True,
                "owner_user_id": esc.get("owner_user_id") or owner,
                "hide_decision_reason": "illegal_lane",
            })
        except Exception:
            logger.exception("on_report_filed: illegal-lane escalation failed for %s", case_id)
        return result

    # Already hidden or (still) non-visible -> nothing new to hide (idempotent).
    if bool(case.get("hidden")) or state != STATE_VISIBLE:
        return result

    # MODX-3: decide on the DISTINCT reporter set + credibility, not raw events.
    rep_summary = evaluate_reporters(reporter_ids, now_ts=ts)
    trusted = rep_summary["any_trusted"] or is_trusted_reporter(reporter_user_id)
    protected = is_protected_target(owner, now_ts=ts)
    # Coordinated fresh-account brigade: a burst of >=N distinct fresh/untrusted
    # reporters with zero credible corroboration -> route to human, never hide.
    velocity_suspect = (
        rep_summary["fresh_untrusted"] >= VELOCITY_BURST_MIN and rep_summary["credible"] == 0 and not trusted
    )
    do_hide, reason = should_auto_hide(
        categories=cats,
        distinct_reporter_count=distinct_reporter_count,
        credible_reporter_count=rep_summary["credible"],
        any_trusted=trusted,
        protected_target=protected,
        velocity_suspect=velocity_suspect,
    )
    result["hide_decision_reason"] = reason
    result["trusted_reporter"] = trusted
    result["protected_target"] = protected
    result["velocity_suspect"] = velocity_suspect

    if not do_hide:
        # Flag brigades / suppressed auto-hides for a human on the case so a mod
        # can see the coordinated-report signal and act (never a silent hide).
        if velocity_suspect or reason in ("awaiting_corroboration", "awaiting_corroboration_protected"):
            _flag_needs_human_review(case_id, reason=reason, distinct=distinct_reporter_count, now_ts=ts)
            result["needs_human_review"] = True
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


def _flag_needs_human_review(case_id: str, *, reason: str, distinct: int, now_ts: int) -> None:
    """Mark a case that a guard SUPPRESSED (brigade / uncorroborated) for human
    triage. Best-effort; keeps the content visible (no silent hide)."""
    try:
        T.moderation_cases.update_item(
            Key={"case_id": case_id},
            UpdateExpression=(
                "SET needs_human_review = :t, human_review_reason = :r, "
                "distinct_reporter_count = :d, human_review_flagged_at = :ts"
            ),
            ExpressionAttributeValues={":t": True, ":r": str(reason or "")[:64], ":d": int(distinct), ":ts": int(now_ts)},
        )
    except ClientError:
        logger.exception("moderation_case._flag_needs_human_review failed for %s", case_id)
    try:
        from app.services.moderation_audit_log import write_moderation_audit_event
        write_moderation_audit_event(
            action="auto_hide_suppressed_human_review",
            actor_user_id="system",
            ticket_id="",
            content_type="",
            content_id="",
            target_user_id="",
            metadata={"case_id": case_id, "reason": reason, "distinct_reporter_count": int(distinct)},
        )
    except Exception:
        logger.exception("moderation_case._flag_needs_human_review audit failed for %s", case_id)
