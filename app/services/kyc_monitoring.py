"""KYC ongoing monitoring — periodic review scheduling, trigger events,
re-screening, and automatic tier downgrade (KYC-016).

This service implements the ongoing-monitoring layer on top of the one-time
KYC verification flow:

* A review schedule is created when a case is approved, with the next review
  date derived from the user's risk tier.
* Trigger events (country change, large transaction, screening hit, manual)
  flag a user for ad-hoc review.
* A review checker moves overdue schedules into a grace period and, once the
  grace deadline passes, automatically downgrades the user's KYC tier.
* A re-screening pass re-checks approved users against sanctions lists. In dev
  mode the screening result is deterministically derived from the input via
  ``zlib.crc32`` (NOT the builtin ``hash()``, which is salted per-process).

Records live in the dedicated ``kyc_review_schedule`` table:

    PK: USER#{user_sub}  SK: SCHEDULE              -> review schedule
    PK: USER#{user_sub}  SK: TRIGGER#{ts}#{id}     -> trigger event log

GSI ``ByNextReviewDate``: PK = gsi_status_pk (schedule status), SK =
next_review_date (N).
"""
from __future__ import annotations

import uuid
import zlib
from typing import Any

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event, write_alert

DAY_SECONDS = 86400

REVIEW_FREQUENCY_DAYS: dict[str, int] = {
    "low": 1095,      # 3 years
    "medium": 365,    # 1 year
    "high": 182,      # 6 months
    "critical": 91,   # 3 months
}

TRIGGER_TYPES: set[str] = {
    "large_transaction",
    "country_change",
    "name_change",
    "screening_hit",
    "manual",
}

# Schedule status lifecycle:
#   active        -> normal, next review in the future
#   needs_review  -> a trigger event requires ad-hoc review
#   grace_period  -> review is overdue but within the grace window
#   downgraded    -> grace window expired, tier was auto-downgraded
SCHEDULE_STATUS_ACTIVE = "active"
SCHEDULE_STATUS_NEEDS_REVIEW = "needs_review"
SCHEDULE_STATUS_GRACE = "grace_period"
SCHEDULE_STATUS_DOWNGRADED = "downgraded"


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _schedule_key(user_sub: str) -> dict[str, str]:
    return {"pk": f"USER#{user_sub}", "sk": "SCHEDULE"}


# ── Schedule lifecycle ──────────────────────────────────────────────────────


def create_review_schedule(
    *,
    user_sub: str,
    risk_tier: str,
    case_id: str,
    actor_sub: str | None = None,
) -> dict[str, Any]:
    """Create or reset a review schedule for a user after KYC approval."""
    ts = now_ts()
    frequency = REVIEW_FREQUENCY_DAYS.get(risk_tier, REVIEW_FREQUENCY_DAYS["medium"])
    next_review = ts + (frequency * DAY_SECONDS)
    grace_days = int(S.kyc_review_grace_period_days)
    grace_deadline = next_review + (grace_days * DAY_SECONDS)

    item = {
        "pk": f"USER#{user_sub}",
        "sk": "SCHEDULE",
        "user_sub": user_sub,
        "risk_tier": risk_tier,
        "review_frequency_days": frequency,
        "last_review_date": ts,
        "next_review_date": next_review,
        "grace_period_days": grace_days,
        "grace_deadline": grace_deadline,
        "status": SCHEDULE_STATUS_ACTIVE,
        "case_id": case_id,
        "created_at": ts,
        "updated_at": ts,
        "gsi_status_pk": SCHEDULE_STATUS_ACTIVE,
    }
    T.kyc_review_schedule.put_item(Item=item)

    audit_event(
        "kyc.monitoring.schedule_created",
        actor_sub or "system",
        None,
        outcome="success",
        user_sub=user_sub,
        risk_tier=risk_tier,
        next_review_date=next_review,
    )
    return item


def get_review_schedule(user_sub: str) -> dict[str, Any] | None:
    """Get the review schedule for a user (consistent read)."""
    resp = T.kyc_review_schedule.get_item(
        Key=_schedule_key(user_sub),
        ConsistentRead=True,
    )
    return resp.get("Item")


def _set_schedule_status(user_sub: str, status: str) -> None:
    ts = now_ts()
    T.kyc_review_schedule.update_item(
        Key=_schedule_key(user_sub),
        UpdateExpression="SET #status = :status, updated_at = :ts, gsi_status_pk = :gsi_pk",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":status": status,
            ":ts": ts,
            ":gsi_pk": status,
        },
    )


def complete_review(
    *,
    user_sub: str,
    new_risk_tier: str | None = None,
    case_id: str | None = None,
    admin_sub: str,
    request: Any = None,
) -> dict[str, Any]:
    """Mark a periodic review as completed and reset the schedule."""
    schedule = get_review_schedule(user_sub)
    if not schedule:
        raise ValueError("no_schedule_found")

    risk_tier = new_risk_tier or str(schedule.get("risk_tier") or "medium")
    item = create_review_schedule(
        user_sub=user_sub,
        risk_tier=risk_tier,
        case_id=case_id or str(schedule.get("case_id") or ""),
        actor_sub=admin_sub,
    )
    audit_event(
        "kyc.monitoring.review_completed",
        admin_sub,
        request,
        outcome="success",
        user_sub=user_sub,
        risk_tier=risk_tier,
    )
    return item


# ── Trigger events ──────────────────────────────────────────────────────────


def create_trigger_event(
    *,
    user_sub: str,
    trigger_type: str,
    details: dict[str, Any] | None = None,
    actor_sub: str | None = None,
    request: Any = None,
) -> dict[str, Any]:
    """Record a trigger event that may require ad-hoc review."""
    if trigger_type not in TRIGGER_TYPES:
        raise ValueError(f"invalid_trigger_type:{trigger_type}")

    ts = now_ts()
    event_id = uuid.uuid4().hex[:12]
    item = {
        "pk": f"USER#{user_sub}",
        "sk": f"TRIGGER#{ts:013d}#{event_id}",
        "event_id": event_id,
        "user_sub": user_sub,
        "trigger_type": trigger_type,
        "details": details or {},
        "created_at": ts,
        "created_by": actor_sub or "system",
    }
    T.kyc_review_schedule.put_item(Item=item)

    # Flag the schedule for review (only when currently active so we don't
    # clobber grace_period / downgraded states).
    schedule = get_review_schedule(user_sub)
    if schedule and schedule.get("status") == SCHEDULE_STATUS_ACTIVE:
        _set_schedule_status(user_sub, SCHEDULE_STATUS_NEEDS_REVIEW)

    audit_event(
        "kyc.monitoring.trigger_event",
        actor_sub or "system",
        request,
        outcome="info",
        user_sub=user_sub,
        trigger_type=trigger_type,
    )

    write_alert(
        user_sub,
        event="kyc.review.triggered",
        outcome="warning",
        title=f"KYC review triggered: {trigger_type}",
        details={
            "trigger_type": trigger_type,
            "user_sub": user_sub,
            **(details or {}),
        },
        action_url="/kyc",
    )
    return item


def list_trigger_events(user_sub: str, *, limit: int = 50) -> list[dict[str, Any]]:
    """List trigger events for a user, newest first."""
    resp = T.kyc_review_schedule.query(
        KeyConditionExpression=(
            Key("pk").eq(f"USER#{user_sub}") & Key("sk").begins_with("TRIGGER#")
        ),
        ScanIndexForward=False,
        Limit=max(1, min(int(limit or 50), 100)),
    )
    return resp.get("Items", [])


# ── GSI scan helper ─────────────────────────────────────────────────────────


def _query_by_status(
    status: str,
    *,
    le_now: int | None = None,
    between: tuple[int, int] | None = None,
) -> list[dict[str, Any]]:
    """Query schedules on the ByNextReviewDate GSI, looping LastEvaluatedKey."""
    items: list[dict[str, Any]] = []
    start_key: dict[str, Any] | None = None
    while True:
        cond = Key("gsi_status_pk").eq(status)
        if between is not None:
            cond = cond & Key("next_review_date").between(between[0], between[1])
        elif le_now is not None:
            cond = cond & Key("next_review_date").lte(le_now)
        kwargs: dict[str, Any] = {
            "IndexName": "ByNextReviewDate",
            "KeyConditionExpression": cond,
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = T.kyc_review_schedule.query(**kwargs)
        items.extend(resp.get("Items", []))
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break
    return items


# ── Review checker ──────────────────────────────────────────────────────────


def run_review_checker(*, dry_run: bool = False) -> dict[str, Any]:
    """Check for overdue reviews and apply grace-period / downgrade logic."""
    now = now_ts()
    results = {
        "checked_at": now,
        "dry_run": dry_run,
        "entered_grace_period": 0,
        "auto_downgraded": 0,
    }

    # Active schedules whose next_review_date has passed.
    for item in _query_by_status(SCHEDULE_STATUS_ACTIVE, le_now=now):
        user_sub = str(item.get("user_sub") or "")
        if not user_sub:
            continue
        grace_deadline = _coerce_int(item.get("grace_deadline"))
        if grace_deadline and now > grace_deadline:
            if not dry_run:
                _auto_downgrade(user_sub, item)
            results["auto_downgraded"] += 1
        else:
            if not dry_run:
                _enter_grace_period(user_sub, item)
            results["entered_grace_period"] += 1

    # Schedules already flagged (needs_review / grace_period) whose grace
    # deadline has now passed -> downgrade.
    for status in (SCHEDULE_STATUS_NEEDS_REVIEW, SCHEDULE_STATUS_GRACE):
        for item in _query_by_status(status):
            user_sub = str(item.get("user_sub") or "")
            if not user_sub:
                continue
            grace_deadline = _coerce_int(item.get("grace_deadline"))
            if grace_deadline and now > grace_deadline:
                if not dry_run:
                    _auto_downgrade(user_sub, item)
                results["auto_downgraded"] += 1

    return results


def _enter_grace_period(user_sub: str, schedule: dict[str, Any]) -> None:
    """Move a schedule into the grace period and notify the user."""
    _set_schedule_status(user_sub, SCHEDULE_STATUS_GRACE)
    write_alert(
        user_sub,
        event="kyc.review.grace_period",
        outcome="warning",
        title="Verification review overdue",
        details={
            "message": (
                "Your periodic verification review is overdue. Please complete "
                "re-verification within the grace period to maintain your tier."
            ),
            "grace_deadline": schedule.get("grace_deadline"),
        },
        action_url="/kyc",
    )


def _auto_downgrade(user_sub: str, schedule: dict[str, Any]) -> None:
    """Automatically downgrade a user's tier due to an overdue review."""
    from app.services.kyc_tiers import get_user_kyc_tier, upgrade_tier

    current_tier = get_user_kyc_tier(user_sub)
    if current_tier <= 0:
        # Already at the minimum tier — just mark the schedule downgraded.
        _set_schedule_status(user_sub, SCHEDULE_STATUS_DOWNGRADED)
        return

    new_tier = max(0, current_tier - 1)
    upgrade_tier(
        user_sub=user_sub,
        new_tier=new_tier,
        reason="periodic_review_overdue",
        actor_sub="system:kyc_monitoring",
    )
    _set_schedule_status(user_sub, SCHEDULE_STATUS_DOWNGRADED)

    audit_event(
        "kyc.monitoring.auto_downgrade",
        "system:kyc_monitoring",
        None,
        outcome="warning",
        user_sub=user_sub,
        from_tier=current_tier,
        to_tier=new_tier,
        reason="periodic_review_overdue",
    )
    write_alert(
        user_sub,
        event="kyc.review.overdue",
        outcome="error",
        title="Verification tier downgraded",
        details={
            "message": "Your verification tier was downgraded due to an overdue review.",
            "from_tier": current_tier,
            "to_tier": new_tier,
        },
        action_url="/kyc",
    )


# ── Re-screening ────────────────────────────────────────────────────────────


def _deterministic_screening_hit(user_sub: str) -> bool:
    """Deterministic mock sanctions match derived from the input.

    Uses ``zlib.crc32`` so the result is stable across processes (the builtin
    ``hash()`` is salted per-process and must NOT be used here). Any user whose
    sub contains ``"flagged"`` always matches; otherwise ~1-in-N users match
    deterministically by checksum.
    """
    if "flagged" in (user_sub or "").lower():
        return True
    checksum = zlib.crc32((user_sub or "").encode("utf-8"))
    # Deterministic but sparse: only a small fraction of arbitrary subs match.
    return checksum % 97 == 0


def run_rescreening(*, dry_run: bool = False) -> dict[str, Any]:
    """Re-screen approved users against sanctions lists.

    Iterates active schedules (the set of approved users), runs a deterministic
    mock screening on each, and records a ``screening_hit`` trigger event on a
    match. Triggerable via the admin endpoint or the background loop.
    """
    results = {
        "screened_at": now_ts(),
        "dry_run": dry_run,
        "total_screened": 0,
        "matches_found": 0,
        "triggers_created": 0,
    }

    if not S.kyc_rescreening_enabled:
        results["skipped"] = True
        results["reason"] = "rescreening_disabled"
        return results

    for item in _query_by_status(SCHEDULE_STATUS_ACTIVE):
        user_sub = str(item.get("user_sub") or "")
        if not user_sub:
            continue
        results["total_screened"] += 1
        if _deterministic_screening_hit(user_sub):
            results["matches_found"] += 1
            if not dry_run:
                create_trigger_event(
                    user_sub=user_sub,
                    trigger_type="screening_hit",
                    details={"source": "rescreening", "match_type": "mock_match"},
                )
                results["triggers_created"] += 1

    return results


# ── Dashboard ───────────────────────────────────────────────────────────────


def get_monitoring_dashboard() -> dict[str, Any]:
    """Admin dashboard data — upcoming reviews, overdue reviews, trigger stats."""
    now = now_ts()
    upcoming_window = now + (30 * DAY_SECONDS)

    dashboard: dict[str, Any] = {
        "generated_at": now,
        "upcoming_reviews": [],
        "overdue_reviews": [],
        "needs_review_count": 0,
    }

    for item in _query_by_status(SCHEDULE_STATUS_ACTIVE, between=(now, upcoming_window)):
        next_review = _coerce_int(item.get("next_review_date"))
        dashboard["upcoming_reviews"].append(
            {
                "user_sub": item.get("user_sub"),
                "risk_tier": item.get("risk_tier"),
                "next_review_date": next_review,
                "days_until_due": max(0, (next_review - now) // DAY_SECONDS),
            }
        )

    for status in (SCHEDULE_STATUS_GRACE, SCHEDULE_STATUS_NEEDS_REVIEW):
        for item in _query_by_status(status):
            next_review = _coerce_int(item.get("next_review_date"))
            dashboard["overdue_reviews"].append(
                {
                    "user_sub": item.get("user_sub"),
                    "risk_tier": item.get("risk_tier"),
                    "next_review_date": next_review,
                    "status": status,
                    "days_overdue": max(0, (now - next_review) // DAY_SECONDS),
                    "grace_deadline": _coerce_int(item.get("grace_deadline")),
                }
            )
            if status == SCHEDULE_STATUS_NEEDS_REVIEW:
                dashboard["needs_review_count"] += 1

    return dashboard
