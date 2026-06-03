# KYC-016: Ongoing Monitoring & Periodic Review

**Status**: Implemented  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: High  
**Estimated effort**: 10-12 days  
**Dependencies**: KYC-006 (Sanctions & PEP Screening), KYC-008 (Risk Scoring Engine), KYC-009 (Tiered Verification Levels)

---

## 1. Overview & Motivation

### 1.1 The Gap

The current KYC system is a one-time verification process. Once a user is approved (`status: "approved"` in `app/services/kyc_cases.py`), their verification is considered complete indefinitely — or until the retention purge deletes the case after `kyc_retention_approved_days` (default 365 days, see `app/core/settings.py:1070`). There is no mechanism for:

1. **Periodic re-verification** based on risk tier — regulators require low-risk users to be reviewed every 3 years, high-risk users every 6 months.
2. **Event-triggered review** — A user changes their country, makes a large transaction, or appears in an updated sanctions list, and the system should flag them for review.
3. **Automatic tier downgrade** — If a periodic review is overdue and the user does not re-verify within a grace period, their verification tier should be downgraded.
4. **Re-screening** — Daily batch re-check of all approved users against updated sanctions/PEP lists.
5. **Monitoring dashboard** — Admin view of upcoming reviews, overdue reviews, and trigger event logs.

### 1.2 What This Ticket Adds

1. **Review schedule management** — Each approved user gets a review schedule based on their risk tier.
2. **Risk-based review frequencies**:
   - Low risk: every 3 years (1095 days)
   - Medium risk: every 1 year (365 days)
   - High risk: every 6 months (182 days)
   - Critical: every 3 months (91 days)
3. **Trigger events** for ad-hoc review:
   - `large_transaction`: Transaction exceeding a threshold (e.g., $5000)
   - `country_change`: User updates their country/nationality
   - `name_change`: User changes their legal name
   - `screening_hit`: New match on sanctions/PEP re-screening
   - `manual`: Admin manually triggers review
4. **Grace period** — 30 days after review due date before automatic tier downgrade.
5. **Re-screening cron job** — Daily batch re-check against sanctions lists.
6. **New DDB table**: `kyc_review_schedule` with GSI by next review date.
7. **Admin monitoring dashboard** — Upcoming reviews, overdue reviews, trigger event log.

### 1.3 Architecture

```
Monitoring System Components:

  ┌────────────────────────────────────────────────────┐
  │                 Background Jobs                      │
  │                                                      │
  │  1. Review Checker (hourly)                          │
  │     Query GSI: next_review_date <= now               │
  │     → Flag overdue reviews                           │
  │     → Auto-downgrade after grace period              │
  │                                                      │
  │  2. Re-Screening Job (daily)                         │
  │     Scan all approved users                          │
  │     → Run sanctions check on each                    │
  │     → Create trigger event on match                  │
  │                                                      │
  └────────────────────────────────────────────────────┘
                         │
                         ▼
  ┌────────────────────────────────────────────────────┐
  │              kyc_review_schedule Table               │
  │                                                      │
  │  PK: USER#{user_sub}                                │
  │  SK: SCHEDULE                                        │
  │  Fields: risk_tier, next_review_date,               │
  │          last_review_date, review_frequency_days,   │
  │          grace_period_days, status                   │
  │                                                      │
  │  PK: USER#{user_sub}                                │
  │  SK: TRIGGER#{ts}#{event_id}                         │
  │  Fields: trigger_type, details, created_at          │
  │                                                      │
  │  GSI ByNextReviewDate:                              │
  │    PK: schedule_status (active|overdue|grace)       │
  │    SK: next_review_date (N)                         │
  │                                                      │
  └────────────────────────────────────────────────────┘

Trigger Flow:

  Profile Update (country/name change)
       │
       ▼
  profile_change_monitor()
       │
       ├── Is user KYC-approved?
       ├── Yes → create_trigger_event(user_sub, "country_change")
       │           → update schedule to "needs_review"
       └── No → ignore

  Large Transaction
       │
       ▼
  transaction_monitor()
       │
       ├── Amount > threshold?
       ├── Yes → create_trigger_event(user_sub, "large_transaction")
       │           → update schedule to "needs_review"
       └── No → ignore

  Grace Period Expiry
       │
       ▼
  review_checker_job()
       │
       ├── Grace period elapsed?
       ├── Yes → downgrade_tier(user_sub)
       │           → create_trigger_event(user_sub, "auto_downgrade")
       │           → notify user via KYC-011
       └── No → send reminder notification
```

---

## 2. Current State Analysis

### 2.1 KYC Case Approval (see `app/services/kyc_cases.py:534`)

The `apply_admin_decision()` method transitions a case to `"approved"` or `"rejected"`. When a case is approved, there is no downstream scheduling of future reviews. The approval is final until the retention purge deletes the case.

### 2.2 Risk Scoring (KYC-008)
<!-- NOTE: KYC-008 (Risk Scoring Engine) is a dependency — the risk scoring service does not exist yet and must be implemented first or in parallel. -->

The risk scoring engine assigns a risk tier (low, medium, high, critical) to each case. This risk tier should determine the review frequency. The `risk_tier` field on the case review should be used as input to the review schedule.

### 2.3 Sanctions Screening (KYC-006)

The screening system checks users against sanctions and PEP lists at case submission time. There is no ongoing re-screening after approval. The screening service should be called in batch for re-screening.

### 2.4 KYC Tiers (KYC-009)
<!-- NOTE: app/services/kyc_tiers.py does not exist yet — KYC-009 is a dependency that must be implemented first. -->

The tier system supports `upgrade_tier()` and has no `downgrade_tier()` concept beyond admin override. Automatic downgrade on overdue review is a new behavior that uses the existing `upgrade_tier()` function with a lower tier value.

### 2.5 KYC Notifications (KYC-011)

The notification system can dispatch alerts for tier changes and case events. New events `kyc.review.due`, `kyc.review.overdue`, `kyc.review.grace_period` should be added.

### 2.6 Background Tasks (`app/main.py`)

Background tasks are registered via `app.add_event_handler("startup", ...)` (see `app/main.py:358-379`, `466-469`). The review checker and re-screening jobs should follow this pattern.

### 2.7 Retention Purge (see `app/services/kyc_cases.py:747`)

The `run_retention_purge()` method runs on demand (triggered by admin via `POST /v1/kyc/cases/admin/purge/run`). The review checker should be a similar on-demand or scheduled operation.

---

## 3. Technical Design

### 3.1 New DDB Table: `kyc_review_schedule`
<!-- NOTE: kyc_review_schedule table does not exist yet in scripts/local-ddb-init.py — new table definition required -->

**Table definition for `scripts/local-ddb-init.py`**:

```python
TableDef(
    _resolve_table_name(S.kyc_review_schedule_table_name, "kyc_review_schedule"),
    partition_key="pk",
    sort_key="sk",
    gsis=[
        {
            "index_name": "ByNextReviewDate",
            "partition_key": "gsi_status_pk",
            "sort_key": "next_review_date",
        },
    ],
    attr_types={"next_review_date": "N"},
),
```

### 3.2 Settings (`app/core/settings.py`)
<!-- NOTE: These settings do not exist yet — add near existing KYC settings at line 1072 -->

```python
kyc_review_schedule_table_name: str = os.environ.get("KYC_REVIEW_SCHEDULE_TABLE_NAME", "kyc_review_schedule")
kyc_review_grace_period_days: int = int(os.environ.get("KYC_REVIEW_GRACE_PERIOD_DAYS", "30"))
kyc_large_transaction_threshold_cents: int = int(os.environ.get("KYC_LARGE_TRANSACTION_THRESHOLD_CENTS", "500000"))  # $5000
kyc_rescreening_enabled: bool = os.environ.get("KYC_RESCREENING_ENABLED", "true").lower() in ("1", "true", "yes")
```

### 3.3 Table Handle (`app/core/tables.py`)

```python
kyc_review_schedule: Any
# In T initialization:
kyc_review_schedule=ddb.Table(S.kyc_review_schedule_table_name),
```

### 3.4 Review Frequency Constants

```python
REVIEW_FREQUENCY_DAYS = {
    "low": 1095,      # 3 years
    "medium": 365,     # 1 year
    "high": 182,       # 6 months
    "critical": 91,    # 3 months
}
```

### 3.5 New Service: `app/services/kyc_monitoring.py`
<!-- NOTE: app/services/kyc_monitoring.py does not exist yet — new implementation required -->

```python
"""KYC ongoing monitoring — periodic review scheduling and trigger events."""
from __future__ import annotations

import uuid
from typing import Any, Literal

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event, write_alert  # see app/services/alerts.py:695 and :355

REVIEW_FREQUENCY_DAYS = {
    "low": 1095,
    "medium": 365,
    "high": 182,
    "critical": 91,
}

TRIGGER_TYPES = {"large_transaction", "country_change", "name_change", "screening_hit", "manual"}


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
    next_review = ts + (frequency * 86400)

    item = {
        "pk": f"USER#{user_sub}",
        "sk": "SCHEDULE",
        "user_sub": user_sub,
        "risk_tier": risk_tier,
        "review_frequency_days": frequency,
        "last_review_date": ts,
        "next_review_date": next_review,
        "grace_period_days": S.kyc_review_grace_period_days,
        "grace_deadline": next_review + (S.kyc_review_grace_period_days * 86400),
        "status": "active",  # active | needs_review | grace_period | overdue | downgraded
        "case_id": case_id,
        "created_at": ts,
        "updated_at": ts,
        "gsi_status_pk": "active",
        "gsi_status_sk": next_review,  # Not used; next_review_date is the GSI SK
    }
    T.kyc_review_schedule.put_item(Item=item)
    return item


def get_review_schedule(user_sub: str) -> dict[str, Any] | None:
    """Get the review schedule for a user."""
    return T.kyc_review_schedule.get_item(
        Key={"pk": f"USER#{user_sub}", "sk": "SCHEDULE"}
    ).get("Item")


def create_trigger_event(
    *,
    user_sub: str,
    trigger_type: str,
    details: dict[str, Any] | None = None,
    actor_sub: str | None = None,
    request=None,
) -> dict[str, Any]:
    """Record a trigger event that may require ad-hoc review."""
    if trigger_type not in TRIGGER_TYPES:
        raise ValueError(f"Invalid trigger type: {trigger_type}")

    ts = now_ts()
    event_id = uuid.uuid4().hex[:12]
    item = {
        "pk": f"USER#{user_sub}",
        "sk": f"TRIGGER#{ts:013d}#{event_id}",
        "trigger_type": trigger_type,
        "details": details or {},
        "created_at": ts,
        "created_by": actor_sub or "system",
    }
    T.kyc_review_schedule.put_item(Item=item)

    # Update schedule status to needs_review
    schedule = get_review_schedule(user_sub)
    if schedule and schedule.get("status") == "active":
        T.kyc_review_schedule.update_item(
            Key={"pk": f"USER#{user_sub}", "sk": "SCHEDULE"},
            UpdateExpression="SET #status = :status, updated_at = :ts, gsi_status_pk = :gsi_pk",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":status": "needs_review",
                ":ts": ts,
                ":gsi_pk": "needs_review",
            },
        )

    # Audit
    audit_event(
        "kyc.monitoring.trigger_event",
        actor_sub or "system",
        request,
        outcome="info",
        user_sub=user_sub,
        trigger_type=trigger_type,
    )

    # Alert to admins
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
    )

    return item


def list_trigger_events(user_sub: str, *, limit: int = 50) -> list[dict[str, Any]]:
    """List trigger events for a user."""
    resp = T.kyc_review_schedule.query(
        KeyConditionExpression=(
            Key("pk").eq(f"USER#{user_sub}") & Key("sk").begins_with("TRIGGER#")
        ),
        ScanIndexForward=False,
        Limit=limit,
    )
    return resp.get("Items", [])


def complete_review(
    *,
    user_sub: str,
    new_risk_tier: str | None = None,
    case_id: str | None = None,
    admin_sub: str,
    request=None,
) -> dict[str, Any]:
    """Mark a periodic review as completed, reset the schedule."""
    schedule = get_review_schedule(user_sub)
    if not schedule:
        raise ValueError("no_schedule_found")

    risk_tier = new_risk_tier or schedule.get("risk_tier", "medium")
    return create_review_schedule(
        user_sub=user_sub,
        risk_tier=risk_tier,
        case_id=case_id or schedule.get("case_id", ""),
        actor_sub=admin_sub,
    )


def run_review_checker(*, dry_run: bool = False) -> dict[str, Any]:
    """Check for overdue reviews and apply grace period / downgrade logic.

    Called by background job or admin endpoint.
    """
    now = now_ts()
    results = {
        "checked_at": now,
        "dry_run": dry_run,
        "newly_overdue": 0,
        "entered_grace_period": 0,
        "auto_downgraded": 0,
        "reminders_sent": 0,
    }

    # Query active schedules where next_review_date <= now
    resp = T.kyc_review_schedule.query(
        IndexName="ByNextReviewDate",
        KeyConditionExpression=(
            Key("gsi_status_pk").eq("active") & Key("next_review_date").lte(now)
        ),
        Limit=100,
    )

    for item in resp.get("Items", []):
        user_sub = item.get("user_sub")
        next_review = int(item.get("next_review_date", 0))
        grace_deadline = int(item.get("grace_deadline", 0))

        if now > grace_deadline:
            # Past grace period — auto-downgrade
            if not dry_run:
                _auto_downgrade(user_sub, item)
            results["auto_downgraded"] += 1
        elif now > next_review:
            # Past due but within grace period
            if not dry_run:
                _enter_grace_period(user_sub, item)
            results["entered_grace_period"] += 1

    # Also check "needs_review" and "grace_period" statuses
    for status in ["needs_review", "grace_period"]:
        resp2 = T.kyc_review_schedule.query(
            IndexName="ByNextReviewDate",
            KeyConditionExpression=(
                Key("gsi_status_pk").eq(status) & Key("next_review_date").lte(now)
            ),
            Limit=100,
        )
        for item in resp2.get("Items", []):
            grace_deadline = int(item.get("grace_deadline", 0))
            if now > grace_deadline and not dry_run:
                _auto_downgrade(item.get("user_sub"), item)
                results["auto_downgraded"] += 1

    return results


def run_rescreening(*, dry_run: bool = False) -> dict[str, Any]:
    """Re-screen all approved users against sanctions lists.

    Called by daily cron job. In dev mode, this is a no-op placeholder.
    """
    results = {
        "screened_at": now_ts(),
        "dry_run": dry_run,
        "total_screened": 0,
        "matches_found": 0,
        "triggers_created": 0,
    }

    if not S.kyc_rescreening_enabled:
        return {**results, "skipped": True, "reason": "rescreening_disabled"}

    # Query all active schedules
    resp = T.kyc_review_schedule.query(
        IndexName="ByNextReviewDate",
        KeyConditionExpression=Key("gsi_status_pk").eq("active"),
        Limit=500,
    )

    for item in resp.get("Items", []):
        results["total_screened"] += 1
        user_sub = item.get("user_sub")

        # In dev mode, mock screening (no actual list check)
        if S.dev_mode:
            # Mock: flag users whose sub contains "flagged"
            if "flagged" in str(user_sub):
                results["matches_found"] += 1
                if not dry_run:
                    create_trigger_event(
                        user_sub=user_sub,
                        trigger_type="screening_hit",
                        details={"source": "daily_rescreening", "match_type": "mock_match"},
                    )
                    results["triggers_created"] += 1

    return results


def _enter_grace_period(user_sub: str, schedule: dict) -> None:
    """Move schedule to grace period status."""
    ts = now_ts()
    T.kyc_review_schedule.update_item(
        Key={"pk": f"USER#{user_sub}", "sk": "SCHEDULE"},
        UpdateExpression="SET #status = :status, updated_at = :ts, gsi_status_pk = :gsi_pk",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":status": "grace_period",
            ":ts": ts,
            ":gsi_pk": "grace_period",
        },
    )

    # Notify user
    write_alert(
        user_sub,
        event="kyc.review.grace_period",
        outcome="warning",
        title="Verification review overdue",
        details={
            "message": "Your periodic verification review is overdue. "
                       "Please complete re-verification within the grace period to maintain your current tier.",
            "grace_deadline": schedule.get("grace_deadline"),
        },
        action_url="/kyc",
    )


def _auto_downgrade(user_sub: str, schedule: dict) -> None:
    """Automatically downgrade user's tier due to overdue review."""
    ts = now_ts()
    from app.services.kyc_tiers import get_user_kyc_tier, upgrade_tier  # NOTE: kyc_tiers.py does not exist yet — KYC-009 dependency

    current_tier = get_user_kyc_tier(user_sub)
    if current_tier <= 0:
        return  # Already at minimum

    new_tier = max(0, current_tier - 1)
    upgrade_tier(
        user_sub=user_sub,
        new_tier=new_tier,
        reason="periodic_review_overdue",
        actor_sub="system:kyc_monitoring",
    )

    # Update schedule status
    T.kyc_review_schedule.update_item(
        Key={"pk": f"USER#{user_sub}", "sk": "SCHEDULE"},
        UpdateExpression="SET #status = :status, updated_at = :ts, gsi_status_pk = :gsi_pk",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":status": "downgraded",
            ":ts": ts,
            ":gsi_pk": "downgraded",
        },
    )

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


def get_monitoring_dashboard(*, status_filter: str | None = None) -> dict[str, Any]:
    """Admin dashboard data — upcoming and overdue reviews."""
    now = now_ts()
    upcoming_window = now + (30 * 86400)  # Next 30 days

    dashboard: dict[str, Any] = {
        "generated_at": now,
        "upcoming_reviews": [],
        "overdue_reviews": [],
        "needs_review": [],
        "trigger_events_today": 0,
    }

    # Upcoming reviews (due within 30 days)
    resp = T.kyc_review_schedule.query(
        IndexName="ByNextReviewDate",
        KeyConditionExpression=(
            Key("gsi_status_pk").eq("active")
            & Key("next_review_date").between(now, upcoming_window)
        ),
        Limit=50,
    )
    dashboard["upcoming_reviews"] = [
        {
            "user_sub": item.get("user_sub"),
            "risk_tier": item.get("risk_tier"),
            "next_review_date": item.get("next_review_date"),
            "days_until_due": (int(item.get("next_review_date", 0)) - now) // 86400,
        }
        for item in resp.get("Items", [])
    ]

    # Overdue reviews
    for status in ["grace_period", "needs_review"]:
        resp2 = T.kyc_review_schedule.query(
            IndexName="ByNextReviewDate",
            KeyConditionExpression=Key("gsi_status_pk").eq(status),
            Limit=50,
        )
        for item in resp2.get("Items", []):
            dashboard["overdue_reviews"].append({
                "user_sub": item.get("user_sub"),
                "risk_tier": item.get("risk_tier"),
                "next_review_date": item.get("next_review_date"),
                "status": status,
                "days_overdue": (now - int(item.get("next_review_date", 0))) // 86400,
                "grace_deadline": item.get("grace_deadline"),
            })

    return dashboard
```

### 3.6 Integration Points

**After KYC case approval** (see `app/routers/kyc_cases.py:1099` — `_admin_decide_case`):

```python
if decision == "approved":
    from app.services.kyc_monitoring import create_review_schedule
    risk_tier = (case.get("review") or {}).get("risk_tier", "medium")
    create_review_schedule(
        user_sub=case["user_sub"],
        risk_tier=risk_tier,
        case_id=case_id,
        actor_sub=user.sub,
    )
```

**After profile country/name change** (see `app/routers/profile.py`):

```python
# In profile update handler, after saving:
if "nationality" in changes or "country" in changes:
    from app.services.kyc_monitoring import create_trigger_event
    create_trigger_event(
        user_sub=user_sub,
        trigger_type="country_change",
        details={"old": old_value, "new": new_value},
    )
if "first_name" in changes or "last_name" in changes:
    create_trigger_event(
        user_sub=user_sub,
        trigger_type="name_change",
        details={"old": old_name, "new": new_name},
    )
```

**After large transaction** (see `app/routers/billing.py`):

```python
# In payment processing, after successful payment:
if amount_cents >= S.kyc_large_transaction_threshold_cents:
    from app.services.kyc_monitoring import create_trigger_event
    create_trigger_event(
        user_sub=user_sub,
        trigger_type="large_transaction",
        details={"amount_cents": amount_cents, "transaction_id": txn_id},
    )
```

### 3.7 Background Jobs

**Review Checker** (hourly):

```python
# app/services/kyc_monitoring_scheduler.py

import asyncio
from app.services.kyc_monitoring import run_review_checker, run_rescreening
from app.core.settings import S

async def _kyc_review_checker_loop():
    """Background loop that checks for overdue reviews every hour."""
    while True:
        try:
            run_review_checker(dry_run=False)
        except Exception:
            import logging
            logging.getLogger(__name__).exception("Review checker failed")
        await asyncio.sleep(3600)  # 1 hour

async def _kyc_rescreening_loop():
    """Background loop that re-screens all users daily."""
    while True:
        try:
            run_rescreening(dry_run=False)
        except Exception:
            import logging
            logging.getLogger(__name__).exception("Re-screening failed")
        await asyncio.sleep(86400)  # 24 hours

def startup():
    """Register background tasks at app startup."""
    asyncio.ensure_future(_kyc_review_checker_loop())
    if S.kyc_rescreening_enabled:
        asyncio.ensure_future(_kyc_rescreening_loop())
```

Register in `app/main.py`:

```python
from app.services.kyc_monitoring_scheduler import startup as kyc_monitoring_startup
app.add_event_handler("startup", kyc_monitoring_startup)
```

### 3.8 API Endpoints

**New Router**: `app/routers/kyc_monitoring.py`

```python
router = APIRouter(prefix="/v1/kyc/monitoring", tags=["kyc-monitoring"])
```

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/schedule` | `require_ui_session` | Get user's own review schedule |
| `GET` | `/triggers` | `require_ui_session` | List user's trigger events |
| `GET` | `/admin/dashboard` | `require_ui_session` + admin role check | Admin monitoring dashboard |
| `POST` | `/admin/review-check` | `require_ui_session` + admin role check | Run review checker manually |
| `POST` | `/admin/rescreening` | `require_ui_session` + admin role check | Run re-screening manually |
| `POST` | `/admin/{user_sub}/trigger` | `require_ui_session` + admin role check | Admin manually triggers review |
| `POST` | `/admin/{user_sub}/complete-review` | `require_ui_session` + admin role check | Mark review as completed |
| `GET` | `/admin/{user_sub}/schedule` | `require_ui_session` + admin role check | Get any user's schedule |
<!-- NOTE: Existing KYC admin endpoints use require_ui_session + manual role check, not require_root_session. Follow the same pattern (see app/routers/kyc_cases.py:1000-1003). -->

```python
@router.get("/schedule")
async def get_my_schedule(ctx=Depends(require_ui_session)):
    schedule = get_review_schedule(ctx["user_sub"])
    if not schedule:
        return {"schedule": None}
    return {"schedule": schedule}


@router.get("/admin/dashboard")
async def admin_dashboard(user=Depends(require_root_session)):
    return get_monitoring_dashboard()


@router.post("/admin/review-check")
async def admin_run_review_check(
    dry_run: bool = Query(False),
    user=Depends(require_root_session),
):
    return run_review_checker(dry_run=dry_run)


@router.post("/admin/rescreening")
async def admin_run_rescreening(
    dry_run: bool = Query(False),
    user=Depends(require_root_session),
):
    return run_rescreening(dry_run=dry_run)


@router.post("/admin/{user_sub}/trigger")
async def admin_trigger_review(
    user_sub: str,
    body: TriggerEventRequest,
    request: Request,
    user=Depends(require_root_session),
):
    return create_trigger_event(
        user_sub=user_sub,
        trigger_type="manual",
        details={"reason": body.reason},
        actor_sub=user.sub,
        request=request,
    )


@router.post("/admin/{user_sub}/complete-review")
async def admin_complete_review(
    user_sub: str,
    body: CompleteReviewRequest,
    request: Request,
    user=Depends(require_root_session),
):
    return complete_review(
        user_sub=user_sub,
        new_risk_tier=body.new_risk_tier,
        case_id=body.case_id,
        admin_sub=user.sub,
        request=request,
    )
```

### 3.9 Pydantic Models

```python
class TriggerEventRequest(BaseModel):
    reason: str = Field(min_length=5, max_length=500)

class CompleteReviewRequest(BaseModel):
    new_risk_tier: Literal["low", "medium", "high", "critical"] | None = None
    case_id: str | None = None
```

### 3.10 Frontend Components

**File**: `frontend/src/pages/admin/KycMonitoringDashboard.tsx`

- Upcoming reviews table (sortable by due date, risk tier)
- Overdue reviews table with warning/critical severity badges
- Trigger event log timeline
- "Run Review Check" and "Run Re-screening" buttons
- Per-user detail view with "Complete Review" and "Manual Trigger" actions

**File**: `frontend/src/api/endpoints/kyc-monitoring.ts`

```typescript
export const getMySchedule = () =>
  client.get("/v1/kyc/monitoring/schedule");
export const getMonitoringDashboard = () =>
  client.get("/v1/kyc/monitoring/admin/dashboard");
export const runReviewCheck = (dryRun = false) =>
  client.post(`/v1/kyc/monitoring/admin/review-check?dry_run=${dryRun}`);
export const runRescreening = (dryRun = false) =>
  client.post(`/v1/kyc/monitoring/admin/rescreening?dry_run=${dryRun}`);
export const triggerReview = (userSub: string, reason: string) =>
  client.post(`/v1/kyc/monitoring/admin/${userSub}/trigger`, { reason });
export const completeReview = (userSub: string, data: CompleteReviewRequest) =>
  client.post(`/v1/kyc/monitoring/admin/${userSub}/complete-review`, data);
```

**Route**: `/admin/kyc/monitoring` in `App.tsx`

### 3.11 Registration

```python
# app/main.py
from app.routers.kyc_monitoring import router as kyc_monitoring_router
app.include_router(kyc_monitoring_router)
```

---

## 4. Implementation Plan

### Phase 1: DDB Table + Core Service (3 days)

| File | Change |
|------|--------|
| `scripts/local-ddb-init.py` | Add `kyc_review_schedule` table with GSI, `attr_types={"next_review_date": "N"}` |
| `app/core/settings.py` | Add `kyc_review_schedule_table_name`, `kyc_review_grace_period_days`, `kyc_large_transaction_threshold_cents`, `kyc_rescreening_enabled` |
| `app/core/tables.py` | Add `kyc_review_schedule` table handle |
| `app/services/kyc_monitoring.py` | New: monitoring service (~400 lines) |

### Phase 2: Background Jobs (2 days)

| File | Change |
|------|--------|
| `app/services/kyc_monitoring_scheduler.py` | New: background loops for review checker + re-screening (~80 lines) |
| `app/main.py` | Register `kyc_monitoring_startup` event handler |

### Phase 3: Router + Integration Points (2 days)

| File | Change |
|------|--------|
| `app/routers/kyc_monitoring.py` | New: 8 endpoints (~200 lines) |
| `app/routers/kyc_cases.py` | Call `create_review_schedule()` after approval |
| `app/routers/profile.py` | Call `create_trigger_event()` on country/name change |
| `app/contracts/kyc_cases_contract.py` | Add `TriggerEventRequest`, `CompleteReviewRequest` models |

### Phase 4: Frontend (2 days)

| File | Change |
|------|--------|
| `frontend/src/pages/admin/KycMonitoringDashboard.tsx` | New: admin monitoring dashboard (~300 lines) |
| `frontend/src/api/endpoints/kyc-monitoring.ts` | New: API endpoint wrappers |
| `frontend/src/App.tsx` | Add `/admin/kyc/monitoring` route |

### Phase 5: E2E Tests (3 days)

| File | Change |
|------|--------|
| `frontend/e2e/kyc-monitoring.spec.ts` | New: ~18 tests, sections 210-213 |

---

## 5. E2E Test Plan (`frontend/e2e/kyc-monitoring.spec.ts`)

**Test file**: `frontend/e2e/kyc-monitoring.spec.ts`  
**Total tests**: ~18  
**Sections**: 210-213

### Section 210: Review Schedule API (5 tests)

1. `Schedule created after KYC case approval` — Approve a KYC case; GET `/v1/kyc/monitoring/schedule`; verify `status: "active"`, `risk_tier` matches, `next_review_date` is in the future.
2. `Review frequency matches risk tier` — Approve with `risk_tier: "high"`; verify `review_frequency_days: 182`.
3. `GET /v1/kyc/monitoring/schedule returns null for unverified user` — Bob (no KYC); verify `schedule: null`.
4. `Complete review resets schedule` — Admin completes review; verify new `next_review_date` is further in the future and `status: "active"`.
5. `Complete review with new risk tier updates frequency` — Change from "high" to "low"; verify `review_frequency_days: 1095`.

### Section 211: Trigger Events API (4 tests)

1. `Admin manual trigger creates event and sets status to needs_review` — POST trigger; verify event stored; GET schedule shows `status: "needs_review"`.
2. `GET /v1/kyc/monitoring/triggers lists events` — After 2 triggers; verify array length is 2.
3. `Trigger with invalid reason (too short) returns 422` — Reason "ab" fails validation.
4. `Alert generated on trigger event` — After trigger; query alerts; verify alert with `event: "kyc.review.triggered"`.

### Section 212: Review Checker & Re-screening API (5 tests)

1. `POST /admin/review-check with dry_run returns counts` — Seed overdue schedule (set `next_review_date` to past via DDB); run checker with `dry_run=true`; verify `entered_grace_period` count > 0 without actually changing status.
2. `POST /admin/review-check without dry_run enters grace period` — Run without dry_run; verify schedule `status: "grace_period"`.
3. `Auto-downgrade after grace period` — Set `grace_deadline` to past via DDB; run checker; verify schedule `status: "downgraded"`.
4. `POST /admin/rescreening with dry_run returns stats` — Verify response has `total_screened`, `matches_found`.
5. `Non-root user cannot run review checker` — Alice calls; returns 403.

### Section 213: Monitoring Dashboard API (4 tests)

1. `GET /admin/dashboard returns upcoming and overdue lists` — With seeded schedules; verify `upcoming_reviews` and `overdue_reviews` arrays populated.
2. `Dashboard shows days_until_due for upcoming reviews` — Verify positive integer.
3. `Dashboard shows days_overdue for overdue reviews` — Verify positive integer.
4. `Dashboard is empty when no schedules exist` — Fresh state; verify empty arrays.

### Test Setup

```typescript
const TS = Date.now();
let alicePage: Page;
let rootPage: Page;

test.beforeAll(async ({ browser }) => {
  alicePage = await browser.newPage();
  await injectAuth(alicePage, "alice");
  rootPage = await browser.newPage();
  await injectAuth(rootPage, "root");

  // Create and approve a KYC case to generate a review schedule
  const caseResp = await apiPost(alicePage, "alice", "/v1/kyc/cases", {});
  const caseId = caseResp.case.kyc_case_id;
  // ... attach files, submit, approve as root
});
```

### Flakiness Mitigations

| Risk | Mitigation |
|------|------------|
| Background job timing | E2E tests use manual admin endpoints (`/admin/review-check`), not the background loop |
| DDB eventual consistency on GSI | Review checker does consistent read on schedule after GSI query |
| Past-date seeding | Directly write to DDB to set `next_review_date` and `grace_deadline` in the past |
| Re-screening mock | Only matches `user_sub` containing "flagged"; test users don't match by default |
| Tier downgrade side effects | Use isolated test user for downgrade tests to avoid affecting other test sections |

---

## 6. Security Considerations

- Review schedules are user-scoped. A user can only see their own schedule via `GET /schedule`.
- Admin endpoints require `require_root_session` for running review checks, re-screening, triggering reviews, and completing reviews.
- Auto-downgrade uses `actor_sub="system:kyc_monitoring"` in audit records to distinguish from admin actions.
- Large transaction monitoring threshold is configurable via environment variable, defaulting to $5000.
- Re-screening can be disabled via `KYC_RESCREENING_ENABLED=false` without code changes.

---

## 7. Rollback Plan

### 7.1 Feature Flags

- `KYC_RESCREENING_ENABLED=false`: Disables the daily re-screening job.
- Remove `kyc_monitoring_startup` from `app/main.py`: Stops both background jobs.

### 7.2 DDB Changes

- The `kyc_review_schedule` table is independent. Existing code ignores it.
- Remove integration calls from `kyc_cases.py`, `profile.py`, and `billing.py`.

### 7.3 Endpoint Removal

- Remove `app/routers/kyc_monitoring.py` from `app/main.py`.
- Schedules and trigger events remain in DDB but are inert without the router and background jobs.

---

## Codebase References

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `apply_admin_decision()` | `app/services/kyc_cases.py` | 534 | Exists |
| `run_retention_purge()` | `app/services/kyc_cases.py` | 747 | Exists |
| `_admin_decide_case()` | `app/routers/kyc_cases.py` | 1099 | Exists |
| `kyc_retention_approved_days` | `app/core/settings.py` | 1070 | Exists |
| `audit_event()` | `app/services/alerts.py` | 695 | Exists |
| `write_alert()` | `app/services/alerts.py` | 355 | Exists |
| Startup event handlers | `app/main.py` | 358-379, 466-469 | Exists |
| Profile router | `app/routers/profile.py` | -- | Exists |
| Billing router | `app/routers/billing.py` | -- | Exists |
| KYC admin auth pattern | `app/routers/kyc_cases.py` | 1000-1003 | Exists — uses `require_ui_session` + role check |
| `kyc_review_schedule_table_name` | -- | -- | Does NOT exist — new setting required |
| `kyc_review_schedule` DDB table | -- | -- | Does NOT exist — new table required |
| `app/services/kyc_monitoring.py` | -- | -- | Does NOT exist — new implementation required |
| `app/services/kyc_monitoring_scheduler.py` | -- | -- | Does NOT exist — new implementation required |
| `app/routers/kyc_monitoring.py` | -- | -- | Does NOT exist — new implementation required |
| `app/services/kyc_tiers.py` (KYC-009) | -- | -- | Does NOT exist — dependency on KYC-009 |
| `frontend/src/pages/admin/KycMonitoringDashboard.tsx` | -- | -- | Does NOT exist — new implementation required |
| `frontend/src/api/endpoints/kyc-monitoring.ts` | -- | -- | Does NOT exist — new file required |

---

## Testing Strategy

### Unit Tests (`tests/test_kyc_monitoring.py`)
**Framework**: pytest + moto (DynamoDB/S3 mock)

| # | Test Function | What It Verifies |
|---|--------------|-----------------|
| 1 | `test_create_review_schedule_sets_correct_frequency` | Create review schedule sets correct frequency |
| 2 | `test_create_review_schedule_stores_grace_deadline` | Create review schedule stores grace deadline |
| 3 | `test_get_review_schedule_returns_none_for_missing` | Get review schedule returns none for missing |
| 4 | `test_create_trigger_event_updates_status` | Create trigger event updates status |
| 5 | `test_create_trigger_event_rejects_invalid_type` | Create trigger event rejects invalid type |
| 6 | `test_list_trigger_events_ordered_desc` | List trigger events ordered desc |
| 7 | `test_complete_review_resets_schedule` | Complete review resets schedule |
| 8 | `test_run_review_checker_dry_run` | Run review checker dry run |
| 9 | `test_run_review_checker_enters_grace_period` | Run review checker enters grace period |
| 10 | `test_run_rescreening_disabled_skipped` | Run rescreening disabled skipped |

### Integration Tests

1. KYC case approval creates review schedule with correct frequency
2. Profile country change creates trigger event and sets needs_review
3. Large transaction over threshold triggers event and alert
4. Review checker transitions overdue -> grace_period -> downgraded
5. Dashboard returns correct upcoming/overdue counts

### Test Data Requirements
- Test users: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- DDB table: `kyc_review_schedule` created in `scripts/local-ddb-init.py`
- Session seeding: `python3 e2e_admin_session_setup.py` before test run

### CI/Pipeline
- Feature flags: `KYC_RESCREENING_ENABLED=true`
- Tests run serially (single Playwright worker, `workers: 1`)
- Retry safety: 1 retry configured; tests use unique timestamps (`Date.now()`) for isolation
- Run: `cd frontend && npx playwright test e2e/<spec-file>`

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What It Provides | Hard/Soft |
|--------|-----------------|-----------|
| KYC-006 | Sanctions & PEP Screening service for re-screening | Hard |
| KYC-008 | Risk Scoring Engine for risk_tier input | Hard |
| KYC-009 | Tiered Verification Levels for tier downgrade | Hard |
| KYC-011 | Notifications for review due/overdue alerts | Soft |

### Depended On By

| Ticket | What It Needs |
|--------|--------------|
| KYC-024 | Analytics dashboard aggregates monitoring data |

### Merge Strategy
**Sequential -- requires KYC-006, KYC-008, and KYC-009 merged first. Auto-downgrade imports from kyc_tiers.py (KYC-009); rescreening calls screening service (KYC-006).**

### Merge Checklist
- [ ] DDB table `kyc_review_schedule` added to `scripts/local-ddb-init.py`
- [ ] Feature flags configured in `.env.local`: KYC_RESCREENING_ENABLED=true
- [ ] Service file created/modified: `app/services/kyc_monitoring.py`
- [ ] Router registered in `app/main.py`
- [ ] No endpoint prefix conflicts with existing routers
- [ ] Unit tests pass: `.venv/bin/pytest tests/test_kyc_monitoring.py`
