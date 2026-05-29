# KYC-011: KYC Webhooks & Notifications

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: High  
**Estimated effort**: 6-8 days  
**Dependencies**: KYC-001 (Admin Dashboard), KYC-009 (Tiered Verification Levels)

---

## 1. Overview & Motivation

### 1.1 The Gap

The current KYC system (`app/routers/kyc_cases.py`, `app/services/kyc_cases.py`) transitions cases through `draft -> submitted -> under_review -> approved/rejected/needs_more_info -> expired`, but these transitions happen silently. The only feedback mechanism is polling — a user must repeatedly check their case status, and an admin must manually refresh the queue to see new submissions.

The audit system (`audit_event()` in `app/services/alerts.py`, line 695) records KYC events to the audit log, but these are internal telemetry, not user-facing notifications. The alert system (`write_alert()`, line 355) supports in-app alerts, email, and SMS delivery, but no KYC-specific alert types are registered. The webhook system (`app/services/webhook_service.py`) defines event types for messaging, billing, newsfeed, broadcast, and account events — but no KYC events.

### 1.2 What This Ticket Adds

1. **Webhook events** for all KYC state transitions, published through the existing webhook dispatcher (`app/services/webhook_dispatcher.py`).
2. **Email notifications** to users at key moments: submission confirmation, request for additional information, approval, rejection (with reasons).
3. **Email notifications** to admins: new submissions in queue, high-risk case flagged, screening match detected.
4. **SMS notifications** for urgent actions: verification call scheduled, case about to expire.
5. **Notification preferences** per user: toggle email, SMS, and push for KYC events.
6. **Integration with the existing webhook endpoint system** (`app/routers/webhooks.py`) so users can subscribe to KYC events via their configured webhook endpoints.

### 1.3 KYC Event Types

| Event | Trigger | Payload |
|-------|---------|---------|
| `kyc.case.created` | User creates a new KYC case | `case_id`, `user_sub`, `status: "draft"` |
| `kyc.case.submitted` | User submits case for review | `case_id`, `user_sub`, `submitted_at` |
| `kyc.case.approved` | Admin approves case | `case_id`, `user_sub`, `decided_at`, `tier_upgrade` |
| `kyc.case.rejected` | Admin rejects case | `case_id`, `user_sub`, `reason_codes`, `decided_at` |
| `kyc.case.needs_info` | Admin requests more info | `case_id`, `user_sub`, `requested_items`, `note` |
| `kyc.screening.match_found` | Sanctions/PEP screening finds a match | `case_id`, `user_sub`, `match_type`, `match_source` |
| `kyc.tier.upgraded` | User's KYC tier increases | `user_sub`, `from_tier`, `to_tier`, `reason` |
| `kyc.tier.downgraded` | User's KYC tier decreases | `user_sub`, `from_tier`, `to_tier`, `reason` |

### 1.4 Architecture

```
KYC State Transition
       │
       ▼
  _admin_decide_case() / submit_kyc_case() / etc.
       │
       ├── audit_event()                    (existing — audit log)
       ├── kyc_notify()                     (NEW — notification dispatcher)
       │     │
       │     ├── write_alert()              (in-app alert)
       │     ├── send_kyc_email()           (email via SES / mock)
       │     ├── send_kyc_sms()             (SMS via SNS / mock)
       │     └── dispatch_kyc_webhook()     (webhook via webhook_dispatcher)
       │
       └── (existing case update logic)

Admin Notification Flow:
  New submission → query admin notification preferences
                 → send to all subscribed admins

User Notification Preferences:
  users table → USER#{sub}, SK=KYC_NOTIFICATION_PREFS
  {
    email_enabled: true,
    sms_enabled: false,
    push_enabled: true,
    events: ["kyc.case.approved", "kyc.case.rejected", ...]
  }
```

---

## 2. Current State Analysis

### 2.1 Webhook System (`app/services/webhook_service.py`)

The webhook service defines `WEBHOOK_EVENT_TYPES` (line 24) and `WEBHOOK_EVENT_TYPES_V2` (line 60) — dictionaries mapping event type strings to descriptions. No KYC event types exist. The `dispatch_webhook_event()` function (line 503) handles delivery to user-registered endpoints. The `is_valid_event_type()` check (line 154) validates against these dictionaries.

To add KYC events, new entries must be added to `WEBHOOK_EVENT_TYPES_V2` and the `dispatch_webhook_event()` function must be called from KYC state transition points.

### 2.2 Webhook Dispatcher (`app/services/webhook_dispatcher.py`)

The dispatcher handles async delivery, retry logic (`app/services/webhook_retry.py`), circuit breaking (`app/services/webhook_circuit_breaker.py`), dead letter queue (`app/services/webhook_dlq.py`), and SSRF protection (`app/services/webhook_ssrf.py`). KYC webhook events will use this existing infrastructure.

### 2.3 Alert System (`app/services/alerts.py`)

- `write_alert(user_sub, *, event, outcome, title, details)` (line 355): Creates in-app alerts stored in the `alerts` table.
- `send_alert_email(to_emails, subject, body_text)` (line 458): Sends email via SES (mocked in dev).
- `send_alert_sms(to_numbers, body_text)` (line 481): Sends SMS via SNS (mocked in dev).
- `send_alert_webhook(payload, *, alert_type, alert_id)` (line 600): Sends webhook to the platform-level webhook URL.

### 2.4 Email Templates (`app/services/alert_email_templates.py`)

Existing email template infrastructure. KYC emails will follow the same pattern with KYC-specific templates.

### 2.5 Notification Preferences

The alert preferences system (`app/services/alerts.py`) stores per-user preferences including `email_types`, `sms_types`, `push_types` — lists of event type strings the user has opted into. The `can_send_alert_channel(user_sub, channel)` function (imported from `app/services/rate_limit.py`) enforces rate limits per channel.

### 2.6 KYC State Transitions (`app/routers/kyc_cases.py`)

The `_audit_state_transition()` helper (line 85) is called at every state change. It calls `audit_event()` with KYC-specific event names. This is the integration point — `kyc_notify()` should be called alongside `_audit_state_transition()`.

---

## 3. Technical Design

### 3.1 New Webhook Event Types

Add to `WEBHOOK_EVENT_TYPES_V2` in `app/services/webhook_service.py`:

```python
WEBHOOK_EVENT_TYPES_V2: Dict[str, str] = {
    **WEBHOOK_EVENT_TYPES,
    # ... existing v2 events ...

    # KYC (KYC-011)
    "kyc.case.created": "A new KYC verification case was created",
    "kyc.case.submitted": "A KYC case was submitted for review",
    "kyc.case.approved": "A KYC case was approved",
    "kyc.case.rejected": "A KYC case was rejected",
    "kyc.case.needs_info": "Additional information was requested for a KYC case",
    "kyc.screening.match_found": "A sanctions/PEP screening match was found",
    "kyc.tier.upgraded": "User verification tier was upgraded",
    "kyc.tier.downgraded": "User verification tier was downgraded",
}
```

### 3.2 New Service: `app/services/kyc_notifications.py`

```python
"""KYC notification dispatcher — emails, SMS, webhooks, and in-app alerts."""
from __future__ import annotations

from typing import Any
from app.core.settings import S
from app.core.time import now_ts
from app.services.alerts import write_alert, send_alert_email, send_alert_sms, audit_event
from app.services.webhook_service import dispatch_webhook_event
from app.services.profile import get_profile

KYC_NOTIFICATION_EVENTS = {
    "kyc.case.created",
    "kyc.case.submitted",
    "kyc.case.approved",
    "kyc.case.rejected",
    "kyc.case.needs_info",
    "kyc.screening.match_found",
    "kyc.tier.upgraded",
    "kyc.tier.downgraded",
}

_KYC_EMAIL_SUBJECTS = {
    "kyc.case.submitted": "Your verification application has been submitted",
    "kyc.case.approved": "Your identity verification has been approved",
    "kyc.case.rejected": "Your identity verification requires attention",
    "kyc.case.needs_info": "Additional information needed for your verification",
}

_ADMIN_EVENTS = {
    "kyc.case.submitted": "New KYC submission in review queue",
    "kyc.screening.match_found": "Screening match requires attention",
}


def kyc_notify(
    *,
    event: str,
    user_sub: str,
    case_id: str | None = None,
    request=None,
    **payload,
) -> dict[str, Any]:
    """Dispatch KYC notification across all channels.

    Called from KYC state transition points (kyc_cases router).
    Respects user notification preferences.
    """
    if event not in KYC_NOTIFICATION_EVENTS:
        return {"dispatched": False, "reason": "unknown_event"}

    ts = now_ts()
    results: dict[str, Any] = {"event": event, "channels": {}}

    # Build base payload
    base_payload = {
        "event": event,
        "case_id": case_id,
        "user_sub": user_sub,
        "timestamp": ts,
        **payload,
    }

    # 1. In-app alert (always)
    title = _build_alert_title(event, payload)
    alert_result = write_alert(
        user_sub,
        event=event,
        outcome="success",
        title=title,
        details=base_payload,
        action_url=f"/kyc/status?case_id={case_id}" if case_id else "/kyc",
    )
    results["channels"]["in_app"] = bool(alert_result)

    # 2. Email (if user has opted in)
    prefs = get_kyc_notification_prefs(user_sub)
    if prefs.get("email_enabled", True) and event in _KYC_EMAIL_SUBJECTS:
        profile = get_profile(user_sub)
        email = profile.get("email")
        if email:
            subject = _KYC_EMAIL_SUBJECTS[event]
            body = _build_email_body(event, base_payload)
            try:
                send_alert_email([email], subject, body)
                results["channels"]["email"] = True
            except Exception:
                results["channels"]["email"] = False

    # 3. SMS (if user has opted in and event is urgent)
    if prefs.get("sms_enabled", False) and event in {"kyc.case.needs_info", "kyc.case.rejected"}:
        profile = get_profile(user_sub)
        phone = profile.get("phone")
        if phone:
            sms_body = _build_sms_body(event, base_payload)
            try:
                send_alert_sms([phone], sms_body)
                results["channels"]["sms"] = True
            except Exception:
                results["channels"]["sms"] = False

    # 4. Webhook (for users with registered webhook endpoints)
    try:
        dispatch_webhook_event(
            user_sub=user_sub,
            event_type=event,
            payload=base_payload,
        )
        results["channels"]["webhook"] = True
    except Exception:
        results["channels"]["webhook"] = False

    # 5. Admin notifications (for admin-relevant events)
    if event in _ADMIN_EVENTS:
        _notify_admin_queue(event, base_payload)
        results["channels"]["admin"] = True

    results["dispatched"] = True
    return results


def get_kyc_notification_prefs(user_sub: str) -> dict[str, Any]:
    """Get KYC notification preferences for a user."""
    from app.core.tables import T
    item = T.users.get_item(
        Key={"pk": f"USER#{user_sub}", "sk": "KYC_NOTIFICATION_PREFS"}
    ).get("Item")
    if not item:
        return {
            "email_enabled": True,
            "sms_enabled": False,
            "push_enabled": True,
            "events": list(KYC_NOTIFICATION_EVENTS),
        }
    return {
        "email_enabled": bool(item.get("email_enabled", True)),
        "sms_enabled": bool(item.get("sms_enabled", False)),
        "push_enabled": bool(item.get("push_enabled", True)),
        "events": list(item.get("events", KYC_NOTIFICATION_EVENTS)),
    }


def update_kyc_notification_prefs(
    user_sub: str,
    *,
    email_enabled: bool | None = None,
    sms_enabled: bool | None = None,
    push_enabled: bool | None = None,
    events: list[str] | None = None,
) -> dict[str, Any]:
    """Update KYC notification preferences."""
    from app.core.tables import T
    current = get_kyc_notification_prefs(user_sub)

    if email_enabled is not None:
        current["email_enabled"] = email_enabled
    if sms_enabled is not None:
        current["sms_enabled"] = sms_enabled
    if push_enabled is not None:
        current["push_enabled"] = push_enabled
    if events is not None:
        current["events"] = [e for e in events if e in KYC_NOTIFICATION_EVENTS]

    T.users.put_item(Item={
        "pk": f"USER#{user_sub}",
        "sk": "KYC_NOTIFICATION_PREFS",
        **current,
    })
    return current


def _build_alert_title(event: str, payload: dict) -> str:
    titles = {
        "kyc.case.created": "Verification case created",
        "kyc.case.submitted": "Verification submitted for review",
        "kyc.case.approved": "Identity verification approved!",
        "kyc.case.rejected": "Identity verification not approved",
        "kyc.case.needs_info": "Additional documents needed",
        "kyc.screening.match_found": "Screening review required",
        "kyc.tier.upgraded": f"Verification level upgraded to Tier {payload.get('to_tier', '?')}",
        "kyc.tier.downgraded": f"Verification level changed to Tier {payload.get('to_tier', '?')}",
    }
    return titles.get(event, f"KYC update: {event}")


def _build_email_body(event: str, payload: dict) -> str:
    case_id = payload.get("case_id", "N/A")
    if event == "kyc.case.submitted":
        return (
            f"Your identity verification application (Case {case_id}) has been submitted "
            f"and is now in our review queue. We will notify you when a decision is made."
        )
    elif event == "kyc.case.approved":
        return (
            f"Great news! Your identity verification (Case {case_id}) has been approved. "
            f"Your account verification level has been upgraded."
        )
    elif event == "kyc.case.rejected":
        reasons = ", ".join(payload.get("reason_codes", []))
        return (
            f"Your identity verification (Case {case_id}) was not approved. "
            f"Reason(s): {reasons or 'See case details'}. "
            f"You may submit a new application with updated documents."
        )
    elif event == "kyc.case.needs_info":
        items = ", ".join(payload.get("requested_items", []))
        return (
            f"Additional information is needed for your verification (Case {case_id}). "
            f"Requested: {items or 'See case details'}. "
            f"Please log in and update your application."
        )
    return f"KYC notification: {event}"


def _build_sms_body(event: str, payload: dict) -> str:
    if event == "kyc.case.needs_info":
        return "Action needed: Additional documents required for your verification. Please log in to update."
    elif event == "kyc.case.rejected":
        return "Your verification was not approved. Please log in for details and to reapply."
    return "KYC update — please check your account."


def _notify_admin_queue(event: str, payload: dict) -> None:
    """Notify subscribed admins about queue-relevant events."""
    from app.core.tables import T
    # Query admin notification subscriptions
    resp = T.users.query(
        IndexName="ByRole",
        KeyConditionExpression="begins_with(sk, :prefix)",
        ExpressionAttributeValues={":prefix": "KYC_ADMIN_NOTIFY"},
        Limit=50,
    )
    # In dev mode, just write to audit log
    audit_event(
        f"kyc.admin_notification.{event}",
        "system",
        None,
        outcome="info",
        payload=payload,
    )
```

### 3.3 API Endpoints

Add to `app/routers/kyc_cases.py` or a new `app/routers/kyc_notifications.py`:

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/v1/kyc/notifications/preferences` | `require_ui_session` | Get user's KYC notification preferences |
| `PATCH` | `/v1/kyc/notifications/preferences` | `require_ui_session` | Update notification preferences |
| `GET` | `/v1/kyc/notifications/history` | `require_ui_session` | List past KYC notifications (from alerts) |
| `GET` | `/v1/kyc/notifications/admin/subscriptions` | `require_root_session` | List admin notification subscriptions |
| `POST` | `/v1/kyc/notifications/admin/subscribe` | `require_root_session` | Subscribe admin to KYC queue notifications |

```python
router = APIRouter(prefix="/v1/kyc/notifications", tags=["kyc-notifications"])


@router.get("/preferences")
async def get_notification_prefs(ctx=Depends(require_ui_session)):
    return get_kyc_notification_prefs(ctx["user_sub"])


@router.patch("/preferences")
async def update_notification_prefs(
    body: KycNotificationPrefsUpdate,
    ctx=Depends(require_ui_session),
):
    return update_kyc_notification_prefs(
        ctx["user_sub"],
        email_enabled=body.email_enabled,
        sms_enabled=body.sms_enabled,
        push_enabled=body.push_enabled,
        events=body.events,
    )


@router.get("/history")
async def get_notification_history(ctx=Depends(require_ui_session)):
    # Query alerts table for KYC events
    from app.core.tables import T
    resp = T.alerts.query(
        KeyConditionExpression=Key("user_sub").eq(ctx["user_sub"]),
        FilterExpression=Attr("event").begins_with("kyc."),
        ScanIndexForward=False,
        Limit=50,
    )
    return {"items": resp.get("Items", [])}
```

### 3.4 Integration Points

Modify `app/routers/kyc_cases.py` to call `kyc_notify()` at each state transition:

```python
# After create_kyc_case (line 518):
kyc_notify(event="kyc.case.created", user_sub=user_sub, case_id=case_id, request=request)

# After submit_kyc_case (line 829):
kyc_notify(event="kyc.case.submitted", user_sub=user_sub, case_id=case_id, request=request)

# In _admin_decide_case (line 1099), after approval:
kyc_notify(event="kyc.case.approved", user_sub=case["user_sub"], case_id=case_id, request=request)

# In _admin_decide_case, after rejection:
kyc_notify(event="kyc.case.rejected", user_sub=case["user_sub"], case_id=case_id,
           reason_codes=body.reason_codes, request=request)

# In admin_request_more_info (line 1021):
kyc_notify(event="kyc.case.needs_info", user_sub=case["user_sub"], case_id=case_id,
           requested_items=body.requested_items, note=body.note, request=request)
```

### 3.5 Pydantic Models

```python
class KycNotificationPrefsUpdate(BaseModel):
    email_enabled: bool | None = None
    sms_enabled: bool | None = None
    push_enabled: bool | None = None
    events: list[str] | None = None
```

### 3.6 Frontend Components

**File**: `frontend/src/pages/kyc/KycNotificationPrefs.tsx`

- Toggle switches for email, SMS, push channels
- Checkboxes for individual event types
- Save button with optimistic update

**File**: `frontend/src/api/endpoints/kyc-notifications.ts`

```typescript
export const getKycNotificationPrefs = () =>
  client.get("/v1/kyc/notifications/preferences");
export const updateKycNotificationPrefs = (data: Partial<KycNotificationPrefs>) =>
  client.patch("/v1/kyc/notifications/preferences", data);
export const getKycNotificationHistory = () =>
  client.get("/v1/kyc/notifications/history");
```

### 3.7 Registration

```python
# app/main.py
from app.routers.kyc_notifications import router as kyc_notifications_router
app.include_router(kyc_notifications_router)
```

---

## 4. Implementation Plan

### Phase 1: Webhook Event Types (1 day)

| File | Change |
|------|--------|
| `app/services/webhook_service.py` | Add 8 KYC event types to `WEBHOOK_EVENT_TYPES_V2` |

### Phase 2: Notification Service (2 days)

| File | Change |
|------|--------|
| `app/services/kyc_notifications.py` | New: notification dispatcher, preferences, email/SMS builders (~300 lines) |

### Phase 3: Router + Integration (2 days)

| File | Change |
|------|--------|
| `app/routers/kyc_notifications.py` | New: 5 endpoints (~100 lines) |
| `app/routers/kyc_cases.py` | Add `kyc_notify()` calls at 5 state transition points |
| `app/contracts/kyc_cases_contract.py` | Add `KycNotificationPrefsUpdate` model |
| `app/main.py` | Register `kyc_notifications_router` |

### Phase 4: Frontend (1 day)

| File | Change |
|------|--------|
| `frontend/src/pages/kyc/KycNotificationPrefs.tsx` | New: notification preferences UI |
| `frontend/src/api/endpoints/kyc-notifications.ts` | New: API endpoint wrappers |
| `frontend/src/api/types.ts` | Add `KycNotificationPrefs` type |

### Phase 5: E2E Tests (2 days)

| File | Change |
|------|--------|
| `frontend/e2e/kyc-notifications.spec.ts` | New: ~15 tests, sections 191-193 |

---

## 5. E2E Test Plan (`frontend/e2e/kyc-notifications.spec.ts`)

**Test file**: `frontend/e2e/kyc-notifications.spec.ts`  
**Total tests**: ~15  
**Sections**: 191-193

### Section 191: Notification Preferences API (5 tests)

1. `GET /v1/kyc/notifications/preferences returns defaults for new user` — Verify `email_enabled: true`, `sms_enabled: false`, `push_enabled: true`, all events listed.
2. `PATCH preferences updates email_enabled` — Set `email_enabled: false`; GET returns `email_enabled: false`.
3. `PATCH preferences filters invalid event types` — Send `events: ["kyc.case.approved", "invalid.event"]`; GET returns only `kyc.case.approved`.
4. `PATCH is idempotent` — Same PATCH twice; second returns same values.
5. `Preferences are per-user` — Alice's prefs change does not affect Bob's prefs.

### Section 192: Notification Dispatch API (6 tests)

1. `Submitting KYC case generates in-app alert` — Submit a case; query alerts for user; verify alert with `event: "kyc.case.submitted"`.
2. `Admin approval generates approval alert for user` — Root approves case; verify user has alert with `event: "kyc.case.approved"`.
3. `Admin rejection generates rejection alert with reason codes` — Root rejects case with reason codes; verify alert details contain `reason_codes`.
4. `Admin request-info generates alert with requested items` — Root requests info; verify alert contains `requested_items`.
5. `Webhook event dispatched on case submission` — Register a webhook endpoint for Alice subscribing to `kyc.case.submitted`; submit case; verify webhook delivery record exists.
6. `Notification history endpoint returns KYC alerts only` — Create non-KYC alert and KYC alert; GET history returns only KYC-prefixed events.

### Section 193: Admin Notifications (4 tests)

1. `New submission triggers admin queue notification audit event` — Submit case; query audit log; verify `kyc.admin_notification.kyc.case.submitted` event exists.
2. `Admin can subscribe to KYC queue notifications` — POST subscribe; verify subscription stored.
3. `Notification preferences do not affect admin alerts` — User disables email; admin still receives queue notifications.
4. `Screening match event is flagged as admin-relevant` — Trigger screening match event; verify admin notification audit entry.

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
});
```

### Edge Cases

| Edge Case | Expected Behavior |
|-----------|-------------------|
| User has no email on profile | Email notification skipped; other channels still fire |
| User has no phone on profile | SMS notification skipped |
| User disables all channels | Only in-app alert is created (always-on) |
| Webhook endpoint is down | Delivery fails; enters DLQ via existing retry/DLQ infrastructure |
| Rate limit exceeded for email channel | `can_send_alert_channel` returns false; email skipped |
| Same event dispatched twice (idempotent) | Two alerts created (alerts are append-only); webhook deduplication handled by dispatcher |

---

## 6. Security Considerations

- Notification preferences are scoped to the authenticated user. No user can modify another user's preferences.
- Email content does not include sensitive KYC data (no document numbers, no PII). It includes only the case ID and a generic message directing the user to log in.
- SMS messages are similarly generic — no PII in SMS body.
- Webhook payloads include `case_id` and `user_sub` but not document contents or extracted PII. The receiving endpoint can query the full case details via API if needed.
- Admin notification subscriptions require `require_root_session`.

---

## 7. Rollback Plan

- Remove `kyc_notify()` calls from `app/routers/kyc_cases.py` state transition points.
- Remove KYC event types from `WEBHOOK_EVENT_TYPES_V2` in `app/services/webhook_service.py`.
- Delete `app/services/kyc_notifications.py` and `app/routers/kyc_notifications.py`.
- Notification preference records (`SK=KYC_NOTIFICATION_PREFS`) in the users table are inert and can remain.
