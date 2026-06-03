# KYC-011: KYC Webhooks & Notifications

**Status**: Implemented  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: High  
**Estimated effort**: 6-8 days  
**Dependencies**: KYC-001 (Admin Dashboard), KYC-009 (Tiered Verification Levels)

---

## 1. Overview & Motivation

### 1.1 The Gap

The current KYC system (`app/routers/kyc_cases.py`, `app/services/kyc_cases.py`) transitions cases through `draft -> submitted -> under_review -> approved/rejected/needs_more_info -> expired`, but these transitions happen silently. The only feedback mechanism is polling — a user must repeatedly check their case status, and an admin must manually refresh the queue to see new submissions.

The audit system (`audit_event()` — see `app/services/alerts.py:695`) records KYC events to the audit log, but these are internal telemetry, not user-facing notifications. The alert system (`write_alert()` — see `app/services/alerts.py:355`) supports in-app alerts, email, and SMS delivery, but no KYC-specific alert types are registered. The webhook system (see `app/services/webhook_service.py:24` for `WEBHOOK_EVENT_TYPES`) defines event types for messaging, billing, newsfeed, broadcast, and account events -- but no KYC events.

### 1.2 What This Ticket Adds

1. **Webhook events** for all KYC state transitions, published through the existing webhook dispatcher (see `app/services/webhook_dispatcher.py`).
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

The webhook service defines `WEBHOOK_EVENT_TYPES` (see `app/services/webhook_service.py:24`) and `WEBHOOK_EVENT_TYPES_V2` (see `:60`) -- dictionaries mapping event type strings to descriptions. No KYC event types exist. The `dispatch_webhook_event()` function (see `:503`) handles delivery to user-registered endpoints. The `is_valid_event_type()` check (see `:154`) validates against these dictionaries.

To add KYC events, new entries must be added to `WEBHOOK_EVENT_TYPES_V2` and the `dispatch_webhook_event()` function must be called from KYC state transition points.

### 2.2 Webhook Dispatcher (`app/services/webhook_dispatcher.py`)

The dispatcher handles async delivery, retry logic (see `app/services/webhook_retry.py`), circuit breaking (see `app/services/webhook_circuit_breaker.py`), dead letter queue (see `app/services/webhook_dlq.py`), and SSRF protection (see `app/services/webhook_ssrf.py`). KYC webhook events will use this existing infrastructure.

### 2.3 Alert System (`app/services/alerts.py`)

- `write_alert(user_sub, *, event, outcome, title, details)` (see `app/services/alerts.py:355`): Creates in-app alerts stored in the `alerts` table.
- `send_alert_email(to_emails, subject, body_text)` (see `app/services/alerts.py:458`): Sends email via SES (mocked in dev).
- `send_alert_sms(to_numbers, body_text)` (see `app/services/alerts.py:481`): Sends SMS via SNS (mocked in dev).
- `send_alert_webhook(payload, *, alert_type, alert_id)` (see `app/services/alerts.py:600`): Sends webhook to the platform-level webhook URL.

### 2.4 Email Templates (`app/services/alert_email_templates.py`)

Existing email template infrastructure. KYC emails will follow the same pattern with KYC-specific templates.

### 2.5 Notification Preferences

The alert preferences system (`app/services/alerts.py`) stores per-user preferences including `email_types`, `sms_types`, `push_types` — lists of event type strings the user has opted into. The `can_send_alert_channel(user_sub, channel)` function (imported from `app/services/rate_limit.py`) enforces rate limits per channel.

### 2.6 KYC State Transitions (`app/routers/kyc_cases.py`)

The `_audit_state_transition()` helper (see `app/routers/kyc_cases.py:85`) is called at every state change. It calls `audit_event()` with KYC-specific event names. This is the integration point -- `kyc_notify()` should be called alongside `_audit_state_transition()`.

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

---

## 8. Architecture & Data Flow

```
┌────────────────────────────────────────────────────────────────────────────┐
│                           Frontend                                         │
│                                                                            │
│  KycNotificationPrefs.tsx                  AlertsBell (header)             │
│  ┌──────────────────────────────┐         ┌──────────────────────────┐    │
│  │ ChannelToggles                │         │ KYC alert items in       │    │
│  │  ├─ Switch (Email)            │         │ notification dropdown    │    │
│  │  ├─ Switch (SMS)              │         │  ├─ "Verification         │    │
│  │  └─ Switch (Push)             │         │  │   submitted"          │    │
│  │ EventCheckboxes               │         │  ├─ "Approved!"          │    │
│  │  ├─ ☑ case.submitted          │         │  └─ "Info needed"        │    │
│  │  ├─ ☑ case.approved           │         └──────────────────────────┘    │
│  │  ├─ ☑ case.rejected           │                                         │
│  │  ├─ ☑ case.needs_info         │                                         │
│  │  ├─ ☐ screening.match_found   │                                         │
│  │  ├─ ☑ tier.upgraded           │                                         │
│  │  └─ ☑ tier.downgraded         │                                         │
│  │ Button "Save Preferences"     │                                         │
│  └──────────────────────────────┘                                          │
└──────────────────┬─────────────────────────────────────────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                      Backend (FastAPI)                                      │
│                                                                            │
│  KYC State Transition (kyc_cases.py)                                      │
│  ┌──────────────────────────────────────────────────────────────────┐     │
│  │ create_kyc_case()     → kyc_notify("kyc.case.created")          │     │
│  │ submit_kyc_case()     → kyc_notify("kyc.case.submitted")        │     │
│  │ _admin_decide_case()  → kyc_notify("kyc.case.approved")         │     │
│  │                       → kyc_notify("kyc.case.rejected")          │     │
│  │ admin_request_info()  → kyc_notify("kyc.case.needs_info")       │     │
│  └──────────────────────────────────────────────────────────────────┘     │
│                         │                                                  │
│                         ▼                                                  │
│  kyc_notify() dispatcher (kyc_notifications.py)                           │
│  ┌──────────────────────────────────────────────────────────────────┐     │
│  │ 1. write_alert()         → alerts table (always)                  │     │
│  │ 2. send_alert_email()    → SES mock (if email_enabled + event)   │     │
│  │ 3. send_alert_sms()      → SNS mock (if sms_enabled + urgent)   │     │
│  │ 4. dispatch_webhook()    → webhook_dispatcher (if endpoint set)  │     │
│  │ 5. _notify_admin_queue() → audit_event (for admin events)        │     │
│  └──────────────────────────────────────────────────────────────────┘     │
│                                                                            │
│  Notification Preferences (users table)                                   │
│  ┌──────────────────────────────────────────────────────────────────┐     │
│  │ PK=USER#{sub}, SK=KYC_NOTIFICATION_PREFS                         │     │
│  │ { email_enabled, sms_enabled, push_enabled, events[] }           │     │
│  └──────────────────────────────────────────────────────────────────┘     │
└──────────────────┬─────────────────────────────────────────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  External channels (all mocked in dev)                                    │
│  ┌─────────────┐ ┌─────────────┐ ┌──────────────────┐ ┌──────────────┐  │
│  │ alerts table │ │ SES (email) │ │ SNS (SMS)        │ │ webhooks     │  │
│  │ (in-app)    │ │ mocked by   │ │ mocked by moto   │ │ dispatcher + │  │
│  │             │ │ moto        │ │                   │ │ retry + DLQ  │  │
│  └─────────────┘ └─────────────┘ └──────────────────┘ └──────────────┘  │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 9. DynamoDB Access Patterns

| # | Access Pattern | Table | Key Condition | Notes |
|---|---------------|-------|---------------|-------|
| 1 | Get notification prefs | `users` | PK=`USER#{sub}`, SK=`KYC_NOTIFICATION_PREFS` | Returns defaults if not found |
| 2 | Update notification prefs | `users` | PK=`USER#{sub}`, SK=`KYC_NOTIFICATION_PREFS` | PutItem (full replace) |
| 3 | Write in-app alert | `alerts` | PK=`{user_sub}`, SK=`{alert_id}` | Via existing `write_alert()` |
| 4 | Query KYC notification history | `alerts` | PK=`{user_sub}`, filter `event begins_with "kyc."` | ScanIndexForward=False, Limit=50 |
| 5 | Query admin subscriptions | `users` | GSI `ByRole`, filter SK begins_with `KYC_ADMIN_NOTIFY` | For admin notification dispatch |
| 6 | Get user profile (for email/phone) | `users` | PK=`USER#{sub}`, SK=`PROFILE` | For email and SMS delivery |

---

## 10. API Request/Response Examples

### 10.1 Get Notification Preferences

```bash
curl -X GET "http://localhost:8000/v1/kyc/notifications/preferences" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=csrf_a"
```

**Response (200):**
```json
{
  "email_enabled": true,
  "sms_enabled": false,
  "push_enabled": true,
  "events": [
    "kyc.case.created",
    "kyc.case.submitted",
    "kyc.case.approved",
    "kyc.case.rejected",
    "kyc.case.needs_info",
    "kyc.screening.match_found",
    "kyc.tier.upgraded",
    "kyc.tier.downgraded"
  ]
}
```

### 10.2 Update Notification Preferences

```bash
curl -X PATCH "http://localhost:8000/v1/kyc/notifications/preferences" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=csrf_a" \
  -H "x-csrf-token: csrf_a" \
  -H "Content-Type: application/json" \
  -d '{
    "email_enabled": false,
    "sms_enabled": true,
    "events": ["kyc.case.approved", "kyc.case.rejected", "kyc.case.needs_info"]
  }'
```

**Response (200):**
```json
{
  "email_enabled": false,
  "sms_enabled": true,
  "push_enabled": true,
  "events": ["kyc.case.approved", "kyc.case.rejected", "kyc.case.needs_info"]
}
```

### 10.3 Get Notification History

```bash
curl -X GET "http://localhost:8000/v1/kyc/notifications/history" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=csrf_a"
```

**Response (200):**
```json
{
  "items": [
    {
      "alert_id": "alert_abc123",
      "event": "kyc.case.approved",
      "title": "Identity verification approved!",
      "details": {
        "case_id": "kyc_a1b2c3d4",
        "user_sub": "e2e_alice@test.local",
        "timestamp": 1716768000
      },
      "action_url": "/kyc/status?case_id=kyc_a1b2c3d4",
      "created_at": 1716768000,
      "read": false
    },
    {
      "alert_id": "alert_def456",
      "event": "kyc.case.submitted",
      "title": "Verification submitted for review",
      "details": {
        "case_id": "kyc_a1b2c3d4",
        "timestamp": 1716681600
      },
      "action_url": "/kyc/status?case_id=kyc_a1b2c3d4",
      "created_at": 1716681600,
      "read": true
    }
  ]
}
```

---

## 11. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|----------------|
| Get prefs for non-authenticated user | 401 | `unauthorized` | "Authentication required." | Log in |
| Update prefs with invalid event type | 200 | — | Invalid events silently filtered out | Normal behavior |
| Update prefs with empty events list | 200 | — | Sets empty events list (no notifications) | Re-enable events |
| Notification history with no KYC alerts | 200 | — | Returns empty items array | Normal behavior |
| Email delivery failure (SES error) | N/A | — | Alert still written; email channel marked failed in result | Retry or check email |
| SMS delivery failure (SNS error) | N/A | — | Alert still written; SMS channel marked failed in result | Check phone number |
| Webhook endpoint down | N/A | — | Enters retry/DLQ pipeline | Webhook retry handles |
| Admin subscribe without ROOT session | 403 | `root_session_required` | "Root access required." | Use root credentials |

---

## 12. Pydantic Models

### 12.1 Request Models

```python
from pydantic import BaseModel, Field
from typing import Literal


class NotificationPreferencesUpdateRequest(BaseModel):
    """Request to update a user's KYC notification preferences."""
    enabled_events: list[str] = Field(
        default_factory=list,
        max_length=20,
        description="List of KYC event names to receive notifications for.",
        examples=[["case.approved", "case.rejected", "case.needs_more_info"]],
    )
    channels: list[Literal["in_app", "email", "sms"]] = Field(
        default_factory=lambda: ["in_app"],
        max_length=3,
        description="Notification delivery channels. in_app is always active.",
        examples=[["in_app", "email"]],
    )
    email_override: str | None = Field(
        default=None,
        max_length=254,
        description="Override email for KYC notifications (defaults to account email).",
        examples=["kyc-alerts@mycompany.com"],
    )
    phone_override: str | None = Field(
        default=None,
        max_length=20,
        description="Override phone for SMS notifications.",
        examples=["+15551234567"],
    )


class AdminWebhookSubscribeRequest(BaseModel):
    """Request to subscribe an admin webhook for KYC events."""
    url: str = Field(
        min_length=10,
        max_length=2000,
        pattern=r"^https://",
        description="Webhook URL (must be HTTPS).",
        examples=["https://compliance.example.com/kyc-events"],
    )
    events: list[str] = Field(
        min_length=1,
        max_length=20,
        description="KYC event names to subscribe to.",
        examples=[["case.approved", "case.rejected", "screening.hit"]],
    )
    secret: str | None = Field(
        default=None,
        min_length=16,
        max_length=256,
        description="Shared secret for webhook HMAC signature verification.",
    )


class AdminWebhookUnsubscribeRequest(BaseModel):
    """Request to remove an admin webhook subscription."""
    subscription_id: str = Field(
        min_length=1,
        max_length=64,
        description="ID of the webhook subscription to remove.",
    )
```

### 12.2 Response Models

```python
from pydantic import BaseModel, Field
from typing import Any, Literal


class NotificationPreferencesOut(BaseModel):
    """User's current KYC notification preferences."""
    user_sub: str
    enabled_events: list[str] = Field(default_factory=list)
    channels: list[str] = Field(default_factory=lambda: ["in_app"])
    email_override: str | None = None
    phone_override: str | None = None
    updated_at: int


class NotificationChannelResultOut(BaseModel):
    """Result of a single channel delivery attempt."""
    channel: Literal["in_app", "email", "sms", "webhook"]
    success: bool
    error: str | None = None
    delivered_at: int | None = None


class NotificationDispatchResultOut(BaseModel):
    """Result of a notification dispatch across all channels."""
    event: str
    user_sub: str
    channels: list[NotificationChannelResultOut]
    alert_id: str | None = Field(description="In-app alert ID, if created")
    dispatched_at: int


class NotificationHistoryItemOut(BaseModel):
    """A single notification history entry."""
    alert_id: str
    event: str
    title: str
    body: str
    channels: list[str]
    read: bool
    created_at: int


class NotificationHistoryOut(BaseModel):
    """List of past KYC notifications for a user."""
    items: list[NotificationHistoryItemOut]
    total: int
    cursor: str | None = None


class WebhookSubscriptionOut(BaseModel):
    """An admin webhook subscription."""
    subscription_id: str
    url: str
    events: list[str]
    created_at: int
    created_by: str
    last_delivery_at: int | None = None
    failure_count: int = Field(ge=0, default=0)


class AdminWebhookListOut(BaseModel):
    """List of all admin webhook subscriptions."""
    subscriptions: list[WebhookSubscriptionOut]
    total: int


class KycEventPayload(BaseModel):
    """Payload structure for KYC event notifications (webhook body)."""
    event: str = Field(description="Event name (e.g., case.approved)")
    case_id: str
    user_sub: str
    status: str
    timestamp: int
    details: dict[str, Any] = Field(default_factory=dict)
    signature: str | None = Field(
        default=None,
        description="HMAC-SHA256 signature of the payload (if webhook secret configured)",
    )
```

---

## 13. Frontend Component Tree

```
NotificationPreferencesPage.tsx  (/settings/notifications or embedded in KycStatusPage)
├── Props: none (uses auth context for user_sub)
├── State:
│   ├── form: useForm<NotificationPreferencesUpdateRequest>()
│   └── saving: boolean (from useMutation)
├── Queries:
│   └── useQuery(["kyc","notification-prefs"]) → NotificationPreferencesOut
├── Mutations:
│   └── useMutation(updateNotificationPrefs)
│       → onSuccess: invalidate ["kyc","notification-prefs"], toast "Preferences saved"
│
├── <Card>
│   ├── <CardHeader>
│   │   └── <CardTitle>"KYC Notification Preferences"</CardTitle>
│   │
│   ├── <CardContent>
│   │   ├── <h4>"Events"</h4>
│   │   ├── <CheckboxGroup>
│   │   │   ├── <Checkbox label="Case Approved" value="case.approved" />
│   │   │   ├── <Checkbox label="Case Rejected" value="case.rejected" />
│   │   │   ├── <Checkbox label="More Info Requested" value="case.needs_more_info" />
│   │   │   ├── <Checkbox label="Case Under Review" value="case.under_review" />
│   │   │   ├── <Checkbox label="Screening Hit" value="screening.hit" />
│   │   │   └── <Checkbox label="Risk Tier Changed" value="risk.tier_changed" />
│   │   │
│   │   ├── <Separator />
│   │   │
│   │   ├── <h4>"Delivery Channels"</h4>
│   │   ├── <CheckboxGroup>
│   │   │   ├── <Checkbox label="In-App Alerts" value="in_app" checked disabled />
│   │   │   │   └── <span className="text-muted-foreground">"Always active"</span>
│   │   │   ├── <Checkbox label="Email" value="email" />
│   │   │   └── <Checkbox label="SMS" value="sms" />
│   │   │
│   │   ├── {channels.includes("email") &&
│   │   │   <Input label="Email Override (optional)" placeholder="Default: account email"
│   │   │          {...register("email_override")} />}
│   │   │
│   │   ├── {channels.includes("sms") &&
│   │   │   <Input label="Phone Override (optional)" placeholder="Default: account phone"
│   │   │          {...register("phone_override")} />}
│   │   │
│   │   └── <Button type="submit" disabled={saving}>"Save Preferences"</Button>
│   │
│   └── </CardContent>
└── </Card>

NotificationHistorySection.tsx  (embedded in KycStatusPage)
├── Props: none
├── Queries:
│   └── useQuery(["kyc","notification-history"]) → NotificationHistoryOut
│
├── <Card>
│   ├── <CardHeader>
│   │   └── <CardTitle>"Notification History"</CardTitle>
│   │
│   ├── <CardContent>
│   │   ├── {items.length === 0 && <p>"No notifications yet."</p>}
│   │   └── items.map(item =>
│   │       <div className={`p-3 border-b ${!item.read ? "bg-blue-50" : ""}`}>
│   │         ├── <div className="flex justify-between">
│   │         │   ├── <span className="font-medium">{item.title}</span>
│   │         │   └── <span className="text-xs text-muted-foreground">
│   │         │       {formatRelative(item.created_at)}
│   │         │   </span>
│   │         ├── <p className="text-sm">{item.body}</p>
│   │         └── <div className="flex gap-1">
│   │             {item.channels.map(ch => <Badge variant="outline">{ch}</Badge>)}
│   │         </div>
│   │       </div>)
│   │
│   └── {history.cursor && <Button variant="ghost">"Load More"</Button>}
└── </Card>

AdminWebhookManager.tsx  (admin-only, /admin/kyc/webhooks)
├── Props: none
├── State:
│   ├── showAddDialog: boolean
│   └── addForm: useForm<AdminWebhookSubscribeRequest>()
├── Queries:
│   └── useQuery(["kyc","admin-webhooks"]) → AdminWebhookListOut
├── Mutations:
│   ├── useMutation(adminSubscribeWebhook) → invalidate ["kyc","admin-webhooks"]
│   └── useMutation(adminUnsubscribeWebhook) → invalidate ["kyc","admin-webhooks"]
│
├── <Card>
│   ├── <CardHeader className="flex justify-between">
│   │   ├── <CardTitle>"KYC Webhook Subscriptions"</CardTitle>
│   │   └── <Button onClick={() => setShowAddDialog(true)}>"Add Webhook"</Button>
│   │
│   ├── <CardContent>
│   │   └── <DataTable columns={["URL","Events","Last Delivery","Failures","Actions"]}>
│   │       └── subscriptions.map(sub =>
│   │           <TableRow>
│   │             ├── <td>{sub.url}</td>
│   │             ├── <td>{sub.events.join(", ")}</td>
│   │             ├── <td>{sub.last_delivery_at ? formatDate(...) : "Never"}</td>
│   │             ├── <td>{sub.failure_count > 0 ?
│   │             │     <Badge variant="destructive">{sub.failure_count}</Badge>
│   │             │     : "0"}</td>
│   │             └── <td><Button variant="ghost" size="sm"
│   │                   onClick={() => unsubscribe(sub.subscription_id)}>"Remove"</Button></td>
│   │           </TableRow>)
│   │
│   └── <Dialog open={showAddDialog}>
│       └── <DialogContent>
│           ├── <DialogTitle>"Add Webhook Subscription"</DialogTitle>
│           ├── <Form>
│           │   ├── <Input label="URL (HTTPS)" {...register("url")} />
│           │   ├── <CheckboxGroup label="Events" options={KYC_EVENTS} />
│           │   ├── <Input label="Shared Secret (optional)" type="password" />
│           │   └── <Button type="submit">"Subscribe"</Button>
│           └── </Form>
└── </Card>
```

### React Query Keys

| Key | Endpoint | Stale Time | Invalidation |
|-----|----------|------------|--------------|
| `["kyc","notification-prefs"]` | `GET /v1/kyc/notifications/preferences` | 60s | After prefs update |
| `["kyc","notification-history"]` | `GET /v1/kyc/notifications/history` | 30s | After new notification |
| `["kyc","admin-webhooks"]` | `GET /v1/kyc/notifications/admin/webhooks` | 30s | After subscribe/unsubscribe |

---

## 14. Observability & Monitoring

### Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kyc_notification_dispatched` | Counter | `event`, `channel` | Notifications sent per event and channel |
| `kyc_notification_channel_failure` | Counter | `event`, `channel` | Channel delivery failures |
| `kyc_notification_prefs_updated` | Counter | — | Preference update requests |
| `kyc_notification_admin_queue` | Counter | `event` | Admin queue notifications generated |
| `kyc_notification_latency_ms` | Histogram | `event` | Time to dispatch across all channels |

### Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| Email delivery failure rate | > 10% failures in 1h | P2 |
| SMS delivery failure rate | > 20% failures in 1h | P2 |
| Webhook DLQ growing | > 50 KYC webhook events in DLQ | P3 |
| No notifications dispatched | 0 notifications for > 24h (in production with active KYC flow) | P3 |

---

## 15. Performance Considerations

| Operation | Latency Target | DDB Cost | Notes |
|-----------|---------------|----------|-------|
| Get notification prefs | < 50ms | 1 RCU | Single GetItem |
| Update notification prefs | < 100ms | 1 WCU | Single PutItem |
| kyc_notify() dispatch | < 300ms | 2-3 WCU | Alert write + audit; email/SMS/webhook are fire-and-forget |
| Notification history query | < 200ms | 5-10 RCU | Query with filter; may scan past non-KYC alerts |
| Admin queue notification | < 100ms | 1 WCU | Single audit event write |

### Design Note

The `kyc_notify()` function is called synchronously in the request path of state transitions. To avoid adding latency to case submission/approval, email and SMS delivery are fire-and-forget (exceptions caught and logged). Only the in-app alert write blocks the response. If delivery latency becomes a concern, email/SMS/webhook dispatch can be moved to a background task.

---

## 16. Expanded E2E Tests

### Section 191 Additions: Preference Edge Cases (3 additional tests)

```typescript
test("191.6 Setting events to empty array disables all event notifications", async () => {
  // PATCH with events: []
  // GET prefs
  // Verify events is empty array
});

test("191.7 Push_enabled toggle persists independently", async () => {
  // PATCH with push_enabled: false (leave others unchanged)
  // GET prefs
  // Verify push_enabled: false, email/sms unchanged from previous state
});

test("191.8 Concurrent preference updates from same user are safe", async () => {
  // PATCH twice quickly with different values
  // GET prefs
  // Verify latest write wins (last-write-wins DDB PutItem)
});
```

### Section 192 Additions: Dispatch Edge Cases (4 additional tests)

```typescript
test("192.7 Email not sent when user has email_enabled=false", async () => {
  // Set email_enabled: false
  // Submit case
  // Verify in-app alert exists but no email delivery record
});

test("192.8 SMS sent only for urgent events (needs_info, rejected)", async () => {
  // Set sms_enabled: true
  // Submit case (kyc.case.submitted)
  // Verify no SMS sent (submitted is not an urgent event)
  // Then have admin request info
  // Verify SMS sent for kyc.case.needs_info
});

test("192.9 In-app alert always created regardless of preferences", async () => {
  // Disable all channels (email, sms, push)
  // Set events to empty array
  // Submit case
  // Verify in-app alert still created (always-on channel)
});

test("192.10 Notification includes action_url pointing to KYC status page", async () => {
  // Submit case
  // Get notification history
  // Verify action_url contains "/kyc/status?case_id="
});
```

### Section 193 Additions: Admin Notification Edge Cases (3 additional tests)

```typescript
test("193.5 Admin audit event includes full payload for submitted event", async () => {
  // Submit case
  // Query audit log for kyc.admin_notification.kyc.case.submitted
  // Verify payload includes case_id and user_sub
});

test("193.6 Multiple admin subscriptions receive independent notifications", async () => {
  // Subscribe two admins
  // Submit case
  // Verify audit events for both admins
});

test("193.7 Tier upgrade event dispatched when KYC case approved with tier change", async () => {
  // Approve case that results in tier upgrade
  // Verify kyc.tier.upgraded event in notification history
  // Verify payload includes from_tier and to_tier
});
```

---

## Codebase References

> **Verification performed**: 2026-05-29

### Verified (EXISTS in codebase)

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `audit_event()` | `app/services/alerts.py` | 695 | VERIFIED |
| `write_alert()` | `app/services/alerts.py` | 355 | VERIFIED |
| `send_alert_email()` | `app/services/alerts.py` | 458 | VERIFIED |
| `send_alert_sms()` | `app/services/alerts.py` | 481 | VERIFIED |
| `send_alert_webhook()` | `app/services/alerts.py` | 600 | VERIFIED |
| `can_send_alert_channel()` import | `app/services/alerts.py` | 22 | VERIFIED (imported from rate_limit) |
| `WEBHOOK_EVENT_TYPES` | `app/services/webhook_service.py` | 24 | VERIFIED |
| `WEBHOOK_EVENT_TYPES_V2` | `app/services/webhook_service.py` | 60 | VERIFIED |
| `is_valid_event_type()` | `app/services/webhook_service.py` | 154 | VERIFIED |
| `dispatch_webhook_event()` | `app/services/webhook_service.py` | 503 | VERIFIED |
| Webhook dispatcher | `app/services/webhook_dispatcher.py` | exists | VERIFIED |
| Webhook retry | `app/services/webhook_retry.py` | exists | VERIFIED |
| Webhook circuit breaker | `app/services/webhook_circuit_breaker.py` | exists | VERIFIED |
| Webhook DLQ | `app/services/webhook_dlq.py` | exists | VERIFIED |
| Webhook SSRF protection | `app/services/webhook_ssrf.py` | exists | VERIFIED |
| Alert email templates | `app/services/alert_email_templates.py` | exists | VERIFIED |
| `_audit_state_transition()` | `app/routers/kyc_cases.py` | 85 | VERIFIED |
| `submit_kyc_case()` | `app/routers/kyc_cases.py` | 830 | VERIFIED |
| `_admin_decide_case()` | `app/routers/kyc_cases.py` | 1099 | VERIFIED |
| `admin_request_more_info()` | `app/routers/kyc_cases.py` | 1021 | VERIFIED |
| `create_kyc_case()` | `app/routers/kyc_cases.py` | 519 | VERIFIED |
| `get_profile()` | `app/services/profiles.py` | 220 | VERIFIED |
| `kyc_cases` DDB table | `scripts/local-ddb-init.py` | 91-96 | VERIFIED |
| KYC cases router registration | `app/main.py` | 406 | VERIFIED |
| `app/contracts/kyc_cases_contract.py` | `app/contracts/` | exists | VERIFIED |
| `require_ui_session` | `app/auth/deps.py` | exists | VERIFIED |
| `require_root_session` | `app/auth/deps.py` | 273 | VERIFIED |

### Not Yet Implemented (requires new code)

| Reference | Expected Location | Status |
|-----------|-------------------|--------|
| `app/services/kyc_notifications.py` | `app/services/` | NOT FOUND -- new service required |
| `app/routers/kyc_notifications.py` | `app/routers/` | NOT FOUND -- new router required |
| `kyc_notifications_router` registration | `app/main.py` | NOT FOUND -- needs `app.include_router()` |
| `KycNotificationPrefsUpdate` model | `app/contracts/kyc_cases_contract.py` | NOT FOUND -- new model required |
| `kyc_notify()` calls in state transitions | `app/routers/kyc_cases.py` | NOT FOUND -- needs integration |
| KYC event types in `WEBHOOK_EVENT_TYPES_V2` | `app/services/webhook_service.py` | NOT FOUND -- needs 8 new event types |
| `KYC_NOTIFICATION_PREFS` sort key in users table | DDB `users` table | NOT FOUND -- new item pattern |
| `ByRole` GSI on users table (for admin notifications) | `scripts/local-ddb-init.py` | VERIFY -- may or may not exist |
| `frontend/src/pages/kyc/KycNotificationPrefs.tsx` | `frontend/src/pages/kyc/` | NOT FOUND -- new page required |
| `frontend/src/api/endpoints/kyc-notifications.ts` | `frontend/src/api/endpoints/` | NOT FOUND -- new endpoint file required |

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_kyc_webhooks.py`

Mock external dependencies with `moto` (DynamoDB) and `unittest.mock`. All tests run without the dev stack.

  - `test_register_webhook_endpoint`
  - `test_dispatch_verification_approved_event`
  - `test_dispatch_tier_changed_event`
  - `test_webhook_retry_on_failure`
  - `test_webhook_signature_hmac`
  - `test_list_webhook_delivery_log`
  - `test_deactivate_webhook`

### Integration Tests

  - Submission approval dispatches webhook to registered endpoint
  - Tier upgrade dispatches tier_changed event with old and new tier
  - Failed delivery retried with exponential backoff

### E2E Tests (Playwright)

**File**: `frontend/e2e/kyc-webhooks.spec.ts`
**Test count**: 10

**Auth pattern**: Use `injectAuth(page, "root")` for admin endpoints; use `injectAuth(page, "alice")` for user-level endpoints. All POST/PATCH/DELETE requests include `x-csrf-token` header matching the session's CSRF token.

**Negative tests**:
- 401: Unauthenticated request returns 401
- 403: Non-admin/non-owner access returns 403
- 404: Non-existent resource returns 404
- 409: Conflict on duplicate or already-processed resource
- 422: Invalid input (bad field values, missing required fields)

**Edge cases**:
- Empty result sets return 200 with empty arrays (not 404)
- Pagination cursor works correctly across pages
- Concurrent requests do not produce inconsistent state

### Test Data Requirements

- **DDB seeds**: Seed `kyc_webhooks` table with test records in `beforeAll`
- **Test users**: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- **Cleanup**: Tests use unique timestamps/IDs per run to avoid cross-run interference

### CI/Pipeline Considerations

- **Feature flag**: `KYC_WEBHOOKS_ENABLED=true` must be set in test environment
- **Serial execution**: E2E tests run with `workers: 1` to avoid shared-state conflicts
- **Retry safety**: All tests are idempotent; retries do not produce duplicate records

## Dependencies & Merge Safety

### Depends On

| Ticket | Title | Why |
|--------|-------|-----|
| KYC-001 | Admin KYC Review Dashboard | Dashboard actions trigger webhook events |
| KYC-009 | Tiered Verification Levels | Tier changes trigger webhooks |

### Depended On By

| Ticket | Title | Impact |
|--------|-------|--------|
| (none) | — | No other tickets depend on this one |

### Merge Strategy

**Sequential**

Merge after KYC-001, KYC-009. This ticket depends on tables/services introduced by those tickets.

### Merge Checklist

- [ ] All new DDB tables added to `scripts/local-ddb-init.py` with correct `attr_types` for numeric GSI keys
- [ ] New settings added to `app/core/settings.py` and `.env.local.example`
- [ ] New table handles added to `app/core/tables.py`
- [ ] Router registered in `app/main.py`
- [ ] Pydantic models added to `app/models.py`
- [ ] TypeScript types added to `frontend/src/api/types.ts`
- [ ] Route added to `frontend/src/App.tsx`
- [ ] Feature flag defaults to `true` in `.env.local.example`
- [ ] E2E session setup updated if new test identities needed
- [ ] `just restart` completes cleanly with new tables
- [ ] All 10 E2E tests pass with `npx playwright test kyc-webhooks.spec.ts`
