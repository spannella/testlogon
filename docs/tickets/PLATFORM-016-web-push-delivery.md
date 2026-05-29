# PLATFORM-016: Web Push Delivery

**Ticket**: PLATFORM-016
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 8-10 days

---

## 1. Overview & Motivation

### 1.1 Purpose

PLATFORM-016 completes the Web Push delivery pipeline. The codebase already has placeholder infrastructure -- `app/services/push.py` contains `web_push_send()` with VAPID signing, `upsert_push_device()` for device registration, and `send_push_for_alert()` for dispatching to all user devices. The frontend has a `PushDevices.tsx` page and `lib/pushSetup.ts` with `registerServiceWorker()` and `subscribeToPush()`. However, the service worker file itself is missing, the VAPID key generation flow is manual, push subscription JSON is stored but never validated, per-category push opt-in/opt-out preferences are not wired up, and the actual delivery path from platform events (new message, tip received, broadcast start, etc.) to push notification is incomplete. This ticket closes all those gaps to deliver real browser push notifications end-to-end.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| User | As a user, I want to receive browser push notifications for new messages so that I stay informed even when the tab is closed. | Service worker shows notification with sender name and message preview; clicking it opens the conversation. |
| User | As a user, I want to control which notification categories I receive pushes for so that I only get alerts I care about. | Preferences page shows toggles per category; disabling "tips" stops tip push but not message push. |
| User | As a user, I want to grant push permission once and have it persist across sessions. | Service worker registration persists; subscription is stored in DDB; re-login does not require re-granting. |
| Creator | As a creator, I want my subscribers to get a push when I start a broadcast so that they tune in. | `broadcast.started` event triggers push to all followers with push enabled for broadcasts. |
| Creator | As a creator, I want to know that tips trigger a push to me so that I can thank the tipper promptly. | `billing.tip_received` event triggers push with amount and tipper name. |
| Admin | As an admin, I want to see push delivery metrics (sent, failed, expired subscriptions) for monitoring. | Admin endpoint returns aggregate push delivery stats. |
| System | As the system, I want to auto-revoke expired subscriptions (410 Gone) to keep the device table clean. | `web_push_send` returning 410 triggers `revoke_push_device`; device disappears from user's list. |

### 1.3 Why This Is Needed

The platform currently supports SSE for real-time in-tab updates and email/SMS alerts for offline notifications, but has no browser push capability. Users who close the tab receive no timely notification of new messages, tips, or broadcasts. Web Push (RFC 8030 + VAPID) fills this gap without requiring a native mobile app, enabling re-engagement and reducing notification latency from minutes (email) to seconds.

---

## 2. Architecture Diagram

```
+----------------------------------+     +--------------------------+
|          Browser Client          |     |     Backend (FastAPI)    |
|                                  |     |                          |
| +-----------+   +--------------+ |     | +----------------------+ |
| | React App |   | Service      | |     | | push.py              | |
| |           |   | Worker (sw)  | |     | | - web_push_send()    | |
| +-----+-----+   +------+------+ |     | | - send_push_for_alert| |
|       |                |         |     | +----------+-----------+ |
+-------|---------+------|---------+     |            |             |
        |         |      |               | +----------v-----------+ |
  1. Register SW  | 4. Show            | | alerts.py            | |
  2. Subscribe    |    Notification     | | - write_alert()      | |
  3. Store sub    |                     | | - get_alert_prefs()  | |
                  |                     | +----------+-----------+ |
                  |                     |            |             |
        +---------v---------+           | +----------v-----------+ |
        | Push Service      |<----------| | pywebpush / VAPID    | |
        | (Google FCM /     |  5. Send  | +----------------------+ |
        | Mozilla autopush) |     Push  |                          |
        +-------------------+           | +----------------------+ |
                                        | | DynamoDB             | |
                                        | | - push_devices       | |
                                        | | - alert_prefs        | |
                                        | | - push_stats         | |
                                        | +----------------------+ |
                                        +--------------------------+

Flow:
1. React app calls navigator.serviceWorker.register("/sw.js")
2. pushSetup.ts calls PushManager.subscribe() with VAPID public key
3. Subscription JSON (endpoint + keys) POSTed to /ui/push/register
4. Platform event triggers write_alert() -> send_push_for_alert()
5. pywebpush encrypts payload and POSTs to push service endpoint
6. Push service delivers to browser; SW fires "push" event
7. SW calls self.registration.showNotification(title, options)
8. User clicks notification; SW handles "notificationclick" event
9. SW focuses existing tab or opens new window at target URL
```

---

## 3. Current State Analysis

### 3.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Push service | `app/services/push.py` (~300 lines) | `web_push_send()` with VAPID signing via pywebpush; `upsert_push_device()`; `revoke_push_device()`; `send_push_for_alert()` dispatcher; FCM support for native mobile |
| Push router | `app/routers/push.py` | `GET /vapid-key`, `GET /push/devices`, `POST /push/register`, `POST /push/revoke`, `POST /push/test` |
| Push devices table | `T.push_devices` (DDB) | PK: `user_sub`, SK: `device_id` (SHA256 of token); stores `token`, `platform`, `created_at`, `last_seen_at` |
| Frontend push setup | `frontend/src/lib/pushSetup.ts` | `registerServiceWorker()`, `subscribeToPush()`, `unsubscribeFromPush()` |
| Push devices page | `frontend/src/pages/alerts/PushDevices.tsx` | UI for enabling push, listing devices, revoking |
| Alert preferences | `app/services/alerts.py:get_alert_prefs()` / `set_alert_prefs()` | Per-channel preferences (email, sms, webhook); no push category granularity |
| Alert write | `app/services/alerts.py:write_alert()` | Central alert dispatch; calls `send_push_for_alert()` |
| Service worker registration | `frontend/src/main.tsx:33-35` | `registerServiceWorker()` called on app mount |
| Settings env | `app/core/settings.py` | `S.vapid_private_key`, `S.vapid_public_key`, `S.vapid_subject`, `S.web_push_enabled`, `S.push_enabled` |

### 3.2 Gaps

1. **No service worker file** -- `registerServiceWorker()` in `pushSetup.ts` calls `navigator.serviceWorker.register("/sw.js")` but `public/sw.js` does not exist. No push event listener, no notification display logic, no click handler.
2. **No push category preferences** -- `get_alert_prefs()` / `set_alert_prefs()` support channel toggles (`email_enabled`, `sms_enabled`) but have no per-event-type push opt-in/opt-out. `send_push_for_alert()` checks `push_enabled` globally but not per category.
3. **No subscription validation** -- `upsert_push_device()` stores the raw token string; for web push, the full subscription JSON (endpoint + keys.p256dh + keys.auth) is needed. The `PushRegisterReq` model accepts a `token` string but does not validate it as valid subscription JSON.
4. **No VAPID key auto-generation** -- VAPID keys must be manually set in `.env.local`. No setup script generates them; no guidance in `.env.local.example`.
5. **No stale subscription cleanup** -- `web_push_send()` returns `False` on 410 Gone but `send_push_for_alert()` does not call `revoke_push_device()` on failure.
6. **No push delivery stats** -- no counter or log of push attempts, successes, failures, or expirations.
7. **Dev mode push testing gap** -- `web_push_send()` logs in dev mode but returns `True` unconditionally; no way to verify the payload shape in E2E tests.

---

## 4. Technical Design

### 4.1 Service Worker File

**New file**: `frontend/public/sw.js` (~80 lines)

```javascript
/* Service Worker for Web Push Notifications (PLATFORM-016) */

self.addEventListener("install", (event) => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("push", (event) => {
  if (!event.data) return;
  const payload = event.data.json();
  const { title, body, url, tag, alert_id, alert_type, timestamp } = payload;

  const options = {
    body: body || "",
    icon: "/icon-192.png",
    badge: "/badge-72.png",
    tag: tag || "default",
    data: { url: url || "/", alert_id, alert_type },
    requireInteraction: alert_type === "new_message",
    timestamp: timestamp ? timestamp * 1000 : Date.now(),
  };

  event.waitUntil(self.registration.showNotification(title || "Notification", options));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = event.notification.data?.url || "/";
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((clients) => {
      for (const client of clients) {
        if (client.url.includes(self.location.origin) && "focus" in client) {
          client.navigate(url);
          return client.focus();
        }
      }
      return self.clients.openWindow(url);
    })
  );
});
```

### 4.2 Push Category Preferences

**Extend `app/services/alerts.py`**:

Add push category constants and extend preference get/set:

```python
PUSH_CATEGORIES = {
    "messages": ["new_message", "messaging.new_message"],
    "tips": ["billing.tip_received", "post_tip", "message_tip"],
    "subscriptions": ["subscription_started", "subscription_renewed", "subscription_cancelled"],
    "broadcasts": ["broadcast.started", "broadcast.ending_soon"],
    "content": ["content.unlocked", "post.comment", "post.reaction"],
    "security": ["security_event", "login_failure", "mfa_failure", "device_new"],
    "billing": ["payment_received", "refund_processed", "wallet.deposit"],
}

DEFAULT_PUSH_PREFS = {cat: True for cat in PUSH_CATEGORIES}
```

Modify `get_alert_prefs()` to return `push_categories: Dict[str, bool]` alongside existing prefs. Modify `set_alert_prefs()` to accept and persist `push_categories`.

### 4.3 Push Delivery Pipeline Enhancement

**Modify `app/services/push.py`**:

1. **`send_push_for_alert()`** -- check per-category preference before sending:
```python
def send_push_for_alert(user_sub, alert_type, title, body, alert_id):
    if not S.push_enabled:
        return
    prefs = get_alert_prefs(user_sub)
    push_cats = prefs.get("push_categories", DEFAULT_PUSH_PREFS)
    category = _alert_type_to_category(alert_type)
    if category and not push_cats.get(category, True):
        return  # User opted out of this category
    # ... existing device dispatch logic
```

2. **Stale subscription cleanup** -- after `web_push_send()` returns `False` with 410/404:
```python
for device in devices:
    success = web_push_send(device["token"], ...)
    if not success:
        # Check if subscription is dead (410/404)
        revoke_push_device(user_sub, device["device_id"])
```

3. **Push delivery stats** -- increment counters in `T.push_stats` table:
```python
def _record_push_stat(user_sub: str, outcome: str, alert_type: str):
    T.push_stats.update_item(
        Key={"pk": "GLOBAL", "sk": f"DAILY#{_today()}"},
        UpdateExpression="ADD sent_count :one, ...",
    )
```

### 4.4 DynamoDB Schema Changes

#### 4.4.1 Push Preferences (stored in existing alerts_prefs)

No new table needed. Extend the existing alert preferences item stored in `T.alert_prefs` with a `push_categories` map:

```json
{
  "user_sub": "alice@test.local",
  "push_categories": {
    "messages": true,
    "tips": true,
    "subscriptions": true,
    "broadcasts": true,
    "content": false,
    "security": true,
    "billing": true
  }
}
```

#### 4.4.2 Push Stats Table

**Table name**: `push_stats` (new table)
**PK**: `pk` (S), **SK**: `sk` (S)

| PK Pattern | SK Pattern | Purpose | Key Fields |
|------------|------------|---------|------------|
| `GLOBAL` | `DAILY#{date}` | Daily aggregate stats | `sent_count`, `success_count`, `failed_count`, `expired_count` |
| `USER#{user_sub}` | `DAILY#{date}` | Per-user daily stats | `sent_count`, `success_count` |

#### 4.4.3 TableDef Entry

```python
TableDef(
    "push_stats", "pk", "sk",
),
```

---

## 5. DynamoDB Access Patterns

### 5.1 Push Devices Table (existing)

| Access Pattern | PK | SK | Operation | Notes |
|---------------|----|----|-----------|-------|
| Get user's devices | `user_sub` | -- | Query | Returns all devices for user |
| Register device | `user_sub` | `device_id` (SHA256) | put_item | Upsert with ConditionExpression |
| Revoke device | `user_sub` | `device_id` | delete_item | Remove subscription |
| List all devices | `user_sub` | begins_with("") | Query | For cleanup/audit |

**Example item (web push subscription):**

```json
{
  "user_sub": "e2e_alice@test.local",
  "device_id": "a3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1",
  "token": "{\"endpoint\":\"https://fcm.googleapis.com/fcm/send/abc123\",\"keys\":{\"p256dh\":\"BN...\",\"auth\":\"xy...\"}}",
  "platform": "web",
  "created_at": 1748520000,
  "last_seen_at": 1748523600,
  "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0"
}
```

### 5.2 Push Stats Table (new)

| Access Pattern | PK | SK | Operation | Notes |
|---------------|----|----|-----------|-------|
| Get global daily stats | `GLOBAL` | `DAILY#2026-05-29` | get_item | Single row per day |
| Increment global stats | `GLOBAL` | `DAILY#2026-05-29` | update_item ADD | Atomic counter increment |
| Get user daily stats | `USER#alice@test.local` | `DAILY#2026-05-29` | get_item | Per-user breakdown |
| List global stats range | `GLOBAL` | between `DAILY#2026-05-01` and `DAILY#2026-05-31` | Query | Admin dashboard time series |

**Example global daily stats item:**

```json
{
  "pk": "GLOBAL",
  "sk": "DAILY#2026-05-29",
  "sent_count": 1523,
  "success_count": 1489,
  "failed_count": 12,
  "expired_count": 22,
  "category_breakdown": {
    "messages": { "sent": 890, "success": 878 },
    "tips": { "sent": 210, "success": 205 },
    "broadcasts": { "sent": 150, "success": 148 },
    "subscriptions": { "sent": 120, "success": 118 },
    "content": { "sent": 80, "success": 75 },
    "security": { "sent": 43, "success": 40 },
    "billing": { "sent": 30, "success": 25 }
  },
  "updated_at": 1748523600
}
```

### 5.3 Alert Preferences (existing table, extended)

| Access Pattern | PK | SK | Operation | Notes |
|---------------|----|----|-----------|-------|
| Get push prefs | `user_sub` | -- | get_item | Read push_categories map |
| Update push prefs | `user_sub` | -- | update_item SET | Merge push_categories |

---

## 6. API Request/Response Examples

### 6.1 GET /ui/push/vapid-key

```bash
curl -s http://localhost:8000/ui/push/vapid-key
```

**Response (200):**
```json
{
  "vapid_key": "BEl62iUYgUivxIkv69yViEuiBIa-Ib9-SkvMeAtA3LFgDzkCs7U2QJzTLEYRw4e8hkx-iJNKpSbUx7kC_gLR74"
}
```

### 6.2 POST /ui/push/register

```bash
curl -s -X POST http://localhost:8000/ui/push/register \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_abc123; ui_csrf=csrf_abc123; ui_access_token=jwt_abc123" \
  -H "x-csrf-token: csrf_abc123" \
  -d '{
    "token": "{\"endpoint\":\"https://fcm.googleapis.com/fcm/send/dQZK...\",\"keys\":{\"p256dh\":\"BNcR...\",\"auth\":\"tBH...\"}}",
    "platform": "web"
  }'
```

**Response (200):**
```json
{
  "ok": true,
  "device_id": "a3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1"
}
```

**Error Response (422 -- invalid subscription JSON):**
```json
{
  "detail": [
    {
      "loc": ["body", "token"],
      "msg": "Web push subscription must be valid JSON with endpoint and keys",
      "type": "value_error"
    }
  ]
}
```

### 6.3 GET /ui/push/devices

```bash
curl -s http://localhost:8000/ui/push/devices \
  -H "Cookie: ui_session=sess_abc123; ui_csrf=csrf_abc123; ui_access_token=jwt_abc123"
```

**Response (200):**
```json
{
  "devices": [
    {
      "device_id": "a3f2b1c4...",
      "platform": "web",
      "created_at": 1748520000,
      "last_seen_at": 1748523600
    }
  ]
}
```

### 6.4 GET /ui/push/preferences

```bash
curl -s http://localhost:8000/ui/push/preferences \
  -H "Cookie: ui_session=sess_abc123; ui_csrf=csrf_abc123; ui_access_token=jwt_abc123"
```

**Response (200):**
```json
{
  "push_enabled": true,
  "categories": {
    "messages": true,
    "tips": true,
    "subscriptions": true,
    "broadcasts": true,
    "content": true,
    "security": true,
    "billing": true
  }
}
```

### 6.5 PUT /ui/push/preferences

```bash
curl -s -X PUT http://localhost:8000/ui/push/preferences \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_abc123; ui_csrf=csrf_abc123; ui_access_token=jwt_abc123" \
  -H "x-csrf-token: csrf_abc123" \
  -d '{
    "push_enabled": true,
    "categories": {
      "tips": false,
      "content": false
    }
  }'
```

**Response (200):**
```json
{
  "ok": true,
  "push_enabled": true,
  "categories": {
    "messages": true,
    "tips": false,
    "subscriptions": true,
    "broadcasts": true,
    "content": false,
    "security": true,
    "billing": true
  }
}
```

### 6.6 POST /ui/push/test

```bash
curl -s -X POST http://localhost:8000/ui/push/test \
  -H "Cookie: ui_session=sess_abc123; ui_csrf=csrf_abc123; ui_access_token=jwt_abc123" \
  -H "x-csrf-token: csrf_abc123"
```

**Response (200):**
```json
{
  "ok": true,
  "devices_sent": 1,
  "dev_mode": true,
  "payload_preview": {
    "title": "Test Push Notification",
    "body": "This is a test push from the platform.",
    "url": "/alerts",
    "tag": "test",
    "alert_type": "test_push"
  }
}
```

### 6.7 GET /ui/admin/push/stats

```bash
curl -s "http://localhost:8000/ui/admin/push/stats?from=2026-05-28&to=2026-05-29" \
  -H "Cookie: ui_session=root_sess; ui_csrf=root_csrf; ui_access_token=root_jwt"
```

**Response (200):**
```json
{
  "stats": [
    {
      "date": "2026-05-28",
      "sent_count": 1200,
      "success_count": 1180,
      "failed_count": 8,
      "expired_count": 12
    },
    {
      "date": "2026-05-29",
      "sent_count": 1523,
      "success_count": 1489,
      "failed_count": 12,
      "expired_count": 22
    }
  ],
  "total_devices": 342
}
```

---

## 7. Error Handling Matrix

| Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---------------|-------------|------------|---------------------|-----------------|
| Invalid subscription JSON (missing endpoint) | 422 | `validation_error` | "Push subscription is invalid. Please re-enable push notifications." | Unsubscribe and re-subscribe via pushSetup.ts |
| Invalid subscription JSON (missing keys) | 422 | `validation_error` | "Push subscription keys missing. Please re-enable push." | Re-register service worker |
| Token is not JSON and platform is web | 422 | `validation_error` | "Invalid web push subscription format." | Re-subscribe |
| Platform not in (web, android, ios) | 422 | `validation_error` | "Unsupported platform." | None (client bug) |
| CSRF token missing on POST | 403 | `csrf_error` | "Session expired. Please refresh the page." | Reload page |
| Unauthenticated request | 401 | `auth_required` | "Please log in to manage push notifications." | Redirect to /login |
| Push not enabled globally (S.push_enabled=false) | 503 | `push_disabled` | "Push notifications are temporarily unavailable." | Wait for admin to enable |
| VAPID keys not configured | 503 | `push_not_configured` | "Push notifications are not configured." | Admin sets VAPID keys |
| Device registration rate limit exceeded | 429 | `rate_limited` | "Too many registrations. Please try again later." | Wait and retry |
| Test push rate limit exceeded | 429 | `rate_limited` | "Too many test pushes. Wait a few minutes." | Wait 5 minutes |
| Push delivery failed (410 Gone) | -- | `subscription_expired` | (no user message; device auto-revoked) | Device removed; re-subscribe on next visit |
| Push delivery failed (404 Not Found) | -- | `subscription_invalid` | (no user message; device auto-revoked) | Device removed; re-subscribe |
| Push delivery failed (network error) | -- | `delivery_failed` | (no user message; logged for admin) | Retry on next alert |
| Admin stats - non-admin user | 403 | `forbidden` | "Admin access required." | None |
| Preference update with invalid category name | 422 | `validation_error` | "Unknown push category." | Fix request body |

---

## 8. Pydantic Models

```python
# -- Push Preferences (PLATFORM-016) --

from typing import Dict, List, Optional
from pydantic import BaseModel, Field, validator
import json


class PushCategoryPrefs(BaseModel):
    """Per-category push notification opt-in/opt-out preferences."""
    messages: bool = True
    tips: bool = True
    subscriptions: bool = True
    broadcasts: bool = True
    content: bool = True
    security: bool = True
    billing: bool = True

    class Config:
        json_schema_extra = {
            "example": {
                "messages": True,
                "tips": False,
                "subscriptions": True,
                "broadcasts": True,
                "content": False,
                "security": True,
                "billing": True,
            }
        }


class PushPrefsOut(BaseModel):
    """Response model for GET /ui/push/preferences."""
    push_enabled: bool = True
    categories: PushCategoryPrefs = Field(default_factory=PushCategoryPrefs)


class PushPrefsUpdateIn(BaseModel):
    """Request model for PUT /ui/push/preferences.
    
    Only provided fields are updated; omitted categories retain their current value.
    """
    push_enabled: Optional[bool] = None
    categories: Optional[PushCategoryPrefs] = None


class PushRegisterReq(BaseModel):
    """Request model for POST /ui/push/register.
    
    For web platform, token must be a JSON-encoded PushSubscription object
    containing 'endpoint' and 'keys' with 'p256dh' and 'auth' sub-fields.
    For android/ios, token is an opaque FCM/APNs registration token.
    """
    token: str = Field(..., min_length=1, max_length=4096)
    platform: str = Field(..., pattern="^(web|android|ios)$")

    @validator("token")
    def validate_token(cls, v, values):
        if values.get("platform") == "web":
            try:
                sub = json.loads(v)
                assert "endpoint" in sub, "Missing 'endpoint'"
                assert "keys" in sub, "Missing 'keys'"
                assert "p256dh" in sub["keys"], "Missing 'keys.p256dh'"
                assert "auth" in sub["keys"], "Missing 'keys.auth'"
                assert sub["endpoint"].startswith("https://"), "Endpoint must be HTTPS"
            except json.JSONDecodeError:
                raise ValueError("Web push subscription must be valid JSON")
            except (AssertionError, KeyError) as e:
                raise ValueError(f"Web push subscription invalid: {e}")
        return v


class PushRegisterOut(BaseModel):
    """Response model for POST /ui/push/register."""
    ok: bool = True
    device_id: str


class PushDeviceOut(BaseModel):
    """Single push device in the device list response."""
    device_id: str
    platform: str
    created_at: int = 0
    last_seen_at: int = 0


class PushDevicesListOut(BaseModel):
    """Response model for GET /ui/push/devices."""
    devices: List[PushDeviceOut] = Field(default_factory=list)


class PushTestOut(BaseModel):
    """Response model for POST /ui/push/test."""
    ok: bool = True
    devices_sent: int = 0
    dev_mode: bool = False
    payload_preview: Optional[Dict] = None


class PushStatsOut(BaseModel):
    """Single day of push delivery statistics."""
    date: str
    sent_count: int = 0
    success_count: int = 0
    failed_count: int = 0
    expired_count: int = 0


class PushAdminStatsOut(BaseModel):
    """Response model for GET /ui/admin/push/stats."""
    stats: List[PushStatsOut] = Field(default_factory=list)
    total_devices: int = 0
```

---

## 9. Frontend Component Tree

```
PushDevices (pages/alerts/PushDevices.tsx)
├── PageHeader
│   ├── title: "Push Notifications"
│   └── description: "Manage browser push notification settings"
├── Card: "Enable Push Notifications"
│   ├── Switch: pushEnabled (global toggle)
│   │   └── useMutation → PUT /ui/push/preferences { push_enabled }
│   └── Button: "Enable Push" (if no SW subscription)
│       └── onClick → subscribeToPush() → POST /ui/push/register
├── Card: "Registered Devices"
│   ├── useQuery(["push", "devices"]) → GET /ui/push/devices
│   └── DeviceList
│       └── For each device:
│           ├── Platform badge ("web" | "android" | "ios")
│           ├── Created date (formatDate(created_at))
│           ├── Last seen date
│           └── Button: "Revoke"
│               └── useMutation → POST /ui/push/revoke { device_id }
│                   └── onSuccess: invalidateQueries(["push", "devices"])
├── Card: "Notification Categories" (NEW)
│   ├── useQuery(["push", "preferences"]) → GET /ui/push/preferences
│   └── CategoryToggles
│       ├── Switch: "Messages" (categories.messages)
│       ├── Switch: "Tips" (categories.tips)
│       ├── Switch: "Subscriptions" (categories.subscriptions)
│       ├── Switch: "Broadcasts" (categories.broadcasts)
│       ├── Switch: "Content" (categories.content)
│       ├── Switch: "Security" (categories.security)
│       └── Switch: "Billing" (categories.billing)
│       └── Each Switch → useMutation → PUT /ui/push/preferences
│           └── onSuccess: invalidateQueries(["push", "preferences"])
└── Card: "Test Push"
    └── Button: "Send Test Notification"
        └── useMutation → POST /ui/push/test
            └── onSuccess: toast("Test push sent!")

Props Interfaces:
  DeviceList: { devices: PushDeviceOut[]; onRevoke: (deviceId: string) => void }
  CategoryToggles: { prefs: PushCategoryPrefs; onUpdate: (category: string, enabled: boolean) => void }
```

---

## 10. Subscription JSON Validation

**Modify `app/routers/push.py`**:

Update `PushRegisterReq` to accept either a plain FCM token string OR a Web Push subscription JSON object:

```python
class PushRegisterReq(BaseModel):
    token: str = Field(..., min_length=1, max_length=4096)
    platform: str = Field(..., pattern="^(web|android|ios)$")

    @validator("token")
    def validate_token(cls, v, values):
        if values.get("platform") == "web":
            try:
                sub = json.loads(v)
                assert "endpoint" in sub
                assert "keys" in sub
                assert "p256dh" in sub["keys"]
                assert "auth" in sub["keys"]
            except (json.JSONDecodeError, AssertionError, KeyError):
                raise ValueError("Web push subscription must be valid JSON with endpoint and keys")
        return v
```

### 10.1 VAPID Key Generation Script

**New file**: `scripts/generate_vapid_keys.py` (~30 lines)

Generates ECDSA P-256 key pair in base64url format and prints `.env.local` entries:

```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import base64

key = ec.generate_private_key(ec.SECP256R1())
private_bytes = key.private_numbers().private_value.to_bytes(32, "big")
public_bytes = key.public_key().public_bytes(
    serialization.Encoding.X962,
    serialization.PublicFormat.UncompressedPoint,
)
print(f"VAPID_PRIVATE_KEY={base64.urlsafe_b64encode(private_bytes).decode().rstrip('=')}")
print(f"VAPID_PUBLIC_KEY={base64.urlsafe_b64encode(public_bytes).decode().rstrip('=')}")
```

---

## 11. Backend Router Enhancements

**Modify `app/routers/push.py`**:

| Method | Path | Auth | Description | Status |
|--------|------|------|-------------|--------|
| `GET` | `/ui/push/vapid-key` | None | Return VAPID public key | Exists |
| `GET` | `/ui/push/devices` | `require_ui_session` | List user's push devices | Exists |
| `POST` | `/ui/push/register` | `require_ui_session` | Register push subscription (with JSON validation) | Modify |
| `POST` | `/ui/push/revoke` | `require_ui_session` | Revoke push device | Exists |
| `POST` | `/ui/push/test` | `require_ui_session` | Send test push notification | Exists |
| `GET` | `/ui/push/preferences` | `require_ui_session` | Get push category preferences | **New** |
| `PUT` | `/ui/push/preferences` | `require_ui_session` | Update push category preferences | **New** |
| `GET` | `/ui/admin/push/stats` | `require_admin_session` | Get push delivery stats | **New** |

---

## 12. Push Event Mapping

### 12.1 Event-to-Push Mapping

| Platform Event | Push Category | Push Title | Push Body | Click URL |
|----------------|---------------|------------|-----------|-----------|
| `messaging.new_message` | messages | "New message from {sender}" | Message preview (first 100 chars) | `/messages/{conversation_id}` |
| `billing.tip_received` | tips | "Tip received!" | "{sender} tipped you ${amount}" | `/billing` |
| `post_tip` | tips | "Post tip received!" | "{sender} tipped your post ${amount}" | `/feed/{post_id}` |
| `subscription_started` | subscriptions | "New subscriber!" | "{user} subscribed to your plan" | `/billing` |
| `broadcast.started` | broadcasts | "{creator} is live!" | "Tune in now" | `/broadcasts/{broadcast_id}` |
| `content.unlocked` | content | "Content unlocked!" | "{user} unlocked your content" | `/billing` |
| `security_event` | security | "Security alert" | Event description | `/alerts` |
| `payment_received` | billing | "Payment received" | "${amount} received" | `/billing` |

### 12.2 Notification Behavior

- **Tag deduplication**: Messages from the same conversation share a tag (`msg_{conversation_id}`) so newer notifications replace older ones.
- **requireInteraction**: Set to `true` for message notifications (stay visible until dismissed).
- **Badge**: Platform icon shown on mobile browsers.
- **Vibration pattern**: `[200, 100, 200]` for messages; `[100]` for other events.

---

## 13. Observability & Monitoring

### 13.1 Metrics to Track

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `push_sent_total` | Counter | `category`, `platform`, `outcome` | Total push notifications sent |
| `push_delivery_latency_ms` | Histogram | `category`, `platform` | Time from alert write to push service response |
| `push_subscription_registrations` | Counter | `platform` | New device registrations |
| `push_subscription_revocations` | Counter | `reason` (expired/user/cleanup) | Device revocations |
| `push_category_opt_out` | Gauge | `category` | Number of users with category disabled |
| `push_active_devices` | Gauge | `platform` | Total active push devices |

### 13.2 Log Events

| Event | Level | Fields | Trigger |
|-------|-------|--------|---------|
| `push.send.success` | INFO | user_sub, device_id, alert_type, category | Successful push delivery |
| `push.send.failed` | WARN | user_sub, device_id, alert_type, status_code, error | Push service returned error |
| `push.send.expired` | INFO | user_sub, device_id | 410 Gone received; device auto-revoked |
| `push.register.success` | INFO | user_sub, platform, device_id | New device registered |
| `push.register.invalid` | WARN | user_sub, platform, error | Invalid subscription JSON |
| `push.category.opted_out` | INFO | user_sub, alert_type, category | Push skipped due to category preference |
| `push.stats.recorded` | DEBUG | date, sent, success, failed, expired | Daily stats row updated |

### 13.3 Alert Thresholds

| Condition | Threshold | Alert | Severity |
|-----------|-----------|-------|----------|
| Push failure rate > 10% in 1 hour | `failed / sent > 0.10` | Slack + PagerDuty | Warning |
| Push failure rate > 25% in 30 min | `failed / sent > 0.25` | PagerDuty | Critical |
| Expired subscriptions > 50 in 1 hour | `expired_count > 50` | Slack | Info |
| Zero pushes sent in 4 hours (during business hours) | `sent_count == 0` | Slack | Warning |
| VAPID key not configured | At startup | Startup log | Critical |

### 13.4 Dashboard Queries

**Admin stats endpoint** (`GET /ui/admin/push/stats`):
- Input: `?from=YYYY-MM-DD&to=YYYY-MM-DD`
- Query: `T.push_stats` table, `pk=GLOBAL`, SK range `DAILY#{from}` to `DAILY#{to}`
- Returns: time series of daily stats + total_devices count from `T.push_devices` scan

---

## 14. Rollout Plan

### 14.1 Feature Flag Strategy

| Flag | Location | Default | Purpose |
|------|----------|---------|---------|
| `S.push_enabled` | `app/core/settings.py` | `True` | Master kill switch for all push delivery |
| `S.web_push_enabled` | `app/core/settings.py` | `True` | Web push specifically (vs FCM native) |
| `VITE_PUSH_ENABLED` | `frontend/.env.local` | `true` | Frontend: show/hide push UI components |

### 14.2 Migration Steps

1. **Deploy backend** with new endpoints, stats table, and scheduler preferences. Push delivery is gated by `S.push_enabled` (already exists, default True).
2. **Deploy `sw.js`** to CDN/public directory. Service workers auto-install on next page load.
3. **Deploy frontend** with updated PushDevices.tsx category toggles. Existing push subscribers continue working; new UI lets them opt out of categories.
4. **Run VAPID key generation** if not already configured. Add keys to environment.
5. **Verify** via admin stats endpoint that pushes are being sent and delivered.

### 14.3 Canary Deployment

- **Stage 1**: Enable for internal team accounts only (`user_sub in CANARY_USERS`).
- **Stage 2**: Enable for 10% of users via consistent hashing on `user_sub`.
- **Stage 3**: Enable for 50% of users.
- **Stage 4**: Full rollout (100%).

Canary gating is applied in `send_push_for_alert()` before dispatch:
```python
if S.push_canary_pct < 100:
    if hash(user_sub) % 100 >= S.push_canary_pct:
        return  # Not in canary group
```

### 14.4 Rollback Procedure

1. Set `PUSH_ENABLED=0` in environment to immediately stop all push delivery.
2. Frontend continues to show the UI but pushes are silently dropped.
3. Service worker remains installed but receives no push events.
4. To fully rollback the SW: update `sw.js` to a no-op that unregisters itself:
   ```javascript
   self.addEventListener("install", () => self.skipWaiting());
   self.addEventListener("activate", () => self.registration.unregister());
   ```

---

## 15. Performance Considerations

### 15.1 Query Costs

| Operation | DDB Cost (RCU/WCU) | Frequency | Notes |
|-----------|---------------------|-----------|-------|
| Get user devices | 1 RCU (eventually consistent) | Per alert dispatch | Usually 1-3 devices |
| Get alert prefs | 1 RCU | Per alert dispatch | Single item read |
| Push stat increment | 1 WCU | Per push sent | Atomic ADD on counter |
| Register device | 1 WCU | On first visit/re-subscribe | Rare (once per browser) |
| Revoke device | 1 WCU | On 410/404 or user action | Rare |

### 15.2 Caching Strategy

- **VAPID public key**: Cached in frontend memory (fetched once on app load, never changes during session).
- **Alert preferences**: Cached in-process for 60 seconds per user_sub using `functools.lru_cache` with TTL wrapper. Avoids DDB read on every alert.
- **Push stats write batching**: Stats are buffered in-memory and flushed to DDB every 10 seconds (not per push). This reduces WCU by ~90% under high volume.

### 15.3 Pagination Limits

- Device list: No pagination needed (max ~10 devices per user).
- Admin stats: Limited to 90-day range to prevent unbounded queries.

### 15.4 Rate Limiting

| Endpoint | Limit | Window | Key |
|----------|-------|--------|-----|
| POST /ui/push/register | 10 | 1 hour | user_sub |
| POST /ui/push/test | 5 | 1 hour | user_sub |
| PUT /ui/push/preferences | 20 | 1 hour | user_sub |
| GET /ui/admin/push/stats | 30 | 1 minute | admin_sub |

---

## 16. Frontend Components

**Modified files**:

| File | Change | Estimated Lines Changed |
|------|--------|------------------------|
| `frontend/public/sw.js` | New service worker file | ~80 |
| `frontend/src/lib/pushSetup.ts` | Validate SW registration; pass subscription JSON to register endpoint | ~20 |
| `frontend/src/pages/alerts/PushDevices.tsx` | Add category preference toggles below device list | ~80 |
| `frontend/src/api/endpoints/push.ts` | Add `getPushPrefs()`, `updatePushPrefs()` wrappers | ~20 |
| `frontend/src/api/types.ts` | Add `PushCategoryPrefs`, `PushPrefsOut` interfaces | ~15 |

### 16.1 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/public/sw.js` | Service worker for push events | ~80 |
| `scripts/generate_vapid_keys.py` | VAPID key pair generator | ~30 |
| `frontend/e2e/push-delivery.spec.ts` | E2E tests | ~450 |

### 16.2 Files to Modify

| File | Change |
|------|--------|
| `app/services/push.py` | Add category check in `send_push_for_alert`; add stale subscription cleanup; add stats recording |
| `app/services/alerts.py` | Extend `get_alert_prefs`/`set_alert_prefs` with `push_categories` map |
| `app/routers/push.py` | Add preference endpoints; add admin stats endpoint; validate subscription JSON |
| `app/models.py` | Add `PushCategoryPrefs`, `PushPrefsOut`, `PushPrefsUpdateIn`, `PushStatsOut`, `PushAdminStatsOut` |
| `app/core/settings.py` | Add `push_stats_table_name` setting |
| `app/core/tables.py` | Add `T.push_stats` handle |
| `scripts/local-ddb-init.py` | Add `push_stats` TableDef |
| `frontend/src/lib/pushSetup.ts` | Pass full subscription JSON; handle SW update flow |
| `frontend/src/pages/alerts/PushDevices.tsx` | Add category preference toggles |
| `frontend/src/api/endpoints/push.ts` | Add preference API wrappers |
| `frontend/src/api/types.ts` | Add push preference TypeScript types |

---

## 17. E2E Test Plan

**File**: `frontend/e2e/push-delivery.spec.ts`

> Note: Playwright cannot intercept real Web Push (no push service in test). Tests verify the API layer, preference persistence, device registration/revocation, and service worker registration. Push payload shape is tested via the `/push/test` endpoint response in dev mode.

### Section 523: Push Device Registration API (6 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 523.1 | Register a web push device with valid subscription JSON | POST `/ui/push/register` with `platform=web`, `token=<valid subscription JSON>`; 200; device appears in GET `/ui/push/devices` |
| 523.2 | Register with invalid subscription JSON returns 422 | POST with `token=not-json`; 422 response |
| 523.3 | Register with missing keys in subscription returns 422 | POST with `token={"endpoint":"https://x.com"}` (no keys); 422 |
| 523.4 | List push devices returns registered device | GET `/ui/push/devices`; response includes device with `platform=web`, `device_id` is SHA256 prefix |
| 523.5 | Revoke push device removes it | POST `/ui/push/revoke` with `device_id`; 200; GET devices no longer includes it |
| 523.6 | Re-register same subscription is idempotent | POST same subscription twice; GET devices returns exactly 1 device with that device_id |

### Section 524: Push Category Preferences API (6 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 524.1 | Get default push preferences returns all enabled | GET `/ui/push/preferences`; all 7 categories are `true` |
| 524.2 | Disable tips push category | PUT `/ui/push/preferences` with `categories.tips=false`; 200; GET confirms `tips=false`, others unchanged |
| 524.3 | Disable all categories | PUT with all categories `false`; GET confirms all `false` |
| 524.4 | Re-enable messages category | PUT with `categories.messages=true`; GET confirms `messages=true`, others still `false` |
| 524.5 | Disable global push_enabled | PUT with `push_enabled=false`; GET confirms `push_enabled=false` |
| 524.6 | Partial update preserves unmentioned categories | Disable tips only; then PUT with `categories.security=false`; GET shows tips still false, security now false, others unchanged |

### Section 525: Push Test Delivery API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 525.1 | Send test push returns success in dev mode | Register device; POST `/ui/push/test`; 200; response `{ ok: true }` |
| 525.2 | VAPID public key endpoint returns key | GET `/ui/push/vapid-key`; 200; response has `vapid_key` string starting with valid base64url chars |
| 525.3 | Test push without registered device returns zero deliveries | Revoke all devices; POST `/ui/push/test`; 200; response `{ ok: true, devices_sent: 0 }` |
| 525.4 | Test push payload preview includes expected fields | POST `/ui/push/test` in dev mode; response has `payload_preview` with `title`, `body`, `url`, `tag`, `alert_type` |

### Section 526: Push Devices UI (6 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 526.1 | Push Devices page renders category preference toggles | Navigate to alerts/push-devices; 7 toggle switches visible with labels: Messages, Tips, Subscriptions, Broadcasts, Content, Security, Billing |
| 526.2 | Toggling a category off saves preference | Click "Tips" toggle off; reload page; "Tips" toggle is still off |
| 526.3 | Device list shows registered device | Register device via API; navigate to page; device entry shows platform badge "web" |
| 526.4 | Revoke device via UI removes it from list | Click "Revoke" on device; confirm dialog; device disappears from list |
| 526.5 | Global push toggle disables all category toggles visually | Turn off global push; all category toggles appear disabled/grayed |
| 526.6 | Test push button shows success toast | Click "Send Test Notification"; toast message appears confirming send |

### Section 527: Push Admin Stats API (3 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 527.1 | Admin can retrieve push delivery stats | Root GET `/ui/admin/push/stats?from=2026-05-28&to=2026-05-29`; 200; response has `stats` array and `total_devices` |
| 527.2 | Non-admin cannot access push stats | Alice GET `/ui/admin/push/stats`; 403 |
| 527.3 | Stats with no data returns empty array | GET for a date range with no pushes; response `{ stats: [], total_devices: 0 }` |

### Section 528: Edge Cases and Concurrent Access (3 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 528.1 | Registering 11th device in 1 hour is rate-limited | Register 10 devices rapidly; 11th returns 429 |
| 528.2 | Concurrent preference updates do not corrupt state | Two PUT requests simultaneously changing different categories; final GET shows both changes applied |
| 528.3 | Revoking non-existent device returns 404 or 200 (idempotent) | POST revoke with fake device_id; 200 (no-op) or 404 |

**Total E2E tests: 28**

---

## 18. Security Considerations

### 18.1 VAPID Key Security

- Private key stored in `.env.local` (gitignored); never exposed to frontend.
- Public key served via unauthenticated `/ui/push/vapid-key` endpoint (required by Push API spec).
- Key rotation: generate new pair, update `.env.local`, restart backend. Existing subscriptions become invalid; users re-subscribe on next visit.

### 18.2 Subscription Privacy

- Push subscription endpoint URLs contain opaque tokens issued by browser vendors (Google FCM, Mozilla autopush). They are stored in DDB encrypted at rest.
- Subscription JSON is never returned to the frontend after registration (only `device_id` is returned).

### 18.3 Notification Content

- Push payloads are encrypted end-to-end by the Web Push protocol (RFC 8291 ECDH + HKDF + AES-128-GCM).
- Notification bodies are truncated to 180 characters to prevent PII leakage in lockscreen previews.
- Encrypted messages show "New encrypted message" instead of plaintext.

### 18.4 Rate Limiting

- Device registration: max 10 per user per hour.
- Test push: max 5 per user per hour.
- Preference update: max 20 per user per hour.
- All endpoints inherit global rate limiter.

### 18.5 Stale Subscription Handling

- 410 Gone responses from push services trigger automatic `revoke_push_device()`.
- 404 Not Found responses are treated as permanent failures; device is revoked.
- Devices with no successful push in 30 days are candidates for TTL expiry (existing 180-day TTL on `push_devices` table).

---

## 19. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| `app/services/push.py` | Exists | Core push delivery; modify for category checks and cleanup |
| `app/routers/push.py` | Exists | Push API; modify for preferences and stats endpoints |
| `app/services/alerts.py` | Exists | Alert preferences; extend with push categories |
| `pywebpush` library | Exists in requirements | VAPID signing and push encryption |
| `T.push_devices` table | Exists | Device storage |
| `T.alert_prefs` (alerts table) | Exists | Preference storage |
| `scripts/local-ddb-init.py` | Exists (modify) | Add push_stats table |
| `app/core/settings.py` | Exists (modify) | Add push_stats_table_name |

---

## 20. Acceptance Criteria

1. Service worker file exists at `public/sw.js` and handles push + notificationclick events.
2. Service worker registers successfully on app load.
3. Push subscription JSON is validated on registration (endpoint, keys.p256dh, keys.auth required).
4. Per-category push preferences are stored and respected during delivery.
5. Stale subscriptions (410 Gone) are automatically revoked.
6. VAPID key generation script produces valid key pairs.
7. Push delivery stats are recorded in DDB for admin monitoring.
8. Dev mode push logs payload instead of delivering (existing behavior preserved).
9. All 28 E2E tests pass.
10. Category toggles render and persist on the PushDevices UI page.
