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

## 2. Current State Analysis

### 2.1 Existing Infrastructure

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

### 2.2 Gaps

1. **No service worker file** -- `registerServiceWorker()` in `pushSetup.ts` calls `navigator.serviceWorker.register("/sw.js")` but `public/sw.js` does not exist. No push event listener, no notification display logic, no click handler.
2. **No push category preferences** -- `get_alert_prefs()` / `set_alert_prefs()` support channel toggles (`email_enabled`, `sms_enabled`) but have no per-event-type push opt-in/opt-out. `send_push_for_alert()` checks `push_enabled` globally but not per category.
3. **No subscription validation** -- `upsert_push_device()` stores the raw token string; for web push, the full subscription JSON (endpoint + keys.p256dh + keys.auth) is needed. The `PushRegisterReq` model accepts a `token` string but does not validate it as valid subscription JSON.
4. **No VAPID key auto-generation** -- VAPID keys must be manually set in `.env.local`. No setup script generates them; no guidance in `.env.local.example`.
5. **No stale subscription cleanup** -- `web_push_send()` returns `False` on 410 Gone but `send_push_for_alert()` does not call `revoke_push_device()` on failure.
6. **No push delivery stats** -- no counter or log of push attempts, successes, failures, or expirations.
7. **Dev mode push testing gap** -- `web_push_send()` logs in dev mode but returns `True` unconditionally; no way to verify the payload shape in E2E tests.

---

## 3. Technical Design

### 3.1 Service Worker File

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

### 3.2 Push Category Preferences

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

### 3.3 Push Delivery Pipeline Enhancement

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

### 3.4 DynamoDB Schema Changes

#### 3.4.1 Push Preferences (stored in existing alerts_prefs)

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

#### 3.4.2 Push Stats Table

**Table name**: `push_stats` (new table)
**PK**: `pk` (S), **SK**: `sk` (S)

| PK Pattern | SK Pattern | Purpose | Key Fields |
|------------|------------|---------|------------|
| `GLOBAL` | `DAILY#{date}` | Daily aggregate stats | `sent_count`, `success_count`, `failed_count`, `expired_count` |
| `USER#{user_sub}` | `DAILY#{date}` | Per-user daily stats | `sent_count`, `success_count` |

#### 3.4.3 TableDef Entry

```python
TableDef(
    "push_stats", "pk", "sk",
),
```

### 3.5 Subscription JSON Validation

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

### 3.6 VAPID Key Generation Script

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

### 3.7 Backend Router Enhancements

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

### 3.8 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Push Preferences (PLATFORM-016) --

class PushCategoryPrefs(BaseModel):
    messages: bool = True
    tips: bool = True
    subscriptions: bool = True
    broadcasts: bool = True
    content: bool = True
    security: bool = True
    billing: bool = True

class PushPrefsOut(BaseModel):
    push_enabled: bool = True
    categories: PushCategoryPrefs = Field(default_factory=PushCategoryPrefs)

class PushPrefsUpdateIn(BaseModel):
    push_enabled: Optional[bool] = None
    categories: Optional[PushCategoryPrefs] = None

class PushStatsOut(BaseModel):
    date: str
    sent_count: int = 0
    success_count: int = 0
    failed_count: int = 0
    expired_count: int = 0

class PushAdminStatsOut(BaseModel):
    stats: List[PushStatsOut] = Field(default_factory=list)
    total_devices: int = 0
```

### 3.9 Frontend Components

**Modified files**:

| File | Change | Estimated Lines Changed |
|------|--------|------------------------|
| `frontend/public/sw.js` | New service worker file | ~80 |
| `frontend/src/lib/pushSetup.ts` | Validate SW registration; pass subscription JSON to register endpoint | ~20 |
| `frontend/src/pages/alerts/PushDevices.tsx` | Add category preference toggles below device list | ~80 |
| `frontend/src/api/endpoints/push.ts` | Add `getPushPrefs()`, `updatePushPrefs()` wrappers | ~20 |
| `frontend/src/api/types.ts` | Add `PushCategoryPrefs`, `PushPrefsOut` interfaces | ~15 |

**PushDevices.tsx component tree** (updated):

```
PushDevices
├── "Enable Push Notifications" button (if no subscription)
├── Device list (existing)
│   └── For each device: platform badge, created_at, Revoke button
├── Push Category Preferences (NEW)
│   ├── "Messages" toggle
│   ├── "Tips" toggle
│   ├── "Subscriptions" toggle
│   ├── "Broadcasts" toggle
│   ├── "Content" toggle
│   ├── "Security" toggle
│   └── "Billing" toggle
└── "Send Test Notification" button (existing)
```

### 3.10 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/public/sw.js` | Service worker for push events | ~80 |
| `scripts/generate_vapid_keys.py` | VAPID key pair generator | ~30 |
| `frontend/e2e/push-delivery.spec.ts` | E2E tests | ~450 |

### 3.11 Files to Modify

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

## 4. Push Event Mapping

### 4.1 Event-to-Push Mapping

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

### 4.2 Notification Behavior

- **Tag deduplication**: Messages from the same conversation share a tag (`msg_{conversation_id}`) so newer notifications replace older ones.
- **requireInteraction**: Set to `true` for message notifications (stay visible until dismissed).
- **Badge**: Platform icon shown on mobile browsers.
- **Vibration pattern**: `[200, 100, 200]` for messages; `[100]` for other events.

---

## 5. E2E Test Plan

**File**: `frontend/e2e/push-delivery.spec.ts`

> Note: Playwright cannot intercept real Web Push (no push service in test). Tests verify the API layer, preference persistence, device registration/revocation, and service worker registration. Push payload shape is tested via the `/push/test` endpoint response in dev mode.

### Section 523: Push Device Registration API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 523.1 | Register a web push device with valid subscription JSON | POST `/ui/push/register` with `platform=web`, `token=<valid subscription JSON>`; 200; device appears in GET `/ui/push/devices` |
| 523.2 | Register with invalid subscription JSON returns 422 | POST with `token=not-json`; 422 response |
| 523.3 | List push devices returns registered device | GET `/ui/push/devices`; response includes device with `platform=web`, `device_id` is SHA256 prefix |
| 523.4 | Revoke push device removes it | POST `/ui/push/revoke` with `device_id`; 200; GET devices no longer includes it |

### Section 524: Push Category Preferences API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 524.1 | Get default push preferences returns all enabled | GET `/ui/push/preferences`; all 7 categories are `true` |
| 524.2 | Disable tips push category | PUT `/ui/push/preferences` with `categories.tips=false`; 200; GET confirms `tips=false`, others unchanged |
| 524.3 | Disable all categories | PUT with all categories `false`; GET confirms all `false` |
| 524.4 | Re-enable messages category | PUT with `categories.messages=true`; GET confirms `messages=true`, others still `false` |

### Section 525: Push Test Delivery API (3 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 525.1 | Send test push returns success in dev mode | Register device; POST `/ui/push/test`; 200; response `{ ok: true }` |
| 525.2 | VAPID public key endpoint returns key | GET `/ui/push/vapid-key`; 200; response has `vapid_key` string starting with valid base64url chars |
| 525.3 | Test push without registered device returns success with zero deliveries | Revoke all devices; POST `/ui/push/test`; 200; response `{ ok: true, devices_sent: 0 }` |

### Section 526: Push Devices UI (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 526.1 | Push Devices page renders category preference toggles | Navigate to alerts/push-devices; 7 toggle switches visible with labels: Messages, Tips, Subscriptions, Broadcasts, Content, Security, Billing |
| 526.2 | Toggling a category off saves preference | Click "Tips" toggle off; reload page; "Tips" toggle is still off |
| 526.3 | Device list shows registered device | Register device via API; navigate to page; device entry shows platform badge "web" |
| 526.4 | Revoke device via UI removes it from list | Click "Revoke" on device; confirm dialog; device disappears from list |

**Total E2E tests: 15**

---

## 6. Security Considerations

### 6.1 VAPID Key Security

- Private key stored in `.env.local` (gitignored); never exposed to frontend.
- Public key served via unauthenticated `/ui/push/vapid-key` endpoint (required by Push API spec).
- Key rotation: generate new pair, update `.env.local`, restart backend. Existing subscriptions become invalid; users re-subscribe on next visit.

### 6.2 Subscription Privacy

- Push subscription endpoint URLs contain opaque tokens issued by browser vendors (Google FCM, Mozilla autopush). They are stored in DDB encrypted at rest.
- Subscription JSON is never returned to the frontend after registration (only `device_id` is returned).

### 6.3 Notification Content

- Push payloads are encrypted end-to-end by the Web Push protocol (RFC 8291 ECDH + HKDF + AES-128-GCM).
- Notification bodies are truncated to 180 characters to prevent PII leakage in lockscreen previews.
- Encrypted messages show "New encrypted message" instead of plaintext.

### 6.4 Rate Limiting

- Device registration: max 10 per user per hour.
- Test push: max 5 per user per hour.
- Preference update: max 20 per user per hour.
- All endpoints inherit global rate limiter.

### 6.5 Stale Subscription Handling

- 410 Gone responses from push services trigger automatic `revoke_push_device()`.
- 404 Not Found responses are treated as permanent failures; device is revoked.
- Devices with no successful push in 30 days are candidates for TTL expiry (existing 180-day TTL on `push_devices` table).

---

## 7. Dependencies

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

## 8. Acceptance Criteria

1. Service worker file exists at `public/sw.js` and handles push + notificationclick events.
2. Service worker registers successfully on app load.
3. Push subscription JSON is validated on registration (endpoint, keys.p256dh, keys.auth required).
4. Per-category push preferences are stored and respected during delivery.
5. Stale subscriptions (410 Gone) are automatically revoked.
6. VAPID key generation script produces valid key pairs.
7. Push delivery stats are recorded in DDB for admin monitoring.
8. Dev mode push logs payload instead of delivering (existing behavior preserved).
9. All 15 E2E tests pass.
10. Category toggles render and persist on the PushDevices UI page.
