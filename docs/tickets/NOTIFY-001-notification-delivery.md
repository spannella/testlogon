# NOTIFY-001: Notification Delivery Pipeline

**Status**: Proposed
**Author**: Engineering
**Date**: 2026-05-27
**Priority**: High
**Estimated effort**: 7-9 days

---

## 1. Executive Summary

The platform has all the building blocks for a notification system -- `write_alert()` persists alerts to DynamoDB, `sse_publish_alert()` pushes to in-process SSE subscribers, `send_alert_email()` can dispatch via SES or log to a file, and `send_push_for_alert()` integrates with FCM -- but none of these channels are actually connected to the user-facing experience.
<!-- CORRECTED: The channels ARE actually connected. write_alert() at alerts.py:265 calls sse_publish_alert() at line 299, and the audit_event() function at line 492 already calls write_alert(), send_push_for_alert(), send_alert_email(), send_alert_sms(), send_alert_webhook(), send_siem_event(), and send_alert_webhook_fanout() — all gated by user preferences. The statement that "none of these channels are connected" is inaccurate — they are wired together in the audit_event() function. What is MISSING is the frontend integration (bell, SSE hook, toast). --> The notification bell in the frontend header is a static icon with no badge, no dropdown, and no real-time updates. The SSE stream endpoint at `/ui/alerts/stream` exists but the frontend never connects to it. Push tokens are never registered because there is no service worker or subscription flow.

This ticket wires everything together into a complete, end-to-end notification delivery pipeline. On the backend: a unified notification dispatcher that evaluates per-user channel preferences and routes each alert to the appropriate delivery channels (SSE, email, push), an atomic unread counter, and a VAPID-based push subscription registration flow. On the frontend: an SSE EventSource hook with auto-reconnect, a notification bell component with real-time unread badge and dropdown, toast popups for high-priority events, and a push service worker for background notifications.

The result is that every event the platform generates -- security alerts, social interactions (follows, tips, reactions), messaging notifications, billing events -- will actually reach the user through at least one channel, transforming the app from a passive pull experience to an active push experience.

---

## 2. Detailed Problem Analysis

### User Stories

| As a... | I want to... | So that... |
|---------|-------------|-----------|
| User | See a badge on the bell icon when I have unread notifications | I know something happened without checking every page |
| User | Click the bell to see my latest notifications without navigating away | I can quickly triage what needs attention |
| User | Receive a push notification when someone tips me | I know about revenue events even when the tab is closed |
| User | Receive an email when someone subscribes to my content | I stay informed about subscriber growth without being online |
| User | Configure which notifications I receive on which channels | I can reduce noise for low-priority events while keeping critical alerts |
| User | See a toast popup when a security event occurs (new device login) | I am immediately aware of potential account compromise |
| User | Mark all notifications as read | I can clear my badge and start fresh |
| Admin | Ensure notification delivery is best-effort | Failed email/push does not block the triggering action (message send, tip, etc.) |

### Pain Points

1. **Silent platform**: Users discover new followers, tips, and subscription events only by manually visiting specific pages. The "notification bell" is decorative.
2. **Security blind spot**: Login-from-new-device alerts are written to DDB but never surfaced. Users cannot detect account compromise.
3. **Email exists but is unused**: `send_alert_email()` works (logs to file in dev, sends via SES in prod) but no email templates exist for common events. All emails would be plain-text with raw event data.
4. **Push infrastructure is dead code**: `send_push_for_alert()` calls `fcm_send()` but the push token table is always empty because the frontend never registers tokens.
5. **SSE stream is orphaned**: The endpoint works and publishes events, but no frontend component connects to it.

### Competitive Analysis

| Platform | In-app bell | Push | Email | Preferences |
|----------|------------|------|-------|-------------|
| YouTube | Yes + dropdown | Yes (FCM) | Yes (digest) | Per-channel, per-creator |
| Instagram | Yes + dropdown | Yes | Yes | Per-type |
| Discord | Yes + badge | Yes | Yes (optional) | Per-server, per-channel |
| OnlyFans | Yes | Yes | Yes | Limited |
| This ticket | Yes + dropdown + toast | Yes (FCM, mocked in dev) | Yes (SES, mocked in dev) | Per-type, per-channel |

---

## 3. Technical Architecture

### System Diagram

```
                        Event Origin
                    (message, tip, follow, login, etc.)
                             |
                             v
                    write_alert(user_id, event_type, details)
                    [existing -- app/services/alerts.py]
                             |
                +------------+------------+
                |            |            |
                v            v            v
          DDB Write     SSE Publish    Notification
          (alerts tbl)  (in-process)   Dispatcher (NEW)
          [existing]    [existing]          |
                                    +------+------+------+
                                    |      |      |      |
                                    v      v      v      v
                                 Unread  Email   Push   Toast
                                 Counter  SES    FCM    Flag
                                 (DDB)  (mock)  (mock)
                                  [NEW]  [ext]   [ext]   [NEW]

Frontend:
+-------------------------------------------------------------------+
|                                                                   |
|   useNotificationStream() -----> EventSource(/ui/alerts/stream)   |
|        |         |                                                |
|        v         v                                                |
|   NotificationBell       NotificationToast                        |
|   (badge + dropdown)     (high-priority popup)                    |
|                                                                   |
|   Service Worker (sw.js) ----> Push subscription registration     |
|        |                                                          |
|        v                                                          |
|   Browser push notification (background)                          |
+-------------------------------------------------------------------+
```

### Data Flow: End-to-End Notification

1. **Event trigger**: A user tips Alice. The tip handler calls `write_alert("alice-uuid", "billing.tip_received", {from: "bob", amount: 500})`.
2. **Existing `write_alert()`**: Writes alert row to `T.alerts` (PK=alice-uuid, SK=alert_id). Calls `sse_publish_alert(alice-uuid, alert_data)`.
3. **NEW notification dispatcher** (called from `write_alert()`): 
   a. Reads Alice's notification preferences from `T.alert_prefs`.
   b. For `billing.tip_received`: email=true, push=true, toast=true (defaults).
   c. Atomically increments the UNREAD_COUNT sentinel row for Alice.
   d. Dispatches email via `send_alert_email()` with a templated HTML body.
   e. Dispatches push via `send_push_for_alert()` to all registered push subscriptions.
   f. Includes `toast_priority: "normal"` in the SSE event payload.
4. **Frontend SSE handler**: Alice's browser has an active EventSource connection. The `useNotificationStream` hook receives the SSE event.
   a. Updates the unread count badge on `NotificationBell`.
   b. Adds the notification to the dropdown list.
   c. If `toast_priority` is "normal" or "high", shows a `NotificationToast` popup.
5. **Background push**: If Alice's tab is closed but she has a registered service worker, the browser receives the FCM push and shows a system notification.

### Component Interactions

- **`app/services/notification_dispatcher.py`** (new): Imports `get_alert_prefs()`, `send_alert_email()`, `send_push_for_alert()`. Called at the end of `write_alert()`. Runs in a fire-and-forget asyncio task to avoid blocking the caller.
  <!-- CORRECTED: This dispatch logic ALREADY EXISTS in audit_event() at alerts.py:605-676. The function already reads prefs via get_alert_prefs(), checks email_event_types/sms_event_types/webhook_event_types/push_event_types, and dispatches to the appropriate channels. A separate notification_dispatcher.py may be cleaner but is not strictly necessary — extending audit_event() may suffice. -->
- **`app/services/notification_templates.py`** (new): Maps event types to email subject/body templates. Uses Python f-strings (not Jinja2 -- no new dependency). <!-- NOTE: render_ticket_email_template() at alerts.py:144-178 already provides templated emails for ticket events. This pattern can be extended. -->
- **`app/services/notification_unread.py`** (new): Atomic increment/decrement of the UNREAD_COUNT sentinel row in `T.alerts`. Uses DDB `UpdateExpression: SET #count = if_not_exists(#count, :zero) + :delta`. <!-- VERIFIED: T.alerts at tables.py:19/103, alerts table PK=user_sub, SK=alert_id (local-ddb-init.py:56) -->
- **`app/routers/alerts.py`** (extended): New endpoints for unread count, mark-all-read, push subscription, and notification preferences. <!-- NOTE: Existing alerts endpoints include GET/POST for alert list/read. The UnreadCountResponse model exists at models.py:2342-2344 and MarkAllReadResponse at models.py:2347-2349. -->
- **Frontend `useNotificationStream.ts`**: SSE EventSource with exponential backoff reconnect (1s, 2s, 4s, 8s, max 30s). Parses event data and dispatches to React Query cache updates.

---

## 4. Data Model Deep Dive

### Unread Count (existing `alerts` table)

No new table needed. A sentinel row is added to the existing `alerts` table (PK=`user_sub`, SK=`UNREAD_COUNT`).

```json
{
  "user_sub": "alice-uuid-1234",
  "alert_id": "UNREAD_COUNT",
  "count": 7,
  "updated_at": 1748361600
}
```

**Atomic increment DDB operation:**

```python
T.alerts.update_item(
    Key={"user_sub": user_id, "alert_id": "UNREAD_COUNT"},
    UpdateExpression="SET #c = if_not_exists(#c, :zero) + :delta, updated_at = :now",
    ExpressionAttributeNames={"#c": "count"},
    ExpressionAttributeValues={":delta": 1, ":zero": 0, ":now": now_ts()},
)
```

**Reset on mark-all-read:**

```python
T.alerts.update_item(
    Key={"user_sub": user_id, "alert_id": "UNREAD_COUNT"},
    UpdateExpression="SET #c = :zero, updated_at = :now",
    ExpressionAttributeNames={"#c": "count"},
    ExpressionAttributeValues={":zero": 0, ":now": now_ts()},
)
```

### Push Subscriptions (existing `push_devices` table)

The `push_devices` table already exists (PK=`user_sub`, SK=`device_id`). Browser push subscriptions use a different SK prefix to distinguish from mobile device tokens.

```json
{
  "user_sub": "alice-uuid-1234",
  "device_id": "WEB_PUSH#sub_abc123",
  "type": "web_push",
  "endpoint": "https://fcm.googleapis.com/fcm/send/abc123...",
  "keys_p256dh": "BL7...",
  "keys_auth": "A2...",
  "user_agent": "Mozilla/5.0 Chrome/120",
  "created_at": 1748350000
}
```

### Notification Preferences (existing `alert_prefs` table)

The `alert_prefs` table already exists (PK=`user_sub`). <!-- VERIFIED: alert_prefs at tables.py:20/104, settings.py:77, local-ddb-init.py:57, PK=user_sub (no SK) -->

<!-- CORRECTED: The existing alert_prefs schema is DIFFERENT from what this ticket proposes. The actual schema (per get_alert_prefs() at alerts.py:181-199) stores: emails (list), sms_numbers (list), email_event_types (list), sms_event_types (list), toast_event_types (list), push_event_types (list), webhook_urls (list), webhook_event_types (list). It does NOT use a nested per_type dict. The existing model uses flat lists of enabled event types per channel. The proposed nested per_type schema would require migrating or extending the existing format. -->

**Current actual schema:**
```json
{
  "user_sub": "alice-uuid-1234",
  "emails": ["alice@example.com"],
  "sms_numbers": ["+15551234567"],
  "email_event_types": ["login_success", "new_follower"],
  "sms_event_types": ["login_failure"],
  "toast_event_types": ["new_follower"],
  "push_event_types": ["new_follower", "post_tip"],
  "webhook_urls": ["https://example.com/hook"],
  "webhook_event_types": ["login_success"]
}
```

**Proposed extension** (per_type nested structure):
```json
{
  "user_sub": "alice-uuid-1234",
  "email_enabled": true,
  "push_enabled": true,
  "toast_enabled": true,
  "per_type": {
    "billing.tip_received": {"email": true, "push": true, "toast": true},
    "social.new_follower": {"email": true, "push": true, "toast": false},
    "security.new_device_login": {"email": true, "push": true, "toast": true},
    "messaging.new_message": {"email": false, "push": false, "toast": true}
  }
}
```

**Default behavior**: If a user has no preferences row, or a specific event type is not listed in `per_type`, all channels are enabled (opt-out model). <!-- NOTE: The current behavior (alerts.py:607-610) is opt-IN: alerts are only sent to channels where the event type is in the enabled list. This is the opposite of the proposed opt-out model. -->

### Access Patterns

| Pattern | Key | Index | Notes |
|---------|-----|-------|-------|
| Get unread count | PK=user_sub, SK=UNREAD_COUNT | alerts table | Single get_item |
| Increment unread | PK=user_sub, SK=UNREAD_COUNT | alerts table | Atomic update_item |
| Get push subscriptions | PK=user_sub, SK begins_with "WEB_PUSH#" | push_devices table | Query |
| Get notification prefs | PK=user_sub | alert_prefs table | Single get_item |
| List recent alerts | PK=user_sub, SK desc, Limit 10 | alerts table | Existing pattern for dropdown |

---

## 5. API Contract Design

### GET `/ui/alerts/unread-count`

**Response 200:**

```json
{
  "count": 7
}
```

### POST `/ui/alerts/mark-all-read`

**No request body.**

**Response 200:**

```json
{
  "ok": true,
  "count": 0
}
```

**Side effects**: Resets `UNREAD_COUNT` sentinel to 0. Does NOT update individual alert rows' `read` flag (that is handled by existing `PATCH /ui/alerts/{alert_id}/read`).

### GET `/ui/alerts/stream` (existing, enhanced)

**Enhanced SSE event format:**

```
event: alert
data: {"alert_id":"a_123","event":"billing.tip_received","title":"You received a $5.00 tip","details":{"from":"bob","amount_cents":500},"ts":1748361600,"toast_priority":"normal","unread_delta":1}

event: heartbeat
data: {"ts":1748361630}
```

New fields in alert event:
- `toast_priority`: `"high"` (security events), `"normal"` (social/billing), `"none"` (suppressed by prefs).
- `unread_delta`: `1` for a new unread alert, `0` if the channel was suppressed.

Heartbeat interval: every 30 seconds.

### GET `/ui/push/vapid-key`

**Response 200:**

```json
{
  "public_key": "BL7d3F5lKYFR..."
}
```

### POST `/ui/push/subscribe`

**Request body:**

```json
{
  "endpoint": "https://fcm.googleapis.com/fcm/send/abc123...",
  "keys_p256dh": "BL7...",
  "keys_auth": "A2..."
}
```

**Response 201:**

```json
{
  "ok": true,
  "subscription_id": "WEB_PUSH#sub_abc123"
}
```

### DELETE `/ui/push/subscribe`

**Query parameter:** `subscription_id`.

**Response 200:**

```json
{
  "ok": true
}
```

### GET `/ui/alerts/preferences`

**Response 200:**

```json
{
  "email_enabled": true,
  "push_enabled": true,
  "toast_enabled": true,
  "per_type": {
    "billing.tip_received": {"email": true, "push": true, "toast": true},
    "social.new_follower": {"email": true, "push": true, "toast": false},
    "security.new_device_login": {"email": true, "push": true, "toast": true},
    "messaging.new_message": {"email": false, "push": false, "toast": true}
  },
  "available_types": [
    {"type": "billing.tip_received", "label": "Tip received", "category": "Billing"},
    {"type": "social.new_follower", "label": "New follower", "category": "Social"},
    {"type": "security.new_device_login", "label": "Login from new device", "category": "Security"},
    {"type": "messaging.new_message", "label": "New message", "category": "Messaging"}
  ]
}
```

### PUT `/ui/alerts/preferences`

**Request body:**

```json
{
  "email_enabled": true,
  "push_enabled": true,
  "toast_enabled": true,
  "per_type": {
    "social.new_follower": {"email": false, "push": true, "toast": false}
  }
}
```

**Response 200:**

```json
{
  "ok": true
}
```

**Validation**: `per_type` keys must be from `ALERT_EVENT_TYPES` (existing constant in `alerts.py`). Unknown types are rejected with 400. <!-- VERIFIED: ALERT_EVENT_TYPES at alerts.py:46-57. Includes login/mfa/api_key/session/totp/device/calendar/ticket events and social events (new_follower, post_liked, etc.). The set_alert_prefs() function at line 243-248 already validates against this list. -->

---

## 6. Frontend Component Design

### Component Tree

```
<Header>
  <NotificationBell
    count={unreadCount}
    notifications={recentNotifications}
    onMarkAllRead={markAllReadMutation.mutate}
  >
    <NotificationDropdown>
      {notifications.map(n => (
        <NotificationItem
          key={n.alert_id}
          notification={n}
          onClick={() => navigate(n.link)}
        />
      ))}
      <Link to="/alerts">View all</Link>
    </NotificationDropdown>
  </NotificationBell>
</Header>

<AppShell>
  <NotificationToast notification={latestToast} />
  {/* Rendered via portal, top-right corner */}
</AppShell>
```

### State Management

- **`useNotificationStream` hook**: Manages the SSE EventSource lifecycle.
  - Connects to `/ui/alerts/stream` on mount (only when user is authenticated).
  - On `alert` event: updates `unreadCount` state, prepends to `recentNotifications`, shows toast if `toast_priority !== "none"`.
  - On `heartbeat` event: resets the reconnect backoff timer.
  - On disconnect: exponential backoff reconnect (1s, 2s, 4s, 8s, 16s, 30s max).
  - Cleanup: closes EventSource on unmount or logout.

- **React Query keys**:
  - `["notifications", "unread-count"]`: `useQuery` polling every 60 seconds as fallback (in case SSE misses events).
  - `["notifications", "recent"]`: `useQuery` fetching latest 10 alerts for dropdown (refreshed on SSE events).
  - `["notifications", "preferences"]`: `useQuery` for preferences page.

- **Unread count state**: Maintained in both the SSE hook (real-time) and React Query (polling fallback). The SSE hook takes priority when connected.

### Push Service Worker (`frontend/public/sw.js`)

```javascript
// Registered on first visit after user grants notification permission
self.addEventListener("push", (event) => {
  const data = event.data?.json() || {};
  const title = data.title || "New notification";
  const options = {
    body: data.body || "",
    icon: "/icon-192.png",
    badge: "/badge-72.png",
    tag: data.alert_id || "default",
    data: { url: data.url || "/" },
    timestamp: data.ts ? data.ts * 1000 : Date.now(),
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = event.notification.data?.url || "/";
  event.waitUntil(
    clients.matchAll({ type: "window" }).then((windowClients) => {
      for (const client of windowClients) {
        if (client.url.includes(url) && "focus" in client) {
          return client.focus();
        }
      }
      return clients.openWindow(url);
    })
  );
});
```

### Push Registration Flow

```typescript
// In PushSubscription.ts, called after user clicks "Enable push notifications"
async function subscribeToPush() {
  const registration = await navigator.serviceWorker.register("/sw.js");
  const vapidResponse = await api.get("/ui/push/vapid-key");
  const subscription = await registration.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: urlBase64ToUint8Array(vapidResponse.data.public_key),
  });
  await api.post("/ui/push/subscribe", {
    endpoint: subscription.endpoint,
    keys_p256dh: btoa(String.fromCharCode(...new Uint8Array(subscription.getKey("p256dh")!))),
    keys_auth: btoa(String.fromCharCode(...new Uint8Array(subscription.getKey("auth")!))),
  });
}
```

### Navigation Integration

- No new route needed -- the notification bell is in the `Header.tsx` component (always visible when authenticated).
- The "View all" link in the dropdown navigates to the existing `/alerts` page.
- Individual notification clicks navigate to the relevant page (e.g., click on "tip received" goes to `/billing`).

### UI Mockup Descriptions

1. **Notification Bell**: A `Bell` icon (lucide-react) in the header, 24x24px. When `count > 0`, a red circular badge appears at the top-right corner showing the count (capped at "99+" for three-digit counts). Clicking toggles a dropdown panel below.

2. **Notification Dropdown**: A Card component, 320px wide, max-height 400px with overflow scroll. Each `NotificationItem` shows: icon (varies by event type), title (bold), relative time ("2m ago"), and a blue dot for unread. At the bottom: "Mark all as read" button and "View all" link.

3. **Toast Popup**: A shadcn/ui `Toast` component appearing in the top-right corner. Auto-dismisses after 5 seconds. Shows event icon, title, and a brief description. Click navigates to the relevant page.

---

## 7. Security & Privacy Considerations

### Authentication & Authorization

- All endpoints require `require_ui_session` (CSRF for POST/PUT/DELETE).
- SSE stream requires a valid session cookie (existing behavior in `alerts.py`).
- Push subscription endpoints validate that the authenticated user is saving their own subscription.
- VAPID key endpoint is public (no secret data in the public key).

### Input Validation

- Push subscription `endpoint` validated as a URL with `https` scheme.
- `keys_p256dh` and `keys_auth` validated as non-empty base64 strings.
- Preference `per_type` keys validated against `ALERT_EVENT_TYPES`.
- Mark-all-read has no input -- operates on the authenticated user's count.

### Data Protection

- Push subscription keys (`p256dh`, `auth`) are stored in DDB but never returned to the frontend after initial save.
- Email notification bodies are generated from templates; they do not include raw DDB data.
- SSE events only contain alert data that the user already has access to (their own alerts).

### Abuse Prevention

- Push subscription limit: max 5 active web push subscriptions per user. Beyond this, the oldest is silently replaced.
- SSE connection limit: max 3 concurrent SSE connections per user (existing `sse_subscribe` behavior). <!-- VERIFIED: sse_subscribe() at alerts.py:63, uses asyncio.Queue(maxsize=200). However, there is NO explicit per-user connection limit in the current implementation. -->
- Mark-all-read rate limit: max 10 calls per minute per user (prevents abuse as a way to reset audit state).
- Email notification rate limit: existing `can_send_alert_channel()` function at `rate_limit.py:321`. <!-- CORRECTED: was "alerts_email_max_per_window", actually uses can_send_alert_channel() imported in alerts.py:22 -->

---

## 8. Performance & Scalability

### Query Cost Analysis

| Operation | DDB Operations | Estimated Cost |
|-----------|---------------|----------------|
| Get unread count | 1 GetItem | 0.5 RCU |
| Increment unread count | 1 UpdateItem | 1 WCU |
| Mark all read | 1 UpdateItem | 1 WCU |
| Get recent notifications (dropdown) | 1 Query, Limit 10 | ~1 RCU |
| Get preferences | 1 GetItem | 0.5 RCU |
| Save push subscription | 1 PutItem | 1 WCU |

### Caching Strategy

- **Unread count**: SSE provides real-time updates; React Query polls every 60 seconds as fallback. No server-side caching needed.
- **Notification preferences**: Cached in memory on the backend (per-user, invalidated on write). Read on every `write_alert()` to determine channels. A 60-second in-memory cache is acceptable since preference changes are rare.
- **VAPID key**: Static value, can be cached indefinitely. Served from settings.

### SSE Connection Scaling

- Current architecture: in-process SSE using Python dict of subscriber queues. This works for a single-process deployment.
- For multi-process scaling: Migrate SSE subscribers to Redis Pub/Sub. Each backend process subscribes to a Redis channel and forwards events to its local SSE connections. This is out of scope for this ticket but should be planned.
- In-memory SSE subscriber limit: 10,000 concurrent connections per process (configurable). Beyond this, oldest connections are evicted.

### Known Bottlenecks

1. **`write_alert()` is synchronous**: Adding notification dispatch (email, push) inline would slow down the calling code. Mitigation: Dispatch runs in an asyncio background task (`asyncio.create_task()`), so `write_alert()` returns immediately.
2. **Email delivery latency**: SES calls take 100-300ms. Mitigation: Fire-and-forget; failures are logged but do not retry.
3. **Push delivery latency**: FCM calls take 50-200ms. Mitigation: Same fire-and-forget pattern.

---

## 9. Migration & Rollback Plan

### Deployment Phases

1. **Phase 1 -- Backend unread counter**: Add UNREAD_COUNT sentinel logic and `GET /ui/alerts/unread-count` + `POST /ui/alerts/mark-all-read` endpoints. Safe: adds new functionality without changing existing behavior.
2. **Phase 2 -- Notification dispatcher**: Deploy `notification_dispatcher.py` behind `NOTIFICATION_DISPATCH_ENABLED` flag. When disabled, `write_alert()` behaves exactly as before.
3. **Phase 3 -- Email templates**: Deploy `notification_templates.py` with templates for top 10 event types. Email delivery uses existing `send_alert_email()`.
4. **Phase 4 -- Push subscription flow**: Deploy VAPID key endpoint and subscription CRUD. Deploy service worker. Push delivery uses existing `send_push_for_alert()`.
5. **Phase 5 -- Frontend notification bell**: Deploy `NotificationBell`, `useNotificationStream`, and toast components.
6. **Phase 6 -- Preferences UI**: Deploy preferences endpoint and settings page section.

### Feature Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `NOTIFICATION_DISPATCH_ENABLED` | `false` (prod), `true` (dev) | Master flag for notification dispatcher |
| `NOTIFICATION_EMAIL_TEMPLATES_ENABLED` | `true` | Use HTML templates (false = plain text fallback) |
| `NOTIFICATION_TOAST_ENABLED` | `true` | Enable toast popups in frontend |
| `VAPID_PUBLIC_KEY` | env var | Required for push subscriptions |
| `VAPID_PRIVATE_KEY` | env var | Required for push sending |

### Rollback Steps

1. Set `NOTIFICATION_DISPATCH_ENABLED=false` -- disables all new dispatch logic. `write_alert()` reverts to DDB write + SSE only.
2. Frontend notification bell gracefully handles no SSE events (shows count 0, empty dropdown).
3. Push subscriptions in DDB are harmless if not being used.
4. No data migration to revert -- only additive changes.

---

## 10. Testing Strategy

### Unit Tests (`tests/test_notification_delivery.py`)

| Test | Description |
|------|-------------|
| `test_unread_count_starts_at_zero` | New user; get_unread_count returns 0. |
| `test_increment_unread_count` | Call increment; count becomes 1. Call again; count becomes 2. |
| `test_mark_all_read_resets_count` | Increment to 5; mark_all_read; count is 0. |
| `test_dispatcher_routes_to_email` | Write alert with email pref enabled; assert send_alert_email called. |
| `test_dispatcher_skips_disabled_channel` | Disable email for event type; assert send_alert_email NOT called. |
| `test_dispatcher_routes_to_push` | Write alert with push pref enabled; assert send_push_for_alert called. |
| `test_email_template_tip_received` | Render template for billing.tip_received; assert subject and body contain expected strings. |
| `test_email_template_new_follower` | Render template for social.new_follower; assert output. |
| `test_push_subscription_save` | Save subscription; query DDB; assert item exists. |
| `test_push_subscription_delete` | Save then delete; query DDB; assert item gone. |
| `test_push_subscription_limit` | Save 6 subscriptions; assert only 5 remain (oldest evicted). |
| `test_preferences_default_all_enabled` | No prefs row; dispatcher sends to all channels. |
| `test_preferences_partial_override` | Disable email for one type; assert only that combination is skipped. |
| `test_sse_event_includes_toast_priority` | Write security alert; assert SSE event has toast_priority "high". |
| `test_sse_event_includes_unread_delta` | Write alert; assert SSE event has unread_delta=1. |
| `test_mark_all_read_rate_limit` | Call 11 times in 1 minute; assert 429 on 11th. |
| `test_dispatcher_failure_does_not_block` | Mock send_alert_email to raise; assert write_alert still succeeds. |

### E2E Test Matrix (`frontend/e2e/notifications.spec.ts`)

**Section A: Unread Count API (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | New user has unread count of 0 | GET /ui/alerts/unread-count -> count: 0 |
| 2 | Writing an alert increments unread count | POST alert; GET count -> 1 |
| 3 | Mark-all-read resets count to 0 | Increment to 3; POST mark-all-read; GET count -> 0 |
| 4 | Multiple alerts increment correctly | Write 5 alerts; GET count -> 5 |
| 5 | Unread count endpoint requires authentication | No cookies; 401 |

**Section B: SSE Stream (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | SSE connection receives alert event after write_alert() | Connect EventSource; write alert; assert event received within 5s |
| 2 | SSE heartbeat arrives within 30 seconds | Connect EventSource; wait; assert heartbeat event received |
| 3 | SSE reconnection works after server drop | Connect; disconnect server; reconnect; write alert; assert received |
| 4 | SSE stream requires authentication (401) | Connect without cookies; assert connection rejected |

**Section C: Push Subscription (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | VAPID key endpoint returns a public key string | GET /ui/push/vapid-key -> non-empty public_key |
| 2 | Subscribe saves push subscription to DDB | POST subscribe; assert 201; verify DDB row |
| 3 | Unsubscribe removes push subscription | DELETE subscribe; assert 200; verify DDB row gone |
| 4 | List devices includes push subscriptions | Subscribe; GET push devices; assert WEB_PUSH entry present |

**Section D: Notification Preferences (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Get preferences returns default (all enabled) | GET preferences; email_enabled=true, push_enabled=true, toast_enabled=true |
| 2 | Update preferences disables email for a specific type | PUT preferences; GET preferences; per_type has email=false for that type |
| 3 | Disabled channel skips delivery | Disable email for billing.tip_received; write tip alert; assert email log empty |

**Section E: Notification Bell UI (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Bell icon visible in header with no badge when count is 0 | Navigate to /messages; Bell icon visible; no badge element |
| 2 | Badge appears with correct count after alert is written | Write alert via API; assert badge shows "1" within 5 seconds |
| 3 | Dropdown shows latest notifications | Click bell; dropdown visible with at least 1 notification item |
| 4 | Clicking notification navigates to correct page | Click notification for billing.tip_received; assert URL contains /billing |

---

## 11. Monitoring & Alerting

### Metrics to Track

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `notification_dispatch_total` | Counter | `channel` (sse/email/push), `event_type`, `status` (sent/skipped/failed) | Total dispatch attempts per channel |
| `notification_email_send_duration_seconds` | Histogram | - | Email send latency |
| `notification_push_send_duration_seconds` | Histogram | - | Push send latency |
| `notification_sse_connections_active` | Gauge | - | Currently active SSE connections |
| `notification_unread_count_increment_total` | Counter | - | Unread count increments |
| `notification_mark_all_read_total` | Counter | - | Mark-all-read operations |
| `notification_push_subscriptions_active` | Gauge | - | Total active push subscriptions |

### Alert Thresholds

| Alert | Condition | Severity |
|-------|-----------|----------|
| Email delivery failures | `notification_dispatch_total{channel="email", status="failed"}` > 50 in 5 min | Warning |
| Push delivery failures | `notification_dispatch_total{channel="push", status="failed"}` > 50 in 5 min | Warning |
| SSE connection count high | `notification_sse_connections_active` > 8000 (80% of limit) | Warning |
| No dispatches for 10 minutes | `rate(notification_dispatch_total[10m]) == 0` and `rate(alerts_written_total[10m]) > 0` | Critical |

---

## 12. Open Questions & Risks

### Unresolved Decisions

1. **Email digest mode**: Should there be a "digest" option that batches notifications into a single daily email? Recommendation: Defer to a follow-up ticket. Start with immediate email delivery per event.

2. **Do Not Disturb schedule**: Should users be able to set quiet hours (e.g., no push/toast between 10pm and 8am)? Recommendation: Defer. Complexity of timezone handling + schedule storage.

3. **Notification grouping**: Should multiple tips from the same user be grouped into a single notification? Recommendation: Defer. Start with one notification per event.

4. **SSE vs. WebSocket**: The current SSE implementation is one-directional. Should we migrate to WebSocket for bidirectional communication (e.g., mark-as-read from the dropdown without a separate API call)? Recommendation: Keep SSE for v1. WebSocket migration is a larger architectural change.

5. **Push notification content**: How much detail should the push notification body contain? Full "Bob tipped you $5.00" or just "You have a new notification"? Recommendation: Full detail in push body; privacy-conscious users can disable push.

### Technical Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| SSE connection leak | Memory growth from unclosed connections | Heartbeat-based connection pruning; 5-minute idle timeout |
| FCM quota limits | Push delivery silently dropped | Monitor `notification_push_send_duration_seconds` for 429s; implement exponential backoff |
| Email bounce rate | SES reputation damage | Validate email addresses on registration; handle bounces via SES webhook |
| Unread count drift | Count shows wrong number after edge cases (e.g., alert deleted by admin) | Periodic reconciliation job: count actual unread alerts and correct sentinel |

---

## 13. Implementation Timeline

### Phase 1: Unread Counter + Mark All Read (Days 1-2)

| Day | Task |
|-----|------|
| 1 | Implement `notification_unread.py` (increment, reset, get). Add `GET /ui/alerts/unread-count` and `POST /ui/alerts/mark-all-read` to `alerts.py`. Write unit tests. |
| 2 | Modify `write_alert()` to call unread increment. Enhance SSE event format with `unread_delta` and `toast_priority`. Write unit tests for SSE format. |

### Phase 2: Notification Dispatcher + Templates (Days 3-4)

| Day | Task |
|-----|------|
| 3 | Create `notification_dispatcher.py`. Implement channel routing logic with preference evaluation. Create `notification_templates.py` with 10 event type templates. |
| 4 | Integrate dispatcher into `write_alert()` as fire-and-forget asyncio task. Write comprehensive unit tests for dispatcher (channel routing, preference handling, failure isolation). |

### Phase 3: Push Subscription Flow (Day 5)

| Day | Task |
|-----|------|
| 5 | Add VAPID key endpoint, push subscribe/unsubscribe endpoints to `alerts.py` (or new `push.py` extension). Implement subscription limit enforcement. Write unit tests. |

### Phase 4: Frontend (Days 6-8)

| Day | Task |
|-----|------|
| 6 | Create `useNotificationStream.ts` hook (SSE EventSource with reconnect). Create `NotificationBell.tsx` component with badge and dropdown. Integrate into `Header.tsx`. |
| 7 | Create `NotificationToast.tsx`. Create `sw.js` service worker. Implement push subscription flow (`PushSubscription.ts`). Add push opt-in prompt to settings page. |
| 8 | Create notification preferences UI (section in Settings page or standalone page). Wire up React Query hooks for preferences CRUD. |

### Phase 5: E2E Tests + Polish (Day 9)

| Day | Task |
|-----|------|
| 9 | Write `frontend/e2e/notifications.spec.ts` -- 20 tests across 5 sections. Fix bugs found during testing. Final integration testing. |

---

## Appendix: Codebase Citations

| Claim | Verified? | File:Line | Notes |
|-------|-----------|-----------|-------|
| `write_alert()` | Yes | `app/services/alerts.py:265-303` | Writes to T.alerts, calls sse_publish_alert() |
| `sse_publish_alert()` | Yes | `app/services/alerts.py:83-94` | In-memory pubsub via `_SSE_SUBSCRIBERS` dict of asyncio.Queue sets |
| `sse_subscribe()` | Yes | `app/services/alerts.py:63-70` | Queue maxsize=200; no per-user connection limit enforced |
| `send_alert_email()` | Yes | `app/services/alerts.py:315-336` | Dev mode logs to file; prod uses SES. Already functional. |
| `send_alert_sms()` | Yes | `app/services/alerts.py:338-355` | Dev mode logs to file; prod uses SNS. |
| `send_push_for_alert()` | Yes | `app/services/push.py:136-155` | Reads push prefs, queries T.push_devices, calls fcm_send() |
| `fcm_send()` | Yes | `app/services/push.py:71-90` | FCM HTTP v1 API. Requires fcm_project_id, fcm_client_email, fcm_private_key settings. |
| `get_alert_prefs()` | Yes | `app/services/alerts.py:181-199` | Returns dict with emails, sms_numbers, *_event_types lists, webhook_urls |
| `set_alert_prefs()` | Yes | `app/services/alerts.py:201-263` | Validates against ALERT_EVENT_TYPES, normalizes emails/phones |
| `ALERT_EVENT_TYPES` | Yes | `app/services/alerts.py:46-57` | List of ~28 event type strings |
| `audit_event()` | Yes | `app/services/alerts.py:492-684` | Master dispatch function: writes alert, sends email/sms/push/webhook per prefs |
| `can_send_alert_channel()` | Yes | `app/services/rate_limit.py:321` | Rate limits alert channel delivery |
| T.alerts table | Yes | `app/core/tables.py:19/103` | PK=user_sub, SK=alert_id. alerts_table_name at settings.py:76 |
| T.alert_prefs table | Yes | `app/core/tables.py:20/104` | PK=user_sub (no SK). alert_prefs_table_name at settings.py:77 |
| T.push_devices table | Yes | `app/core/tables.py:21/105` | PK=user_sub, SK=device_id. push_devices_table_name at settings.py:227 |
| `upsert_push_device()` | Yes | `app/services/push.py:114-126` | Writes to T.push_devices with TTL (180 days) |
| `revoke_push_device()` | Yes | `app/services/push.py:129-133` | Deletes from T.push_devices |
| `list_push_devices()` | Yes | `app/services/push.py:97-111` | Queries T.push_devices by user_sub |
| `render_ticket_email_template()` | Yes | `app/services/alerts.py:144-178` | Existing email template pattern for ticket events |
| `UnreadCountResponse` model | Yes | `app/models.py:2342-2344` | Already defined |
| `MarkAllReadResponse` model | Yes | `app/models.py:2347-2349` | Already defined |
| `AlertTypePreference` model | Yes | `app/models.py:2328-2334` | Already defined |
| `AlertTypePreferenceUpdate` model | Yes | `app/models.py:2318-2325` | Already defined |
| NOTIFICATION_DISPATCH_ENABLED setting | **Not found** | `app/core/settings.py` | Does not exist yet; must be added |
| VAPID_PUBLIC_KEY setting | **Not found** | `app/core/settings.py` | Does not exist yet; must be added |

**Key finding**: The backend notification dispatch pipeline is MORE COMPLETE than the ticket claims. `audit_event()` already routes to email, SMS, push, and webhook channels based on user preferences. The main gaps are: (1) frontend SSE hook and notification bell, (2) unread count sentinel, (3) toast notifications, (4) VAPID/web push subscription flow. The proposed `notification_dispatcher.py` would largely duplicate logic already in `audit_event()`.

**Schema migration note**: The existing alert_prefs schema uses flat lists (email_event_types, push_event_types, etc.) not nested per_type dicts. The ticket's proposed schema would need to be reconciled with the existing format.
