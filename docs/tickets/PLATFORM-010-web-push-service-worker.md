# PLATFORM-010: Web Push Service Worker

**Ticket**: PLATFORM-010
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: P0 — Core User Experience
**Estimated effort**: 12-16 days

---

## 1. Executive Summary

The platform has a push notification device management UI (`PushDevices.tsx`) and backend registration endpoints (`push.py`), but no actual browser push delivery works. The frontend generates a placeholder token `web-${Date.now()}-${Math.random()}` (PushDevices.tsx:65) instead of obtaining a real Web Push subscription from the browser. There is no service worker file in `frontend/public/`. The backend push delivery function (`send_push_for_alert()` in `app/services/push.py:136-155`) calls `fcm_send()` (line 153) which targets Firebase Cloud Messaging, but no FCM credentials are configured and the tokens it receives are fake placeholders.

The result: users can "enable" push notifications and see their device listed, but no push notification is ever delivered. The test notification button (`POST /ui/push/test` at push.py:39-43) appears to succeed (200 response) but silently fails because `fcm_send()` returns False due to missing credentials and invalid tokens.

This feature implements the complete Web Push pipeline: a service worker file that handles push events, real VAPID key generation and exchange, browser push subscription via `navigator.serviceWorker.register()` + `PushManager.subscribe()`, and backend delivery using the standard Web Push protocol (RFC 8030 + RFC 8291) instead of (or alongside) FCM.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| User | I want to receive real-time push notifications when I get a new message. | Browser shows native push notification with message preview. |
| User | I want push notifications for alerts (security events, billing, tips). | Browser push for all enabled alert types in preferences. |
| User | I want to test that push is working. | "Test" button sends a visible push notification. |
| User | I want to control which events trigger push. | Alert preferences page has push toggle per event type. |
| User | I want to manage my push-enabled devices. | PushDevices page shows real browser subscriptions with revoke. |
| User | I want push to work without leaving the tab open. | Service worker handles push events in background. |
| User | I want clicking a notification to take me to the relevant page. | Notification click navigates to `/messages`, `/alerts`, `/billing`, etc. |
| Admin | I want to see how many push devices are registered. | Admin dashboard or metric shows device count. |

### 2.2 Pain Points

1. **Push is completely non-functional**: The entire push flow is a stub. Users who "enable" notifications get zero notifications.
2. **False positive UX**: The UI shows "Push notifications enabled" and lists the device, but nothing works. The "Test" button appears to succeed (toast: "Test notification sent") but no push arrives.
3. **Placeholder tokens are useless**: `web-${Date.now()}-${Math.random()}` (PushDevices.tsx:65) is stored in DDB but cannot be used by any push service. The token validation in `push.py:24` only checks `len(token) < 20`, which the placeholder passes.
4. **FCM dependency unnecessary for web**: Web Push has a standard protocol (RFC 8030) using VAPID keys. FCM is optional (and only needed for Chrome-specific features). The current code only has FCM delivery, which requires Google Cloud credentials.
5. **No service worker**: `frontend/public/` contains only `favicon.svg`. No service worker file exists, and no code anywhere in `frontend/src/` references `navigator.serviceWorker`.

### 2.3 Current Implementation State

**What works:**
- `PushDevices.tsx` UI: lists devices, revoke button, enable button, test button
- `push.py` router: register (line 19-29), revoke (line 32-35), test (line 39-43), list (line 14-16) endpoints
- `push.py` service: `upsert_push_device()` (line 114-126), `revoke_push_device()` (line 129-133), `list_push_devices()` (line 97-111)
- DDB table: `push_devices` PK=`user_sub`, SK=`device_id` (local-ddb-init.py:58)
- Alert preferences: push event type toggles
- Notification permission request (`PushDevices.tsx:54-62`): correctly asks for browser permission

**What does not work:**
- No service worker file
- No `navigator.serviceWorker.register()` call anywhere in `frontend/src/`
- No `PushManager.subscribe()` call
- No VAPID key generation or exchange
- Token is placeholder string, not a real `PushSubscription` JSON
- `fcm_send()` requires FCM credentials (`fcm_project_id`, `fcm_client_email`, `fcm_private_key`) that are not set
- No Web Push protocol delivery (RFC 8030)
- `send_push_for_alert()` silently fails (`except Exception: pass` at line 154-155)

---

## 3. Current State Analysis

### 3.1 PushDevices.tsx (Frontend)

`frontend/src/pages/alerts/PushDevices.tsx:20-74` implements the enable flow:

```typescript
// Line 46-74
const handleEnable = async () => {
  if (!("Notification" in window)) {
    toast.error("Push notifications are not supported in this browser");
    return;
  }
  setEnabling(true);
  try {
    let permission = Notification.permission;
    if (permission === "default") {
      permission = await Notification.requestPermission();
    }
    if (permission !== "granted") {
      toast.error("Notification permission denied");
      return;
    }
    // Register with a browser-generated token placeholder
    const token = `web-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    await registerPush({ token, platform: "web" });
    qc.invalidateQueries({ queryKey: ["push", "devices"] });
    toast.success("Push notifications enabled");
  } catch {
    toast.error("Failed to enable push notifications");
  } finally {
    setEnabling(false);
  }
};
```

Key observations:
- Line 47-50: checks `Notification` API support (correct)
- Line 54-62: requests browser notification permission (correct, works)
- Line 65: generates a **fake** token -- does not use `PushManager.subscribe()`
- Line 66: registers fake token with backend
- Uses `registerPush` from `api/endpoints/push.ts:12-13`

### 3.2 Push API Client (Frontend)

`frontend/src/api/endpoints/push.ts:1-19`:

```typescript
import { api } from "@/api/client";
import type { PushDevice, PushRegisterReq, PushRevokeReq, OkResp } from "@/api/types";

export const listPushDevices = () =>
  api.get<{ devices: PushDevice[] }>("/ui/push/devices");

export const registerPush = (body: PushRegisterReq) =>
  api.post<PushDevice>("/ui/push/register", body);

export const revokePush = (body: PushRevokeReq) =>
  api.post<OkResp>("/ui/push/revoke", body);

export const testPush = () =>
  api.post<OkResp>("/ui/push/test");
```

### 3.3 Push TypeScript Types

`frontend/src/api/types.ts:2103-2117`:

```typescript
export interface PushDevice {
  device_id: string;
  platform: string;
  created_at: number;
  last_seen_at: number;
}

export interface PushRegisterReq {
  token: string;
  platform: string;
}

export interface PushRevokeReq {
  device_id: string;
}
```

### 3.4 Push Router (Backend)

`app/routers/push.py:1-43`:

```python
router = APIRouter(prefix="/ui", tags=["push"])

@router.get("/push/devices")
async def ui_list_push_devices(ctx=Depends(require_ui_session)):
    return {"devices": list_push_devices(ctx["user_sub"])}

@router.post("/push/register")
async def ui_register_push(req: Request, body: PushRegisterReq, ctx=Depends(require_ui_session)):
    if not S.push_enabled:
        raise HTTPException(400, "Push disabled")
    token = (body.token or "").strip()
    if len(token) < 20:
        raise HTTPException(400, "Bad token")
    platform = (body.platform or "").strip()[:32]
    it = upsert_push_device(ctx["user_sub"], token, platform)
    audit_event("push_device_register", ctx["user_sub"], req, outcome="success", platform=platform)
    return it

@router.post("/push/revoke")
async def ui_revoke_push(req: Request, body: PushRevokeReq, ctx=Depends(require_ui_session)):
    revoke_push_device(ctx["user_sub"], body.device_id)
    audit_event("push_device_revoke", ctx["user_sub"], req, outcome="success", device_id=body.device_id)
    return {"ok": True}

@router.post("/push/test")
async def ui_push_test(req: Request, ctx=Depends(require_ui_session)):
    send_push_for_alert(ctx["user_sub"], "security_event", "Test notification", "This is a test push.", "test")
    audit_event("push_test", ctx["user_sub"], req, outcome="success")
    return {"ok": True}
```

### 3.5 Push Service (Backend)

`app/services/push.py:1-155`:

- `fcm_access_token()` (lines 27-68): Obtains FCM access token via JWT assertion. Requires `S.fcm_project_id`, `S.fcm_client_email`, `S.fcm_private_key` settings, plus `requests` and `cryptography` packages. Returns `None` if any credential is missing.
- `fcm_send()` (lines 71-90): Sends to FCM HTTP v1 API at `https://fcm.googleapis.com/v1/projects/{project_id}/messages:send`. Requires valid FCM access token and a real FCM device token. Returns `False` if credentials missing.
- `push_device_id()` (line 93-94): SHA-256 hash of token, truncated to 32 chars. Used as SK in DDB.
- `upsert_push_device()` (lines 114-126): Writes device to DDB with 180-day TTL via `with_ttl()`.
- `list_push_devices()` (lines 97-111): Queries DDB for user's devices (`Key("user_sub").eq(user_sub)`), returns up to 200 items sorted by `created_at` descending.
- `revoke_push_device()` (lines 129-133): Deletes device from DDB by `user_sub` + `device_id`.
- `send_push_for_alert()` (lines 136-155): Checks `S.push_enabled`, user push preferences, rate limit via `can_send_alert_channel()`, then loops through user's devices calling `fcm_send()`. Wrapped in `except Exception: pass`.

### 3.6 Push Pydantic Models

`app/models.py:628-633`:

```python
class PushRegisterReq(BaseModel):
    token: str
    platform: str

class PushRevokeReq(BaseModel):
    device_id: str
```

### 3.7 Push Settings

`app/core/settings.py:227-232`:

```python
push_devices_table_name: str = os.environ.get("PUSH_DEVICES_TABLE_NAME", "push_devices")
push_enabled: bool = os.environ.get("PUSH_ENABLED", "0") not in ("0","false","False")
fcm_enabled: bool = os.environ.get("FCM_ENABLED", "0") not in ("0","false","False")
fcm_project_id: str = os.environ.get("FCM_PROJECT_ID", "")
fcm_client_email: str = os.environ.get("FCM_CLIENT_EMAIL", "")
fcm_private_key: str = os.environ.get("FCM_PRIVATE_KEY", "")  # keep \n escaped
```

VAPID key settings exist at lines 1320-1321:
```python
vapid_public_key: str = os.environ.get("VAPID_PUBLIC_KEY", "")
vapid_private_key: str = os.environ.get("VAPID_PRIVATE_KEY", "")
```

Note: `push_enabled` defaults to `"0"` (disabled). VAPID keys exist in settings but are empty strings.

### 3.8 DDB Table

`scripts/local-ddb-init.py:58`:
```python
TableDef(_resolve_table_name(S.push_devices_table_name, "push_devices"), "user_sub", "device_id"),
```

Simple table: PK=`user_sub` (S), SK=`device_id` (S). No GSIs. No TTL attribute declared (but `upsert_push_device` writes `ttl_epoch`).

### 3.9 Push Rate Limiting

`app/services/rate_limit.py:326-329`:

```python
if channel == "push":
    max_n = int(os.environ.get("ALERTS_PUSH_MAX_PER_WINDOW", "20"))
    win = int(os.environ.get("ALERTS_PUSH_WINDOW_SECONDS", "3600"))
    return _bucket_limit(user_sub, "rl#alert_push", max_n, win)
```

Push rate limit: 20 pushes per hour per user (env configurable).

### 3.10 Frontend Public Directory

`frontend/public/` contains only `favicon.svg`. No service worker file exists. No file in `frontend/src/` references `navigator.serviceWorker` or `serviceWorker`.

### 3.11 Gaps Summary

1. No service worker file (`frontend/public/sw.js`)
2. No service worker registration (`navigator.serviceWorker.register()`)
3. No `PushManager.subscribe()` call
4. No VAPID public key delivery endpoint
5. Placeholder token instead of real `PushSubscription` JSON
6. `send_push_for_alert()` only calls `fcm_send()`, no Web Push protocol
7. Silent failure in delivery (`except Exception: pass` at push.py:154-155)
8. No push delivery metrics
9. No stale subscription cleanup (410 Gone handling)
10. VAPID settings exist but are empty/unused

---

## 4. Technical Architecture

### 4.1 Web Push Protocol Overview

```
Browser (Service Worker)           Push Service (vendor-operated)     Application Server (Backend)
  |                                   |                                  |
  |-- PushManager.subscribe() ------->|                                  |
  |   (using VAPID public key)        |                                  |
  |<-- PushSubscription {             |                                  |
  |       endpoint: "https://...",    |                                  |
  |       keys: { p256dh, auth }      |                                  |
  |     }                             |                                  |
  |                                   |                                  |
  |-- POST /ui/push/register ---------|--------------------------------->|
  |   { token: <PushSubscription JSON> }                                 |
  |                                   |                                  |
  |   (When alert fires)              |                                  |
  |                                   |<-- POST {endpoint} --------------|
  |                                   |    (encrypted payload, VAPID JWT)|
  |                                   |    RFC 8030 + RFC 8291           |
  |<-- push event -------------------|                                  |
  |   self.addEventListener("push")   |                                  |
  |   self.registration.showNotification()                               |
```

### 4.2 System Diagram

```
PushDevices.tsx                  Backend                        DynamoDB
  |                                |                               |
  |-- SW register + subscribe ---> (browser, local)                |
  |                                |                               |
  |-- POST /ui/push/register ----->|-- upsert_push_device() ----->|  user_sub + device_id
  |   { token: <subscription> }   |   stores full subscription    |  token = JSON subscription
  |                                |                               |
  |                                |                               |
  (Alert fires)                    |                               |
  |                                |-- send_push_for_alert() ---->|  query devices
  |                                |   for each web device:        |
  |                                |   web_push_send(subscription, |
  |                                |     title, body, url)         |
  |                                |                               |
  |                                |-- POST to push endpoint ----> (vendor push service)
  |                                |   (VAPID signed, AES-128-GCM  |
  |                                |    encrypted payload)         |
  |                                |                               |
  SW push event <------ push delivery from vendor push service     |
  |-- showNotification()           |                               |
```

### 4.3 Data Flow -- Enable Push

1. User clicks "Enable Notifications" in PushDevices.tsx
2. Frontend checks browser support (`"Notification" in window && "serviceWorker" in navigator`)
3. Frontend requests notification permission (existing: PushDevices.tsx:54-62)
4. Frontend fetches VAPID public key: `GET /ui/push/vapid-key`
5. Frontend registers service worker: `navigator.serviceWorker.register("/sw.js")`
6. Frontend waits for SW to be ready: `await navigator.serviceWorker.ready`
7. Frontend subscribes to push: `registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: urlBase64ToUint8Array(vapidPublicKey) })`
8. Browser returns `PushSubscription` with `endpoint`, `keys.p256dh`, `keys.auth`
9. Frontend calls `POST /ui/push/register` with `{ token: JSON.stringify(subscription.toJSON()), platform: "web" }`
10. Backend stores full subscription JSON in DDB via `upsert_push_device()` (push.py:114-126)
11. Frontend shows "Push notifications enabled" toast

### 4.4 Data Flow -- Deliver Push

1. Alert system calls `send_push_for_alert(user_sub, alert_type, title, body, alert_id)` (push.py:136)
2. Function checks `S.push_enabled`, user preferences, rate limit via `can_send_alert_channel(user_sub, "push")`
3. Queries user's devices from DDB (push.py:147, Limit=200)
4. For each device (up to 25, push.py:149):
   a. If `platform == "web"`:
      - Parse `token` as JSON to get `PushSubscription` object
      - Create VAPID JWT signed with `S.vapid_private_key` (settings.py:1321)
      - Encrypt payload using AES-128-GCM with `keys.auth` and `keys.p256dh` (RFC 8291)
      - POST encrypted payload to subscription `endpoint` with VAPID Authorization header
      - If push service returns **410 (Gone)**: auto-revoke the stale device from DDB
      - If push service returns **201 (Created)**: success
   b. If platform is not "web": use existing `fcm_send()` path (for future mobile apps)

### 4.5 Data Flow -- Receive Push (Service Worker)

1. Browser receives push from vendor push service (even if tab is closed)
2. Service worker `push` event fires
3. SW extracts payload from `event.data.json()`
4. SW calls `self.registration.showNotification(title, { body, icon, badge, data: { url }, tag })`
5. On notification click: `notificationclick` event fires
6. SW calls `event.notification.close()`
7. SW attempts to find and focus an existing app tab; if none found, opens new tab at `url`

---

## 5. Implementation Plan

### 5.1 Service Worker File

Create `frontend/public/sw.js`:

```javascript
/* sw.js -- Web Push Service Worker (PLATFORM-010)
 *
 * Handles:
 * - push: Show native browser notification
 * - notificationclick: Focus/open app tab at the relevant URL
 *
 * Does NOT handle fetch caching or offline support (Phase 2).
 */

// Activate immediately on install (skip waiting for existing clients to close)
self.addEventListener("install", (event) => {
  self.skipWaiting();
});

// Claim all clients immediately on activate
self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

// Handle incoming push notification
self.addEventListener("push", (event) => {
  if (!event.data) {
    // No payload -- show a generic notification
    event.waitUntil(
      self.registration.showNotification("New notification", {
        body: "You have a new notification",
        icon: "/favicon.svg",
        badge: "/favicon.svg",
      })
    );
    return;
  }

  let payload;
  try {
    payload = event.data.json();
  } catch (e) {
    // Fallback: treat as plain text
    payload = { title: "Notification", body: event.data.text() };
  }

  const title = payload.title || "Notification";
  const options = {
    body: payload.body || "",
    icon: payload.icon || "/favicon.svg",
    badge: payload.badge || "/favicon.svg",
    data: {
      url: payload.url || "/",
      alertId: payload.alert_id || "",
      alertType: payload.alert_type || "",
    },
    tag: payload.tag || payload.alert_type || "default",
    renotify: !!payload.tag, // Re-notify if same tag (replace existing)
    timestamp: payload.timestamp ? new Date(payload.timestamp * 1000).getTime() : Date.now(),
    silent: false,
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

// Handle notification click -- navigate to the relevant page
self.addEventListener("notificationclick", (event) => {
  event.notification.close();

  const url = event.notification.data?.url || "/";
  const fullUrl = new URL(url, self.location.origin).href;

  event.waitUntil(
    self.clients
      .matchAll({ type: "window", includeUncontrolled: true })
      .then((clientList) => {
        // Try to find an existing app tab to focus + navigate
        for (const client of clientList) {
          if (client.url.startsWith(self.location.origin) && "focus" in client) {
            return client.navigate(fullUrl).then(() => client.focus());
          }
        }
        // No existing tab -- open a new one
        return self.clients.openWindow(fullUrl);
      })
  );
});

// Handle notification close (analytics, optional)
self.addEventListener("notificationclose", (event) => {
  // Future: track notification dismissal rate
});
```

### 5.2 Service Worker Registration

Create `frontend/src/lib/pushSetup.ts`:

```typescript
/**
 * Service Worker + Push Subscription helpers (PLATFORM-010).
 *
 * Call registerServiceWorker() on app mount.
 * Call subscribeToPush() when the user clicks "Enable Notifications".
 */

/**
 * Register the service worker. Returns the registration object or null.
 */
export async function registerServiceWorker(): Promise<ServiceWorkerRegistration | null> {
  if (!("serviceWorker" in navigator)) {
    console.warn("Service workers not supported");
    return null;
  }
  try {
    const registration = await navigator.serviceWorker.register("/sw.js", {
      scope: "/",
    });
    console.log("SW registered:", registration.scope);
    return registration;
  } catch (err) {
    console.error("SW registration failed:", err);
    return null;
  }
}

/**
 * Convert a URL-safe base64 string to a Uint8Array (for applicationServerKey).
 *
 * VAPID public keys are encoded as URL-safe base64 without padding.
 * PushManager.subscribe() requires a Uint8Array.
 */
export function urlBase64ToUint8Array(base64String: string): Uint8Array {
  const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");
  const rawData = window.atob(base64);
  const outputArray = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; i++) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
}

/**
 * Subscribe the browser to push notifications using the server's VAPID key.
 *
 * Returns the PushSubscription JSON string to send to POST /ui/push/register.
 * Throws if permission denied or subscription fails.
 */
export async function subscribeToPush(
  vapidPublicKey: string
): Promise<string> {
  const registration = await navigator.serviceWorker.ready;

  // Check for existing subscription
  const existing = await registration.pushManager.getSubscription();
  if (existing) {
    // Already subscribed -- return existing subscription
    return JSON.stringify(existing.toJSON());
  }

  const subscription = await registration.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: urlBase64ToUint8Array(vapidPublicKey),
  });

  return JSON.stringify(subscription.toJSON());
}

/**
 * Unsubscribe from push notifications (called on device revoke).
 */
export async function unsubscribeFromPush(): Promise<boolean> {
  if (!("serviceWorker" in navigator)) return false;
  try {
    const registration = await navigator.serviceWorker.ready;
    const subscription = await registration.pushManager.getSubscription();
    if (subscription) {
      return await subscription.unsubscribe();
    }
  } catch (err) {
    console.error("Push unsubscribe failed:", err);
  }
  return false;
}
```

### 5.3 Service Worker Registration on App Mount

**File: `frontend/src/main.tsx`** -- Add SW registration after app mount:

```typescript
import { registerServiceWorker } from "@/lib/pushSetup";

// ... existing app mount code ...

// Register service worker for push notifications (PLATFORM-010)
if ("serviceWorker" in navigator) {
  registerServiceWorker();
}
```

### 5.4 VAPID Public Key Endpoint

**File: `app/routers/push.py`** -- Add endpoint (no auth required for VAPID key):

```python
@router.get("/push/vapid-key")
async def ui_get_vapid_key():
    """Return the VAPID public key for push subscription.

    The VAPID public key is safe to expose publicly -- it is used by
    the browser to authenticate the application server when subscribing
    to push notifications.

    curl http://localhost:8000/ui/push/vapid-key
    """
    if not S.vapid_public_key:
        raise HTTPException(404, "VAPID not configured")
    return {"vapid_public_key": S.vapid_public_key}
```

### 5.5 VAPID Public Key API Client

**File: `frontend/src/api/endpoints/push.ts`** -- Add `getVapidKey()`:

```typescript
export const getVapidKey = () =>
  api.get<{ vapid_public_key: string }>("/ui/push/vapid-key");
```

### 5.6 Updated PushDevices Enable Flow

**File: `frontend/src/pages/alerts/PushDevices.tsx`** -- Replace placeholder token (line 65) with real push subscription:

```typescript
import { registerServiceWorker, subscribeToPush, unsubscribeFromPush } from "@/lib/pushSetup";
import { getVapidKey } from "@/api/endpoints/push";

const handleEnable = async () => {
  if (!("Notification" in window) || !("serviceWorker" in navigator)) {
    toast.error("Push notifications are not supported in this browser");
    return;
  }

  setEnabling(true);
  try {
    // 1. Request notification permission
    let permission = Notification.permission;
    if (permission === "default") {
      permission = await Notification.requestPermission();
    }
    if (permission !== "granted") {
      toast.error("Notification permission denied");
      return;
    }

    // 2. Fetch VAPID public key from server
    const vapidResp = await getVapidKey();
    const vapidPublicKey = vapidResp.vapid_public_key;
    if (!vapidPublicKey) {
      toast.error("Push not configured on server");
      return;
    }

    // 3. Register service worker (may already be registered)
    await registerServiceWorker();

    // 4. Subscribe to push using VAPID key
    const subscriptionJson = await subscribeToPush(vapidPublicKey);

    // 5. Send subscription to backend
    await registerPush({ token: subscriptionJson, platform: "web" });

    qc.invalidateQueries({ queryKey: ["push", "devices"] });
    toast.success("Push notifications enabled");
  } catch (err) {
    console.error("Push enable failed:", err);
    toast.error("Failed to enable push notifications");
  } finally {
    setEnabling(false);
  }
};
```

### 5.7 VAPID Key Generation Script

Create `scripts/generate_vapid_keys.py`:

```python
#!/usr/bin/env python3
"""Generate VAPID key pair for Web Push (PLATFORM-010).

Usage:
    python3 scripts/generate_vapid_keys.py

Output: VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY values for .env.local.

The private key is PEM-encoded (PKCS8 format).
The public key is URL-safe base64 of the uncompressed EC P-256 point (65 bytes).
"""
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import base64

# Generate P-256 key pair
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# Private key as PEM (for VAPID_PRIVATE_KEY env var)
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode()

# Public key as URL-safe base64 of uncompressed point (for VAPID_PUBLIC_KEY)
public_numbers = public_key.public_numbers()
x = public_numbers.x.to_bytes(32, "big")
y = public_numbers.y.to_bytes(32, "big")
uncompressed = b"\x04" + x + y  # 65 bytes: 0x04 prefix + 32 bytes x + 32 bytes y
public_b64 = base64.urlsafe_b64encode(uncompressed).decode().rstrip("=")

print("# Add these to .env.local:")
print(f"VAPID_PUBLIC_KEY={public_b64}")
# PEM needs to be on one line with literal \n for env var
private_oneline = private_pem.strip().replace("\n", "\\n")
print(f"VAPID_PRIVATE_KEY='{private_oneline}'")
print()
print(f"# Public key length: {len(public_b64)} chars (should decode to 65 bytes)")
print(f"# Private key format: PKCS8 PEM ({len(private_pem.strip().splitlines())} lines)")
```

### 5.8 Web Push Delivery (Backend)

**File: `app/services/push.py`** -- Add Web Push delivery alongside existing FCM:

```python
import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def web_push_send(
    subscription_json: str,
    title: str,
    body: str,
    url: str = "/",
    tag: str = "default",
    alert_id: str = "",
    alert_type: str = "",
) -> bool:
    """Send push via Web Push protocol (RFC 8030 + RFC 8291).

    Uses the pywebpush library for encryption and VAPID signing.

    Args:
        subscription_json: JSON string from PushSubscription.toJSON()
        title: Notification title (max 60 chars displayed)
        body: Notification body (max 180 chars displayed)
        url: Click target URL (relative to app origin)
        tag: Notification tag (replaces existing notification with same tag)
        alert_id: Alert ID for tracking
        alert_type: Alert type for routing

    Returns:
        True if push was accepted by the push service, False otherwise.
    """
    if not (S.vapid_private_key and S.vapid_public_key):
        logger.debug("Web push skipped: VAPID keys not configured")
        return False

    # Parse subscription JSON
    try:
        subscription = json.loads(subscription_json)
        endpoint = subscription.get("endpoint", "")
        keys = subscription.get("keys", {})
        p256dh = keys.get("p256dh", "")
        auth = keys.get("auth", "")

        if not (endpoint and p256dh and auth):
            logger.warning("Web push: invalid subscription (missing fields)")
            return False
    except (json.JSONDecodeError, AttributeError, TypeError):
        logger.warning("Web push: invalid subscription JSON")
        return False

    # Build payload
    payload = json.dumps({
        "title": title[:60],
        "body": body[:180],
        "url": url,
        "tag": tag,
        "alert_id": alert_id,
        "alert_type": alert_type,
        "timestamp": now_ts(),
    })

    # Send using pywebpush
    try:
        from pywebpush import webpush, WebPushException

        vapid_claims = {
            "sub": S.vapid_subject or "mailto:admin@testlogon.local",
        }
        vapid_private_key = S.vapid_private_key.replace("\\n", "\n")

        response = webpush(
            subscription_info=subscription,
            data=payload,
            vapid_private_key=vapid_private_key,
            vapid_claims=vapid_claims,
            timeout=10,
        )
        status = response.status_code if hasattr(response, "status_code") else 201
        if status in (200, 201, 202):
            logger.info("Web push sent: endpoint=%s", endpoint[:80])
            return True
        else:
            logger.warning("Web push failed: status=%s, endpoint=%s", status, endpoint[:80])
            return False

    except Exception as exc:
        exc_str = str(exc)
        # 410 Gone = subscription expired
        if "410" in exc_str or "Gone" in exc_str:
            logger.info("Web push subscription expired (410): endpoint=%s", endpoint[:80])
            return False  # Caller should revoke device
        # 404 Not Found = subscription invalid
        if "404" in exc_str:
            logger.info("Web push subscription not found (404): endpoint=%s", endpoint[:80])
            return False
        logger.exception("Web push send error: endpoint=%s", endpoint[:80])
        return False
```

### 5.9 Modified send_push_for_alert

Update `send_push_for_alert()` (`app/services/push.py:136-155`) to dispatch to `web_push_send()` for web platform devices and `fcm_send()` for other platforms:

```python
def send_push_for_alert(
    user_sub: str,
    alert_type: str,
    title: str,
    body: str,
    alert_id: str,
) -> None:
    """Send push notification for an alert to all user's devices.

    Dispatches to web_push_send() for web devices and fcm_send() for
    native mobile devices. Stale web subscriptions (410 Gone) are
    auto-revoked.
    """
    if not S.push_enabled:
        return
    if not S.web_push_enabled and not S.fcm_enabled:
        return

    from app.services.alerts import get_alert_prefs
    prefs = get_alert_prefs(user_sub)
    enabled = set(prefs.get("push_event_types") or [])
    if alert_type not in enabled:
        return
    if not can_send_alert_channel(user_sub, "push"):
        return

    # Build type-specific URL
    url = _alert_url(alert_type, alert_id)

    try:
        r = T.push_devices.query(
            KeyConditionExpression=Key("user_sub").eq(user_sub),
            Limit=200,
        )
        items = r.get("Items", [])

        for it in items[:25]:
            tok = it.get("token", "")
            device_id = it.get("device_id", "")
            platform = it.get("platform", "")

            if not tok:
                continue

            if platform == "web" and S.web_push_enabled:
                success = web_push_send(
                    tok, title, body,
                    url=url,
                    tag=alert_type,
                    alert_id=alert_id,
                    alert_type=alert_type,
                )
                if not success:
                    # Check if subscription is likely expired
                    try:
                        sub = json.loads(tok)
                        if "endpoint" in sub:
                            # Revoke stale subscription
                            revoke_push_device(user_sub, device_id)
                            logger.info(
                                "Auto-revoked stale push device: user=%s, device=%s",
                                user_sub, device_id,
                            )
                    except (json.JSONDecodeError, TypeError):
                        # Placeholder token -- ignore
                        pass

            elif platform != "web" and S.fcm_enabled:
                fcm_send(
                    tok, title, body,
                    data={"alert_id": alert_id, "alert_type": alert_type},
                )

    except Exception:
        logger.exception("Push delivery error: user=%s, alert_type=%s", user_sub, alert_type)


def _alert_url(alert_type: str, alert_id: str) -> str:
    """Map alert type to a specific app URL for notification click."""
    type_urls = {
        "new_message": "/messages",
        "messaging.new_message": "/messages",
        "post_tip": "/billing",
        "message_tip": "/messages",
        "billing.tip_received": "/billing",
        "payment_received": "/billing",
        "subscription_started": "/billing",
        "refund_processed": "/billing",
        "security_event": "/alerts",
        "login_failure": "/alerts",
        "mfa_failure": "/alerts",
        "access_denied": "/alerts",
        "device_new": "/alerts",
        "device_location_mismatch": "/alerts",
        "rate_limited": "/alerts",
    }
    return type_urls.get(alert_type, "/alerts")
```

---

## 6. Settings Changes

### 6.1 Settings in `app/core/settings.py`

VAPID settings already exist (lines 1320-1321). Additional settings to add:

```python
# Web Push (PLATFORM-010)
web_push_enabled: bool = os.environ.get("WEB_PUSH_ENABLED", "1") not in ("0", "false", "False")
vapid_subject: str = os.environ.get("VAPID_SUBJECT", "mailto:admin@testlogon.local")
```

### 6.2 Environment Variables

Add to `.env.local.example`:
```bash
# Push notifications (PLATFORM-010)
PUSH_ENABLED=1
WEB_PUSH_ENABLED=1
VAPID_PUBLIC_KEY=<generated-by-scripts/generate_vapid_keys.py>
VAPID_PRIVATE_KEY=<generated-by-scripts/generate_vapid_keys.py>
VAPID_SUBJECT=mailto:admin@testlogon.local
```

The `scripts/setup_ubuntu.sh` script should auto-generate VAPID keys if not already set in `.env.local`.

---

## 7. Data Model

### 7.1 Push Device DDB Item (Updated)

The existing `push_devices` table schema remains unchanged (PK=`user_sub`, SK=`device_id`). The `token` field changes from a placeholder string to a full `PushSubscription` JSON:

**Before (placeholder)**:
```json
{
  "user_sub": "e2e_alice@test.local",
  "device_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "token": "web-1748380800000-k7x9m2p4q1",
  "platform": "web",
  "created_at": 1748380800,
  "last_seen_at": 1748380800,
  "ttl_epoch": 1763932800
}
```

**After (real subscription)**:
```json
{
  "user_sub": "e2e_alice@test.local",
  "device_id": "f3a9c7e1d5b2f3a9c7e1d5b2f3a9c7e1",
  "token": "{\"endpoint\":\"https://fcm.googleapis.com/fcm/send/eKB...\",\"expirationTime\":null,\"keys\":{\"p256dh\":\"BNcRd...\",\"auth\":\"tBH...\"}}",
  "platform": "web",
  "created_at": 1748380800,
  "last_seen_at": 1748380800,
  "ttl_epoch": 1763932800
}
```

The `device_id` is `hashlib.sha256(token.encode()).hexdigest()[:32]` (push.py:93-94), so it changes when the token changes.

### 7.2 Push Subscription JSON Structure

A real `PushSubscription.toJSON()` returns:

```json
{
  "endpoint": "https://fcm.googleapis.com/fcm/send/eKBz...-long-random-token",
  "expirationTime": null,
  "keys": {
    "p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8p8nR0SZ8=",
    "auth": "tBHItJI5svbpC7SC64VQow=="
  }
}
```

- `endpoint`: HTTPS URL unique to this browser+origin pair. The backend POSTs encrypted push payloads to this URL.
- `keys.p256dh`: Browser's P-256 public key for payload encryption (base64url, 65 bytes decoded).
- `keys.auth`: Authentication secret for payload encryption (base64url, 16 bytes decoded).
- `expirationTime`: Usually null; some browsers may set this.

---

## 8. Security & Privacy

### 8.1 VAPID Key Security

- VAPID **private key** must be kept server-side only. Never expose in API responses.
- VAPID **public key** is safe to expose (sent to browser via `/push/vapid-key` and used in `PushManager.subscribe()`).
- VAPID JWTs have a 24-hour expiry (`exp` claim) to limit replay attacks.
- VAPID private key should be stored in environment variables, not in code or DDB.

### 8.2 Push Payload Encryption

- All push payloads are encrypted using AES-128-GCM per RFC 8291 ("aes128gcm" content encoding).
- Encryption uses the `p256dh` and `auth` keys from the browser's `PushSubscription`.
- Only the browser with the matching private key can decrypt the payload.
- No sensitive data in unencrypted headers (only `TTL`, `Content-Encoding`, `Content-Type`).
- Payload size limit: 4096 bytes (sufficient for title + body + metadata).

### 8.3 Push Subscription Security

- Push subscription endpoints are unguessable URLs (128+ bit random token in the URL).
- Subscriptions are stored in DDB with a 180-day TTL (`push.py:117`).
- Stale subscriptions (410 Gone responses) are auto-revoked from DDB.
- Each subscription is tied to a specific `user_sub` in DDB.
- The `device_id` is a SHA-256 hash of the full subscription JSON, so different subscriptions produce different device IDs.

### 8.4 Service Worker Scope

- The service worker is scoped to `/` (root) to receive push events for all pages.
- The SW only handles `push`, `notificationclick`, and `notificationclose` events -- it does NOT intercept fetch requests or cache responses.
- No cache-first strategies that could serve stale content or leak data.
- The SW file is served from `frontend/public/sw.js` with `Content-Type: application/javascript`.

### 8.5 Notification Content

- Push payloads contain alert type and a short body preview. No PII beyond what the user has configured in their alert preferences.
- `userVisibleOnly: true` ensures that every push event results in a visible notification (required by spec and Chrome).
- Message bodies are truncated to 180 chars in the payload to stay well under the 4096-byte limit.

---

## 9. Performance & Scalability

### 9.1 Push Delivery Cost

| Operation | Cost | Latency |
|-----------|------|---------|
| Query user devices (DDB) | 1 RCU | ~10ms |
| Encrypt payload per device (AES-GCM) | CPU | ~1-5ms |
| VAPID JWT creation + signing | CPU | ~2ms |
| POST to push endpoint per device | 1 HTTP request | ~100-500ms |
| Auto-revoke stale device (DDB delete) | 1 WCU | ~5ms |
| **Total per user (5 devices)** | **1 RCU + 5 HTTP** | **~500-2500ms** |

### 9.2 Background Delivery

Push delivery is called from the alerts system as a fire-and-forget operation within `write_alert()`. For high-volume scenarios (broadcast to many users), delivery should be queued via SQS. The current implementation processes up to 25 devices per user synchronously.

### 9.3 Service Worker Performance

- The SW file (`sw.js`) is < 2KB. It loads and parses instantly.
- The SW only activates on push events -- no background fetch, no cache interception.
- `skipWaiting()` + `clients.claim()` ensures immediate activation on install, avoiding the "waiting for existing tabs to close" delay.
- The SW does not re-register on every page load -- `navigator.serviceWorker.register()` is a no-op if the SW is already active with the same file.

### 9.4 pywebpush Library

The `pywebpush` library handles:
- ECDH key agreement (P-256)
- AES-128-GCM content encryption (RFC 8291)
- VAPID JWT creation and signing
- HTTP POST to push endpoint with correct headers

This is significantly simpler and more reliable than a manual RFC 8291 implementation.

---

## 10. Migration & Rollback

### 10.1 Feature Flags

| Flag | Default | Effect when disabled |
|------|---------|---------------------|
| `PUSH_ENABLED` | `"0"` | All push disabled (existing behavior) |
| `WEB_PUSH_ENABLED` | `"1"` | Web Push delivery disabled; FCM still works |
| `FCM_ENABLED` | `"0"` | FCM delivery disabled; Web Push still works |

### 10.2 Backward Compatibility

- Existing placeholder tokens in DDB are harmless. `web_push_send()` will fail gracefully on non-JSON tokens (line: `json.loads()` catches `JSONDecodeError`).
- The FCM delivery path in `send_push_for_alert()` remains unchanged for native mobile apps.
- Old devices with placeholder tokens will silently fail delivery and eventually be auto-revoked or expire via TTL.
- Users need to re-enable push to get real subscriptions.

### 10.3 Rollback Steps

1. Set `WEB_PUSH_ENABLED=0` -- push delivery stops for web devices immediately
2. Optionally remove `sw.js` from `frontend/public/` -- existing SW registrations remain in the browser but stop receiving pushes
3. Optionally set `PUSH_ENABLED=0` to disable all push (web + FCM)
4. Existing push subscriptions remain in DDB but are not used; they expire via TTL after 180 days

---

## 11. Testing Strategy

### 11.1 Unit Tests (pytest)

| # | Test | File | Assertion |
|---|------|------|-----------|
| 1 | VAPID key endpoint returns public key | `tests/test_web_push.py` | GET /ui/push/vapid-key returns 200 with non-empty `vapid_public_key` |
| 2 | VAPID key endpoint returns 404 when not configured | `tests/test_web_push.py` | GET returns 404 when `vapid_public_key` is empty |
| 3 | `web_push_send` returns False on invalid subscription JSON | `tests/test_web_push.py` | Returns False, no exception |
| 4 | `web_push_send` returns False on non-JSON token | `tests/test_web_push.py` | Returns False for placeholder token |
| 5 | `web_push_send` returns False when VAPID keys not configured | `tests/test_web_push.py` | Returns False when settings empty |
| 6 | `web_push_send` returns False on missing subscription fields | `tests/test_web_push.py` | Returns False for `{"endpoint": "..."}` without keys |
| 7 | `web_push_send` constructs correct payload JSON | `tests/test_web_push.py` | Payload has title, body, url, tag, timestamp |
| 8 | `send_push_for_alert` dispatches to `web_push_send` for web platform | `tests/test_web_push.py` | `web_push_send` called with correct args |
| 9 | `send_push_for_alert` dispatches to `fcm_send` for non-web platform | `tests/test_web_push.py` | `fcm_send` called, not `web_push_send` |
| 10 | `send_push_for_alert` skips disabled alert types | `tests/test_web_push.py` | No push sent when type not in user prefs |
| 11 | `send_push_for_alert` respects push rate limit | `tests/test_web_push.py` | No push sent when `can_send_alert_channel` returns False |
| 12 | 410 response auto-revokes device | `tests/test_web_push.py` | Device deleted from DDB after 410 |
| 13 | Placeholder token gracefully fails | `tests/test_web_push.py` | No crash on `web-1234567890-abc123` token |
| 14 | Register with real subscription JSON stores correctly | `tests/test_web_push.py` | Full JSON stored in `token` field |
| 15 | `_alert_url` maps types correctly | `tests/test_web_push.py` | `new_message` returns `/messages` |
| 16 | `push_device_id` produces consistent hash | `tests/test_web_push.py` | Same token always produces same device_id |
| 17 | `urlBase64ToUint8Array` correctly converts VAPID key | Integration test | 65-byte output |

### 11.2 E2E Tests

**Test File:** `frontend/e2e/web-push.spec.ts`

Note: Browser push testing in Playwright is limited. Playwright can grant notification permission via browser context options, but cannot intercept or verify actual push delivery. Tests focus on the registration flow, API behavior, and service worker serving.

**Section 1: VAPID Key API (3 tests)**

| # | Test Title | Assertion |
|---|------------|-----------|
| 1 | "VAPID key endpoint returns public key" | GET `/ui/push/vapid-key`; 200; `vapid_public_key` is non-empty string |
| 2 | "VAPID key is valid base64url encoding" | Key string contains only `[A-Za-z0-9_-]` chars |
| 3 | "VAPID key decodes to 65 bytes" | Base64url decode produces 65-byte array (0x04 + 32 + 32) |

**Section 2: Push Registration API (6 tests)**

| # | Test Title | Assertion |
|---|------------|-----------|
| 4 | "Register with valid subscription JSON succeeds" | POST `/ui/push/register` with real-format subscription; 200; `device_id` returned |
| 5 | "Register with short token is rejected" | POST with token < 20 chars; 400 |
| 6 | "List devices shows registered device" | GET `/ui/push/devices`; device with `platform=web` listed |
| 7 | "Revoke device removes it from list" | POST `/ui/push/revoke`; device no longer in list |
| 8 | "Register with same token updates existing device" | POST twice with same token; only 1 device in list |
| 9 | "Test notification endpoint succeeds" | POST `/ui/push/test`; 200 |

**Section 3: Service Worker Serving (3 tests)**

| # | Test Title | Assertion |
|---|------------|-----------|
| 10 | "sw.js is served from public directory" | Fetch `/sw.js`; 200; content-type contains `javascript` |
| 11 | "sw.js contains push event handler" | Response body includes `addEventListener("push"` |
| 12 | "sw.js contains notificationclick handler" | Response body includes `addEventListener("notificationclick"` |

**Section 4: PushDevices UI (5 tests)**

| # | Test Title | Assertion |
|---|------------|-----------|
| 13 | "Enable button is visible on alerts page" | Navigate to `/alerts`; "Enable Notifications" button visible |
| 14 | "Device count text is displayed" | "0 devices registered" text visible |
| 15 | "Device list shows registered device after API registration" | After POST register; refresh; device card visible |
| 16 | "Revoke button is visible on device card" | Device card has trash icon button |
| 17 | "Test button is visible when devices exist" | "Test" button visible |

**Section 5: Push Permission Flow (2 tests, Chromium context options)**

| # | Test Title | Assertion |
|---|------------|-----------|
| 18 | "Permission prompt appears when clicking enable" | With permissions not yet granted; click Enable; permission request fires |
| 19 | "Push subscription is created with granted permission" | With `permissions: ["notifications"]` in browser context; click Enable; device registered via API |

---

## 12. Open Questions & Risks

### 12.1 Unresolved Decisions

1. **pywebpush library vs. manual implementation**: The `pywebpush` package (MIT license) provides high-level Web Push delivery including RFC 8291 encryption. Recommendation: use `pywebpush` -- add to `requirements.txt`. Manual implementation is complex and error-prone.

2. **Push on existing alert triggers**: Which alert types should trigger push? Recommendation: all types that are enabled in the user's push preferences. The existing alert preference infrastructure already handles per-user, per-type push toggles.

3. **Notification click URL routing**: The `_alert_url()` function maps alert types to specific app URLs. This can be extended as new alert types are added.

4. **Service worker caching**: Should the SW also handle asset caching for offline support? Recommendation: **no** (Phase 2). Keep the SW focused on push events only to minimize risk.

5. **VAPID key rotation**: How to handle VAPID key rotation? Existing subscriptions are bound to the VAPID key. After rotation, all existing subscriptions become invalid. Recommendation: store VAPID key version with each subscription; on rotation, prompt users to re-enable push.

### 12.2 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| VAPID key mismatch after rotation | Medium | High | Store key version with subscription; prompt re-subscribe |
| Push endpoint changes across browser updates | Low | Medium | Auto-revoke on 410; handle `pushsubscriptionchange` SW event |
| Encryption implementation complexity | High | High | Use `pywebpush` library instead of manual RFC 8291 |
| Playwright cannot test real push delivery | High | Low | Unit test delivery with mocked HTTP; E2E tests focus on registration |
| Service worker update conflicts | Low | Medium | Use `skipWaiting()` + `clients.claim()` for immediate activation |
| Push service quota limits (Chrome: 1000/day) | Low | Low | Rate limiting already exists (20/hour per user) |

---

## 13. Files to Create

| File | Purpose |
|------|---------|
| `frontend/public/sw.js` | Service worker for push event handling and notification display |
| `frontend/src/lib/pushSetup.ts` | Service worker registration, VAPID key conversion, push subscription helpers |
| `scripts/generate_vapid_keys.py` | VAPID key pair generation utility |
| `frontend/e2e/web-push.spec.ts` | E2E tests |
| `tests/test_web_push.py` | Backend unit tests |

## 14. Files to Modify

| File | Change |
|------|--------|
| `app/services/push.py:71-155` | Add `web_push_send()`, `_alert_url()`; modify `send_push_for_alert()` to dispatch by platform (web vs FCM) |
| `app/routers/push.py` (after line 16) | Add `GET /ui/push/vapid-key` endpoint |
| `app/core/settings.py` (near line 1320) | Add `web_push_enabled: bool`, `vapid_subject: str` |
| `frontend/src/pages/alerts/PushDevices.tsx:46-74` | Replace placeholder token (line 65) with real `PushManager.subscribe()` flow |
| `frontend/src/api/endpoints/push.ts` (after line 19) | Add `getVapidKey()` function |
| `frontend/src/main.tsx` | Add service worker registration on app mount |
| `.env.local.example` | Add `PUSH_ENABLED=1`, `WEB_PUSH_ENABLED=1`, `VAPID_PUBLIC_KEY`, `VAPID_PRIVATE_KEY`, `VAPID_SUBJECT` |
| `scripts/setup_ubuntu.sh` | Auto-generate VAPID keys if not set |
| `requirements.txt` | Add `pywebpush>=2.0.0` |

---

## 15. Dependencies

### 15.1 Existing

- **Alerts system**: `app/services/alerts.py` -- calls `send_push_for_alert()` which is the delivery entry point.
- **Push router**: `app/routers/push.py:1-43` -- registration/revoke/test endpoints already registered in `app/main.py` at the `include_router` block.
- **Push DDB table**: `push_devices` table (`scripts/local-ddb-init.py:58`) -- already created.
- **cryptography package**: Already in requirements for FCM JWT signing (`push.py:37-38`) and KMS operations (`app/core/crypto.py`).
- **Rate limiting**: `can_send_alert_channel(user_sub, "push")` in `rate_limit.py:326-329`.

### 15.2 New

- **pywebpush**: Python library for RFC 8291 encryption and Web Push delivery. Add `pywebpush>=2.0.0` to `requirements.txt`. MIT license, well-maintained, widely used.

---

## 16. Acceptance Criteria

1. `frontend/public/sw.js` exists and is served at `/sw.js` with correct content-type.
2. Service worker is registered on app load via `navigator.serviceWorker.register("/sw.js")`.
3. "Enable Notifications" button calls `PushManager.subscribe()` with the server's VAPID public key.
4. Real `PushSubscription` JSON (with `endpoint`, `keys.p256dh`, `keys.auth`) is sent to `POST /ui/push/register`.
5. `GET /ui/push/vapid-key` returns the server's VAPID public key as a URL-safe base64 string.
6. `send_push_for_alert()` delivers real push notifications to web devices using the Web Push protocol.
7. Push payloads are encrypted per RFC 8291 (AES-128-GCM content encoding) by the `pywebpush` library.
8. Service worker shows browser notification with title, body, and icon on push event.
9. Clicking a push notification focuses the app tab and navigates to the type-specific URL.
10. Stale push subscriptions (410 Gone) are automatically revoked from DDB.
11. "Test" button delivers a visible push notification to the current browser.
12. Placeholder tokens from before this feature are handled gracefully (silent failure, not crash).
13. FCM delivery path remains functional for non-web platforms.
14. `WEB_PUSH_ENABLED` feature flag controls web push delivery independently from `PUSH_ENABLED`.

---

## 17. curl Examples

```bash
# Get VAPID public key (no auth required)
curl -s http://localhost:8000/ui/push/vapid-key
# {"vapid_public_key": "BNcRd..."}

# Register push device (requires auth)
curl -s -X POST -b cookies.txt -H "x-csrf-token: $CSRF" \
  -H "Content-Type: application/json" \
  http://localhost:8000/ui/push/register \
  -d '{"token": "{\"endpoint\":\"https://fcm.googleapis.com/fcm/send/test\",\"keys\":{\"p256dh\":\"BNcRd...\",\"auth\":\"tBH...\"}}","platform":"web"}'
# {"device_id": "a1b2c3...", "platform": "web", "created_at": 1748380800}

# List push devices
curl -s -b cookies.txt http://localhost:8000/ui/push/devices
# {"devices": [{"device_id": "a1b2c3...", "platform": "web", ...}]}

# Test push notification
curl -s -X POST -b cookies.txt -H "x-csrf-token: $CSRF" \
  http://localhost:8000/ui/push/test
# {"ok": true}

# Revoke push device
curl -s -X POST -b cookies.txt -H "x-csrf-token: $CSRF" \
  -H "Content-Type: application/json" \
  http://localhost:8000/ui/push/revoke \
  -d '{"device_id": "a1b2c3..."}'
# {"ok": true}

# Fetch service worker directly
curl -s -o /dev/null -w "%{http_code} %{content_type}" http://localhost:3000/sw.js
# 200 application/javascript
```

---

## Appendix A: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| Placeholder token generation | `frontend/src/pages/alerts/PushDevices.tsx` | 65 | VERIFIED: `web-${Date.now()}-${Math.random()...}` |
| No service worker in public/ | `frontend/public/` | — | VERIFIED: only favicon.svg |
| No navigator.serviceWorker in frontend | `frontend/src/` | — | VERIFIED: grep returns 0 results |
| Push router endpoints (register/revoke/test/list) | `app/routers/push.py` | 14-43 | VERIFIED |
| Push router token validation (len < 20) | `app/routers/push.py` | 24 | VERIFIED |
| Push service functions | `app/services/push.py` | 97-155 | VERIFIED |
| `fcm_access_token()` JWT assertion | `app/services/push.py` | 27-68 | VERIFIED |
| `fcm_send()` FCM HTTP v1 API | `app/services/push.py` | 71-90 | VERIFIED |
| `push_device_id()` SHA-256 hash | `app/services/push.py` | 93-94 | VERIFIED |
| `upsert_push_device()` 180-day TTL | `app/services/push.py` | 114-126 | VERIFIED |
| `send_push_for_alert()` calls `fcm_send()` only | `app/services/push.py` | 153 | VERIFIED |
| `send_push_for_alert()` silent exception | `app/services/push.py` | 154-155 | VERIFIED |
| `push_enabled` defaults to "0" | `app/core/settings.py` | 228 | VERIFIED |
| FCM settings (project_id, client_email, private_key) | `app/core/settings.py` | 229-232 | VERIFIED |
| VAPID key settings exist but empty | `app/core/settings.py` | 1320-1321 | VERIFIED |
| `push_devices` DDB table definition | `scripts/local-ddb-init.py` | 58 | VERIFIED: PK=user_sub, SK=device_id |
| Push router registered in main.py | `app/main.py` | router include block | VERIFIED |
| Push API client functions | `frontend/src/api/endpoints/push.ts` | 1-19 | VERIFIED |
| PushDevice TypeScript interface | `frontend/src/api/types.ts` | 2103-2108 | VERIFIED |
| PushRegisterReq/PushRevokeReq types | `frontend/src/api/types.ts` | 2110-2117 | VERIFIED |
| PushRegisterReq Pydantic model | `app/models.py` | 628-630 | VERIFIED |
| PushDevices handleEnable flow | `frontend/src/pages/alerts/PushDevices.tsx` | 46-74 | VERIFIED |
| Notification permission request (works correctly) | `frontend/src/pages/alerts/PushDevices.tsx` | 54-62 | VERIFIED |
| Push rate limit: 20/hour | `app/services/rate_limit.py` | 326-329 | VERIFIED |
| `sns_client()` in aws.py (for comparison) | `app/core/aws.py` | 30-37 | VERIFIED |

## Appendix B: PushSubscription JSON Reference

### Chrome (FCM)
```json
{
  "endpoint": "https://fcm.googleapis.com/fcm/send/eKBzGMxjKZ8:APA91bG...",
  "expirationTime": null,
  "keys": {
    "p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8p8nR0SZ8=",
    "auth": "tBHItJI5svbpC7SC64VQow=="
  }
}
```

### Firefox
```json
{
  "endpoint": "https://updates.push.services.mozilla.com/wpush/v2/gAAAAAB...",
  "keys": {
    "auth": "k4tR1234567890abcdef==",
    "p256dh": "BG3OGHrl3YJ5PHaYtIN2An-R1...-long-key-..."
  }
}
```

### Safari (macOS 13+)
```json
{
  "endpoint": "https://web.push.apple.com/QGuoy3...",
  "keys": {
    "p256dh": "BAl5JDDhS...",
    "auth": "4e2HS..."
  }
}
```

All major browsers use the same `PushSubscription` JSON format. The `endpoint` URL differs by push service vendor, but the protocol (RFC 8030) is the same.
