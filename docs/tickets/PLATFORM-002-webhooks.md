# PLATFORM-002: Webhook Event Delivery System

**Ticket**: PLATFORM-002
**Author**: Engineering
**Status**: Proposed
**Date**: 2026-05-27
**Priority**: Medium
**Estimated effort**: 8-10 days

---

## 1. Executive Summary

The platform generates events across dozens of domains -- messaging, billing, subscriptions, broadcasts, moderation, file management -- but external systems have no way to subscribe to these events. The only outbound notification channel is the alerts system (`app/services/alerts.py`), which supports a single hardcoded webhook URL per deployment with basic HMAC signing. Developers who want to integrate the platform with external tools (CRMs, analytics pipelines, chat bots, accounting systems) must resort to polling the API, which is inefficient, delayed, and fragile.

This design introduces a complete webhook delivery system with per-user endpoint registration, event type filtering, HMAC-SHA256 signing with per-endpoint secrets encrypted via KMS (`app/core/crypto.py`), reliable delivery with exponential backoff retries (5 attempts over ~2.5 hours), delivery logging with 30-day retention, dead letter tracking for permanently failed deliveries, and automatic endpoint disabling after 50 consecutive failures. The system is implemented as two new DynamoDB tables (`webhook_endpoints` and `webhook_deliveries`), a background dispatcher coroutine registered as a FastAPI startup task, and user-facing + admin management UIs.

The webhook delivery system operates alongside the existing alerts system rather than replacing it. Event dispatch calls are added at the same trigger points where `write_alert()` is already called. A future refactor may centralize both into a unified event bus, but this ticket takes the safer parallel approach to avoid disrupting existing alert functionality.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Developer | I want to receive HTTP notifications when a new message is sent in my conversations. | Register a webhook URL, subscribe to `message.created`, receive POST with message payload. |
| Developer | I want to verify my webhook URL is correctly configured before enabling it. | "Test" button sends a sample payload; I see the request in my server logs. |
| Developer | I want to subscribe to only billing events, not all events. | Event type multi-select; only selected types trigger deliveries. |
| Developer | I want to verify that webhook payloads are authentic and not spoofed. | `X-Webhook-Signature` header with HMAC-SHA256; I verify using my endpoint's secret. |
| Developer | I want to see whether my webhook deliveries are succeeding or failing. | Delivery log shows status, response code, attempt count, and timestamps. |
| Developer | I want to rotate my webhook signing secret without downtime. | "Rotate Secret" generates a new secret; old deliveries are already signed. |
| Admin | I want to see the overall health of webhook deliveries across all users. | Admin dashboard shows success rate, failure rate, and dead letter count. |
| Admin | I want to force-disable a misbehaving webhook that is causing excessive retries. | Admin can disable any endpoint with a reason. |

### 2.2 Pain Points

1. **No integration path**: External systems cannot react to platform events in real-time. The only option is API polling, which wastes resources and introduces latency.
2. **Single deployment-wide webhook**: The existing `ALERTS_WEBHOOK_URL` setting supports only one URL per deployment. Multi-tenant or per-user webhook registration is impossible.
3. **No delivery reliability**: The existing webhook call is fire-and-forget with no retry. If the receiver is temporarily down, the event is lost.
4. **No delivery visibility**: No way to see whether webhook deliveries succeeded or failed. Debugging integration issues is blind.
5. **Shared signing secret**: The existing `ALERTS_WEBHOOK_SECRET` is shared across the deployment. If leaked, all webhook traffic is compromised.

### 2.3 Competitive Analysis

| Platform | Approach |
|----------|----------|
| Stripe | Per-endpoint HMAC-SHA256 signing, exponential backoff retries (up to 72h), delivery log, endpoint verification via challenge |
| GitHub | Per-webhook secret, configurable event types, delivery log with response body, redeliver button |
| Twilio | Configurable event subscriptions, HMAC signing, automatic disable after consecutive failures |
| Slack | Event API with URL verification handshake, retry with exponential backoff, delivery log |

This design follows the Stripe/GitHub pattern: per-endpoint secrets, configurable event types, exponential backoff retries, and a delivery log. Endpoint verification (challenge-response) is deferred to a future iteration.

---

## 3. Current State Analysis

### 3.1 Existing Webhook Support

The alerts system has a rudimentary webhook capability configured via environment variables:

```python
# app/core/settings.py (lines 193-199) <!-- VERIFIED: all 7 settings confirmed at these lines -->
alerts_webhook_url: str = os.environ.get("ALERTS_WEBHOOK_URL", "")
alerts_webhook_secret: str = os.environ.get("ALERTS_WEBHOOK_SECRET", "")
alerts_webhook_timeout_seconds: int = int(os.environ.get("ALERTS_WEBHOOK_TIMEOUT_SECONDS", "5"))
alerts_webhook_event_types: str = os.environ.get("ALERTS_WEBHOOK_EVENT_TYPES", "")
alerts_webhook_enabled: bool = ...
alerts_webhook_max_per_window: int = ...
alerts_webhook_window_seconds: int = ...
```

And in `app/services/rate_limit.py` (line 321): <!-- VERIFIED -->
```python
def can_send_alert_channel(user_sub: str, channel: str) -> bool:
    if channel == "webhook":
        return _bucket_limit(user_sub, "rl#alert_webhook", S.alerts_webhook_max_per_window, S.alerts_webhook_window_seconds)
```

### 3.2 Alert Event Types

`app/services/alerts.py` defines `ALERT_EVENT_TYPES` (line 46) with 30+ event types across login, MFA, device trust, calendar, tickets, social, and billing domains. <!-- VERIFIED --> The webhook system will reuse these event types and add additional ones specific to webhook use cases.

### 3.3 KMS Encryption

`app/core/crypto.py` provides `kms_encrypt()` (line 16) and `kms_decrypt()` (line 22) functions for encrypting and decrypting secrets using the KMS mock (port 7999 in dev). Webhook signing secrets will be encrypted at rest using these functions. <!-- VERIFIED -->

### 3.4 Background Tasks

The platform already runs several background tasks registered in `main.py` (lines 323-328): <!-- VERIFIED -->
- `start_scheduled_messages_task()` (messaging scheduler) <!-- VERIFIED: app/routers/messaging.py:12020 → creates `_messaging_background_loop()` asyncio task -->
- `start_broadcast_scheduler_task()` (broadcast scheduler) <!-- CORRECTED: was `run_broadcast_scheduler_loop()`, which is the internal loop function. The startup function registered in main.py is `start_broadcast_scheduler_task()` (app/services/broadcast_scheduler.py:68). -->
- `newsfeed_startup()` (newsfeed scheduler) <!-- CORRECTED: was `run_scheduler_loop()`, which is the synchronous scheduler function. The startup function registered in main.py:323 is `newsfeed_startup` (imported from app/routers/newsfeed.py:2039). `run_scheduler_loop()` exists in app/services/newsfeed_scheduler.py:369 but is not directly registered as a startup event. -->

The webhook dispatcher will follow the same pattern: an `async def run_webhook_dispatcher_loop()` registered via `app.add_event_handler("startup", ...)`.

### 3.5 Gaps

1. No per-user webhook registration
2. No event type filtering per endpoint
3. No retry logic for failed deliveries
4. No delivery logging or visibility
5. No per-endpoint HMAC signing secrets
6. No dead letter queue
7. No test endpoint for webhook verification

---

## 4. Technical Architecture

### 4.1 System Diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│                      Platform Event Sources                            │
│                                                                        │
│  messaging.py ──┐    billing.py ──┐    broadcast.py ──┐                │
│  newsfeed.py ───┤    alerts.py ───┤    catalog.py ────┤                │
│  moderation.py ─┘    social.py ───┘    filemanager.py ┘                │
│        │                   │                   │                        │
│        └───────────┬───────┘                   │                        │
│                    │                           │                        │
│              write_alert() ────────────────────┘                        │
│                    │                                                    │
│        ┌───────────▼──────────────────┐                                │
│        │   dispatch_webhook_event()   │  ← Added alongside write_alert │
│        │   (in-process, synchronous)  │                                │
│        └───────────┬──────────────────┘                                │
│                    │                                                    │
│        ┌───────────▼──────────────────┐                                │
│        │  DDB: webhook_endpoints      │  Query by event type (GSI)     │
│        │  (per-user endpoint config)  │                                │
│        └───────────┬──────────────────┘                                │
│                    │                                                    │
│        ┌───────────▼──────────────────┐                                │
│        │  DDB: webhook_deliveries     │  Write delivery record         │
│        │  status=pending              │  (status=pending)              │
│        └───────────┬──────────────────┘                                │
│                    │                                                    │
│        ┌───────────▼──────────────────┐                                │
│        │  Webhook Dispatcher          │  Background loop (10s poll)    │
│        │  (startup task in main.py)   │                                │
│        │                              │                                │
│        │  1. Query ByStatus GSI:      │                                │
│        │     pending + failed,        │                                │
│        │     next_retry_at <= now     │                                │
│        │  2. For each due delivery:   │                                │
│        │     a. Decrypt endpoint      │                                │
│        │        secret (KMS)          │                                │
│        │     b. Sign payload (HMAC)   │                                │
│        │     c. POST to URL           │                                │
│        │     d. Log attempt result    │                                │
│        │     e. On fail: schedule     │                                │
│        │        retry or dead letter  │                                │
│        └──────────────────────────────┘                                │
│                                                                        │
│  ┌───────────────────────────────────────────┐                         │
│  │  External Receiver                         │                         │
│  │                                            │                         │
│  │  POST /my-webhook                          │                         │
│  │  Headers:                                  │                         │
│  │    X-Webhook-Signature: sha256=abc123      │                         │
│  │    X-Webhook-Timestamp: 1700000000         │                         │
│  │    X-Webhook-Event: message.created        │                         │
│  │    X-Webhook-Delivery-Id: del_xyz          │                         │
│  │  Body: { id, type, created_at, data }      │                         │
│  └───────────────────────────────────────────┘                         │
└────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Data Flow

1. **Event occurs**: A platform event triggers (e.g., message sent, payment received).
2. **Dispatch**: The event source calls `dispatch_webhook_event(user_sub, event_type, data)` alongside the existing `write_alert()` call.
3. **Endpoint lookup**: The dispatcher queries the `webhook_endpoints` table for endpoints subscribed to this event type.
4. **Delivery creation**: For each matching endpoint, a delivery record is created in `webhook_deliveries` with `status=pending`.
5. **Background processing**: The dispatcher loop picks up pending deliveries, decrypts the endpoint secret, signs the payload, and POSTs to the URL.
6. **Result logging**: The delivery record is updated with the response code, body snippet, and status.
7. **Retry on failure**: If the POST fails (timeout, non-2xx response), the delivery is scheduled for retry with exponential backoff.
8. **Dead letter**: After 5 failed attempts, the delivery is moved to `dead_letter` status.
9. **Auto-disable**: If an endpoint accumulates 50 consecutive failures, it is automatically disabled.

---

## 5. Data Model Deep Dive

### 5.1 Table: `webhook_endpoints`

| Attribute | Type | Description |
|-----------|------|-------------|
| `pk` | S | `USER#{user_sub}` |
| `sk` | S | `ENDPOINT#{endpoint_id}` |
| `endpoint_id` | S | UUID (`wh_<uuid4_hex>`) |
| `user_sub` | S | Owner |
| `url` | S | HTTPS URL to deliver to |
| `description` | S | User-provided label |
| `secret` | S | KMS-encrypted HMAC signing secret (base64) |
| `event_types` | SS | Set of subscribed event types |
| `enabled` | BOOL | Whether this endpoint is active |
| `created_at` | N | Unix timestamp |
| `updated_at` | N | Unix timestamp |
| `last_delivery_at` | N | Unix timestamp of last successful delivery |
| `failure_count` | N | Consecutive failures (reset on success) |
| `disabled_reason` | S | If auto-disabled, the reason |

**Event type index items** (same table, different PK pattern):

| Attribute | Type | Description |
|-----------|------|-------------|
| `pk` | S | `EVENT#{event_type}` |
| `sk` | S | `ENDPOINT#{endpoint_id}` |
| `endpoint_id` | S | Reference to endpoint |
| `user_sub` | S | Endpoint owner |
| `url` | S | Endpoint URL (denormalized for efficiency) |
| `enabled` | BOOL | Endpoint enabled flag (denormalized) |

This is a single-table design where the same table holds both endpoint configuration items (PK: `USER#...`) and event-type index items (PK: `EVENT#...`). When an endpoint is created with event types `["message.created", "payment.received"]`, two additional items are written with `pk=EVENT#message.created` and `pk=EVENT#payment.received`.

### 5.2 Table: `webhook_deliveries`

| Attribute | Type | Description |
|-----------|------|-------------|
| `pk` | S | `ENDPOINT#{endpoint_id}` |
| `sk` | S | `DELIVERY#{delivery_id}` |
| `delivery_id` | S | UUID (`wd_<uuid4_hex>`) |
| `endpoint_id` | S | Target endpoint |
| `user_sub` | S | Endpoint owner |
| `event_type` | S | Event that triggered the delivery |
| `event_id` | S | Unique event identifier (`evt_<uuid4_hex>`) |
| `payload` | S | JSON-serialized event payload |
| `status` | S | `pending`, `success`, `failed`, `dead_letter` |
| `attempt_count` | N | Number of delivery attempts so far |
| `max_attempts` | N | Maximum attempts (default 5) |
| `next_retry_at` | N | Unix timestamp for next retry |
| `last_attempt_at` | N | Unix timestamp of last attempt |
| `last_response_code` | N | HTTP status code from last attempt |
| `last_response_body` | S | First 500 chars of response body |
| `last_error` | S | Error message if delivery failed |
| `created_at` | N | Unix timestamp |
| `ttl_epoch` | N | DDB TTL; auto-expire after 30 days |

### 5.3 Table Definitions for local-ddb-init.py

```python
TableDef(
    _resolve_table_name(S.webhook_endpoints_table_name, "webhook_endpoints"),
    "pk",
    "sk",
),
TableDef(
    _resolve_table_name(S.webhook_deliveries_table_name, "webhook_deliveries"),
    "pk",
    "sk",
    gsi=[
        {"index_name": "ByStatus", "partition_key": "status", "sort_key": "next_retry_at"},
        {"index_name": "ByUser", "partition_key": "user_sub", "sort_key": "created_at"},
    ],
    attr_types={"next_retry_at": "N", "created_at": "N"},
),
```

**Critical note**: `next_retry_at` and `created_at` are numeric (Unix timestamps). They must be declared in `attr_types` or DynamoDB will store them as strings, causing `ValidationException` when queried with integer values.

### 5.4 Example DynamoDB Items

**Webhook endpoint:**
```json
{
  "pk": "USER#alice-sub-001",
  "sk": "ENDPOINT#wh_a1b2c3d4e5f6789012345678abcdef01",
  "endpoint_id": "wh_a1b2c3d4e5f6789012345678abcdef01",
  "user_sub": "alice-sub-001",
  "url": "https://hooks.example.com/my-webhook",
  "description": "Production notification handler",
  "secret": "AQIDAHhBase64EncryptedSecret==",
  "event_types": ["message.created", "payment.received"],
  "enabled": true,
  "created_at": 1748361600,
  "updated_at": 1748361600,
  "last_delivery_at": 1748365200,
  "failure_count": 0
}
```

**Event type index item:**
```json
{
  "pk": "EVENT#message.created",
  "sk": "ENDPOINT#wh_a1b2c3d4e5f6789012345678abcdef01",
  "endpoint_id": "wh_a1b2c3d4e5f6789012345678abcdef01",
  "user_sub": "alice-sub-001",
  "url": "https://hooks.example.com/my-webhook",
  "enabled": true
}
```

**Webhook delivery (pending):**
```json
{
  "pk": "ENDPOINT#wh_a1b2c3d4e5f6789012345678abcdef01",
  "sk": "DELIVERY#wd_f1e2d3c4b5a6987654321098fedcba01",
  "delivery_id": "wd_f1e2d3c4b5a6987654321098fedcba01",
  "endpoint_id": "wh_a1b2c3d4e5f6789012345678abcdef01",
  "user_sub": "alice-sub-001",
  "event_type": "message.created",
  "event_id": "evt_abc123",
  "payload": "{\"id\":\"evt_abc123\",\"type\":\"message.created\",\"created_at\":1748361600,\"data\":{}}",
  "status": "pending",
  "attempt_count": 0,
  "max_attempts": 5,
  "next_retry_at": 1748361600,
  "created_at": 1748361600,
  "ttl_epoch": 1750953600
}
```

### 5.5 Access Patterns Table

| Access Pattern | Table | Key Condition | Notes |
|----------------|-------|---------------|-------|
| List user's endpoints | `webhook_endpoints` | PK = `USER#{user_sub}` | Range query on sk prefix `ENDPOINT#` |
| Get single endpoint | `webhook_endpoints` | PK = `USER#{user_sub}`, SK = `ENDPOINT#{id}` | Single-item get |
| Find endpoints for event type | `webhook_endpoints` | PK = `EVENT#{event_type}` | Range query on sk prefix `ENDPOINT#` |
| List deliveries for endpoint | `webhook_deliveries` | PK = `ENDPOINT#{endpoint_id}` | Range query, most recent first |
| Find due deliveries | `webhook_deliveries` GSI `ByStatus` | PK = `pending`, SK <= `now_ts()` | Dispatcher poll query |
| Find failed deliveries due for retry | `webhook_deliveries` GSI `ByStatus` | PK = `failed`, SK <= `now_ts()` | Dispatcher retry query |
| List user's delivery history | `webhook_deliveries` GSI `ByUser` | PK = `user_sub`, SK range | Admin/user history query |

---

## 6. API Contract Design

### 6.1 User Endpoints (require_ui_session) <!-- VERIFIED: require_ui_session at app/services/sessions.py:283 -->

| Method | Path | Description |
|--------|------|-------------|
| POST | `/ui/webhooks` | Register a new webhook endpoint |
| GET | `/ui/webhooks` | List user's webhook endpoints |
| GET | `/ui/webhooks/{endpoint_id}` | Get endpoint details |
| PATCH | `/ui/webhooks/{endpoint_id}` | Update endpoint |
| DELETE | `/ui/webhooks/{endpoint_id}` | Delete endpoint |
| POST | `/ui/webhooks/{endpoint_id}/test` | Send a test delivery |
| GET | `/ui/webhooks/{endpoint_id}/deliveries` | List delivery history |
| POST | `/ui/webhooks/{endpoint_id}/rotate-secret` | Generate new signing secret |
| GET | `/ui/webhooks/event-types` | List all available event types |

### 6.2 Admin Endpoints (root role via require_ui_session) <!-- CORRECTED: `require_root_session` does not exist. Use `require_ui_session` and check `ctx["role"] == "root"`. -->

| Method | Path | Description |
|--------|------|-------------|
| GET | `/ui/admin/webhooks/endpoints` | List all endpoints across users |
| GET | `/ui/admin/webhooks/health` | Delivery health summary |
| GET | `/ui/admin/webhooks/dead-letter` | List dead letter entries |
| POST | `/ui/admin/webhooks/dead-letter/{delivery_id}/retry` | Retry a dead letter |
| POST | `/ui/admin/webhooks/endpoints/{endpoint_id}/disable` | Force-disable endpoint |

### 6.3 Create Webhook Endpoint (POST /ui/webhooks)

**Request:**
```json
{
  "url": "https://hooks.example.com/my-webhook",
  "description": "Production handler",
  "event_types": ["message.created", "payment.received", "subscription.created"]
}
```

**Response (201):**
```json
{
  "endpoint_id": "wh_a1b2c3d4e5f6789012345678abcdef01",
  "url": "https://hooks.example.com/my-webhook",
  "description": "Production handler",
  "event_types": ["message.created", "payment.received", "subscription.created"],
  "enabled": true,
  "secret": "whsec_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
  "created_at": 1748361600,
  "failure_count": 0
}
```

**Note**: The `secret` field is only returned on create and rotate-secret. Subsequent GET requests return `secret: null`.

**Error responses:**

| Status | Condition | Body |
|--------|-----------|------|
| 400 | URL is not HTTPS | `{ "detail": "URL must use HTTPS" }` |
| 400 | Invalid event type | `{ "detail": "Unknown event type: invalid.type" }` |
| 409 | Max 10 endpoints per user | `{ "detail": "Maximum webhook endpoints reached (10)" }` |

### 6.4 Test Delivery (POST /ui/webhooks/{endpoint_id}/test)

**Request**: No body.

**Response (200):**
```json
{
  "delivery_id": "wd_test_abc123",
  "status": "success",
  "response_code": 200,
  "response_body": "{\"ok\":true}",
  "error": null,
  "duration_ms": 234
}
```

**Failed test (200):**
```json
{
  "delivery_id": "wd_test_abc123",
  "status": "failed",
  "response_code": null,
  "response_body": null,
  "error": "Connection refused: https://hooks.example.com/my-webhook",
  "duration_ms": 5012
}
```

### 6.5 Webhook Delivery Payload

```json
{
  "id": "evt_abc123def456",
  "type": "message.created",
  "created_at": 1700000000,
  "data": {
    "conversation_id": "conv_xyz",
    "message_id": "msg_123",
    "sender_id": "user_456",
    "text": "Hello!",
    "created_at": 1700000000
  }
}
```

### 6.6 HMAC Signature Headers

```
X-Webhook-Signature: sha256=<hex_digest>
X-Webhook-Timestamp: <unix_timestamp>
X-Webhook-Event: <event_type>
X-Webhook-Delivery-Id: <delivery_id>
```

Signature computation:
```python
message = f"{timestamp}.{json_payload}"
signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
```

The receiver should verify the signature and reject deliveries where `abs(now - timestamp) > 300` (5-minute replay window).

### 6.7 Rate Limits

- Endpoint creation: Max 10 endpoints per user (configurable via `WEBHOOKS_MAX_ENDPOINTS_PER_USER`).
- Test delivery: Max 10 test deliveries per endpoint per hour (standard rate limiting).
- Delivery dispatch: No per-endpoint rate limit; bounded by the dispatcher's batch size (50 per poll cycle).

---

## 7. Event Types

### 7.1 Available Event Types

```python
WEBHOOK_EVENT_TYPES = {
    # Messaging
    "message.created": "A new message was sent in a conversation you participate in",
    "message.updated": "A message was edited or its metadata changed",
    "conversation.created": "A new conversation was started with you",

    # Billing
    "payment.received": "A payment was received (tip, unlock, subscription)",
    "payment.failed": "A payment attempt failed",
    "subscription.created": "A new subscription was created",
    "subscription.cancelled": "A subscription was cancelled",
    "subscription.renewed": "A subscription was renewed",
    "wallet.deposit": "A wallet deposit was completed",

    # Newsfeed
    "post.created": "A new post was published",
    "post.comment": "A comment was added to your post",
    "post.reaction": "A reaction was added to your post",
    "post.tip": "A tip was sent on your post",

    # Broadcast
    "broadcast.started": "A broadcast went live",
    "broadcast.stopped": "A broadcast ended",
    "broadcast.scheduled": "A broadcast was scheduled",

    # Account
    "account.login": "A new login to your account",
    "account.mfa_change": "MFA device added or removed",
    "account.profile_update": "Profile was updated",

    # Moderation
    "moderation.action": "A moderation action was taken on your content",

    # Files
    "file.uploaded": "A new file was uploaded",
    "file.shared": "A file was shared with you",

    # Webhook system
    "webhook.test": "Test event for verifying webhook configuration",
}
```

---

## 8. Webhook Delivery Engine

### 8.1 Retry Schedule

| Attempt | Delay | Total elapsed |
|---------|-------|---------------|
| 1 | Immediate | 0 |
| 2 | 1 minute | 1 min |
| 3 | 5 minutes | 6 min |
| 4 | 30 minutes | 36 min |
| 5 | 2 hours | 2h 36m |

```python
RETRY_DELAYS_SECONDS = [0, 60, 300, 1800, 7200]
```

After attempt 5, the delivery is moved to `dead_letter` status.

### 8.2 Auto-Disable Threshold

If an endpoint accumulates 50 consecutive failures:
- `enabled` set to `False`
- `disabled_reason` set to `"auto_disabled_consecutive_failures"`
- Alert sent to the user via `write_alert()`
- The user must manually re-enable the endpoint

### 8.3 Delivery Timeout

- Connection timeout: 5 seconds
- Read timeout: 10 seconds
- Total timeout: 15 seconds

### 8.4 Dispatcher Background Task

```python
# app/services/webhook_dispatcher.py

POLL_INTERVAL_SECONDS = 10
MAX_BATCH_SIZE = 50

async def run_webhook_dispatcher_loop():
    """Background coroutine that processes pending webhook deliveries."""
    while True:
        try:
            now = now_ts()
            # Query ByStatus GSI for pending deliveries
            due_pending = query_due_deliveries(status="pending", now=now, limit=MAX_BATCH_SIZE)
            # Query ByStatus GSI for failed deliveries due for retry
            due_retry = query_due_deliveries(status="failed", now=now, limit=MAX_BATCH_SIZE)
            due = due_pending + due_retry

            for delivery in due:
                try:
                    endpoint = get_endpoint_by_id(delivery["endpoint_id"], delivery["user_sub"])
                    if not endpoint or not endpoint.get("enabled"):
                        mark_delivery_dead_letter(delivery, reason="endpoint_disabled")
                        continue

                    secret = kms_decrypt(endpoint["secret"]).decode("utf-8")
                    result = await deliver_webhook(
                        url=endpoint["url"],
                        payload=delivery["payload"],
                        secret=secret,
                        delivery_id=delivery["delivery_id"],
                        event_type=delivery["event_type"],
                    )

                    if result["success"]:
                        mark_delivery_success(delivery, result)
                        reset_endpoint_failure_count(endpoint["endpoint_id"], endpoint["user_sub"])
                    else:
                        handle_delivery_failure(delivery, endpoint, result)
                except Exception:
                    logger.exception("Webhook delivery error for %s", delivery["delivery_id"])

        except Exception:
            logger.exception("Webhook dispatcher loop error")

        await asyncio.sleep(POLL_INTERVAL_SECONDS)
```

### 8.5 Registration in main.py

```python
# app/main.py
from app.services.webhook_dispatcher import run_webhook_dispatcher_loop

async def start_webhook_dispatcher_task():
    if S.webhooks_enabled:
        asyncio.create_task(run_webhook_dispatcher_loop())

app.add_event_handler("startup", start_webhook_dispatcher_task)
```

---

## 9. Frontend Component Design

### 9.1 Component Tree

```
SettingsPage (/settings)
  └── WebhooksPage (/settings/webhooks)
        ├── "Create Webhook" Button → WebhookForm Dialog
        ├── Empty State ("No webhooks configured")
        └── EndpointCard[] (per endpoint)
              ├── URL (masked middle), description
              ├── Event type badges
              ├── Status indicator (enabled/disabled/error)
              ├── Last delivery time
              ├── Actions: Edit / Delete / Test / Rotate Secret
              └── Expandable: WebhookDeliveryLog
                    ├── Filter by status (success/failed/dead_letter)
                    └── DeliveryRow[] (paginated)
                          ├── Event type, status badge, response code
                          ├── Timestamp, attempt count
                          └── Expandable: full payload, response body

AdminPage (/admin)
  └── AdminWebhooksPage (/admin/webhooks)
        ├── Health summary cards (success rate, failure rate, dead letter count)
        ├── All endpoints table (sortable, filterable)
        └── Dead letter queue (retry/dismiss actions)
```

### 9.2 Routes

```typescript
// App.tsx
{ path: "/settings/webhooks", element: <WebhooksPage /> }
{ path: "/admin/webhooks", element: <AdminWebhooksPage /> }
```

### 9.3 React Query Keys

```typescript
["webhooks"]                          // User's endpoints list
["webhook", endpointId]               // Single endpoint detail
["webhook", endpointId, "deliveries"] // Delivery log
["webhooks", "event-types"]           // Available event types
["admin", "webhooks", "health"]       // Admin health summary
["admin", "webhooks", "dead-letter"]  // Admin dead letter list
```

### 9.4 WebhookForm Component

- URL input with HTTPS validation (pattern: `^https://`)
- Description text input (max 200 chars)
- Event type multi-select with grouped categories:
  - Messaging: `message.created`, `message.updated`, `conversation.created`
  - Billing: `payment.received`, `payment.failed`, `subscription.*`, `wallet.deposit`
  - Newsfeed: `post.*`
  - Broadcast: `broadcast.*`
  - Account: `account.*`
  - Moderation: `moderation.action`
  - Files: `file.*`
- "Test" button to verify URL before saving
- On submit: `POST /ui/webhooks`, display secret in a copyable field with a warning that it won't be shown again

### 9.5 WebhookDeliveryLog Component

- Table columns: Event type | Status (color-coded badge) | Response Code | Attempts | Timestamp
- Click to expand: Full JSON payload, response body snippet (first 500 chars), error message
- Filter by status: All / Success / Failed / Dead Letter
- Pagination with cursor (uses `["webhook", endpointId, "deliveries"]` query key)

---

## 10. Security & Privacy Considerations

### 10.1 HTTPS Requirement

Webhook URLs must use HTTPS. HTTP URLs are rejected at creation time. This prevents credentials and payload data from being transmitted in plaintext.

### 10.2 Secret Management

- Signing secrets are 32 random bytes, Base64-encoded.
- Secrets are encrypted at rest using KMS (`kms_encrypt()` from `app/core/crypto.py`).
- The plaintext secret is returned only once (on creation or rotation).
- The encrypted secret is stored in DDB and decrypted only at delivery time.

### 10.3 Replay Prevention

The `X-Webhook-Timestamp` header allows receivers to reject deliveries older than 5 minutes:

```python
if abs(time.time() - int(timestamp_header)) > 300:
    return Response(status_code=403, content="Replay detected")
```

### 10.4 Payload PII

Webhook payloads may contain user-generated content (message text, profile data). To reduce PII exposure:
- Payloads include only the minimum data needed to identify the event.
- Message text is truncated to 200 characters in webhook payloads.
- Sensitive fields (passwords, tokens) are never included.
- A future enhancement may offer a "headers only" mode that sends event metadata without content.

### 10.5 SSRF Prevention

The webhook dispatcher POSTs to user-provided URLs. To prevent Server-Side Request Forgery:
- URLs must be HTTPS (no HTTP, no custom protocols).
- URLs must not resolve to private/internal IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, ::1).
- DNS resolution is checked before the HTTP request.

---

## 11. Performance & Scalability

### 11.1 Query Costs

- **Event dispatch (find matching endpoints)**: 1 DDB query per event type on `webhook_endpoints` table (PK = `EVENT#{type}`). Typically returns 0-10 items. Cost: 0.5 RCU per query.
- **Delivery creation**: 1 DDB `put_item` per endpoint per event. For an event matching 5 endpoints: 5 WCU.
- **Dispatcher poll**: 2 DDB queries on `webhook_deliveries` GSI `ByStatus` (one for `pending`, one for `failed`). Cost: 1 RCU total for typical batch sizes.
- **Delivery update**: 1 DDB `update_item` per delivery attempt. Cost: 1 WCU.

### 11.2 Throughput Estimation

- **Events per second**: Estimated 10-50 events/second at peak for a busy deployment.
- **Deliveries per second**: With average 2 endpoints per event, this is 20-100 deliveries/second.
- **Dispatcher capacity**: The 10-second poll interval with batch size 50 processes ~5 deliveries/second. This is sufficient for moderate traffic. For higher throughput, reduce poll interval or increase batch size.

### 11.3 Known Bottlenecks

- **Hot partition on ByStatus GSI**: All pending deliveries share `status=pending` as their partition key. At high volume, this can become a hot partition. Mitigation: shard the status key (e.g., `pending#0` through `pending#9`) and fan-out reads across shards.
- **KMS decryption latency**: Each delivery requires a KMS decrypt call (~10ms). For high-throughput deployments, consider caching decrypted secrets in-memory with a short TTL (60 seconds).
- **HTTP client connection pool**: The dispatcher should use a connection pool (via `httpx.AsyncClient` with `limits=httpx.Limits(max_connections=50)`) to avoid creating a new TCP connection for each delivery.

---

## 12. Migration & Rollback Plan

### 12.1 Feature Flag

`WEBHOOKS_ENABLED` (default `true`) controls the entire feature:
- When `false`: CRUD endpoints return 403, dispatcher does not start, no deliveries are created.
- Existing webhook endpoints and delivery history are preserved in DDB.

### 12.2 Incremental Deployment

| Day | Task | Impact |
|-----|------|--------|
| 1 | Deploy DDB tables + settings + table handles | No user impact |
| 2 | Deploy webhook service + router + dispatcher | Feature available but no endpoints registered yet |
| 3 | Deploy frontend WebhooksPage | Users can register endpoints |
| 4 | Add `dispatch_webhook_event()` calls alongside existing `write_alert()` calls | Events start flowing to registered endpoints |
| 5 | Deploy admin dashboard | Admin monitoring available |

### 12.3 Rollback Steps

1. Set `WEBHOOKS_ENABLED=false`. Dispatcher stops, no new deliveries created.
2. Existing endpoints and delivery history remain in DDB (no data loss).
3. Remove `dispatch_webhook_event()` calls from event sources (code revert).
4. Restart backend.

---

## 13. Testing Strategy

### 13.1 Unit Tests (pytest)

| Test | Module | Description |
|------|--------|-------------|
| `test_create_endpoint` | `webhooks.py` | Endpoint created with KMS-encrypted secret |
| `test_create_endpoint_http_rejected` | `webhooks.py` | HTTP URL rejected |
| `test_create_endpoint_max_limit` | `webhooks.py` | 11th endpoint returns 409 |
| `test_event_type_index_items` | `webhooks.py` | N index items created for N event types |
| `test_hmac_signature` | `webhook_dispatcher.py` | Signature matches expected HMAC-SHA256 |
| `test_retry_schedule` | `webhook_dispatcher.py` | Failed delivery scheduled with correct backoff delay |
| `test_dead_letter_after_max_retries` | `webhook_dispatcher.py` | 5th failure moves to dead_letter |
| `test_auto_disable_threshold` | `webhook_dispatcher.py` | 50th consecutive failure disables endpoint |
| `test_success_resets_failure_count` | `webhook_dispatcher.py` | Successful delivery resets failure_count to 0 |
| `test_dispatch_event_matches_endpoints` | `webhooks.py` | Event dispatch finds correct endpoints by type |

### 13.2 E2E Test Matrix

**File**: `frontend/e2e/webhooks.spec.ts`

**Section A: Webhook CRUD API (6 tests)**

1. `User creates a webhook endpoint` -- POST returns endpoint_id + secret
2. `URL must be HTTPS` -- POST with http:// URL returns 400
3. `User lists their endpoints` -- GET returns array with created endpoint
4. `User updates endpoint event types` -- PATCH modifies event_types
5. `User deletes endpoint` -- DELETE returns 204, GET returns 404
6. `Max 10 endpoints per user` -- 11th creation returns 409

**Section B: Webhook Delivery API (5 tests)**

1. `Test delivery to mock server succeeds` -- POST test, verify status=success
2. `Test delivery to non-existent URL fails` -- POST test, verify status=failed with error
3. `Delivery log shows test event` -- GET deliveries, verify test event present
4. `Secret rotation invalidates old secret` -- Rotate, verify new secret differs
5. `Event types list returns all available types` -- GET event-types, verify non-empty

**Section C: Webhook Signature (3 tests)**

1. `Delivery includes X-Webhook-Signature header` -- Verify header present in test delivery
2. `Signature verifies with endpoint secret` -- Compute expected HMAC, compare
3. `Delivery includes X-Webhook-Timestamp and X-Webhook-Event headers`

**Section D: Admin Webhooks API (4 tests)**

1. `Admin lists all endpoints across users` -- GET returns endpoints from multiple users
2. `Admin views delivery health summary` -- GET health returns success/failure rates
3. `Admin can force-disable an endpoint` -- POST disable changes enabled=false
4. `Non-admin cannot access admin webhook endpoints` -- Alice gets 403

**Section E: Webhooks UI (4 tests)**

1. `Webhooks page loads with empty state` -- Navigate, verify "No webhooks" message
2. `Create webhook form validates HTTPS` -- Enter http URL, verify validation error
3. `Created webhook appears in list` -- Create via form, verify card visible
4. `Delivery log shows test event after test button click`

---

## 14. Monitoring & Alerting

### 14.1 Metrics to Track

| Metric | Type | Description |
|--------|------|-------------|
| `webhook_delivery_total` | Counter | Total deliveries, labeled by `status` (success, failed, dead_letter) |
| `webhook_delivery_latency_seconds` | Histogram | HTTP round-trip time for each delivery attempt |
| `webhook_delivery_retry_total` | Counter | Total retry attempts |
| `webhook_endpoint_total` | Gauge | Total registered endpoints, labeled by `enabled` (true/false) |
| `webhook_dead_letter_total` | Counter | Deliveries moved to dead letter |
| `webhook_auto_disable_total` | Counter | Endpoints auto-disabled due to consecutive failures |
| `webhook_dispatcher_poll_duration_seconds` | Histogram | Time per dispatcher poll cycle |
| `webhook_dispatcher_batch_size` | Histogram | Number of deliveries processed per poll cycle |

### 14.2 Dashboard Queries

- **Delivery success rate**: `rate(webhook_delivery_total{status="success"}[5m]) / rate(webhook_delivery_total[5m])` -- target >95%.
- **Dead letter rate**: `rate(webhook_dead_letter_total[1h])` -- should be <1% of total deliveries.
- **Average delivery latency**: `histogram_quantile(0.50, webhook_delivery_latency_seconds)` -- P50 should be <2s.

### 14.3 Alert Thresholds

| Alert | Condition | Severity |
|-------|-----------|----------|
| Delivery success rate low | Success rate < 90% for 10 minutes | Warning |
| Dead letter spike | >50 dead letters in 1 hour | Warning |
| Dispatcher stalled | `webhook_dispatcher_poll_duration_seconds` not updated for 60s | Critical |
| Auto-disable surge | >5 endpoints auto-disabled in 1 hour | Warning |

---

## 15. Open Questions & Risks

### 15.1 Unresolved Decisions

1. **Event bus refactor scope**: Should all existing `write_alert()` calls be routed through a centralized event bus, or should webhooks be a parallel system? **Recommendation**: Start parallel (add `dispatch_webhook_event()` alongside `write_alert()`), refactor to centralized bus later.

2. **Webhook payload PII**: Message content in webhook payloads could be sensitive. Should we offer a "headers only" mode that sends event metadata without message text?

3. **IP allowlisting for webhook sources**: Should we publish a list of source IPs that webhook deliveries originate from, so receivers can allowlist?

4. **Webhook endpoint verification**: Stripe and GitHub require endpoint ownership verification (challenge-response handshake). Should we implement this to prevent a user from registering someone else's URL? **Recommendation**: Defer to Phase 2.

5. **Async vs sync test delivery**: The test endpoint currently delivers synchronously. For consistency with the queue model, should tests also go through the queue?

### 15.2 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| ByStatus GSI hot partition at high volume | Medium | High | Shard status key in future iteration |
| KMS decrypt latency at scale | Low | Medium | In-memory secret cache with short TTL |
| Slow/hanging receiver URLs block dispatcher | Medium | Medium | Async HTTP client with connection pool + per-request timeout |
| SSRF via user-provided webhook URLs | Low | High | Block private IP ranges, require HTTPS |

### 15.3 Dependency Risks

- **`httpx` or `aiohttp`**: Async HTTP client needed for non-blocking delivery. Must be added as a project dependency. `httpx` is preferred (supports HTTP/2, connection pooling, timeout configuration).
- **KMS availability**: In dev mode, the mock KMS server (port 7999) must be running. Secrets cannot be encrypted/decrypted without it.

---

## 16. Settings / Configuration

### 16.1 New Settings (app/core/settings.py)

```python
# Webhooks
webhook_endpoints_table_name: str = os.environ.get("WEBHOOK_ENDPOINTS_TABLE_NAME", "webhook_endpoints")
webhook_deliveries_table_name: str = os.environ.get("WEBHOOK_DELIVERIES_TABLE_NAME", "webhook_deliveries")
webhooks_enabled: bool = os.environ.get("WEBHOOKS_ENABLED", "1") not in ("0", "false", "False")
webhooks_max_endpoints_per_user: int = int(os.environ.get("WEBHOOKS_MAX_ENDPOINTS_PER_USER", "10"))
webhooks_delivery_timeout_seconds: int = int(os.environ.get("WEBHOOKS_DELIVERY_TIMEOUT_SECONDS", "15"))
webhooks_max_retries: int = int(os.environ.get("WEBHOOKS_MAX_RETRIES", "5"))
webhooks_auto_disable_threshold: int = int(os.environ.get("WEBHOOKS_AUTO_DISABLE_THRESHOLD", "50"))
webhooks_dispatcher_poll_interval: int = int(os.environ.get("WEBHOOKS_DISPATCHER_POLL_INTERVAL", "10"))
webhooks_delivery_ttl_days: int = int(os.environ.get("WEBHOOKS_DELIVERY_TTL_DAYS", "30"))
```

### 16.2 New Table Handles (app/core/tables.py)

```python
webhook_endpoints: Any
webhook_deliveries: Any

# In T initialization:
webhook_endpoints=ddb.Table(S.webhook_endpoints_table_name),
webhook_deliveries=ddb.Table(S.webhook_deliveries_table_name),
```

---

## 17. Implementation Timeline

| Day | Task | Deliverable |
|-----|------|-------------|
| 1 | Add settings to `settings.py`; add table definitions to `local-ddb-init.py`; add handles to `tables.py` | Infrastructure |
| 2 | Create `app/services/webhooks.py` (endpoint CRUD, event matching, secret management) | Service layer |
| 3 | Create `app/services/webhook_dispatcher.py` (delivery engine, retry logic, dead letter) | Dispatcher |
| 4 | Create `app/routers/webhooks.py` (user CRUD + test endpoints) | User API |
| 4 | Create `app/routers/admin_webhooks.py` (admin monitoring endpoints) | Admin API |
| 5 | Add `dispatch_webhook_event()` calls alongside `write_alert()` in event sources | Event integration |
| 5 | Register dispatcher in `main.py`; add Pydantic models to `models.py` | Wiring |
| 6 | Create `frontend/src/pages/settings/WebhooksPage.tsx` and `WebhookForm.tsx` | Frontend pages |
| 7 | Create `WebhookDeliveryLog.tsx` and `AdminWebhooksPage.tsx` | Frontend detail views |
| 7 | Create `frontend/src/api/endpoints/webhooks.ts` and TypeScript types | Frontend API |
| 8 | Add routes to `App.tsx`; add "Webhooks" link to settings sidebar | Navigation |
| 9-10 | Write E2E tests (`webhooks.spec.ts`, 22 tests) | E2E suite |

---

## 18. Dependencies

| Dependency | Reason |
|------------|--------|
| `app/core/crypto.py` | KMS encrypt/decrypt for webhook signing secrets |
| `app/services/alerts.py::write_alert()` | Notify user when endpoint is auto-disabled |
| `app/main.py` | Register dispatcher background task |
| `app/core/settings.py::S` | Configuration via environment variables |
| `app/auth/deps.py` | Auth for user and admin endpoints |
| `httpx` | Async HTTP client for webhook delivery (new pip dependency) |

---

## 19. Acceptance Criteria

1. User can register a webhook endpoint with an HTTPS URL and event type subscriptions.
2. Each endpoint receives a unique HMAC signing secret, encrypted at rest with KMS.
3. Platform events matching the endpoint's subscriptions are delivered with HMAC-SHA256 signature.
4. Failed deliveries are retried up to 5 times with exponential backoff.
5. Permanently failed deliveries are moved to dead letter status.
6. Endpoints with 50 consecutive failures are automatically disabled with an alert to the user.
7. User can view delivery history with status, response code, and error details.
8. Admin can view health summary and force-disable endpoints.
9. Test delivery endpoint sends a synchronous test payload and returns the result.
10. All 22 E2E tests pass.
11. Feature can be disabled via `WEBHOOKS_ENABLED=false`.

---

## Appendix: Codebase Citations

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `alerts_webhook_url` setting | `app/core/settings.py` | 203 | VERIFIED |
| `can_send_alert_channel()` | `app/services/rate_limit.py` | 321 | VERIFIED |
| `ALERT_EVENT_TYPES` | `app/services/alerts.py` | 133 | VERIFIED |
| `write_alert()` | `app/services/alerts.py` | 355 | VERIFIED |
| `send_alert_webhook()` | `app/services/alerts.py` | 600 | VERIFIED |
| `_post_webhook_with_retry()` | `app/services/alerts.py` | 565 | VERIFIED (3 retries with exponential backoff) |
| `kms_encrypt()` | `app/core/crypto.py` | 16 | VERIFIED |
| `kms_decrypt()` | `app/core/crypto.py` | 22 | VERIFIED |
| `sha256_str()` | `app/core/crypto.py` | 13 | VERIFIED |
| `start_scheduled_messages_task()` | `app/routers/messaging.py` | 12594 | VERIFIED |
| `start_broadcast_scheduler_task()` | `app/services/broadcast_scheduler.py` | 84 | VERIFIED |
| `run_broadcast_scheduler_loop()` | `app/services/broadcast_scheduler.py` | 16 | VERIFIED (internal async loop) |
| `newsfeed_startup` | `app/routers/newsfeed.py` | 2155 | VERIFIED (registered at main.py:374) |
| Background task registration in main.py | `app/main.py` | 374-378 | VERIFIED |
| `require_ui_session` | `app/services/sessions.py` | 283 | VERIFIED |
| `require_root_session` | N/A | N/A | CORRECTED: does not exist; use `require_ui_session` + role check |
| `get_authenticated_user` | `app/auth/deps.py` | 184 | VERIFIED |
| `now_ts()` | `app/core/time.py` | 2 | VERIFIED |
| `TableDef` dataclass | `scripts/local-ddb-init.py` | 29 | VERIFIED |
| `_resolve_table_name()` | `scripts/local-ddb-init.py` | 38 | VERIFIED |
| `attr_types` for numeric GSI sort keys | `scripts/local-ddb-init.py` | e.g., 247, 517 | VERIFIED (critical for `next_retry_at` and `created_at` GSI sort keys) |
| Settings dataclass | `app/core/settings.py` | entire file | VERIFIED (proposed new settings do not exist yet) |
| Tables dataclass | `app/core/tables.py` | entire file | VERIFIED (proposed new table handles do not exist yet) |
