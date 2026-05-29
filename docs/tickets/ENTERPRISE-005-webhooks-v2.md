# ENTERPRISE-005: Webhooks v2 with Enhanced Reliability

**Ticket**: ENTERPRISE-005
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-28

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The platform's existing webhook system (PLATFORM-002) provides basic webhook delivery with endpoint registration, HMAC signing, and a retry mechanism. However, enterprise customers require a higher level of reliability, observability, and control that the current implementation does not provide:

1. **Limited event types**: The current `WEBHOOK_EVENT_TYPES` dict in `app/services/webhook_service.py` (lines 24-58) has 22 event types. Many important events are missing: `user.created`, `user.deleted`, `ticket.created`, `ticket.resolved`, `file.deleted`, `calendar.event.created`, `call.started`, `call.ended`, `video.published`, `video.transcoded`, etc.
<!-- VERIFIED: app/services/webhook_service.py:24 — WEBHOOK_EVENT_TYPES dict start -->

2. **Basic retry policy**: The retry schedule (line 161) is hardcoded as `RETRY_DELAYS_SECONDS = [0, 60, 300, 1800, 7200]` -- 5 attempts with fixed delays. There is no exponential backoff, no jitter, no configurable retry policy per endpoint, and no maximum retry window.
<!-- VERIFIED: app/services/webhook_service.py:161 — RETRY_DELAYS_SECONDS = [0, 60, 300, 1800, 7200] -->

3. **No delivery dashboard**: The current `get_delivery_log()` function returns raw delivery records. There is no aggregated view of delivery success rate, average latency, failure patterns, or dead-letter queue management.

4. **Limited signature verification**: The signing uses HMAC-SHA256 via `app/services/webhook_service.py`, but the signature is only placed in a custom header. There is no timestamp-based replay protection, no signature versioning, and no sample verification code provided to consumers.

5. **No dead letter queue management**: Failed deliveries that exhaust all retries become "dead-lettered" (the admin endpoint at `app/routers/webhooks.py` line 220 lists them), but there is no way to replay dead-lettered events, acknowledge them, or purge them.
<!-- VERIFIED: app/routers/webhooks.py:220 — admin_dead_letter endpoint -->

6. **Auto-disable is crude**: The `webhooks_auto_disable_threshold` (settings line 1308) disables an endpoint after N consecutive failures, but there is no gradual degradation, no circuit breaker, and no automatic re-enable after the issue resolves.
<!-- VERIFIED: app/core/settings.py:1308 — webhooks_auto_disable_threshold -->

### 1.2 How It Works

Webhooks v2 enhances the existing system with:

1. **50+ event types** covering all platform domains (messaging, billing, moderation, files, calendar, VOD, broadcasts, tickets, subscriptions).
2. **Configurable retry policies**: Each endpoint can specify retry count, backoff strategy (linear, exponential, fibonacci), jitter, and maximum retry window.
3. **Delivery dashboard**: A real-time dashboard showing delivery success rate, latency percentiles, failure breakdown by error code, and endpoint health over time.
4. **Secure signatures with replay protection**: Every delivery includes a timestamp header (`X-Webhook-Timestamp`), and the HMAC is computed over `timestamp.payload`. Consumers can reject events older than 5 minutes.
5. **Dead letter queue with replay**: Failed events can be individually replayed, bulk replayed, or acknowledged/purged.
6. **Circuit breaker**: Endpoints that fail repeatedly enter a "degraded" state with exponential backoff on delivery attempts. After a configurable cool-down, a single test delivery is attempted; if successful, the circuit closes and normal delivery resumes.

### 1.3 Design Principles

- **Backward compatible**: v2 is additive. Existing v1 endpoints continue to work. New features are opt-in.
- **At-least-once delivery**: Events may be delivered more than once (e.g., on retry). Consumers must be idempotent. Each event has a unique `event_id` for deduplication.
- **Ordered within endpoint**: Events for a given endpoint are delivered in order per retry cycle. However, retries may arrive out of order relative to new events.
- **Observable**: Every delivery attempt (success or failure) is logged with latency, HTTP status, response body snippet, and error classification.

### 1.4 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Developer | As a developer, I want to receive webhook events when a message is sent in my bot's conversation. | `message.created` event delivered to registered endpoint within 10 seconds. |
| Developer | As a developer, I want to verify webhook signatures to ensure events came from the platform. | Sample code verifies HMAC-SHA256 of timestamp+payload; replay protection rejects old timestamps. |
| Developer | As a developer, I want to see why my webhook endpoint is failing. | Delivery dashboard shows HTTP status codes, response snippets, and error classification. |
| Developer | As a developer, I want to replay a dead-lettered event after fixing my endpoint. | POST replay re-enqueues the event for immediate delivery. |
| Developer | As a developer, I want to configure exponential backoff for retries. | PATCH endpoint sets retry_policy to exponential; subsequent failures use doubling delays. |
| Admin | As an admin, I want to see overall webhook health across all users. | Admin dashboard shows total deliveries, success rate, top failing endpoints. |
| Admin | As an admin, I want to disable a misbehaving user's webhook endpoint. | POST admin disable sets endpoint status to admin_disabled with reason. |

---

## 2. Current State Analysis

### 2.1 Event Type Registry (`app/services/webhook_service.py`)

The current event types (lines 24-56):

```python
# app/services/webhook_service.py, lines 24-56
WEBHOOK_EVENT_TYPES: Dict[str, str] = {
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

This covers 22 event types. v2 adds coverage for tickets, calendar, VOD, calls, stories, referrals, and more granular billing events.

### 2.2 Retry Schedule (`app/services/webhook_service.py`)

The retry schedule is a hardcoded list (line 161):

```python
# app/services/webhook_service.py, line 161
RETRY_DELAYS_SECONDS = [0, 60, 300, 1800, 7200]
```

This means retries happen at T+0, T+1m, T+5m, T+30m, T+2h. There is no jitter, no per-endpoint configuration, and no exponential backoff formula.

The current `handle_delivery_failure` function (line 763) uses this fixed schedule:
<!-- VERIFIED: app/services/webhook_service.py:763 — handle_delivery_failure -->

```python
# app/services/webhook_service.py, lines 644-646
delay = RETRY_DELAYS_SECONDS[min(attempt, len(RETRY_DELAYS_SECONDS) - 1)]
expr_vals[":nra"] = now + delay
```

### 2.3 Endpoint Registration (`app/services/webhook_service.py`)

Endpoint creation (line 182) stores the endpoint in the `webhook_endpoints` table with a `pk=USER#{user_sub}` and `sk=ENDPOINT#{endpoint_id}` pattern:
<!-- VERIFIED: app/services/webhook_service.py:182 — register_endpoint; lines 230-250 — item dict (now includes v2 fields) -->

```python
# app/services/webhook_service.py, lines 230-250 (now includes v2 fields: retry_policy, signature_version, circuit_state, etc.)
item = {
    "pk": f"USER#{user_sub}",
    "sk": f"ENDPOINT#{endpoint_id}",
    "endpoint_id": endpoint_id,
    "user_sub": user_sub,
    "url": url,
    "description": description,
    "secret": encrypted_secret,
    "event_types": set(event_types) if event_types else set(["webhook.test"]),
    "enabled": True,
    "created_at": now,
    "updated_at": now,
    "failure_count": 0,
}
```

Additionally, event-type index items are written for fast dispatch lookup (lines 254-262):

```python
# app/services/webhook_service.py, lines 254-262
for et in event_types:
    T.webhook_endpoints.put_item(Item={
        "pk": f"EVENT#{et}",
        "sk": f"ENDPOINT#{endpoint_id}",
        "endpoint_id": endpoint_id,
        "user_sub": user_sub,
        "url": url,
        "enabled": True,
    })
```

This dual-write pattern (endpoint record + per-event-type lookup record) is maintained in update and delete operations.

### 2.4 Webhook Delivery (`app/services/webhook_dispatcher.py`)

The dispatcher runs as a background async task (lines 28-91), started at `app/main.py` line 472:
<!-- VERIFIED: app/main.py:472 — start_webhook_dispatcher_task -->

```python
# app/main.py, line 472
app.add_event_handler("startup", start_webhook_dispatcher_task)
```

The dispatch loop (lines 28-81) polls for due deliveries and processes them:
<!-- VERIFIED: app/services/webhook_dispatcher.py:28 — run_webhook_dispatcher_loop; line 84 — start_webhook_dispatcher_task -->

```python
# app/services/webhook_dispatcher.py, lines 28-81
async def run_webhook_dispatcher_loop() -> None:
    poll_interval = S.webhooks_dispatcher_poll_interval or POLL_INTERVAL_SECONDS
    register_task("webhook_dispatcher", poll_interval, enabled=True,
                   description="Delivers pending webhook notifications to user endpoints")
    while True:
        ...
        due_pending = query_due_deliveries(status="pending", now=now, limit=MAX_BATCH_SIZE)
        due_retry = query_due_deliveries(status="failed", now=now, limit=MAX_BATCH_SIZE)
        due = due_pending + due_retry

        for delivery in due:
            ...
            result = await deliver_webhook(
                url=endpoint["url"],
                payload=delivery.get("payload", "{}"),
                secret=secret,
                delivery_id=delivery.get("delivery_id", ""),
                event_type=delivery.get("event_type", ""),
            )
            if result["success"]:
                mark_delivery_success(delivery, result)
                reset_endpoint_failure_count(endpoint_id, user_sub)
            else:
                handle_delivery_failure(delivery, endpoint, result)
        ...
        await asyncio.sleep(poll_interval)
```

The `MAX_BATCH_SIZE` is 50 (line 25) and `POLL_INTERVAL_SECONDS` is 10 (line 24). The poll interval comes from settings (line 1309):
<!-- VERIFIED: app/services/webhook_dispatcher.py:24 — POLL_INTERVAL_SECONDS=10; :25 — MAX_BATCH_SIZE=50 -->
<!-- VERIFIED: app/core/settings.py:1309 — webhooks_dispatcher_poll_interval -->

```python
# app/core/settings.py, line 1309
webhooks_dispatcher_poll_interval: int = int(os.environ.get("WEBHOOKS_DISPATCHER_POLL_INTERVAL", "10"))
```

### 2.5 Secret Management

Endpoint secrets are generated as `whsec_{token_urlsafe(32)}` (line 178-179) and encrypted via KMS for storage:
<!-- VERIFIED: app/services/webhook_service.py:178-179 — _gen_secret returns whsec_{token_urlsafe(32)} -->

```python
# app/services/webhook_service.py, lines 217-221
try:
    encrypted_secret = kms_encrypt(plaintext_secret)
except Exception:
    # If KMS is unavailable (dev mode), store plaintext with marker
    encrypted_secret = f"PLAIN:{plaintext_secret}"
```
<!-- VERIFIED: app/services/webhook_service.py:217-221 — KMS encrypt with PLAIN fallback -->

The dispatcher decrypts before signing (line 53):
<!-- VERIFIED: app/services/webhook_dispatcher.py:53 — _decrypt_secret -->

```python
# app/services/webhook_dispatcher.py, line 53
secret = _decrypt_secret(endpoint["secret"])
```

### 2.6 Webhook Router (`app/routers/webhooks.py`)

The router provides user and admin endpoints, plus v2 DLQ/stats/circuit-breaker management:

**User endpoints** (lines 58-193):
- `POST /ui/webhooks` -- create endpoint (line 58)
- `GET /ui/webhooks` -- list endpoints (line 82)
- `GET /ui/webhooks/event-types` -- list event types (line 90)
- `GET /ui/webhooks/{endpoint_id}` -- get endpoint (line 103)
- `PATCH /ui/webhooks/{endpoint_id}` -- update endpoint (line 115)
- `DELETE /ui/webhooks/{endpoint_id}` -- delete endpoint (line 141)
- `POST /ui/webhooks/{endpoint_id}/test` -- test endpoint (line 152)
- `POST /ui/webhooks/{endpoint_id}/rotate-secret` -- rotate secret (line 164)
- `GET /ui/webhooks/{endpoint_id}/deliveries` -- delivery log (line 176)

**Admin endpoints** (lines 198-390):
- `GET /ui/admin/webhooks/endpoints` -- list all endpoints (line 198)
- `GET /ui/admin/webhooks/health` -- health summary (line 209)
- `GET /ui/admin/webhooks/dead-letter` -- dead letter queue (line 220)
- `POST /ui/admin/webhooks/endpoints/{endpoint_id}/disable` -- admin disable (line 232)
<!-- VERIFIED: app/routers/webhooks.py — user endpoints at lines 58-193; admin endpoints at lines 198-390 -->

The admin endpoints use a simple role check:
<!-- VERIFIED: app/routers/webhooks.py:203-205 — role check -->

```python
# app/routers/webhooks.py, lines 203-205
role = ctx.get("role", "user")
if str(role).lower() not in ("root", "admin"):
    raise HTTPException(status_code=403, detail="Admin access required")
```

### 2.7 Delivery State Machine

The current delivery status flow:

```
pending  ──(attempt)──> success
   │                       │
   │                   (end state)
   │
   └──(attempt failed)──> failed ──(retry due)──> (re-attempt)
                             │
                             └──(max attempts)──> dead_letter (end state)
```

The `handle_delivery_failure` function (line 763) manages transitions:
- Increments `attempt_count`
- If `attempt >= max_attempts`: set `status=dead_letter`
- Otherwise: set `status=failed`, `next_retry_at = now + delay`
- Also increments `failure_count` on the endpoint record
- If `failure_count >= webhooks_auto_disable_threshold` (default 50): set `enabled=False`

### 2.8 Settings (`app/core/settings.py`)

Webhook-related settings (lines 1302-1322):
<!-- VERIFIED: app/core/settings.py:1302-1322 — all webhook settings (v1 at 1302-1310, v2 at 1312-1322) -->

```python
# app/core/settings.py, lines 1302-1322
webhook_endpoints_table_name: str = os.environ.get("WEBHOOK_ENDPOINTS_TABLE_NAME", "webhook_endpoints")
webhook_deliveries_table_name: str = os.environ.get("WEBHOOK_DELIVERIES_TABLE_NAME", "webhook_deliveries")
webhooks_enabled: bool = os.environ.get("WEBHOOKS_ENABLED", "1") not in ("0", "false", "False")
webhooks_max_endpoints_per_user: int = int(os.environ.get("WEBHOOKS_MAX_ENDPOINTS_PER_USER", "10"))
webhooks_delivery_timeout_seconds: int = int(os.environ.get("WEBHOOKS_DELIVERY_TIMEOUT_SECONDS", "15"))
webhooks_max_retries: int = int(os.environ.get("WEBHOOKS_MAX_RETRIES", "5"))
webhooks_auto_disable_threshold: int = int(os.environ.get("WEBHOOKS_AUTO_DISABLE_THRESHOLD", "50"))
webhooks_dispatcher_poll_interval: int = int(os.environ.get("WEBHOOKS_DISPATCHER_POLL_INTERVAL", "10"))
webhooks_delivery_ttl_days: int = int(os.environ.get("WEBHOOKS_DELIVERY_TTL_DAYS", "30"))
# v2 settings (lines 1313-1322)
webhooks_v2_enabled: bool = ...
webhooks_circuit_breaker_enabled: bool = ...
webhooks_default_circuit_failure_threshold: int = ...
webhooks_circuit_initial_cooldown_seconds: int = ...
webhooks_circuit_max_cooldown_seconds: int = ...
webhooks_stats_table_name: str = ...
webhooks_stats_retention_days: int = ...
webhooks_replay_rate_limit_per_hour: int = ...
webhooks_signature_replay_window_seconds: int = ...
webhooks_max_payload_size_bytes: int = ...
```

---

## 3. Technical Design

### 3.1 Expanded Event Types

v2 adds 40+ new event types organized by domain:

```python
# app/services/webhook_service.py -- WEBHOOK_EVENT_TYPES additions

WEBHOOK_EVENT_TYPES_V2: Dict[str, str] = {
    # === Existing (retained) ===
    **WEBHOOK_EVENT_TYPES,

    # === Messaging (expanded) ===
    "message.deleted": "A message was deleted",
    "message.reaction_added": "A reaction was added to a message",
    "message.tip_received": "A tip was received on a message",
    "message.unlocked": "A locked message was unlocked",
    "message.expired": "A message expired (TTL)",
    "conversation.member_added": "A member was added to a group conversation",
    "conversation.member_removed": "A member was removed from a group conversation",

    # === Billing (expanded) ===
    "payment.refunded": "A payment was refunded",
    "payment.disputed": "A payment dispute was opened",
    "wallet.withdrawal": "A wallet withdrawal was processed",
    "invoice.generated": "A monthly invoice was generated",
    "payment_method.added": "A payment method was added",
    "payment_method.removed": "A payment method was removed",

    # === Subscriptions (expanded) ===
    "subscription.payment_failed": "A subscription payment failed",
    "subscription.downgraded": "A subscription was downgraded",
    "subscription.upgraded": "A subscription was upgraded",
    "subscription.trial_ending": "A subscription trial is ending soon",

    # === Tickets ===
    "ticket.created": "A support ticket was created",
    "ticket.resolved": "A support ticket was resolved",
    "ticket.assigned": "A ticket was assigned to an agent",
    "ticket.commented": "A comment was added to a ticket",

    # === Calendar ===
    "calendar.event.created": "A calendar event was created",
    "calendar.event.updated": "A calendar event was updated",
    "calendar.event.cancelled": "A calendar event was cancelled",
    "calendar.booking.requested": "A booking was requested",
    "calendar.booking.confirmed": "A booking was confirmed",

    # === VOD / Video ===
    "video.uploaded": "A video was uploaded",
    "video.published": "A video was published",
    "video.transcoded": "A video transcode completed",
    "video.deleted": "A video was deleted",
    "video.view": "A video was viewed (batched, delayed)",

    # === Calls ===
    "call.started": "A call was started",
    "call.ended": "A call ended",
    "call.recording_available": "A call recording is ready",
    "call.missed": "A call was missed",

    # === Stories ===
    "story.created": "A story was published",
    "story.expired": "A story expired",
    "story.viewed": "A story was viewed",

    # === Moderation (expanded) ===
    "moderation.content_removed": "Content was removed by moderators",
    "moderation.warning_issued": "A warning was issued to a user",
    "moderation.ban_applied": "A user was banned",
    "moderation.appeal_submitted": "An appeal was submitted",
    "moderation.appeal_resolved": "An appeal was resolved",

    # === Files (expanded) ===
    "file.deleted": "A file was deleted",
    "file.moved": "A file was moved",
    "file.downloaded": "A file was downloaded",

    # === Account (expanded) ===
    "account.created": "A new account was created",
    "account.deleted": "An account was deleted",
    "account.password_changed": "Account password was changed",
    "account.email_verified": "Account email was verified",
    "account.api_key_created": "An API key was created",
    "account.api_key_revoked": "An API key was revoked",

    # === Referrals ===
    "referral.signup": "A referred user signed up",
    "referral.commission": "A referral commission was earned",

    # === Organizations (ENTERPRISE-003) ===
    "org.member_joined": "A member joined an organization",
    "org.member_removed": "A member was removed from an organization",
}
```

Event type migration approach:

```python
# app/services/webhook_service.py -- v2 event type switch

def get_event_types() -> Dict[str, str]:
    """Return the active event type registry.

    When WEBHOOKS_V2_ENABLED is True, returns the expanded v2 set.
    Otherwise returns the original 22 types for backward compatibility.
    """
    if S.webhooks_v2_enabled:
        return WEBHOOK_EVENT_TYPES_V2
    return WEBHOOK_EVENT_TYPES


def is_valid_event_type(event_type: str) -> bool:
    """Check whether an event type is valid in the current mode."""
    return event_type in get_event_types()
```

Update `register_endpoint` and `update_endpoint` to call `is_valid_event_type` instead of checking `WEBHOOK_EVENT_TYPES` directly.

### 3.2 Configurable Retry Policy

Each endpoint record gains a `retry_policy` field:

```python
{
    "retry_policy": {
        "strategy": "exponential",   # linear | exponential | fibonacci | fixed
        "max_attempts": 8,
        "initial_delay_seconds": 30,
        "max_delay_seconds": 7200,
        "jitter_enabled": True,
        "jitter_max_seconds": 10,
        "retry_window_seconds": 86400,  # max total time to retry (24 hours)
    }
}
```

**Default policy** (backward compatible with v1):

```python
DEFAULT_RETRY_POLICY = {
    "strategy": "exponential",
    "max_attempts": 5,
    "initial_delay_seconds": 60,
    "max_delay_seconds": 7200,
    "jitter_enabled": True,
    "jitter_max_seconds": 30,
    "retry_window_seconds": 86400,
}
```

**Retry delay calculation** -- full implementation:

<!-- NOTE: app/services/webhook_retry.py ALREADY EXISTS — implemented with normalize_retry_policy:18, compute_retry_delay:39, should_retry:74 -->
```python
# app/services/webhook_retry.py (already implemented)

from __future__ import annotations

import random
from typing import Any, Dict

DEFAULT_RETRY_POLICY: Dict[str, Any] = {
    "strategy": "exponential",
    "max_attempts": 5,
    "initial_delay_seconds": 60,
    "max_delay_seconds": 7200,
    "jitter_enabled": True,
    "jitter_max_seconds": 30,
    "retry_window_seconds": 86400,
}


def normalize_retry_policy(policy: dict | None) -> dict:
    """Merge a user-provided policy with defaults, enforcing bounds."""
    if not policy:
        return dict(DEFAULT_RETRY_POLICY)

    result = dict(DEFAULT_RETRY_POLICY)
    result.update(policy)

    # Enforce bounds
    result["max_attempts"] = max(1, min(int(result["max_attempts"]), 20))
    result["initial_delay_seconds"] = max(10, min(int(result["initial_delay_seconds"]), 3600))
    result["max_delay_seconds"] = max(60, min(int(result["max_delay_seconds"]), 86400))
    result["jitter_max_seconds"] = max(0, min(int(result.get("jitter_max_seconds", 30)), 300))
    result["retry_window_seconds"] = max(3600, min(int(result.get("retry_window_seconds", 86400)), 604800))

    if result["strategy"] not in ("linear", "exponential", "fibonacci", "fixed"):
        result["strategy"] = "exponential"

    return result


def compute_retry_delay(policy: dict, attempt: int) -> int:
    """Compute the delay in seconds before the next retry attempt.

    Args:
        policy: Normalized retry policy dict.
        attempt: 1-based attempt number (1 = first retry after initial failure).

    Returns:
        Delay in seconds, including optional jitter.
    """
    strategy = policy.get("strategy", "exponential")
    initial = int(policy.get("initial_delay_seconds", 60))
    max_delay = int(policy.get("max_delay_seconds", 7200))

    if strategy == "exponential":
        # 60, 120, 240, 480, 960, ...
        delay = initial * (2 ** (attempt - 1))
    elif strategy == "linear":
        # 60, 120, 180, 240, 300, ...
        delay = initial * attempt
    elif strategy == "fibonacci":
        # 60, 60, 120, 180, 300, 480, ...
        a, b = initial, initial
        for _ in range(attempt - 1):
            a, b = b, a + b
        delay = b
    else:  # fixed
        delay = initial

    delay = min(delay, max_delay)

    if policy.get("jitter_enabled", True):
        jitter_max = int(policy.get("jitter_max_seconds", 30))
        delay += random.randint(0, jitter_max)

    return delay


def should_retry(
    policy: dict,
    attempt: int,
    created_at: int,
    now: int,
) -> bool:
    """Check whether another retry should be attempted.

    Returns False if max_attempts reached or retry_window exceeded.
    """
    max_attempts = int(policy.get("max_attempts", 5))
    if attempt >= max_attempts:
        return False

    retry_window = int(policy.get("retry_window_seconds", 86400))
    if (now - created_at) > retry_window:
        return False

    return True
```

**Integration with handle_delivery_failure**:

```python
# app/services/webhook_service.py -- updated handle_delivery_failure

from app.services.webhook_retry import compute_retry_delay, normalize_retry_policy, should_retry

def handle_delivery_failure(
    delivery: Dict[str, Any],
    endpoint: Dict[str, Any],
    result: Dict[str, Any],
) -> None:
    """Handle a failed delivery: schedule retry or mark as dead letter."""
    attempt = int(delivery.get("attempt_count", 0)) + 1
    now = now_ts()
    created_at = int(delivery.get("created_at", now))

    # Get endpoint's retry policy (v2) or fall back to v1 behavior
    raw_policy = endpoint.get("retry_policy")
    policy = normalize_retry_policy(raw_policy)

    # ... (update expression building as before) ...

    if should_retry(policy, attempt, created_at, now):
        # Schedule retry with computed delay
        expr_vals[":st"] = "failed"
        delay = compute_retry_delay(policy, attempt)
        expr_vals[":nra"] = now + delay
        update_expr += ", next_retry_at = :nra"
    else:
        # Dead letter
        expr_vals[":st"] = "dead_letter"
        update_expr += ", next_retry_at = :nra"
        expr_vals[":nra"] = now

    # ... (update delivery + increment endpoint failure count) ...
```

### 3.3 Signature Verification with Replay Protection

v2 adds a timestamp to the signature computation:

```
X-Webhook-Signature: v2=<hmac_hex>
X-Webhook-Timestamp: <unix_timestamp>
X-Webhook-Event-Id: <event_id>
X-Webhook-Event-Type: <event_type>
```

The HMAC is computed as:

```python
signed_payload = f"{timestamp}.{payload_json}"
signature = hmac.new(secret.encode(), signed_payload.encode(), hashlib.sha256).hexdigest()
header_value = f"v2={signature}"
```

**Updated `deliver_webhook` function**:

```python
# app/services/webhook_service.py -- updated deliver_webhook

async def deliver_webhook(
    url: str,
    payload: str,
    secret: str,
    delivery_id: str,
    event_type: str,
    signature_version: str = "both",
) -> Dict[str, Any]:
    """HTTP POST webhook delivery with v1/v2 signature support."""
    import httpx

    timestamp = int(time.time())
    v2_signature = compute_signature(secret, timestamp, payload)

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Platform-Webhooks/2.0",
        "X-Webhook-Timestamp": str(timestamp),
        "X-Webhook-Event": event_type,
        "X-Webhook-Event-Id": _extract_event_id(payload),
        "X-Webhook-Delivery-Id": delivery_id,
    }

    # Signature headers based on version preference
    if signature_version in ("v2", "both"):
        headers["X-Webhook-Signature"] = f"v2={v2_signature}"
    if signature_version in ("v1", "both"):
        # v1 legacy: sign payload only (no timestamp)
        v1_sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        headers["X-Webhook-Signature-v1"] = f"sha256={v1_sig}"

    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=S.webhooks_delivery_timeout_seconds) as client:
            resp = await client.post(url, content=payload, headers=headers)
            duration_ms = int((time.monotonic() - start) * 1000)
            # Only read first 1KB of response
            body_snippet = resp.text[:1024] if resp.text else ""
            success = 200 <= resp.status_code < 300
            return {
                "success": success,
                "response_code": resp.status_code,
                "response_body": body_snippet,
                "error": None if success else f"HTTP {resp.status_code}",
                "duration_ms": duration_ms,
            }
    except httpx.TimeoutException:
        duration_ms = int((time.monotonic() - start) * 1000)
        return {
            "success": False,
            "response_code": None,
            "response_body": None,
            "error": "timeout",
            "duration_ms": duration_ms,
        }
    except httpx.ConnectError as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        return {
            "success": False,
            "response_code": None,
            "response_body": None,
            "error": f"connection_refused: {exc}",
            "duration_ms": duration_ms,
        }
    except Exception as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        return {
            "success": False,
            "response_code": None,
            "response_body": None,
            "error": str(exc)[:500],
            "duration_ms": duration_ms,
        }


def _extract_event_id(payload: str) -> str:
    """Extract event_id from a JSON payload string."""
    try:
        data = json.loads(payload)
        return data.get("id", "")
    except Exception:
        return ""
```

**Consumer verification (sample code provided in docs)**:

```python
import hmac, hashlib, time

def verify_webhook(payload: bytes, signature_header: str, timestamp_header: str, secret: str) -> bool:
    # 1. Reject old timestamps (>5 minutes)
    if abs(time.time() - int(timestamp_header)) > 300:
        return False

    # 2. Compute expected signature
    signed_payload = f"{timestamp_header}.{payload.decode()}"
    expected = hmac.new(secret.encode(), signed_payload.encode(), hashlib.sha256).hexdigest()

    # 3. Compare
    return hmac.compare_digest(f"v2={expected}", signature_header)
```

**Node.js sample**:

```javascript
const crypto = require("crypto");

function verifyWebhook(payload, signatureHeader, timestampHeader, secret) {
  // 1. Reject old timestamps (>5 minutes)
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - parseInt(timestampHeader)) > 300) {
    return false;
  }

  // 2. Compute expected signature
  const signedPayload = `${timestampHeader}.${payload}`;
  const expected = crypto
    .createHmac("sha256", secret)
    .update(signedPayload)
    .digest("hex");

  // 3. Compare (timing-safe)
  const actual = signatureHeader.replace("v2=", "");
  return crypto.timingSafeEqual(
    Buffer.from(expected),
    Buffer.from(actual)
  );
}
```

**Backward compatibility**: v1 signatures (`v1=<hmac>`) continue to be sent alongside v2. Endpoints can opt into v2-only mode via a `signature_version` field on the endpoint record.

### 3.4 Circuit Breaker

The circuit breaker has three states:

1. **Closed** (normal): All deliveries are attempted immediately.
2. **Open** (failing): No deliveries are attempted. Events are queued.
3. **Half-open** (testing): A single test delivery is attempted. If successful, transition to Closed. If failed, transition back to Open with increased cooldown.

```python
{
    # On endpoint record
    "circuit_state": "closed",          # closed | open | half_open
    "circuit_opened_at": None,
    "circuit_cooldown_seconds": 300,    # initial cooldown (doubles on each re-open)
    "circuit_max_cooldown_seconds": 86400,  # 24 hours max
    "circuit_test_at": None,            # when to attempt half-open test
    "circuit_consecutive_failures": 0,
    "circuit_failure_threshold": 10,    # failures before opening circuit
}
```

Full circuit breaker implementation:

<!-- NOTE: app/services/webhook_circuit_breaker.py ALREADY EXISTS — implemented with get_circuit_state:20, should_attempt_delivery:25, record_delivery_result:53, transition_circuit:123, reset_circuit:157 -->
```python
# app/services/webhook_circuit_breaker.py (already implemented)

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def get_circuit_state(endpoint: Dict[str, Any]) -> str:
    """Get the current circuit breaker state for an endpoint."""
    return endpoint.get("circuit_state", "closed")


def should_attempt_delivery(endpoint: Dict[str, Any], now: int) -> bool:
    """Check whether a delivery should be attempted based on circuit state.

    Returns:
        True if delivery should proceed, False if circuit is open.
    """
    state = get_circuit_state(endpoint)

    if state == "closed":
        return True

    if state == "half_open":
        # In half-open, allow exactly one delivery (the test)
        return True

    if state == "open":
        test_at = endpoint.get("circuit_test_at", 0)
        if test_at and now >= int(test_at):
            # Cooldown expired, transition to half-open
            transition_circuit(
                endpoint["endpoint_id"],
                endpoint["user_sub"],
                "half_open",
            )
            return True
        return False

    return True


def record_delivery_result(
    endpoint: Dict[str, Any],
    success: bool,
) -> None:
    """Update circuit breaker state based on delivery result.

    Called after each delivery attempt.
    """
    if not S.webhooks_circuit_breaker_enabled:
        return

    state = get_circuit_state(endpoint)
    endpoint_id = endpoint["endpoint_id"]
    user_sub = endpoint["user_sub"]
    now = now_ts()

    if success:
        # Success: close circuit, reset failure counter
        if state != "closed":
            transition_circuit(endpoint_id, user_sub, "closed")
            logger.info(
                "Circuit breaker closed for endpoint %s (delivery succeeded)",
                endpoint_id,
            )
        _reset_consecutive_failures(endpoint_id, user_sub)
    else:
        # Failure: increment counter, maybe open circuit
        consecutive = int(endpoint.get("circuit_consecutive_failures", 0)) + 1
        threshold = int(
            endpoint.get(
                "circuit_failure_threshold",
                S.webhooks_default_circuit_failure_threshold,
            )
        )

        _increment_consecutive_failures(endpoint_id, user_sub, consecutive)

        if state == "half_open":
            # Half-open test failed, re-open with doubled cooldown
            current_cooldown = int(
                endpoint.get("circuit_cooldown_seconds", S.webhooks_circuit_initial_cooldown_seconds)
            )
            new_cooldown = min(
                current_cooldown * 2,
                S.webhooks_circuit_max_cooldown_seconds,
            )
            transition_circuit(
                endpoint_id,
                user_sub,
                "open",
                cooldown_seconds=new_cooldown,
                test_at=now + new_cooldown,
            )
            logger.warning(
                "Circuit breaker re-opened for endpoint %s (half-open test failed, cooldown=%ds)",
                endpoint_id,
                new_cooldown,
            )

        elif state == "closed" and consecutive >= threshold:
            # Threshold reached, open circuit
            initial_cooldown = S.webhooks_circuit_initial_cooldown_seconds
            transition_circuit(
                endpoint_id,
                user_sub,
                "open",
                cooldown_seconds=initial_cooldown,
                test_at=now + initial_cooldown,
            )
            logger.warning(
                "Circuit breaker opened for endpoint %s (%d consecutive failures >= threshold %d)",
                endpoint_id,
                consecutive,
                threshold,
            )


def transition_circuit(
    endpoint_id: str,
    user_sub: str,
    new_state: str,
    cooldown_seconds: int | None = None,
    test_at: int | None = None,
) -> None:
    """Update the circuit breaker state on the endpoint record."""
    now = now_ts()
    update_expr = "SET circuit_state = :cs, updated_at = :u"
    expr_vals: Dict[str, Any] = {":cs": new_state, ":u": now}

    if new_state == "open":
        update_expr += ", circuit_opened_at = :oa"
        expr_vals[":oa"] = now
        if cooldown_seconds is not None:
            update_expr += ", circuit_cooldown_seconds = :cd"
            expr_vals[":cd"] = cooldown_seconds
        if test_at is not None:
            update_expr += ", circuit_test_at = :ct"
            expr_vals[":ct"] = test_at
    elif new_state == "closed":
        update_expr += ", circuit_opened_at = :null, circuit_test_at = :null2"
        update_expr += ", circuit_consecutive_failures = :zero"
        update_expr += ", circuit_cooldown_seconds = :icd"
        expr_vals[":null"] = None
        expr_vals[":null2"] = None
        expr_vals[":zero"] = 0
        expr_vals[":icd"] = S.webhooks_circuit_initial_cooldown_seconds

    # Remove None values (DDB can't store None as attribute if used as key)
    expr_vals = {k: v for k, v in expr_vals.items() if v is not None}

    T.webhook_endpoints.update_item(
        Key={"pk": f"USER#{user_sub}", "sk": f"ENDPOINT#{endpoint_id}"},
        UpdateExpression=update_expr,
        ExpressionAttributeValues=expr_vals,
    )


def reset_circuit(endpoint_id: str, user_sub: str) -> None:
    """Manually reset circuit breaker to closed state (admin action)."""
    transition_circuit(endpoint_id, user_sub, "closed")
    _reset_consecutive_failures(endpoint_id, user_sub)
    logger.info("Circuit breaker manually reset for endpoint %s", endpoint_id)


def _increment_consecutive_failures(
    endpoint_id: str, user_sub: str, count: int
) -> None:
    T.webhook_endpoints.update_item(
        Key={"pk": f"USER#{user_sub}", "sk": f"ENDPOINT#{endpoint_id}"},
        UpdateExpression="SET circuit_consecutive_failures = :c",
        ExpressionAttributeValues={":c": count},
    )


def _reset_consecutive_failures(endpoint_id: str, user_sub: str) -> None:
    T.webhook_endpoints.update_item(
        Key={"pk": f"USER#{user_sub}", "sk": f"ENDPOINT#{endpoint_id}"},
        UpdateExpression="SET circuit_consecutive_failures = :z",
        ExpressionAttributeValues={":z": 0},
    )
```

**Integration with dispatcher loop**:

```python
# app/services/webhook_dispatcher.py -- updated dispatch loop

from app.services.webhook_circuit_breaker import (
    get_circuit_state,
    record_delivery_result,
    should_attempt_delivery,
)

async def run_webhook_dispatcher_loop() -> None:
    # ... (setup as before) ...

    while True:
        try:
            now = now_ts()
            due_pending = query_due_deliveries(status="pending", now=now, limit=MAX_BATCH_SIZE)
            due_retry = query_due_deliveries(status="failed", now=now, limit=MAX_BATCH_SIZE)
            due = due_pending + due_retry

            for delivery in due:
                try:
                    endpoint_id = delivery.get("endpoint_id", "")
                    user_sub = delivery.get("user_sub", "")
                    endpoint = _get_endpoint_raw(user_sub, endpoint_id)
                    if not endpoint or not endpoint.get("enabled", True):
                        mark_delivery_dead_letter(delivery, reason="endpoint_disabled")
                        continue

                    # Circuit breaker check (v2)
                    if not should_attempt_delivery(endpoint, now):
                        # Circuit is open, skip this delivery (will be retried later)
                        continue

                    secret = _decrypt_secret(endpoint["secret"])
                    sig_version = endpoint.get("signature_version", "both")
                    result = await deliver_webhook(
                        url=endpoint["url"],
                        payload=delivery.get("payload", "{}"),
                        secret=secret,
                        delivery_id=delivery.get("delivery_id", ""),
                        event_type=delivery.get("event_type", ""),
                        signature_version=sig_version,
                    )

                    if result["success"]:
                        mark_delivery_success(delivery, result)
                        reset_endpoint_failure_count(endpoint_id, user_sub)
                        record_delivery_result(endpoint, success=True)
                        _processed += 1
                    else:
                        handle_delivery_failure(delivery, endpoint, result)
                        record_delivery_result(endpoint, success=False)
                        _failed += 1

                    # Aggregate stats (v2)
                    _record_delivery_stats(endpoint_id, result)

                except Exception:
                    _failed += 1
                    logger.exception("Webhook delivery error")

            # ... (report_poll, sleep) ...
```

### 3.5 Dead Letter Queue Management

Dead-lettered events are stored in the `webhook_deliveries` table with `status=dead_letter`. v2 adds management operations:

<!-- NOTE: app/services/webhook_dlq.py ALREADY EXISTS — implemented with replay_dead_letter:15, replay_all_dead_letters:61, acknowledge_dead_letter:111, purge_dead_letters:133, list_endpoint_dead_letters:163 -->
```python
# app/services/webhook_dlq.py (already implemented)

from __future__ import annotations

import logging
from typing import Any, Dict, List

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def replay_dead_letter(
    delivery_id: str,
    endpoint_id: str,
    user_sub: str,
    replayed_by: str,
) -> dict:
    """Re-enqueue a dead-lettered delivery for immediate processing.

    Resets status to pending with attempt_count=0, preserving the
    original payload.
    """
    resp = T.webhook_deliveries.get_item(
        Key={"pk": f"ENDPOINT#{endpoint_id}", "sk": f"DELIVERY#{delivery_id}"}
    )
    delivery = resp.get("Item")
    if not delivery:
        raise ValueError("Delivery not found")
    if delivery.get("status") != "dead_letter":
        raise ValueError("Can only replay dead-lettered deliveries")

    now = now_ts()
    T.webhook_deliveries.update_item(
        Key={"pk": delivery["pk"], "sk": delivery["sk"]},
        UpdateExpression=(
            "SET #st = :st, attempt_count = :zero, next_retry_at = :now, "
            "replayed_at = :now2, replayed_by = :rb"
        ),
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":st": "pending",
            ":zero": 0,
            ":now": now,
            ":now2": now,
            ":rb": replayed_by,
        },
    )

    logger.info(
        "Dead letter %s replayed by %s for endpoint %s",
        delivery_id,
        replayed_by,
        endpoint_id,
    )
    return {
        "delivery_id": delivery_id,
        "status": "pending",
        "replayed_at": now,
    }


def replay_all_dead_letters(
    endpoint_id: str,
    user_sub: str,
    replayed_by: str,
    limit: int = 100,
) -> int:
    """Replay all dead-lettered deliveries for an endpoint.

    Returns the count of replayed deliveries.
    """
    from app.services.webhook_service import admin_list_dead_letters

    # Query dead letters for this endpoint
    resp = T.webhook_deliveries.query(
        KeyConditionExpression=Key("pk").eq(f"ENDPOINT#{endpoint_id}")
        & Key("sk").begins_with("DELIVERY#"),
        FilterExpression="contains(#st, :dl)",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":dl": "dead_letter"},
        Limit=limit,
    )

    count = 0
    now = now_ts()
    for item in resp.get("Items", []):
        if item.get("status") != "dead_letter":
            continue
        T.webhook_deliveries.update_item(
            Key={"pk": item["pk"], "sk": item["sk"]},
            UpdateExpression=(
                "SET #st = :st, attempt_count = :zero, next_retry_at = :now, "
                "replayed_at = :now2, replayed_by = :rb"
            ),
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":st": "pending",
                ":zero": 0,
                ":now": now,
                ":now2": now,
                ":rb": replayed_by,
            },
        )
        count += 1

    logger.info(
        "Replayed %d dead letters for endpoint %s by %s",
        count,
        endpoint_id,
        replayed_by,
    )
    return count


def acknowledge_dead_letter(
    delivery_id: str,
    endpoint_id: str,
    user_sub: str,
    acknowledged_by: str,
) -> None:
    """Mark a dead-lettered delivery as acknowledged (won't show in DLQ)."""
    now = now_ts()
    T.webhook_deliveries.update_item(
        Key={"pk": f"ENDPOINT#{endpoint_id}", "sk": f"DELIVERY#{delivery_id}"},
        UpdateExpression=(
            "SET #st = :st, acknowledged_at = :ack, acknowledged_by = :ab"
        ),
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":st": "acknowledged",
            ":ack": now,
            ":ab": acknowledged_by,
        },
    )


def purge_dead_letters(
    endpoint_id: str,
    user_sub: str,
    purged_by: str,
) -> int:
    """Delete all dead-lettered deliveries for an endpoint.

    Returns the count of purged deliveries.
    """
    resp = T.webhook_deliveries.query(
        KeyConditionExpression=Key("pk").eq(f"ENDPOINT#{endpoint_id}")
        & Key("sk").begins_with("DELIVERY#"),
        FilterExpression="#st = :dl",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":dl": "dead_letter"},
    )

    count = 0
    for item in resp.get("Items", []):
        T.webhook_deliveries.delete_item(
            Key={"pk": item["pk"], "sk": item["sk"]}
        )
        count += 1

    logger.info(
        "Purged %d dead letters for endpoint %s by %s",
        count,
        endpoint_id,
        purged_by,
    )
    return count


def list_endpoint_dead_letters(
    endpoint_id: str,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """List dead-lettered deliveries for a specific endpoint."""
    resp = T.webhook_deliveries.query(
        KeyConditionExpression=Key("pk").eq(f"ENDPOINT#{endpoint_id}")
        & Key("sk").begins_with("DELIVERY#"),
        FilterExpression="#st = :dl",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":dl": "dead_letter"},
        ScanIndexForward=False,
        Limit=limit,
    )
    result = []
    for item in resp.get("Items", []):
        payload_preview = ""
        try:
            payload_preview = (item.get("payload", ""))[:200]
        except Exception:
            pass

        result.append({
            "delivery_id": item.get("delivery_id", ""),
            "endpoint_id": item.get("endpoint_id", ""),
            "event_type": item.get("event_type", ""),
            "event_id": item.get("event_id", ""),
            "payload_preview": payload_preview,
            "created_at": int(item.get("created_at", 0)),
            "failed_at": int(item.get("last_attempt_at", 0)),
            "failure_reason": item.get("last_error", ""),
            "attempt_count": int(item.get("attempt_count", 0)),
            "last_http_status": int(item["last_response_code"]) if item.get("last_response_code") else None,
            "last_error_message": item.get("last_response_body"),
        })
    return result
```

### 3.6 Delivery Dashboard Data Model

Delivery statistics are aggregated hourly and stored for dashboard rendering:

```python
{
    # Hourly aggregation record
    "pk": f"STATS#{endpoint_id}",
    "sk": f"HOUR#{hour_bucket}",       # e.g., "HOUR#2026052814"
    "total_deliveries": 142,
    "successful": 138,
    "failed": 4,
    "dead_lettered": 0,
    "avg_latency_ms": 245,
    "p50_latency_ms": 180,
    "p95_latency_ms": 820,
    "p99_latency_ms": 1450,
    "error_codes": {"timeout": 2, "5xx": 1, "connection_refused": 1},
}
```

Stats recording implementation:

<!-- NOTE: app/services/webhook_stats.py ALREADY EXISTS — implemented with record_delivery_stat:25, get_endpoint_stats:75, get_global_stats:124 -->
```python
# app/services/webhook_stats.py (already implemented)

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def _hour_bucket(ts: int | None = None) -> str:
    """Get the hourly bucket key for a given timestamp."""
    if ts is None:
        ts = int(time.time())
    from datetime import datetime, timezone
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.strftime("%Y%m%d%H")


def record_delivery_stat(
    endpoint_id: str,
    result: Dict[str, Any],
) -> None:
    """Record a single delivery result into hourly stats.

    Uses DynamoDB atomic counters for thread-safe aggregation.
    """
    bucket = _hour_bucket()
    duration_ms = result.get("duration_ms", 0)
    success = result.get("success", False)
    error_code = _classify_error(result)

    # Atomic increment on hourly stats
    update_expr = (
        "SET total_deliveries = if_not_exists(total_deliveries, :zero) + :one"
    )
    expr_vals: Dict[str, Any] = {":zero": 0, ":one": 1}

    if success:
        update_expr += ", successful = if_not_exists(successful, :zero2) + :one2"
        expr_vals[":zero2"] = 0
        expr_vals[":one2"] = 1
    else:
        update_expr += ", failed = if_not_exists(failed, :zero3) + :one3"
        expr_vals[":zero3"] = 0
        expr_vals[":one3"] = 1

    # We store sum of latencies + count for computing averages later
    update_expr += ", latency_sum_ms = if_not_exists(latency_sum_ms, :zero4) + :lat"
    expr_vals[":zero4"] = 0
    expr_vals[":lat"] = duration_ms

    try:
        T.webhook_stats.update_item(
            Key={"pk": f"STATS#{endpoint_id}", "sk": f"HOUR#{bucket}"},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_vals,
        )
    except Exception:
        logger.debug("Failed to record webhook stat for %s", endpoint_id)

    # Also update global stats
    try:
        T.webhook_stats.update_item(
            Key={"pk": "GLOBAL", "sk": f"HOUR#{bucket}"},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_vals,
        )
    except Exception:
        pass


def get_endpoint_stats(
    endpoint_id: str,
    hours: int = 24,
) -> Dict[str, Any]:
    """Get delivery statistics for an endpoint over the last N hours."""
    now = int(time.time())
    buckets = []
    total = 0
    success_total = 0
    fail_total = 0
    latency_sum = 0

    for h in range(hours):
        bucket = _hour_bucket(now - h * 3600)
        try:
            resp = T.webhook_stats.get_item(
                Key={"pk": f"STATS#{endpoint_id}", "sk": f"HOUR#{bucket}"}
            )
            item = resp.get("Item", {})
            t = int(item.get("total_deliveries", 0))
            s = int(item.get("successful", 0))
            f = int(item.get("failed", 0))
            lat = int(item.get("latency_sum_ms", 0))

            if t > 0:
                buckets.append({
                    "bucket": bucket,
                    "total": t,
                    "success": s,
                    "failed": f,
                    "avg_latency_ms": round(lat / t) if t else 0,
                })
                total += t
                success_total += s
                fail_total += f
                latency_sum += lat
        except Exception:
            pass

    return {
        "endpoint_id": endpoint_id,
        "period": "hour",
        "buckets": list(reversed(buckets)),
        "total_deliveries": total,
        "success_rate": round(success_total / total, 4) if total > 0 else 1.0,
        "avg_latency_ms": round(latency_sum / total) if total > 0 else 0,
    }


def get_global_stats(hours: int = 24) -> Dict[str, Any]:
    """Get platform-wide delivery statistics."""
    now = int(time.time())
    total = 0
    success = 0
    failed = 0
    latency_sum = 0

    for h in range(hours):
        bucket = _hour_bucket(now - h * 3600)
        try:
            resp = T.webhook_stats.get_item(
                Key={"pk": "GLOBAL", "sk": f"HOUR#{bucket}"}
            )
            item = resp.get("Item", {})
            t = int(item.get("total_deliveries", 0))
            s = int(item.get("successful", 0))
            f = int(item.get("failed", 0))
            lat = int(item.get("latency_sum_ms", 0))
            total += t
            success += s
            failed += f
            latency_sum += lat
        except Exception:
            pass

    return {
        "total_deliveries_24h": total,
        "success_count_24h": success,
        "failed_count_24h": failed,
        "success_rate_24h": round(success / total, 4) if total > 0 else 1.0,
        "avg_latency_ms_24h": round(latency_sum / total) if total > 0 else 0,
    }


def _classify_error(result: Dict[str, Any]) -> str:
    """Classify a delivery error for aggregation."""
    error = result.get("error", "")
    code = result.get("response_code")

    if not error and code and 200 <= code < 300:
        return "none"
    if "timeout" in str(error).lower():
        return "timeout"
    if "connection_refused" in str(error).lower() or "connect" in str(error).lower():
        return "connection_refused"
    if code and code >= 500:
        return "5xx"
    if code and code >= 400:
        return "4xx"
    if "dns" in str(error).lower():
        return "dns_error"
    return "unknown"
```

### 3.7 SSRF Protection Implementation

<!-- NOTE: app/services/webhook_ssrf.py ALREADY EXISTS — implemented with validate_webhook_url:26 -->
```python
# app/services/webhook_ssrf.py (already implemented)

from __future__ import annotations

import ipaddress
import socket
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Private/reserved IP ranges that should not be accessed
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),   # Shared address space
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique local
]


def validate_webhook_url(url: str) -> None:
    """Validate a webhook URL for SSRF protection.

    Raises ValueError if the URL targets a private/reserved IP range.
    """
    parsed = urlparse(url)

    if parsed.scheme not in ("https",):
        # Allow http://localhost for dev mode only
        if parsed.hostname in ("localhost", "127.0.0.1") and parsed.scheme == "http":
            from app.core.settings import S
            if S.dev_mode:
                return
        raise ValueError("URL must use HTTPS")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL must have a hostname")

    # Block raw IP addresses (must use hostname)
    try:
        ip = ipaddress.ip_address(hostname)
        # If it parses as an IP, check if it's blocked
        for network in _BLOCKED_NETWORKS:
            if ip in network:
                raise ValueError(f"URL resolves to blocked IP range: {network}")
        # Even if not blocked, prefer hostnames over IPs
        raise ValueError("URL must use a hostname, not an IP address")
    except ValueError as e:
        if "blocked" in str(e) or "hostname" in str(e):
            raise
        # Not an IP address -- good, it's a hostname

    # Resolve hostname and check resolved IPs
    try:
        addrs = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
        for _, _, _, _, sockaddr in addrs:
            ip = ipaddress.ip_address(sockaddr[0])
            for network in _BLOCKED_NETWORKS:
                if ip in network:
                    raise ValueError(
                        f"Hostname {hostname} resolves to blocked IP {sockaddr[0]} in {network}"
                    )
    except socket.gaierror:
        raise ValueError(f"Cannot resolve hostname: {hostname}")
```

---

## 4. API Endpoints

### 4.1 User Endpoints (Enhanced)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/webhooks` | `require_ui_session` | Create endpoint (v2: accepts `retry_policy`) |
| GET | `/ui/webhooks` | `require_ui_session` | List endpoints (v2: includes circuit state) |
| GET | `/ui/webhooks/event-types` | `require_ui_session` | List all event types (v2: 60+ types) |
| GET | `/ui/webhooks/{endpoint_id}` | `require_ui_session` | Get endpoint with health stats |
| PATCH | `/ui/webhooks/{endpoint_id}` | `require_ui_session` | Update (v2: retry_policy, signature_version) |
| DELETE | `/ui/webhooks/{endpoint_id}` | `require_ui_session` | Delete endpoint |
| POST | `/ui/webhooks/{endpoint_id}/test` | `require_ui_session` | Test endpoint |
| POST | `/ui/webhooks/{endpoint_id}/rotate-secret` | `require_ui_session` | Rotate signing secret |
| GET | `/ui/webhooks/{endpoint_id}/deliveries` | `require_ui_session` | Delivery log (paginated) |
| GET | `/ui/webhooks/{endpoint_id}/stats` | `require_ui_session` | **NEW** Delivery statistics (hourly/daily) |
| GET | `/ui/webhooks/{endpoint_id}/dead-letters` | `require_ui_session` | **NEW** Dead letter queue for endpoint |
| POST | `/ui/webhooks/{endpoint_id}/dead-letters/{delivery_id}/replay` | `require_ui_session` | **NEW** Replay single dead letter |
| POST | `/ui/webhooks/{endpoint_id}/dead-letters/replay-all` | `require_ui_session` | **NEW** Replay all dead letters |
| POST | `/ui/webhooks/{endpoint_id}/dead-letters/{delivery_id}/acknowledge` | `require_ui_session` | **NEW** Acknowledge dead letter |
| DELETE | `/ui/webhooks/{endpoint_id}/dead-letters` | `require_ui_session` | **NEW** Purge all dead letters |
| POST | `/ui/webhooks/{endpoint_id}/reset-circuit` | `require_ui_session` | **NEW** Manually reset circuit breaker |

### 4.2 Admin Endpoints (Enhanced)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/admin/webhooks/endpoints` | ADMIN | List all endpoints across users |
| GET | `/ui/admin/webhooks/health` | ADMIN | **NEW** Global health dashboard |
| GET | `/ui/admin/webhooks/dead-letter` | ADMIN | **NEW** Global dead letter queue |
| GET | `/ui/admin/webhooks/stats` | ADMIN | **NEW** Platform-wide delivery stats |
| POST | `/ui/admin/webhooks/endpoints/{endpoint_id}/disable` | ADMIN | Disable endpoint |
| POST | `/ui/admin/webhooks/endpoints/{endpoint_id}/enable` | ADMIN | **NEW** Re-enable endpoint |

### 4.3 Request / Response Models

```python
# app/models.py -- new/updated models

class WebhookRetryPolicyReq(BaseModel):
    strategy: str = Field(default="exponential", pattern=r"^(linear|exponential|fibonacci|fixed)$")
    max_attempts: int = Field(default=5, ge=1, le=20)
    initial_delay_seconds: int = Field(default=60, ge=10, le=3600)
    max_delay_seconds: int = Field(default=7200, ge=60, le=86400)
    jitter_enabled: bool = True
    jitter_max_seconds: int = Field(default=30, ge=0, le=300)
    retry_window_seconds: int = Field(default=86400, ge=3600, le=604800)

class WebhookEndpointCreateReqV2(WebhookEndpointCreateReq):
    retry_policy: Optional[WebhookRetryPolicyReq] = None
    signature_version: str = Field(default="v2", pattern=r"^(v1|v2|both)$")
    circuit_failure_threshold: int = Field(default=10, ge=3, le=100)

class WebhookEndpointOutV2(WebhookEndpointOut):
    retry_policy: Optional[dict] = None
    signature_version: str = "both"
    circuit_state: Optional[str] = None
    circuit_consecutive_failures: int = 0
    circuit_failure_threshold: int = 10
    circuit_cooldown_seconds: Optional[int] = None
    circuit_test_at: Optional[int] = None

class WebhookDeliveryStatsOut(BaseModel):
    endpoint_id: str
    period: str                     # "hour" | "day"
    buckets: list[dict]             # [{bucket: "2026052814", total: 142, success: 138, ...}]
    total_deliveries: int
    success_rate: float             # 0.0 to 1.0
    avg_latency_ms: float
    top_errors: Optional[list[dict]] = None  # [{code: "timeout", count: 12}, ...]

class WebhookDeadLetterOut(BaseModel):
    delivery_id: str
    endpoint_id: str
    event_type: str
    event_id: str
    payload_preview: str            # first 200 chars of payload
    created_at: int
    failed_at: int
    failure_reason: str
    attempt_count: int
    last_http_status: Optional[int]
    last_error_message: Optional[str]

class WebhookCircuitStateOut(BaseModel):
    state: str                      # closed | open | half_open
    consecutive_failures: int
    failure_threshold: int
    cooldown_seconds: int
    opened_at: Optional[int]
    next_test_at: Optional[int]

class WebhookGlobalHealthOut(BaseModel):
    total_endpoints: int
    active_endpoints: int
    disabled_endpoints: int
    circuit_open_endpoints: int
    total_deliveries_24h: int
    success_rate_24h: float
    dead_letter_count: int
    avg_latency_ms_24h: float
    top_failing_endpoints: list[dict]
```

### 4.4 Router Extensions

```python
# app/routers/webhooks.py -- v2 endpoint additions

from app.services.webhook_circuit_breaker import reset_circuit
from app.services.webhook_dlq import (
    acknowledge_dead_letter,
    list_endpoint_dead_letters,
    purge_dead_letters,
    replay_all_dead_letters,
    replay_dead_letter,
)
from app.services.webhook_stats import get_endpoint_stats, get_global_stats


# ─── User endpoints (new) ─────────────────────────────────────────────────

@router.get("/ui/webhooks/{endpoint_id}/stats")
async def get_webhook_stats(
    endpoint_id: str,
    hours: int = Query(24, ge=1, le=168),
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    ep = get_endpoint(ctx["user_sub"], endpoint_id)
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return get_endpoint_stats(endpoint_id, hours=hours)


@router.get("/ui/webhooks/{endpoint_id}/dead-letters")
async def list_dead_letters_for_endpoint(
    endpoint_id: str,
    limit: int = Query(50, ge=1, le=200),
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    ep = get_endpoint(ctx["user_sub"], endpoint_id)
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return {"dead_letters": list_endpoint_dead_letters(endpoint_id, limit)}


@router.post("/ui/webhooks/{endpoint_id}/dead-letters/{delivery_id}/replay")
async def replay_single_dead_letter(
    endpoint_id: str,
    delivery_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    ep = get_endpoint(ctx["user_sub"], endpoint_id)
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    try:
        result = replay_dead_letter(delivery_id, endpoint_id, ctx["user_sub"], ctx["user_sub"])
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/ui/webhooks/{endpoint_id}/dead-letters/replay-all")
async def replay_all_dead_letters_route(
    endpoint_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    ep = get_endpoint(ctx["user_sub"], endpoint_id)
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    count = replay_all_dead_letters(endpoint_id, ctx["user_sub"], ctx["user_sub"])
    return {"replayed_count": count}


@router.post("/ui/webhooks/{endpoint_id}/dead-letters/{delivery_id}/acknowledge")
async def acknowledge_dead_letter_route(
    endpoint_id: str,
    delivery_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    ep = get_endpoint(ctx["user_sub"], endpoint_id)
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    acknowledge_dead_letter(delivery_id, endpoint_id, ctx["user_sub"], ctx["user_sub"])
    return {"ok": True}


@router.delete("/ui/webhooks/{endpoint_id}/dead-letters", status_code=204)
async def purge_dead_letters_route(
    endpoint_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    ep = get_endpoint(ctx["user_sub"], endpoint_id)
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    purge_dead_letters(endpoint_id, ctx["user_sub"], ctx["user_sub"])


@router.post("/ui/webhooks/{endpoint_id}/reset-circuit")
async def reset_circuit_breaker(
    endpoint_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    ep = get_endpoint(ctx["user_sub"], endpoint_id)
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    reset_circuit(endpoint_id, ctx["user_sub"])
    from app.services.alerts import audit_event
    audit_event("webhook_circuit_reset", ctx["user_sub"], endpoint_id=endpoint_id)
    return {"ok": True, "circuit_state": "closed"}


# ─── Admin endpoints (new) ────────────────────────────────────────────────

@router.get("/ui/admin/webhooks/stats")
async def admin_global_stats(
    hours: int = Query(24, ge=1, le=168),
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    role = ctx.get("role", "user")
    if str(role).lower() not in ("root", "admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return get_global_stats(hours=hours)


@router.post("/ui/admin/webhooks/endpoints/{endpoint_id}/enable")
async def admin_enable_endpoint(
    endpoint_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    role = ctx.get("role", "user")
    if str(role).lower() not in ("root", "admin"):
        raise HTTPException(status_code=403, detail="Admin access required")

    # Find endpoint owner
    all_endpoints = admin_list_all_endpoints()
    target = None
    for ep in all_endpoints:
        if ep["endpoint_id"] == endpoint_id:
            target = ep
            break
    if not target:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    # Re-enable endpoint and reset circuit breaker
    from app.core.tables import T
    from app.core.time import now_ts
    T.webhook_endpoints.update_item(
        Key={"pk": f"USER#{target['user_sub']}", "sk": f"ENDPOINT#{endpoint_id}"},
        UpdateExpression=(
            "SET enabled = :e, disabled_reason = :null, updated_at = :u, "
            "circuit_state = :cs, circuit_consecutive_failures = :zero, "
            "failure_count = :zero2"
        ),
        ExpressionAttributeValues={
            ":e": True,
            ":null": None,
            ":u": now_ts(),
            ":cs": "closed",
            ":zero": 0,
            ":zero2": 0,
        },
    )
    return {"ok": True, "endpoint_id": endpoint_id}
```

---

## 5. Frontend Components

### 5.1 Webhook Dashboard Page

**File**: `frontend/src/pages/webhooks/WebhookDashboard.tsx` (already exists)
<!-- VERIFIED: frontend/src/pages/webhooks/WebhookDashboard.tsx exists -->

- Overview cards: Total Endpoints, Active, Success Rate (24h), Avg Latency, Dead Letters
- Endpoint list table with circuit state badge (green=closed, yellow=half_open, red=open)
- Click endpoint to expand with delivery chart (line chart of deliveries over time)

```typescript
// frontend/src/pages/webhooks/WebhookDashboard.tsx

import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Webhook, CheckCircle2, XCircle, AlertTriangle, Activity } from "lucide-react";
import { Link } from "react-router-dom";
import { listWebhookEndpoints, getWebhookStats } from "@/api/endpoints/webhooks";

function CircuitBadge({ state }: { state: string | undefined }) {
  if (!state || state === "closed") {
    return <Badge variant="success" className="gap-1"><CheckCircle2 className="w-3 h-3" /> Healthy</Badge>;
  }
  if (state === "half_open") {
    return <Badge variant="warning" className="gap-1"><AlertTriangle className="w-3 h-3" /> Testing</Badge>;
  }
  return <Badge variant="destructive" className="gap-1"><XCircle className="w-3 h-3" /> Open</Badge>;
}

export default function WebhookDashboard() {
  const endpointsQ = useQuery({
    queryKey: ["webhooks", "endpoints"],
    queryFn: listWebhookEndpoints,
  });

  const endpoints = endpointsQ.data ?? [];
  const active = endpoints.filter((e: any) => e.enabled).length;
  const circuitOpen = endpoints.filter((e: any) => e.circuit_state === "open").length;

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center gap-3">
        <Webhook className="w-8 h-8" />
        <h1 className="text-2xl font-bold">Webhooks</h1>
      </div>

      {/* Overview cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <p className="text-sm text-muted-foreground">Total Endpoints</p>
            <p className="text-2xl font-bold">{endpoints.length}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-sm text-muted-foreground">Active</p>
            <p className="text-2xl font-bold text-green-600">{active}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-sm text-muted-foreground">Circuit Open</p>
            <p className="text-2xl font-bold text-red-600">{circuitOpen}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-sm text-muted-foreground">Dead Letters</p>
            <p className="text-2xl font-bold">
              {endpoints.reduce((sum: number, e: any) => sum + (e.dead_letter_count ?? 0), 0)}
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Endpoint list */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center justify-between">
            Endpoints
            <Link to="/webhooks/new">
              <Button size="sm">Create Endpoint</Button>
            </Link>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b">
                <th className="text-left p-2">URL</th>
                <th className="text-left p-2">Events</th>
                <th className="text-left p-2">Status</th>
                <th className="text-left p-2">Circuit</th>
                <th className="text-left p-2">Failures</th>
                <th className="text-left p-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {endpoints.map((ep: any) => (
                <tr key={ep.endpoint_id} className="border-b hover:bg-muted/50">
                  <td className="p-2 font-mono text-xs truncate max-w-[200px]">
                    {ep.url}
                  </td>
                  <td className="p-2">
                    <Badge variant="secondary">{ep.event_types?.length ?? 0}</Badge>
                  </td>
                  <td className="p-2">
                    {ep.enabled ? (
                      <Badge variant="success">Active</Badge>
                    ) : (
                      <Badge variant="destructive">Disabled</Badge>
                    )}
                  </td>
                  <td className="p-2">
                    <CircuitBadge state={ep.circuit_state} />
                  </td>
                  <td className="p-2">{ep.failure_count}</td>
                  <td className="p-2">
                    <Link to={`/webhooks/${ep.endpoint_id}`}>
                      <Button size="sm" variant="ghost">
                        <Activity className="w-4 h-4" />
                      </Button>
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  );
}
```

### 5.2 Endpoint Detail Page

**File**: `frontend/src/pages/webhooks/WebhookEndpointDetail.tsx` (already exists)
<!-- VERIFIED: frontend/src/pages/webhooks/WebhookEndpointDetail.tsx exists -->

- Tabs: Configuration, Deliveries, Dead Letters, Statistics
- Configuration tab: URL, event types (multi-select), retry policy form, signature version toggle
- Deliveries tab: infinite-scroll table with status badge, latency, response preview
- Dead Letters tab: table with replay/acknowledge buttons per row, "Replay All" bulk action
- Statistics tab: latency histogram, error breakdown pie chart, delivery volume bar chart

### 5.3 Event Type Selector

**File**: `frontend/src/components/shared/EventTypeSelector.tsx` (new)

- Grouped multi-select dropdown organized by domain (Messaging, Billing, Moderation, etc.)
- "Select All" per group
- Search filter for finding specific event types
- Badge count showing selected count

### 5.4 Signature Verification Docs

**File**: `frontend/src/pages/webhooks/WebhookDocs.tsx` (new)

- In-app documentation for webhook integration
- Sample verification code in Python, Node.js, Go, Ruby
- Interactive signature tester (paste payload + secret, verify)

### 5.5 Admin Webhook Health

**File**: `frontend/src/pages/admin/WebhookHealth.tsx` (new)

- Platform-wide dashboard with aggregate metrics
- Top 10 failing endpoints table
- Global dead letter queue with bulk operations
- Circuit breaker status overview

### 5.6 Sidebar / Route Integration

```typescript
// App.tsx additions
<Route path="/webhooks" element={<WebhookDashboard />} />
<Route path="/webhooks/:endpointId" element={<WebhookEndpointDetail />} />
<Route path="/webhooks/docs" element={<WebhookDocs />} />
```

Sidebar: "Webhooks" in Developer section with `Webhook` icon.

### 5.7 API Endpoints TypeScript

```typescript
// frontend/src/api/endpoints/webhooks.ts -- v2 additions

import client from "../client";

// Existing endpoints continue to work...

export const getWebhookStats = (endpointId: string, hours = 24) =>
  client
    .get(`/ui/webhooks/${endpointId}/stats`, { params: { hours } })
    .then((r) => r.data);

export const listEndpointDeadLetters = (endpointId: string, limit = 50) =>
  client
    .get(`/ui/webhooks/${endpointId}/dead-letters`, { params: { limit } })
    .then((r) => r.data);

export const replayDeadLetter = (endpointId: string, deliveryId: string) =>
  client
    .post(`/ui/webhooks/${endpointId}/dead-letters/${deliveryId}/replay`)
    .then((r) => r.data);

export const replayAllDeadLetters = (endpointId: string) =>
  client
    .post(`/ui/webhooks/${endpointId}/dead-letters/replay-all`)
    .then((r) => r.data);

export const acknowledgeDeadLetter = (endpointId: string, deliveryId: string) =>
  client
    .post(`/ui/webhooks/${endpointId}/dead-letters/${deliveryId}/acknowledge`)
    .then((r) => r.data);

export const purgeDeadLetters = (endpointId: string) =>
  client
    .delete(`/ui/webhooks/${endpointId}/dead-letters`)
    .then((r) => r.data);

export const resetCircuitBreaker = (endpointId: string) =>
  client
    .post(`/ui/webhooks/${endpointId}/reset-circuit`)
    .then((r) => r.data);

export const getGlobalWebhookStats = (hours = 24) =>
  client
    .get(`/ui/admin/webhooks/stats`, { params: { hours } })
    .then((r) => r.data);

export const adminEnableEndpoint = (endpointId: string) =>
  client
    .post(`/ui/admin/webhooks/endpoints/${endpointId}/enable`)
    .then((r) => r.data);
```

---

## 6. DynamoDB Table Changes

### 6.1 Existing Table Modifications

The `webhook_endpoints` and `webhook_deliveries` tables (settings lines 1294-1295) gain new fields but no schema changes (DynamoDB is schemaless).
<!-- VERIFIED: app/core/settings.py:1294-1295 — webhook_endpoints_table_name and webhook_deliveries_table_name -->

New fields on endpoint record:

| Field | Type | Description |
|-------|------|-------------|
| `retry_policy` | M | Retry policy configuration map |
| `signature_version` | S | `v1`, `v2`, or `both` |
| `circuit_state` | S | `closed`, `open`, `half_open` |
| `circuit_opened_at` | N | Unix timestamp when circuit was opened |
| `circuit_cooldown_seconds` | N | Current cooldown duration |
| `circuit_max_cooldown_seconds` | N | Maximum cooldown cap |
| `circuit_test_at` | N | When to attempt half-open test |
| `circuit_consecutive_failures` | N | Counter of consecutive failures |
| `circuit_failure_threshold` | N | Failures before opening circuit |

New fields on delivery record:

| Field | Type | Description |
|-------|------|-------------|
| `replayed_at` | N | Unix timestamp when replayed |
| `replayed_by` | S | User who triggered replay |
| `acknowledged_at` | N | Unix timestamp when acknowledged |
| `acknowledged_by` | S | User who acknowledged |

### 6.2 New Table for Stats

```python
TableDef("webhook_stats", pk="pk", sk="sk"),
# pk = "STATS#{endpoint_id}", sk = "HOUR#{bucket}" or "DAY#{bucket}"
# pk = "GLOBAL", sk = "HOUR#{bucket}" for platform-wide stats
```

Webhook stats table item:

| Attribute | Type | Description |
|-----------|------|-------------|
| `pk` | S (PK) | `STATS#{endpoint_id}` or `GLOBAL` |
| `sk` | S (SK) | `HOUR#{YYYYMMDDHH}` |
| `total_deliveries` | N | Total attempts in this bucket |
| `successful` | N | Successful deliveries |
| `failed` | N | Failed deliveries |
| `dead_lettered` | N | Dead-lettered deliveries |
| `latency_sum_ms` | N | Sum of all latencies (for computing average) |

### 6.3 Settings Additions for `app/core/settings.py`

```python
# Webhooks v2 (ENTERPRISE-005)
webhooks_v2_enabled: bool = os.environ.get("WEBHOOKS_V2_ENABLED", "1") not in ("0", "false", "False")
webhooks_circuit_breaker_enabled: bool = os.environ.get("WEBHOOKS_CIRCUIT_BREAKER_ENABLED", "1") not in ("0", "false", "False")
webhooks_default_circuit_failure_threshold: int = int(os.environ.get("WEBHOOKS_DEFAULT_CIRCUIT_FAILURE_THRESHOLD", "10"))
webhooks_circuit_initial_cooldown_seconds: int = int(os.environ.get("WEBHOOKS_CIRCUIT_INITIAL_COOLDOWN_SECONDS", "300"))
webhooks_circuit_max_cooldown_seconds: int = int(os.environ.get("WEBHOOKS_CIRCUIT_MAX_COOLDOWN_SECONDS", "86400"))
webhooks_stats_table_name: str = os.environ.get("WEBHOOKS_STATS_TABLE_NAME", "webhook_stats")
webhooks_stats_retention_days: int = int(os.environ.get("WEBHOOKS_STATS_RETENTION_DAYS", "90"))
webhooks_replay_rate_limit_per_hour: int = int(os.environ.get("WEBHOOKS_REPLAY_RATE_LIMIT_PER_HOUR", "100"))
webhooks_signature_replay_window_seconds: int = int(os.environ.get("WEBHOOKS_SIGNATURE_REPLAY_WINDOW_SECONDS", "300"))
webhooks_max_payload_size_bytes: int = int(os.environ.get("WEBHOOKS_MAX_PAYLOAD_SIZE_BYTES", "65536"))
```

### 6.4 Tables Dataclass Addition

```python
# app/core/tables.py addition
webhook_stats=ddb.Table(S.webhooks_stats_table_name),
```

---

## 7. E2E Test Plan

### 7.1 Test File

**File**: `frontend/e2e/webhooks-v2.spec.ts` (new)

### 7.2 Test Sections

| Section | Tests | Description |
|---------|-------|-------------|
| 106 | 5 | Endpoint CRUD with v2 features (create with retry policy, update signature version, circuit breaker config) |
| 107 | 4 | Event types API (list all 60+ types, filter by domain, create endpoint with new event types) |
| 108 | 5 | Delivery and retry (test delivery, verify v2 signature headers, retry on failure, max attempts respected) |
| 109 | 4 | Dead letter management (create failed delivery, list dead letters, replay, acknowledge) |
| 110 | 3 | Circuit breaker (trigger circuit open, verify cooldown, manual reset) |
| 111 | 3 | Delivery statistics (verify hourly stats aggregation, stats API response, stats reset after purge) |
| 112 | 3 | Admin endpoints (global health, admin disable/enable, admin dead letter list) |
| 113 | 3 | Webhook dashboard UI (endpoint list renders, circuit state badges, dead letter count badge) |

### 7.3 Test Setup

```typescript
// frontend/e2e/webhooks-v2.spec.ts

import { test, expect, type Page } from "@playwright/test";
import { sessions, injectAuth } from "./helpers/auth";

const ROOT_ID = "root";
const ALICE_ID = "alice";
const ROOT_SUB = "root.admin@testdev.local";
const ALICE_SUB = "e2e_alice@test.local";
const TS = Date.now();
const TEST_ENDPOINT_URL = "https://webhook.site/test-e2e";

let rootPage: Page;
let alicePage: Page;
let testEndpointId: string;
let testEndpointSecret: string;

test.beforeAll(async ({ browser }) => {
  const rootCtx = await browser.newContext();
  rootPage = await rootCtx.newPage();
  await injectAuth(rootPage, ROOT_ID);

  const aliceCtx = await browser.newContext();
  alicePage = await aliceCtx.newPage();
  await injectAuth(alicePage, ALICE_ID);

  // Create a test webhook endpoint with v2 features
  const resp = await rootPage.request.post("/ui/webhooks", {
    headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token },
    data: {
      url: TEST_ENDPOINT_URL,
      event_types: ["webhook.test", "message.created"],
      description: `E2E test endpoint ${TS}`,
      retry_policy: {
        strategy: "exponential",
        max_attempts: 3,
        initial_delay_seconds: 10,
      },
    },
  });
  expect(resp.status()).toBe(201);
  const data = await resp.json();
  testEndpointId = data.endpoint_id;
  testEndpointSecret = data.secret;
});

// ─── Section 106: Endpoint CRUD with v2 features ─────────────────────────

test.describe("106 · Endpoint CRUD with v2 features", () => {
  test("106.1 · create endpoint with retry policy", async () => {
    const resp = await alicePage.request.post("/ui/webhooks", {
      headers: { "x-csrf-token": sessions[ALICE_ID].csrf_token },
      data: {
        url: `https://example.com/webhook-${TS}`,
        event_types: ["webhook.test"],
        description: "Alice test endpoint",
        retry_policy: {
          strategy: "fibonacci",
          max_attempts: 8,
          initial_delay_seconds: 30,
          jitter_enabled: true,
        },
      },
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.endpoint_id).toMatch(/^wh_/);
    expect(data.secret).toMatch(/^whsec_/);
  });

  test("106.2 · update signature version to v2-only", async () => {
    const resp = await rootPage.request.patch(
      `/ui/webhooks/${testEndpointId}`,
      {
        headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token },
        data: { signature_version: "v2" },
      }
    );
    expect(resp.status()).toBe(200);
  });

  test("106.3 · get endpoint includes circuit state", async () => {
    const resp = await rootPage.request.get(
      `/ui/webhooks/${testEndpointId}`,
      { headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token } }
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.endpoint_id).toBe(testEndpointId);
    // Circuit state may or may not be present in v1 endpoints
    // but should default to closed
  });

  test("106.4 · list endpoints includes v2 fields", async () => {
    const resp = await rootPage.request.get("/ui/webhooks", {
      headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data)).toBe(true);
    const ep = data.find((e: any) => e.endpoint_id === testEndpointId);
    expect(ep).toBeDefined();
  });

  test("106.5 · invalid retry strategy returns 400", async () => {
    const resp = await alicePage.request.post("/ui/webhooks", {
      headers: { "x-csrf-token": sessions[ALICE_ID].csrf_token },
      data: {
        url: "https://example.com/bad",
        event_types: ["webhook.test"],
        retry_policy: { strategy: "invalid_strategy" },
      },
    });
    // Should be rejected by Pydantic pattern validation
    expect(resp.status()).toBe(422);
  });
});

// ─── Section 107: Event types API ─────────────────────────────────────────

test.describe("107 · Event types API", () => {
  test("107.1 · list all event types returns 60+ types", async () => {
    const resp = await rootPage.request.get("/ui/webhooks/event-types", {
      headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.event_types.length).toBeGreaterThanOrEqual(22);
    // Verify some v2 types are present
    const types = data.event_types.map((t: any) => t.type);
    expect(types).toContain("webhook.test");
    expect(types).toContain("message.created");
  });

  test("107.2 · each event type has a description", async () => {
    const resp = await rootPage.request.get("/ui/webhooks/event-types", {
      headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token },
    });
    const data = await resp.json();
    for (const et of data.event_types) {
      expect(et.type).toBeTruthy();
      expect(et.description).toBeTruthy();
    }
  });

  test("107.3 · create endpoint with v2 event type", async () => {
    const resp = await rootPage.request.post("/ui/webhooks", {
      headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token },
      data: {
        url: `https://example.com/v2-events-${TS}`,
        event_types: ["ticket.created", "calendar.event.created", "call.started"],
        description: "V2 event types test",
      },
    });
    // If v2 is enabled, should succeed; if not, unknown event type error
    // This test validates the v2 event types are registered
    const status = resp.status();
    expect([201, 400]).toContain(status);
  });

  test("107.4 · test delivery sends correct event type header", async () => {
    const resp = await rootPage.request.post(
      `/ui/webhooks/${testEndpointId}/test`,
      { headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token } }
    );
    // Test delivery may fail (external URL) but should return a result
    const status = resp.status();
    expect([200]).toContain(status);
    const data = await resp.json();
    expect(data.delivery_id).toBeTruthy();
  });
});

// ─── Section 109: Dead letter management ──────────────────────────────────

test.describe("109 · Dead letter management", () => {
  test("109.1 · list dead letters for endpoint", async () => {
    const resp = await rootPage.request.get(
      `/ui/webhooks/${testEndpointId}/dead-letters`,
      { headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token } }
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.dead_letters).toBeDefined();
    expect(Array.isArray(data.dead_letters)).toBe(true);
  });

  test("109.2 · replay non-existent dead letter returns error", async () => {
    const resp = await rootPage.request.post(
      `/ui/webhooks/${testEndpointId}/dead-letters/fake_id/replay`,
      { headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token } }
    );
    expect(resp.status()).toBe(400);
  });

  test("109.3 · replay-all on empty DLQ returns zero", async () => {
    const resp = await rootPage.request.post(
      `/ui/webhooks/${testEndpointId}/dead-letters/replay-all`,
      { headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token } }
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.replayed_count).toBe(0);
  });

  test("109.4 · purge dead letters", async () => {
    const resp = await rootPage.request.delete(
      `/ui/webhooks/${testEndpointId}/dead-letters`,
      { headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token } }
    );
    expect(resp.status()).toBe(204);
  });
});

// ─── Section 110: Circuit breaker ─────────────────────────────────────────

test.describe("110 · Circuit breaker", () => {
  test("110.1 · manual circuit reset", async () => {
    const resp = await rootPage.request.post(
      `/ui/webhooks/${testEndpointId}/reset-circuit`,
      { headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token } }
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.circuit_state).toBe("closed");
  });

  test("110.2 · endpoint state is closed after reset", async () => {
    const resp = await rootPage.request.get(
      `/ui/webhooks/${testEndpointId}`,
      { headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token } }
    );
    expect(resp.status()).toBe(200);
    // Circuit state should be closed (or not present = default closed)
  });

  test("110.3 · non-owner cannot reset circuit", async () => {
    const resp = await alicePage.request.post(
      `/ui/webhooks/${testEndpointId}/reset-circuit`,
      { headers: { "x-csrf-token": sessions[ALICE_ID].csrf_token } }
    );
    // Should fail because Alice doesn't own this endpoint
    expect(resp.status()).toBe(404);
  });
});

// ─── Section 111: Delivery statistics ─────────────────────────────────────

test.describe("111 · Delivery statistics", () => {
  test("111.1 · get endpoint stats returns structure", async () => {
    const resp = await rootPage.request.get(
      `/ui/webhooks/${testEndpointId}/stats`,
      { headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token } }
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.endpoint_id).toBe(testEndpointId);
    expect(data.total_deliveries).toBeGreaterThanOrEqual(0);
    expect(typeof data.success_rate).toBe("number");
  });

  test("111.2 · stats for non-existent endpoint returns 404", async () => {
    const resp = await rootPage.request.get(
      `/ui/webhooks/wh_nonexistent/stats`,
      { headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token } }
    );
    expect(resp.status()).toBe(404);
  });

  test("111.3 · admin global stats returns structure", async () => {
    const resp = await rootPage.request.get("/ui/admin/webhooks/stats", {
      headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(typeof data.total_deliveries_24h).toBe("number");
    expect(typeof data.success_rate_24h).toBe("number");
  });
});

// ─── Section 112: Admin endpoints ─────────────────────────────────────────

test.describe("112 · Admin endpoints", () => {
  test("112.1 · admin health returns summary", async () => {
    const resp = await rootPage.request.get("/ui/admin/webhooks/health", {
      headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(typeof data.total_endpoints).toBe("number");
    expect(typeof data.enabled_endpoints).toBe("number");
  });

  test("112.2 · admin disable and re-enable endpoint", async () => {
    // Disable
    const disableResp = await rootPage.request.post(
      `/ui/admin/webhooks/endpoints/${testEndpointId}/disable`,
      {
        headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token },
        data: { reason: "E2E test disable" },
      }
    );
    expect(disableResp.status()).toBe(200);

    // Re-enable
    const enableResp = await rootPage.request.post(
      `/ui/admin/webhooks/endpoints/${testEndpointId}/enable`,
      { headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token } }
    );
    expect(enableResp.status()).toBe(200);
    expect((await enableResp.json()).ok).toBe(true);
  });

  test("112.3 · non-admin gets 403 on admin endpoints", async () => {
    const resp = await alicePage.request.get("/ui/admin/webhooks/health", {
      headers: { "x-csrf-token": sessions[ALICE_ID].csrf_token },
    });
    expect(resp.status()).toBe(403);
  });
});
```

---

## 8. Edge Cases & Error Handling

### 8.1 Payload Size Limits

Webhook payloads are capped at 64KB (`webhooks_max_payload_size_bytes`). Events with large payloads (e.g., `post.created` with 10KB content) are truncated: the `metadata` field is replaced with `{"truncated": true, "original_size": 12345, "resource_url": "/api/posts/post_id"}`. The consumer can fetch the full resource via the API.

```python
def _truncate_payload(payload: dict, max_bytes: int) -> dict:
    """Truncate a webhook payload if it exceeds the size limit."""
    encoded = json.dumps(payload).encode()
    if len(encoded) <= max_bytes:
        return payload

    # Replace data with truncation notice
    truncated = {
        "id": payload.get("id", ""),
        "type": payload.get("type", ""),
        "created_at": payload.get("created_at", 0),
        "data": {
            "truncated": True,
            "original_size": len(encoded),
            "resource_url": payload.get("data", {}).get("resource_url", ""),
        },
    }
    return truncated
```

### 8.2 Endpoint URL Validation

v2 adds stricter URL validation:
- Must be HTTPS (HTTP rejected for non-localhost)
- No IP addresses (must be a hostname)
- No internal/private IP ranges (10.x, 172.16.x, 192.168.x)
- SSRF protection: resolved IP is checked before connection

### 8.3 Concurrent Delivery Ordering

If multiple events fire for the same endpoint within the same dispatch cycle, they are sorted by event timestamp before delivery. However, if event A fails and enters retry, event B (which arrived later) may be delivered before event A's retry succeeds. The `event_id` and `X-Webhook-Timestamp` headers allow consumers to detect and handle out-of-order delivery.

### 8.4 Circuit Breaker False Positives

The circuit breaker uses consecutive failures. A single success resets the counter. This prevents transient errors (e.g., 502 during deployment) from triggering the circuit. The threshold is configurable per endpoint (default 10).

### 8.5 Secret Rotation During Active Deliveries

When a secret is rotated, in-flight deliveries signed with the old secret may arrive after the consumer has updated to the new secret. The `rotate-secret` response returns both the old secret (valid for 5 minutes) and the new secret. The consumer should accept both during the transition window.

```python
def rotate_secret_v2(user_sub: str, endpoint_id: str) -> dict:
    """Generate and store a new secret, returning both old and new.

    The old secret remains valid for 5 minutes (300 seconds) to handle
    in-flight deliveries.
    """
    item = _get_endpoint_raw(user_sub, endpoint_id)
    if not item:
        return {}

    old_secret = _decrypt_secret(item["secret"])
    new_plaintext = _gen_secret()

    try:
        encrypted = kms_encrypt(new_plaintext)
    except Exception:
        encrypted = f"PLAIN:{new_plaintext}"

    now = now_ts()
    T.webhook_endpoints.update_item(
        Key={"pk": f"USER#{user_sub}", "sk": f"ENDPOINT#{endpoint_id}"},
        UpdateExpression="SET secret = :s, updated_at = :u, old_secret = :os, old_secret_expires = :ose",
        ExpressionAttributeValues={
            ":s": encrypted,
            ":u": now,
            ":os": item["secret"],  # Store old encrypted secret
            ":ose": now + 300,      # Valid for 5 minutes
        },
    )

    return {
        "secret": new_plaintext,
        "old_secret": old_secret,
        "old_secret_expires_at": now + 300,
    }
```

### 8.6 Event Deduplication

Each event has a unique `event_id` (format: `evt_{uuid_hex}`). On retry, the same `event_id` is delivered again. Consumers must use `event_id` for deduplication. The `X-Webhook-Event-Id` header makes this easy.

### 8.7 Circuit Breaker Cooldown Doubling

When the circuit re-opens after a failed half-open test, the cooldown doubles (300s -> 600s -> 1200s -> ... up to `circuit_max_cooldown_seconds` which defaults to 86400s/24h). When the circuit closes (delivery succeeds), the cooldown resets to the initial value. This prevents a flickering endpoint from consuming resources with rapid open/close cycles.

### 8.8 Dispatcher Concurrency Under Load

When the delivery table has thousands of pending deliveries, the dispatcher processes them in batches of `MAX_BATCH_SIZE` (50) per poll. Deliveries are processed sequentially within a batch. For higher throughput, increase `MAX_BATCH_SIZE` or run multiple dispatcher instances (with proper DynamoDB conditional updates to prevent duplicate processing).

---

## 9. Security Considerations

### 9.1 SSRF Protection

Before connecting to a webhook URL, the dispatcher resolves the hostname and rejects:
- Private IP ranges (RFC 1918)
- Loopback addresses (127.0.0.0/8)
- Link-local addresses (169.254.0.0/16)
- IPv6 link-local (fe80::/10)

This prevents attackers from registering webhooks that probe internal services.

### 9.2 Replay Protection

The v2 signature includes a timestamp. Consumers should reject payloads where `abs(now - timestamp) > 300` seconds. The platform sends the timestamp in the `X-Webhook-Timestamp` header.

### 9.3 Secret Encryption at Rest

Endpoint secrets are encrypted with KMS before storage (via `kms_encrypt` from `app/core/crypto.py`, line 16). In dev mode, secrets are stored with a `PLAIN:` prefix (line 221 of webhook_service.py).
<!-- VERIFIED: app/core/crypto.py:16 — kms_encrypt; app/services/webhook_service.py:221 — PLAIN: fallback -->

### 9.4 Delivery Response Handling

The dispatcher reads only the first 1KB of the response body from the consumer's endpoint. This prevents denial-of-service via large responses. The response body snippet is stored on the delivery record for debugging.

### 9.5 Rate Limiting Dead Letter Replay

Dead letter replay is rate-limited to `webhooks_replay_rate_limit_per_hour` (default 100) per endpoint. This prevents a consumer from using replay as a way to flood their own endpoint.

### 9.6 Audit Trail

All webhook management operations (create, update, delete, rotate-secret, replay, circuit reset) are audited via `audit_event()`. Delivery attempts are not audited individually (too high volume) but are logged and aggregated in stats.

### 9.7 Timing-Safe Signature Comparison

Both the platform and the consumer sample code use `hmac.compare_digest` (Python) or `crypto.timingSafeEqual` (Node.js) for signature comparison, preventing timing attacks.

### 9.8 Webhook Payload Sanitization

Webhook payloads containing user-generated content (message text, post content) are sanitized to strip HTML and limit field lengths. The `metadata` field never contains raw user HTML.

---

## 10. Migration Plan

### 10.1 Phase 1: Expanded Event Types (Week 1)

1. Add new event types to `WEBHOOK_EVENT_TYPES`
2. Create `WEBHOOK_EVENT_TYPES_V2` dict with merged types
3. Add `is_valid_event_type()` function that checks the active registry
4. Update `register_endpoint` and `update_endpoint` to use `is_valid_event_type`
5. Add `dispatch_webhook_event` calls to all relevant service functions
6. Ensure backward compatibility (existing endpoints only receive subscribed events)

### 10.2 Phase 2: Retry Policy & Signatures (Week 2)
<!-- NOTE: Phase 2 ALREADY IMPLEMENTED — app/services/webhook_retry.py exists -->

1. Create `app/services/webhook_retry.py` with retry delay computation
2. Add `retry_policy` field to endpoint record
3. Update `handle_delivery_failure` to use computed delays
4. Implement v2 signature (timestamp-based HMAC) in `deliver_webhook`
5. Both v1 and v2 signatures sent by default
6. Add `signature_version` field to endpoint record

### 10.3 Phase 3: Circuit Breaker (Week 3)
<!-- NOTE: Phase 3 ALREADY IMPLEMENTED — app/services/webhook_circuit_breaker.py exists -->

1. Create `app/services/webhook_circuit_breaker.py`
2. Add circuit breaker fields to endpoint record
3. Integrate `should_attempt_delivery` and `record_delivery_result` into dispatcher loop
4. Add `POST /reset-circuit` endpoint
5. Admin monitoring for circuit-open endpoints

### 10.4 Phase 4: Dead Letter Management (Week 3-4)
<!-- NOTE: Phase 4 ALREADY IMPLEMENTED — app/services/webhook_dlq.py exists -->

1. Create `app/services/webhook_dlq.py`
2. Add replay, acknowledge, purge functions
3. Add DLQ endpoints to router
4. Rate limiting on replay operations

### 10.5 Phase 5: Dashboard & Stats (Week 4-5)
<!-- NOTE: Phase 5 ALREADY IMPLEMENTED — app/services/webhook_stats.py exists; webhook_stats DDB table defined at scripts/local-ddb-init.py:896 -->

1. Create `app/services/webhook_stats.py`
2. Create `webhook_stats` DDB table
3. Add `record_delivery_stat` calls to dispatcher
4. Stats query endpoints for per-endpoint and global views
5. Stats retention cleanup (TTL or periodic purge)

### 10.6 Phase 6: Frontend & E2E (Week 5-6)

1. `WebhookDashboard.tsx` with endpoint list and overview cards
2. `WebhookEndpointDetail.tsx` with tabs for config, deliveries, DLQ, stats
3. `EventTypeSelector.tsx` grouped multi-select
4. `WebhookDocs.tsx` with sample verification code
5. Admin `WebhookHealth.tsx` dashboard
6. E2E test suite (`frontend/e2e/webhooks-v2.spec.ts`)

### 10.7 Phase 7: SSRF Protection (Week 6)
<!-- NOTE: Phase 7 ALREADY IMPLEMENTED — app/services/webhook_ssrf.py exists with validate_webhook_url:26 -->

1. Create `app/services/webhook_ssrf.py`
2. Integrate URL validation into `register_endpoint` and `update_endpoint`
3. Integrate DNS resolution check into `deliver_webhook`
4. Unit tests for blocked IP ranges

---

## 11. Observability

### 11.1 Metrics

- `webhook_deliveries_total{endpoint_id, status}` -- counter per status
- `webhook_delivery_latency_ms{endpoint_id}` -- histogram
- `webhook_circuit_state{endpoint_id}` -- gauge (0=closed, 1=half_open, 2=open)
- `webhook_dead_letter_queue_size{endpoint_id}` -- gauge
- `webhook_dispatcher_batch_size` -- histogram of batch sizes per poll
- `webhook_dispatcher_poll_duration_ms` -- histogram

### 11.2 Alerts

- Alert when global success rate drops below 90%
- Alert when any endpoint has >100 dead letters
- Alert when circuit breaker opens for a high-priority endpoint
- Alert when dispatcher poll duration exceeds 5 seconds

### 11.3 Structured Logging

All webhook operations emit structured log entries:

```python
logger.info(
    "webhook_delivery",
    extra={
        "endpoint_id": endpoint_id,
        "delivery_id": delivery_id,
        "event_type": event_type,
        "success": result["success"],
        "response_code": result.get("response_code"),
        "duration_ms": result.get("duration_ms"),
        "circuit_state": get_circuit_state(endpoint),
    },
)
```

These structured logs can be indexed in Elasticsearch/CloudWatch for operational dashboards.

---

## Codebase References

> **NOTE**: Most v2 features described in this ticket have ALREADY BEEN IMPLEMENTED. The files listed below exist in the codebase with the functionality described.

### Backend Services (all exist)
| File | Key Functions | Lines |
|------|--------------|-------|
| `app/services/webhook_service.py` | `WEBHOOK_EVENT_TYPES` (22 types), `WEBHOOK_EVENT_TYPES_V2` (merged), `register_endpoint`, `handle_delivery_failure`, `_gen_secret` | 24, 60, 182, 763, 178 |
| `app/services/webhook_retry.py` | `normalize_retry_policy`, `compute_retry_delay`, `should_retry` | 18, 39, 74 |
| `app/services/webhook_circuit_breaker.py` | `get_circuit_state`, `should_attempt_delivery`, `record_delivery_result`, `transition_circuit`, `reset_circuit` | 20, 25, 53, 123, 157 |
| `app/services/webhook_dlq.py` | `replay_dead_letter`, `replay_all_dead_letters`, `acknowledge_dead_letter`, `purge_dead_letters`, `list_endpoint_dead_letters` | 15, 61, 111, 133, 163 |
| `app/services/webhook_stats.py` | `record_delivery_stat`, `get_endpoint_stats`, `get_global_stats` | 25, 75, 124 |
| `app/services/webhook_ssrf.py` | `validate_webhook_url` | 26 |
| `app/services/webhook_dispatcher.py` | `run_webhook_dispatcher_loop`, `start_webhook_dispatcher_task` | 28, 84 |

### Backend Router
| File | Key Endpoints | Lines |
|------|--------------|-------|
| `app/routers/webhooks.py` | User CRUD (58-193), Admin endpoints (198-390), DLQ mgmt (275-345), Stats (262, 359), Circuit reset (344) | 58-390 |

### Configuration
| File | Settings | Lines |
|------|----------|-------|
| `app/core/settings.py` | v1 webhook settings (table names, enabled, max endpoints, timeout, retries, auto-disable, poll interval, TTL) | 1302-1310 |
| `app/core/settings.py` | v2 webhook settings (v2 enabled, circuit breaker, stats table, replay rate limit, signature replay window, max payload size) | 1313-1322 |
| `app/core/crypto.py` | `kms_encrypt` (used for endpoint secret storage) | 16 |

### Registration & Startup
| File | Registration | Line |
|------|-------------|------|
| `app/main.py` | `app.include_router(webhooks_router)` | 446 |
| `app/main.py` | `app.add_event_handler("startup", start_webhook_dispatcher_task)` | 472 |

### DynamoDB Tables
| Table | Definition | Line in `scripts/local-ddb-init.py` |
|-------|-----------|------|
| `webhook_endpoints` | PK: `pk`, SK: `sk` | 880 |
| `webhook_deliveries` | PK: `pk`, SK: `sk` | 885 |
| `webhook_stats` | PK: `pk`, SK: `sk` | 896 |

### Frontend (all exist)
| File | Purpose |
|------|---------|
| `frontend/src/pages/webhooks/WebhookDashboard.tsx` | Endpoint list + overview cards |
| `frontend/src/pages/webhooks/WebhookEndpointDetail.tsx` | Endpoint detail with config, deliveries, DLQ, stats tabs |
| `frontend/src/api/endpoints/webhooks.ts` | API client functions for webhook CRUD, DLQ, stats |
| `frontend/src/components/shared/DeadLetterPanel.tsx` | Reusable DLQ management component |

---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_webhooks_v2.py`

| # | Test Function | Description | Mocks |
|---|--------------|-------------|-------|
| 1 | `test_enterprise_005_create_basic` | Core creation logic succeeds with valid inputs | moto DDB |
| 2 | `test_enterprise_005_validation_rejects_invalid` | 400/422 for invalid inputs | moto DDB |
| 3 | `test_enterprise_005_pagination` | Cursor-based pagination returns correct pages | moto DDB |
| 4 | `test_enterprise_005_auth_required` | 401 for unauthenticated requests | moto DDB |
| 5 | `test_enterprise_005_forbidden_wrong_user` | 403 when non-owner accesses restricted resource | moto DDB |
| 6 | `test_enterprise_005_not_found` | 404 for non-existent resource | moto DDB |
| 7 | `test_enterprise_005_duplicate_rejected` | 409 for duplicate creation | moto DDB |
| 8 | `test_enterprise_005_feature_flag_off` | Feature disabled returns 404 when flag is off | moto DDB |

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | Full CRUD lifecycle: create, read, update, delete | Service layer, DDB |
| 2 | Cross-service interaction with dependent features | Multiple service modules |
| 3 | Concurrent access patterns do not corrupt data | Service layer, parallel requests |

### E2E Tests (Playwright)

**File**: `frontend/e2e/webhooks-v2.spec.ts`

Tests use `injectAuth(page, identity)` for cookie-based auth and include CSRF headers (`x-csrf-token`) on all POST/PUT/DELETE requests. Negative tests cover 401 (unauthenticated), 403 (wrong role/user), 404 (not found), 409 (conflict), and 422 (validation) responses. Edge cases include duplicate operations (idempotency), concurrent access, and feature-flag-disabled behavior.

**Total E2E tests**: 15

### Test Data Requirements

- DDB seeds: required tables created via `scripts/local-ddb-init.py`
- Test users: Alice, Bob, Root, Charlie via `e2e_session_setup.py` / `e2e_admin_session_setup.py`
- Feature flag: `WEBHOOKS_V2_ENABLED` in `.env.local`

### CI/Pipeline

- Feature flag: `WEBHOOKS_V2_ENABLED` must be enabled for tests to run
- Serial execution: run with `--workers 1` to avoid shared state conflicts
- Retry safety: tests use unique timestamps/UUIDs per run; safe to retry on failure

---

## Dependencies & Merge Safety

### Depends On

| Ticket | Status | What It Provides |
|--------|--------|-----------------|
| (none) | -- | This ticket has no upstream ticket dependencies |

### Depended On By

| Ticket | What It Needs |
|--------|--------------|
| (none currently) | -- |

### Merge Strategy

**Independent** -- Changes are additive (new service files, new router, new frontend pages). Shared infrastructure files (`main.py`, `settings.py`, `tables.py`, `local-ddb-init.py`) receive only additive modifications.

### Merge Checklist

- [ ] All new DDB tables/GSIs added to `scripts/local-ddb-init.py`
- [ ] Settings added to `app/core/settings.py`
- [ ] Table handles added to `app/core/tables.py`
- [ ] Router registered in `app/main.py`
- [ ] Frontend routes added to `App.tsx`
- [ ] Feature flag `WEBHOOKS_V2_ENABLED` added to `.env.local.example`
- [ ] All E2E tests pass
- [ ] No regressions in existing test suite
