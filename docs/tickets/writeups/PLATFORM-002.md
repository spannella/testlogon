# PLATFORM-002: Webhook Event Delivery System — Investigation & Implementation Write-up

> Type: feature | Priority: Medium | Status: Implemented

## 1. Summary & Classification

External systems that want to react to platform events — new messages, payments, subscriptions, file uploads — previously had no integration path beyond polling the API. The only outbound notification was a single deployment-wide webhook URL configured via `ALERTS_WEBHOOK_URL` in `app/core/settings.py` (line 203), served by `send_alert_webhook()` in `app/services/alerts.py` (line 600) with a fire-and-forget HTTP POST and basic HMAC signing. PLATFORM-002 replaces this with a complete per-user webhook delivery system: endpoint registration with per-endpoint KMS-encrypted HMAC-SHA256 signing secrets, event-type filtering, exponential backoff retries (5 attempts over ~2.5 hours), a delivery log, dead-letter tracking, automatic endpoint disabling after 50 consecutive failures, and admin monitoring.

- **Type**: Feature
- **Priority**: Medium
- **User personas affected**: developer integrators (registering endpoints), content creators (receive notification of deliveries), platform admins (monitoring health)
- **Cross-references**: SECOPS-007 (dev/prod parity — mock KMS port 7999 in dev, real AWS KMS in prod), SEC-002 (webhook signature integrity), PLATFORM-001 (webhook test endpoint benefits from rate limiting)

---

## 2. Current-State Investigation

### 2.1 Existing alert webhook channel

`app/core/settings.py` lines 193–199 define seven settings for the legacy single-URL webhook:

```python
alerts_webhook_url: str = os.environ.get("ALERTS_WEBHOOK_URL", "")
alerts_webhook_secret: str = os.environ.get("ALERTS_WEBHOOK_SECRET", "")
alerts_webhook_timeout_seconds: int = ...   # default 5
alerts_webhook_event_types: str = ...       # default ""
alerts_webhook_enabled: bool = ...
alerts_webhook_max_per_window: int = ...
alerts_webhook_window_seconds: int = ...
```

`send_alert_webhook()` (`alerts.py:600`) calls `_post_webhook_with_retry()` (`alerts.py:565`), which makes up to 3 retries with exponential backoff. The HMAC signature uses `sha256_str()` from `app/core/crypto.py` (line 13). This shared secret is the same for every delivery to every URL in the deployment — a security gap.

`can_send_alert_channel(user_sub, "webhook")` at `app/services/rate_limit.py:330–336` limits webhook alert rate per user using `_bucket_limit()` on `T.sessions`.

### 2.2 KMS infrastructure

`app/core/crypto.py` exports `kms_encrypt()` (line 16) and `kms_decrypt()` (line 22). In dev mode these call the mock KMS server on port 7999 (`scripts/mock_kms_server.py`). In production they call real AWS KMS. The call is transparent to callers — the same code path runs in both environments (SECOPS-007 compliance).

### 2.3 Background task pattern

`app/main.py` (lines 374–378) registers three startup tasks:
- `start_scheduled_messages_task()` (`app/routers/messaging.py:12594`)
- `start_broadcast_scheduler_task()` (`app/services/broadcast_scheduler.py:84`)
- `newsfeed_startup` (`app/routers/newsfeed.py:2155`)

All follow the same pattern: an `async def start_*_task()` that calls `asyncio.create_task(run_*_loop())`. The webhook dispatcher follows this pattern.

### 2.4 Existing event type registry

`app/services/alerts.py` defines `ALERT_EVENT_TYPES` (line 133) with 30+ strings covering login, MFA, calendar, tickets, social, and billing domains. The webhook system reuses these plus adds webhook-specific types (`webhook.test`, `file.uploaded`, `post.created`, etc.).

### 2.5 What now exists in the repository

- `app/services/webhook_service.py` — endpoint CRUD + KMS secret management
- `app/services/webhook_dispatcher.py` — background delivery loop
- `app/services/webhook_retry.py` — retry scheduling + backoff logic
- `app/services/webhook_dlq.py` — dead-letter queue management
- `app/services/webhook_circuit_breaker.py` — auto-disable logic
- `app/services/webhook_ssrf.py` — SSRF guard (rejects private IP URLs)
- `app/services/webhook_stats.py` — delivery health aggregation
- `app/routers/webhooks.py` — user CRUD + test endpoint
- Settings at `app/core/settings.py` lines 1718–1719: `webhook_endpoints_table_name`, `webhook_deliveries_table_name`, `webhooks_enabled` (line 1720)

### 2.6 Gaps before implementation

1. No per-user endpoint registration
2. No per-endpoint secrets (all shared one `ALERTS_WEBHOOK_SECRET`)
3. No retry beyond `_post_webhook_with_retry()`'s 3 hardcoded attempts
4. No delivery log or visibility
5. No dead letter queue
6. No SSRF guard on caller-supplied URLs

---

## 3. Gap / Threat Analysis

### 3.1 SSRF via user-supplied webhook URLs

A user registers `https://169.254.169.254/latest/meta-data/` as a webhook URL. The dispatcher would POST to the EC2 metadata service, potentially leaking instance credentials. `app/services/webhook_ssrf.py` addresses this by resolving DNS and rejecting private/link-local IP ranges before the HTTP call.

### 3.2 Endpoint exhaustion (DoS against self)

Without a per-user limit, a user could register thousands of endpoints, each receiving every matching event, overwhelming the dispatcher. The 10-endpoint-per-user limit (`WEBHOOKS_MAX_ENDPOINTS_PER_USER=10`, `settings.py:1720`) caps this; each delivery attempt is bounded by the 50-item batch size and 10-second poll interval.

### 3.3 ByStatus GSI hot partition

All pending deliveries share `status = "pending"` as the GSI partition key. At high volume (10,000+ active deliveries) this creates a DDB hot partition. The mitigation is to shard the status key (e.g., `pending#0`…`pending#9`) in a future iteration; for initial deployment the on-demand billing mode absorbs burst traffic.

### 3.4 Replay attacks against receivers

Without a timestamp-based validation window, a stolen delivery body could be replayed at any future time. The `X-Webhook-Timestamp` header plus the signature combining `{timestamp}.{payload}` gives receivers a 5-minute replay window to reject stale deliveries.

### 3.5 Secret leakage via admin endpoints

The `secret` field in the endpoint response is only returned on `POST /ui/webhooks` (creation) and `POST /ui/webhooks/{id}/rotate-secret`. All subsequent `GET` requests return `secret: null`. The plaintext secret never touches DDB — only the KMS ciphertext is stored.

### 3.6 Code sites that must change

| File | Change |
|---|---|
| `app/services/webhook_service.py` | New — endpoint CRUD, event dispatch, KMS management |
| `app/services/webhook_dispatcher.py` | New — background delivery loop |
| `app/services/webhook_ssrf.py` | New — SSRF guard for caller-supplied URLs |
| `app/routers/webhooks.py` | New — user + admin API endpoints |
| `app/main.py` | Register dispatcher startup task + webhooks router |
| `scripts/local-ddb-init.py` | Add `webhook_endpoints` + `webhook_deliveries` tables |
| `app/core/settings.py` | Add webhook settings (confirmed 1718–1720) |
| `app/core/tables.py` | Add table handles |
| `app/models.py` | Add Pydantic webhook models |
| `frontend/src/pages/settings/WebhooksPage.tsx` | New user settings page |
| `frontend/src/App.tsx` | Add `/settings/webhooks` + `/admin/webhooks` routes |

---

## 4. Proposed Design / Fix

### 4.1 Single-table design: webhook_endpoints

The `webhook_endpoints` DynamoDB table uses two PK patterns in a single-table design:

- `PK: USER#{user_sub}` / `SK: ENDPOINT#{endpoint_id}` — endpoint configuration item
- `PK: EVENT#{event_type}` / `SK: ENDPOINT#{endpoint_id}` — fan-out index item (one per subscribed event type)

When an endpoint is created with `event_types: ["message.created", "payment.received"]`, three items are written: one config item and two index items. When an event fires, `dispatch_webhook_event("message.created", data)` queries `PK = EVENT#message.created` to get the list of endpoints to notify — a single DDB query.

### 4.2 webhook_deliveries table schema

```python
TableDef(
    "webhook_deliveries", "pk", "sk",
    gsi=[
        {"index_name": "ByStatus",  "partition_key": "status",   "sort_key": "next_retry_at"},
        {"index_name": "ByUser",    "partition_key": "user_sub", "sort_key": "created_at"},
    ],
    attr_types={"next_retry_at": "N", "created_at": "N"},   # CRITICAL: numeric GSI sort keys
)
```

The `attr_types` declaration is mandatory — omitting it causes DynamoDB to store the values as strings, producing `ValidationException` on integer comparisons (documented CLAUDE.md gotcha).

### 4.3 Dispatcher loop

```python
# app/services/webhook_dispatcher.py
POLL_INTERVAL_SECONDS = 10
MAX_BATCH_SIZE = 50

async def run_webhook_dispatcher_loop():
    while True:
        try:
            now = now_ts()
            due = query_due_deliveries(status="pending", now=now, limit=MAX_BATCH_SIZE)
            due += query_due_deliveries(status="failed", now=now, limit=MAX_BATCH_SIZE)
            for delivery in due:
                endpoint = get_endpoint_by_id(delivery["endpoint_id"], delivery["user_sub"])
                if not endpoint or not endpoint.get("enabled"):
                    mark_delivery_dead_letter(delivery, reason="endpoint_disabled")
                    continue
                secret = kms_decrypt(endpoint["secret"]).decode("utf-8")
                result = await deliver_webhook(endpoint["url"], delivery["payload"],
                                               secret, delivery["delivery_id"], delivery["event_type"])
                if result["success"]:
                    mark_delivery_success(delivery, result)
                    reset_endpoint_failure_count(endpoint)
                else:
                    handle_delivery_failure(delivery, endpoint, result)
        except Exception:
            logger.exception("Webhook dispatcher loop error")
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
```

Registered in `app/main.py` alongside existing startup tasks:
```python
async def start_webhook_dispatcher_task():
    if S.webhooks_enabled:
        asyncio.create_task(run_webhook_dispatcher_loop())
app.add_event_handler("startup", start_webhook_dispatcher_task)
```

### 4.4 Retry schedule

| Attempt | Delay | Elapsed |
|---|---|---|
| 1 | immediate | 0 s |
| 2 | 60 s | 1 min |
| 3 | 300 s | 6 min |
| 4 | 1800 s | 36 min |
| 5 | 7200 s | 2 h 36 min |

After attempt 5: `status = "dead_letter"`. After 50 consecutive failures: `enabled = False` + `write_alert()` to notify the user.

### 4.5 HMAC signature

```python
# Receiver-side verification recipe (documented for integrators)
message = f"{timestamp}.{json_payload}"
expected = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
assert request.headers["X-Webhook-Signature"] == f"sha256={expected}"
assert abs(time.time() - int(request.headers["X-Webhook-Timestamp"])) < 300
```

### 4.6 Dev/Prod parity (SECOPS-007)

- **KMS**: In dev, `kms_encrypt()`/`kms_decrypt()` call mock KMS on port 7999 (same code path). Production uses real AWS KMS in the same region as DDB.
- **HTTP delivery**: In dev, the `httpx.AsyncClient` will POST to whatever URL the developer registers (local webhook receivers are fine). SSRF guard still applies — it rejects RFC 1918 addresses.
- **DDB**: DDB Local (port 8001) stores `webhook_endpoints` and `webhook_deliveries`. Both tables are created by `scripts/local-ddb-init.py` at stack startup.
- **Feature flag**: `WEBHOOKS_ENABLED=1` in `.env.local.example`; set to `0` to disable the dispatcher and all endpoints.

### 4.7 Alternatives considered

- **SNS/SQS for delivery queue**: Adds AWS service dependency and complicates local dev (LocalStack). Rejected for v1; the DDB-based queue is sufficient and avoids a new infra dependency.
- **Synchronous delivery (no queue)**: Blocks request handlers on external HTTP calls. Rejected — a slow or down receiver would cascade timeouts into the platform.

---

## 5. Testing, Verification & Rollout

### 5.1 pytest unit tests (tests/test_webhooks.py)

| # | Test | What to assert |
|---|---|---|
| 1 | `test_create_endpoint` | DDB item written; `secret` field is KMS ciphertext; plaintext returned once |
| 2 | `test_create_http_rejected` | `http://` URL → 400 |
| 3 | `test_max_endpoint_limit` | 11th endpoint → 409 |
| 4 | `test_event_type_index_items` | Two event types → 3 DDB items (1 config + 2 index) |
| 5 | `test_hmac_signature` | `X-Webhook-Signature` matches expected HMAC-SHA256 of `"{ts}.{body}"` |
| 6 | `test_retry_schedule` | Attempt 1 `next_retry_at = now + 60`; attempt 2 = `now + 300` |
| 7 | `test_dead_letter_after_max_retries` | `attempt_count = 5` → `status = "dead_letter"` |
| 8 | `test_auto_disable_threshold` | 50th consecutive failure → `enabled = False`, alert written |
| 9 | `test_success_resets_failure_count` | Successful delivery → `failure_count = 0` |
| 10 | `test_ssrf_private_ip_rejected` | URL resolving to 10.0.0.1 → delivery aborted without HTTP call |

All use moto-mocked DDB; KMS mock intercepted via `pytest-mock` or the running mock KMS server.

### 5.2 Playwright E2E tests (frontend/e2e/webhooks.spec.ts)

22 tests across 5 sections:

- Section A (6): CRUD API — create endpoint returns `endpoint_id` + `secret`; HTTP URL rejected; list; update; delete; max-10 limit.
- Section B (5): Delivery API — test delivery to mock server; failed delivery; delivery log; secret rotation; event-types list.
- Section C (3): Signature — verify `X-Webhook-Signature`, `X-Webhook-Timestamp`, `X-Webhook-Event` headers present in test delivery.
- Section D (4): Admin API — list all endpoints; health summary; force-disable; non-admin gets 403.
- Section E (4): UI — empty state; HTTPS validation in form; created endpoint in list; delivery log after test button.

Auth: `injectAuth(page, "alice")` + CSRF header. KMS mock must be running (`scripts/mock_kms_server.py`).

### 5.3 Manual QA steps

1. Register a webhook endpoint pointing at `https://webhook.site` (or `ngrok`).
2. Trigger a `message.created` event (send a message via the UI).
3. Verify delivery appears in the delivery log with `status=success` and `response_code=200`.
4. Stop the receiver; trigger another event; verify retry appears in the delivery log.
5. After 5 retries, verify `status=dead_letter`.

### 5.4 Observability

Metrics to add to `app/metrics.py`:
- `webhook_delivery_total{status}` (counter)
- `webhook_delivery_latency_seconds` (histogram)
- `webhook_dead_letter_total` (counter)
- `webhook_auto_disable_total` (counter)

Alerts: success rate < 90% for 10 min (warning); dispatcher stalled for 60 s (critical).

### 5.5 Rollout and rollback

Deployment order: DDB tables → webhook service + dispatcher → webhooks router (registered in `main.py`) → frontend WebhooksPage → add `dispatch_webhook_event()` calls at event sources alongside existing `write_alert()` calls.

Rollback: set `WEBHOOKS_ENABLED=0`. Dispatcher stops; no new deliveries created; existing DDB records preserved.

**Effort**: M (8–10 days as estimated).
