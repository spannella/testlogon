# Plan: Mass Message (Send Now or Schedule) to DMs and Groups

## Goal
Add a product capability where one sender can submit **one identical message payload** and fan it out to multiple existing conversations (DMs and/or groups), either:
- delivered immediately, or
- scheduled for future delivery.

The exact same message body/attachments/settings should be applied to every selected destination conversation.

---

## Current-State Notes (from code)
- Messaging already supports per-conversation send operations and `send_at` scheduling semantics at the message level.
- Scheduled message delivery is already implemented via background processing that transitions messages from `scheduled` to delivered.
- Message send paths include policy checks, quota checks, metering, archive events, and fanout side effects.

Implication: implement mass messaging as an orchestration layer that reuses existing per-conversation message creation/delivery logic wherever possible.

---

## Scope Definition
### In scope
1. A new API to submit one mass-message request with multiple destination conversation IDs.
2. Support both immediate and scheduled modes.
3. Support destination conversations that are either DM or group chats.
4. Idempotent submission, partial-failure handling, and per-destination status visibility.
5. Reuse existing moderation/compliance/metering where possible.

### Out of scope (initial)
1. Auto-creating new DM conversations from user IDs.
2. Personalization tokens per recipient (must be exact same content for all destinations).
3. Cross-tenant sends.

---

## Proposed Backend Design

## 1) Data model additions
Create a lightweight campaign model to track one mass-send request:
- `MassMessageCampaigns` table (or equivalent)
  - `campaign_id`, `sender_id`, `created_at`, `mode` (`immediate`/`scheduled`), `send_at`, `status`.
  - canonical payload hash for dedupe/audit.
  - aggregate counters: `total`, `queued`, `sent`, `failed`, `cancelled`.
- `MassMessageCampaignDestinations`
  - key: `campaign_id + conversation_id`.
  - fields: `state` (`pending`, `sent`, `failed`, `skipped`), `error_code`, `message_id`, `updated_at`.

Why: avoids overloading existing message rows and gives observability/retry/cancel semantics.

## 2) API surface
Add endpoints under messaging router namespace:
- `POST /messaging/mass-messages`
  - Input:
    - `conversation_ids: string[]`
    - one message payload shape (text/image/gallery/file/calendar subset that we initially support)
    - optional `send_at`
    - optional idempotency key
  - Behavior:
    - validates destinations + sender permissions
    - creates campaign + destination records
    - either enqueues immediate processing or marks for scheduled execution
  - Output: `campaign_id`, accepted destinations count, rejected destinations list.

- `GET /messaging/mass-messages/{campaign_id}`
  - Returns aggregate status and destination-level outcomes.

- (Optional phase 2) `POST /messaging/mass-messages/{campaign_id}/cancel`
  - Only for campaigns not fully sent.

## 3) Validation & authorization rules
Per destination conversation:
1. Sender must be an active participant with send permission.
2. Conversation type must be DM or group (reject helpdesk/system-only types if incompatible).
3. Apply existing send constraints (muted/locked/role constraints/rate limits).

Campaign-level constraints:
1. Max destinations per request (e.g., 100 initially).
2. Max payload size inherited from existing send endpoints.
3. `send_at` must be in allowed future window.

## 4) Execution model
Implement as asynchronous fanout worker path:
- Immediate campaigns:
  1. write campaign + destination `pending` rows
  2. enqueue one background job per campaign
  3. worker iterates destinations with bounded concurrency
- Scheduled campaigns:
  1. write campaign rows with `scheduled` status
  2. scheduler picks due campaigns by `send_at`
  3. executes same worker fanout path

Important:
- For each destination, call a shared internal helper that reuses existing single-conversation message creation logic so receipts, unread counters, archive events, and metering remain consistent.
- Persist per-destination result immediately after each attempt to allow resumability.

## 5) Idempotency & retry strategy
- Request-level idempotency key maps to existing/new campaign:
  - same sender + key returns existing campaign response.
- Destination-level idempotency key:
  - deterministic key: `campaign_id + conversation_id`.
  - prevents duplicate sends if worker retries.
- Retry transient failures with capped backoff; keep permanent failures terminal.

## 6) Observability & compliance
Add metrics/logging:
- campaign created, campaign completed.
- destination send success/failure counters and latency.
- retry counts and terminal failure reasons.

Compliance/audit:
- campaign-level audit event at submission and completion.
- destination-level audit links to resulting `message_id`.
- ensure archive pipeline receives standard message lifecycle events through reused send helper.

---

## Delivery Phases

### Phase 1 — Foundation
1. Add campaign data model + storage access helpers.
2. Add request/response schemas.
3. Add `POST /messaging/mass-messages` + `GET` status endpoint.
4. Add asynchronous worker skeleton.

### Phase 2 — Fanout integration
1. Extract/reuse shared single-destination send helper from existing send flows.
2. Implement immediate fanout execution with bounded concurrency.
3. Implement scheduled campaign pickup and execution.
4. Add destination-level idempotency and retry behavior.

### Phase 3 — Hardening
1. Add cancellation support (optional, if required).
2. Add operational dashboards/alerts.
3. Tune rate limits and per-campaign max recipient count.
4. Add admin/debug endpoint for failed-destination replay (optional).

---

## Test Plan

## Unit tests
- Payload validation, conversation type filtering, permission checks.
- Idempotency behavior (same key returns same campaign).
- Retry classifier (transient vs permanent errors).

## Integration tests
- Immediate campaign to mixed DM/group destinations => all messages created.
- Scheduled campaign => no sends before `send_at`, sends after due time.
- Partial failure campaign => status reflects sent+failed correctly.
- Duplicate worker execution => no duplicate destination messages.

## Non-functional
- Load test: N destinations per campaign under configured limit.
- Verify metering and unread counters align with normal sends.
- Verify archive events emitted once per destination message.

---

## Rollout Plan
1. Feature flag: `messaging.mass_send.enabled`.
2. Internal-only rollout for staff users.
3. Canary to small percentage of tenants/users.
4. Full rollout after metric/error SLOs are stable.

Rollback:
- Disable feature flag (blocks new campaigns).
- Worker can drain/stop based on flag policy.

---

## Open Questions
1. Should failed destinations be manually retryable from UI/API?
2. Should we support all message types in v1, or text-only first?
3. What is acceptable max recipients per campaign for abuse and cost control?
4. Should scheduled campaigns allow edit-before-send or cancel-only?
