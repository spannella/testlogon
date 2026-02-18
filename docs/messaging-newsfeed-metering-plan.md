# Messaging + Newsfeed Metering & Billing Implementation Plan

## Objective
Extend existing usage metering so billing is not limited to File Manager transfer/storage. Add billable usage for:
- **Messaging sends** (per message, with optional media add-ons)
- **Newsfeed posts** (per post, with optional media add-ons)
- **Media transfer** tied to messaging/newsfeed files (images/videos/audio/other attachments)

This should preserve the current event-based metering model and billing snapshot flow already used for file usage.

---

## Scope and principles

## In scope
1. Meter **message send units** when a user successfully sends a message.
2. Meter **post publish units** when a user successfully creates a post.
3. Meter **upload/download bytes** for media attached to messages/posts.
4. Surface these dimensions in usage summary + admin usage views.
5. Add quota checks and policy hooks (warn/block) per subscription plan.
6. Keep events idempotent so retries do not double-charge.

## Out of scope (phase 1)
- Retroactive billing for old messaging/newsfeed content (handled by explicit backfill in phase 4).
- New payment provider integration; reuse existing billing finalization pipeline.
- Fine-grained per-recipient pricing (e.g., group-message fanout multipliers) unless product opts in.

---

## Proposed usage model

## New billable dimensions
Add these normalized dimensions to the metering domain:
- `message_send_count` (integer unit)
- `post_publish_count` (integer unit)
- `messaging_upload_bytes`
- `messaging_download_bytes`
- `newsfeed_upload_bytes`
- `newsfeed_download_bytes`

## Event taxonomy
Extend the usage event vocabulary with explicit event types/sources, e.g.:
- Event type `unit` with source `messaging_send`
- Event type `unit` with source `newsfeed_post`
- Existing byte event types (`upload`/`download`) but with sources:
  - `messaging_attachment_upload`
  - `messaging_attachment_download`
  - `newsfeed_attachment_upload`
  - `newsfeed_attachment_download`

Rationale: keeps transfer accounting compatible with existing file usage logic while enabling count-based billing.

## Idempotency keys
Construct deterministic idempotency keys from stable identifiers:
- Messaging send: `user_id|messaging_send|conversation_id|message_id`
- Newsfeed publish: `user_id|newsfeed_post|post_id`
- Attachment transfer: include attachment key + request/operation id

This avoids double billing when API requests are retried.

---

## Data model and service-layer changes

## 1) `app/services/usage_metering.py`
- Extend event type handling to support count-based usage (either via a new `unit` event type or a generic quantity field).
- Add aggregate fields for period/daily counters:
  - `message_send_count_total`
  - `post_publish_count_total`
  - segmented transfer totals for messaging/newsfeed media (or add a `source`-bucket map if preferred).
- Keep existing upload/download/storage behavior untouched for backwards compatibility.

## 2) Billing snapshot schema
- Extend billing snapshot builder and finalize flow to include new counters so invoices can reference message/post units and media transfer.
- Version the snapshot schema (e.g., `version=2`) and keep compatibility with older snapshots.

## 3) Plan limits config (`app/core/settings.py` + plan catalog)
Introduce configurable limits/prices:
- `monthly_message_send_limit`
- `monthly_post_publish_limit`
- messaging/newsfeed media transfer caps (if desired independently from file-manager caps)

---

## API and router instrumentation

## Messaging (`app/routers/messaging.py`)
Instrument all send paths:
- `POST /messaging/conversations/{conversation_id}/messages` (text)
- `POST /messaging/conversations/{conversation_id}/messages/image`
- `POST /messaging/conversations/{conversation_id}/messages/file`

Implementation notes:
1. After successful message persistence, emit one `messaging_send` unit event.
2. For attachment upload/presign completion, meter authoritative byte size from stored metadata/S3 head (not client-provided size).
3. For attachment fetch/download endpoints, meter actual streamed bytes.
4. Apply pre-send quota checks via subscription access guard so over-limit sends can be blocked or downgraded by plan policy.

## Newsfeed (`app/routers/newsfeed.py`)
Instrument post/media paths:
- `POST /newsfeed/posts`
- `POST /newsfeed/uploads/presign` + attachment retrieval endpoints

Implementation notes:
1. On successful post creation, emit one `newsfeed_post` unit event.
2. On media upload completion, emit upload byte event with `newsfeed_attachment_upload` source.
3. On media download/serve, emit download byte event with `newsfeed_attachment_download` source.
4. Enforce per-period post limits before create-post execution.

---

## Billing and policy integration

## Charge calculation
Update billing calculator/catalog mapping so line items can be computed from:
- message send units (e.g., per 1,000 messages)
- post publish units (e.g., per 100 posts)
- optional messaging/newsfeed transfer overages by GB

## Enforcement behavior
- Soft thresholds: 80% and 95% usage notifications.
- Hard limits: return explicit API errors when send/post cap exceeded.
- Policy flexibility: allow plan-level switch between hard block vs overage billing.

---

## Observability, audit, and abuse controls

1. Add metrics for new dimensions (unit counters + media transfer counters by source).
2. Add audit records for quota denials and period finalization containing new counters.
3. Dashboards:
   - top users by message send volume
   - top users by post volume
   - media transfer split by product surface (filemanager vs messaging vs newsfeed)
4. Abuse checks:
   - burst limits for automated message spam
   - anomalous media transfer spikes from repeated download loops

---

## Delivery phases

## Phase 0 — Contract and schema design (1 sprint)
- Finalize event taxonomy, aggregate fields, and snapshot versioning.
- Confirm pricing semantics (unit pricing vs bundled allowances).

## Phase 1 — Messaging metering MVP (1 sprint)
- Instrument message send + messaging attachment upload/download.
- Expose counters in usage summary/admin endpoints.
- Add tests for idempotency and retry safety.

## Phase 2 — Newsfeed metering MVP (1 sprint)
- Instrument post publish + newsfeed media transfer.
- Add pre-post quota checks and policy responses.
- Extend billing snapshots with new fields.

## Phase 3 — Billing rollout + UI (1 sprint)
- Generate invoice line items for message/post usage.
- Show new counters on user usage page and admin usage panel.
- Enable warnings + enforcement toggles per plan.

## Phase 4 — Backfill/reconciliation hardening (ongoing)
- Optional historical backfill jobs from existing messages/posts.
- Recompute tooling + anomaly reconciliation playbooks.

---

## Test plan

1. **Unit tests** (`tests/test_usage_metering.py`):
   - new event type serialization and aggregate updates
   - idempotency across retries for send/post events
2. **Router tests** (`tests/test_routes.py` + new focused tests):
   - successful message send increments unit counter once
   - successful post creation increments unit counter once
   - failed send/post does not increment usage
3. **Integration tests**:
   - upload/download media in messaging/newsfeed increments correct byte buckets
   - monthly caps enforced at boundaries
4. **Billing tests**:
   - snapshot finalization includes new fields
   - invoice math for included allowance + overage

---

## Rollout strategy

1. Ship behind feature flags:
   - `metering_messaging_enabled`
   - `metering_newsfeed_enabled`
   - `enforce_message_post_limits_enabled`
2. Start in **observe-only mode** (meter but do not block/charge).
3. Reconcile measured totals for at least one full billing period.
4. Enable billing and then enforcement gradually by plan cohort.

---

## Open product decisions

1. Should group messages count as **1 send per API call** or **N sends per recipient**?
2. Are edited/retracted messages billable events or excluded?
3. Are draft/scheduled posts billed at creation time or at publish time?
4. Should messaging/newsfeed media transfer share a global transfer cap with file-manager, or remain separate buckets?
5. Should first-party bot/system messages be billable or excluded by source?
