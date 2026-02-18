# File Manager Metering, Quotas, and Billing Plan

## Objective
Introduce end-to-end metering for:
- upload bandwidth (bytes uploaded)
- download bandwidth (bytes downloaded)
- storage footprint (bytes stored over time)

So we can:
1. show user-visible usage in UI,
2. enforce limits/quotas,
3. support billing (charge by usage over a period).

---

## Product outcomes

## Core outcomes
- Every user has a measurable usage profile for a period (daily/monthly):
  - uploaded bytes
  - downloaded bytes
  - average and/or peak storage bytes
- Admin/ops can reconcile measured values against billable records.
- Users can self-serve usage visibility from UI (current month + trend + plan limits).

## Billing-ready outcomes
- Billable usage snapshots are immutable once invoiced.
- Usage is auditable (raw events -> aggregate tables -> invoice line items).
- Backfill/recompute workflows exist for corrections.

---

## Metering model

## Dimensions to meter
1. **Transfer upload bytes**
   - direct upload endpoint
   - presigned upload completion
   - archive extraction fan-out (count actual stored bytes written)
2. **Transfer download bytes**
   - direct download
   - shared download
   - zip bundle downloads (count zip payload bytes delivered)
3. **Storage bytes**
   - live logical bytes per file node
   - include encrypted and unencrypted equally
   - soft-deleted files excluded from active storage once logically deleted (policy decision)

## Time windows
- Real-time counters (near-live dashboard)
- Daily aggregates (for analytics)
- Billing period aggregates (month by default)

## Canonical period key
- `period_id = YYYY-MM` in UTC for monthly billing
- keep UTC as source-of-truth to avoid timezone ambiguity

---

## Data architecture

## Event layer (append-only)
Create `usage_events` records for auditable atomic usage:
- `event_id` (uuid)
- `user_id`
- `event_type` (`upload`, `download`, `storage_delta`)
- `bytes`
- `resource_path` (optional)
- `timestamp`
- `request_id` / trace id
- `source` (`api_upload`, `presign_complete`, `shared_download`, `zip_download`, etc.)

Use idempotency key on write (`event_id` or derived deterministic key) to avoid duplicate counting on retries.

## Aggregate layer
### A) User-period counters
`usage_period_totals` keyed by `(user_id, period_id)` with atomic increments:
- `upload_bytes_total`
- `download_bytes_total`
- `storage_bytes_current`
- `storage_bytes_peak`
- `storage_byte_seconds` (optional, for average storage billing)
- `updated_at`

### B) Daily snapshots
`usage_daily` keyed by `(user_id, date_utc)`:
- uploaded/downloaded/storage end-of-day
- useful for charting and reconciliation

### C) Billing snapshots (immutable)
`billing_usage_snapshots` keyed by `(user_id, period_id, version)`:
- frozen values used for invoice generation
- status (`draft`, `finalized`, `invoiced`)

---

## Instrumentation plan (backend)

## Upload metering
- Record transfer bytes at successful completion points:
  - `/upload`
  - `/complete-upload`
  - archive extracted entries (`upload_archive`/zip path)
- Prefer authoritative stored size from metadata/object head over client-declared size.

## Download metering
- Meter bytes actually streamed to client:
  - `/download`
  - `/shared-download`
  - `/download-zip` and `/shared-download-zip`
- For streaming responses, increment via wrapped iterator/chunk accounting.

## Storage metering
Maintain `storage_delta` events and aggregate storage counters on:
- create/upload (+size)
- overwrite/replace (new_size - old_size)
- delete/purge (-size)
- move/rename (0 delta)

For existing data, run one-time backfill job to seed `storage_bytes_current`.

## Reliability
- Write event + aggregate in a resilient pattern:
  - best: transactional write if datastore supports it,
  - otherwise append event first, aggregate async with replay-safe consumer.
- Add repair job to recompute period totals from events.

---

## Quotas and enforcement

## Plan limits
Add configurable per-plan limits:
- monthly upload bytes
- monthly download bytes
- storage bytes cap

## Enforcement behavior
- Soft warning at thresholds (80%, 95%).
- Hard block at 100% where applicable:
  - block uploads if upload/storage cap exceeded,
  - optionally throttle downloads for abuse controls.
- Return clear API errors with machine-readable reason and remaining allowance.

---

## Billing integration

## Pricing model support
Design to support one or more:
- included base allowance + overage per GB
- pure metered (per GB upload/download/storage)
- storage average (GB-month) from `storage_byte_seconds`

## Invoice pipeline
1. Close billing period.
2. Finalize immutable `billing_usage_snapshot`.
3. Compute charges from pricing catalog version.
4. Emit invoice line items:
   - upload usage
   - download usage
   - storage usage
   - overage breakdown

## Adjustments
- support credit/debit adjustment entries linked to snapshot version.

---

## API additions

## User usage endpoints
- `GET /v1/fs/usage/summary?period=YYYY-MM`
  - totals + limits + percent used
- `GET /v1/fs/usage/daily?from=...&to=...`
  - daily series for charts
- `GET /v1/fs/usage/storage`
  - current storage and top directories/files (optional)

## Admin/billing endpoints
- `POST /v1/admin/usage/recompute`
- `POST /v1/admin/billing/finalize-period`
- `GET /v1/admin/usage/user/{user_id}`

---

## UI plan

## New “Usage & Billing” page
For end users:
- current period cards:
  - Upload used / limit
  - Download used / limit
  - Storage current / limit
- trend chart (daily upload/download/storage)
- estimated bill/overage section (if enabled)
- period selector (current + previous periods)

## File Manager integration
- compact usage widget in Files toolbar/header:
  - storage used,
  - monthly transfer used,
  - quick link to Usage page
- warning banners near limit breaches.

## Admin UI (optional phase)
- top users by transfer/storage
- anomaly detection cards (sudden spikes)
- recompute/finalization controls

---

## Observability and governance

## Metrics
Add/promote metrics for:
- `filemgr_usage_upload_bytes_total{user,source}`
- `filemgr_usage_download_bytes_total{user,source}`
- `filemgr_storage_bytes_current{user}`
- metering pipeline lag/errors

## Audit events
Emit structured audit events for:
- period finalization
- snapshot versioning
- manual adjustments
- recompute runs

## Data retention
- raw usage events retention (e.g., 18–24 months)
- aggregated billing records retained per compliance requirements

---

## Security and abuse concerns
- Ensure meter updates are server-authoritative; never trust client-submitted byte counts.
- Protect admin metering endpoints with elevated authz.
- Detect suspicious patterns (download amplification, repeated failed uploads).
- Keep user privacy: avoid storing sensitive filenames in billing exports unless necessary.

---

## Rollout phases

## Phase 0 — Design and schema
- finalize event/aggregate schemas
- migration design and backfill strategy

## Phase 1 — Backend metering foundation
- instrument upload/download/storage paths
- build aggregate writer + recompute tooling
- add usage summary API

## Phase 2 — UI visibility
- Usage & Billing page
- Files header usage widget + warnings

## Phase 3 — Quotas and enforcement
- plan limits
- soft/hard enforcement

## Phase 4 — Billing closeout
- period finalization
- immutable snapshots
- invoice integration

---

## Testing plan

## Unit tests
- event emission for each operation path
- aggregate counter correctness (including retries/idempotency)
- storage delta correctness (create/update/delete/purge)

## Integration tests
- upload/download flows update period totals correctly
- shared download attributed to downloader user
- archive extraction meters actual extracted bytes
- recompute produces same totals as incremental pipeline

## Failure tests
- duplicate event delivery does not overcount
- partial pipeline outage with replay recovery
- period finalization race conditions

## UI tests
- summary cards render accurate values
- chart range/period behavior
- quota warning and limit-block messaging

---

## Definition of done
- Usage can be queried per user per period for upload/download/storage.
- UI displays usage and limit progress.
- Quotas can be enforced with clear errors.
- Billing snapshots are finalizable and auditable.
- Recompute/backfill tools exist and pass reconciliation tests.
