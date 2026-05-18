# Google Calendar Integration Plan

## Objective
Enable two-way sync between the app's existing calendar system and Google Calendar so users can:
1. View Google Calendar events alongside app-native events.
2. Create/update/delete events in the app and have those changes reflected in Google Calendar.

## Current-System Baseline (what we will extend)
- The backend already supports first-party calendar/event CRUD and scheduling workflows under `/ui/calendars` and `/ui/calendars/{calendarId}/events`.
- Event payloads already capture key fields needed for external sync (`start_utc`, `end_utc`, `all_day`, recurrence, attendees, status, etc.).
- Frontend calendar views already consume this API and can be extended to show external-provider connection state and merged event feeds.

## Scope
### In scope
- Google OAuth connection flow for calendar access.
- Importing/reading Google events into app views.
- Outbound sync from app event writes to Google.
- Conflict-safe, idempotent bidirectional synchronization model.
- Basic observability, retries, and user-facing sync status.

### Out of scope (phase 1)
- Multi-provider support (Outlook/iCloud) beyond interface abstractions.
- Full cross-provider attendee response reconciliation.
- Advanced Google resource calendars/rooms and delegated domain-wide admin controls.

---

## High-Level Architecture

## 1) Connection & Authorization Layer
- Add a "Connect Google Calendar" flow from app settings/calendar pages.
- Use OAuth 2.0 Authorization Code flow with offline access and incremental scopes.
- Store provider connection records per user (encrypted refresh token + token metadata + selected Google calendar IDs).
- Add a disconnect flow that revokes tokens and marks mappings inactive.

**Recommended scopes (least privilege first):**
- `openid`, `email`, `profile` (identity)
- `https://www.googleapis.com/auth/calendar.events` (read/write events)
- Optional fallback if needed for metadata discovery: `.../calendar.readonly`

## 2) Data Model Additions
Create provider-specific mapping tables/items:

- `calendar_provider_connection`
  - `connection_id`, `user_sub`, `provider=google`, encrypted tokens, token expiry, sync status, last_sync cursor.
- `calendar_external_mapping`
  - maps internal `calendar_id` <-> Google `calendarId` (support many-to-many but start 1:1 UX).
- `event_external_mapping`
  - maps internal `(calendar_id,event_id)` <-> Google `event.id`, `etag`, `last_synced_at`, `sync_fingerprint`.
- `calendar_sync_job`
  - job metadata for backfill, incremental pulls, retries, dead-letter context.

Design notes:
- Keep source-of-truth field per event (`source=internal|google`) and `sync_state` (`pending`, `synced`, `error`, `conflict`).
- Add soft-delete tombstones so deletes propagate safely.

## 3) Sync Engine
Implement a dedicated sync service (background worker + queue):

### Inbound sync (Google -> app)
- Poll Google Calendar incremental sync (`syncToken`) per connected calendar.
- Upsert internal events with mapping records.
- Respect Google deletions (`status=cancelled`) as deletes/tombstones in app.
- Store latest valid `syncToken`; if invalidated, trigger full re-sync.

### Outbound sync (app -> Google)
- On app event create/update/delete, enqueue outbound sync jobs.
- Use idempotency keys and mapping table to determine create vs update vs delete.
- Use Google `etag`/version checks to prevent blind overwrites.

### Conflict strategy (phase 1)
- Last-write-wins with safety rails:
  - If both sides changed since `last_synced_at`, mark `conflict` and surface to user.
  - Preserve conflict snapshots for manual resolution UI (phase 2 can add rich resolver).

## 4) API & Backend Changes
Add integration-focused endpoints under `/ui/calendar/integrations/google`:
- `GET /status` -> connection + health + last sync.
- `POST /connect/start` -> OAuth URL/state.
- `GET /connect/callback` -> token exchange and account linking.
- `POST /disconnect` -> revoke/unlink.
- `GET /calendars` -> list Google calendars for mapping selection.
- `POST /mappings` -> map internal calendar to Google calendar.
- `POST /sync/run` -> manual sync trigger.

Enhance existing event handlers:
- Hook create/update/delete routes to emit sync jobs.
- Add provider sync metadata in event responses where useful for UI badges.

## 5) Frontend Changes
- Add "Google Calendar" integration card in Calendar settings.
- Add connect/disconnect CTA and linked account display.
- Add per-calendar mapping UI (internal calendar -> Google calendar selector).
- Merge synced events into Calendar View with source badges.
- Show sync states/errors (e.g., "Sync delayed", "Re-auth required").

## 6) Reliability, Security, and Compliance

### Reliability
- Queue-based processing with exponential backoff and dead-letter queue.
- Idempotent job processing and dedup keys (`event_id + change_version`).
- Scheduled reconciliation job (nightly) to heal drift.

### Security
- Encrypt refresh tokens at rest (KMS/secret manager envelope encryption).
- Never log access/refresh tokens.
- Use OAuth state + nonce and strict redirect URI checks.
- Principle of least privilege for scopes.

### Compliance/Audit
- Emit audit events for connect/disconnect/sync-failure/conflict-resolution actions.
- Include actor, provider account, calendar mapping, and outcome metadata.

## 7) Observability
Add metrics and dashboards:
- `calendar_sync_jobs_total{direction,status}`
- `calendar_sync_latency_seconds`
- `calendar_sync_conflicts_total`
- `calendar_token_refresh_failures_total`
- `calendar_sync_backlog_depth`

Add structured logs with correlation IDs:
- `connection_id`, `calendar_id`, `event_id`, `google_event_id`, `job_id`.

## 8) Rollout Plan

### Phase 0: Foundation
- Data model + secure token storage + OAuth handshake endpoints.
- Feature flag integration (`google_calendar_sync_enabled`).

### Phase 1: Read-only import
- Inbound sync only; render Google events in app calendar.
- Manual sync button + status indicators.

### Phase 2: Two-way sync
- Enable outbound sync for app-created/updated/deleted events.
- Add conflict detection/state badges.

### Phase 3: Harden & scale
- Webhook push notifications (Google watch channels) to reduce polling latency.
- Reconciliation jobs, improved conflict UX, org-level controls.

## 9) Testing Strategy

### Unit tests
- OAuth callback/token refresh logic.
- Event transformation mappers (internal <-> Google schema).
- Conflict detection and idempotency behavior.

### Integration tests
- Mock Google APIs for:
  - Initial full sync
  - Incremental sync token flow
  - Token expiry and refresh failures
  - Concurrent edits/conflicts

### End-to-end tests
- Connect account -> map calendar -> sync events visible in UI.
- Create event in app -> appears in mocked Google feed.
- Delete in Google -> removed/tombstoned in app.

## 10) Execution Backlog (suggested)
1. Create provider connection/mapping data models + migrations.
2. Implement OAuth start/callback/disconnect endpoints.
3. Build Google API client wrapper with token refresh.
4. Add inbound sync worker + incremental token handling.
5. Add outbound event job hooks on CRUD routes.
6. Implement calendar mapping UI + integration settings.
7. Add metrics, dashboards, alerting, and runbooks.
8. Run staged rollout behind feature flags; expand cohort progressively.

## 11) Risks & Mitigations
- **Token revocation / auth expiry** -> proactive refresh + re-auth UX.
- **API quota limits** -> incremental sync, backoff, batching, watch channels.
- **Event model mismatch (recurrence/timezones)** -> deterministic mapping layer + extensive contract tests.
- **Duplicate events** -> stable mapping keys + idempotency guards.
- **Silent drift** -> scheduled reconciliation + discrepancy alerts.

## 12) Definition of Done (phase 2)
- User can connect Google Calendar and map at least one app calendar.
- Google events appear in app calendar within defined SLA.
- App event CRUD syncs to Google with retry + observability.
- Conflicts are detectable and visible to users/admin logs.
- Security review completed for OAuth/token handling.
