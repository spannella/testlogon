# Apple Calendar (iCal) Bi-Directional Sync — Implementation Plan

## 1) Objective
Enable users to connect Apple Calendar (iCloud/CalDAV) to our calendar system so that:
- Existing events in Apple Calendar are imported and kept up-to-date in our system.
- Events created or edited in our system are synced back to Apple Calendar.
- Sync is reliable, observable, and safe for user data.

---

## 2) Scope and assumptions

### In scope
- User-level connection to Apple Calendar using CalDAV credentials.
- Initial historical import from selected Apple calendars.
- Ongoing two-way sync (create/update/delete) between Apple and our platform.
- Per-event conflict detection and deterministic merge policy.
- Support for core event fields:
  - title, description, location
  - start/end datetime + timezone
  - all-day events
  - recurrence basics (RRULE + exceptions where possible)
  - attendees (phase-gated)

### Out of scope (initial release)
- Full Apple-native advanced properties parity (custom metadata, travel time, etc.).
- Organization-wide delegated calendars.
- Real-time push webhooks from Apple (CalDAV does not provide native webhook parity like Google/Microsoft).

### Key assumptions
- For iCloud calendars, users authenticate using Apple ID + app-specific password.
- Polling will be required for change detection from Apple side.
- We can store encrypted external credentials and sync state securely.

---

## 3) Integration approach

### Protocol decision
Use **CalDAV** as the primary protocol for Apple Calendar read/write interoperability.

### Why CalDAV
- Standards-based and supported by iCloud Calendar.
- Supports calendar discovery, event CRUD, ETag-based updates, and sync tokens.
- Enables bidirectional synchronization without Apple-only SDK dependencies.

### High-level architecture
1. **Connection service**
   - Validates credentials and discovers user calendars.
2. **Sync orchestrator**
   - Schedules initial import + incremental sync jobs.
3. **CalDAV adapter**
   - Handles REPORT/PROPFIND/PUT/DELETE requests and mapping to internal models.
4. **Mapping layer**
   - Converts iCalendar payloads (`VEVENT`, `VTIMEZONE`, `RRULE`) to internal event schema and back.
5. **Sync state store**
   - Tracks per-calendar sync token, ETag, remote UID/resource URL, last synced timestamp.
6. **Conflict resolver**
   - Applies merge policy for concurrent edits.

---

## 4) User experience and product flow

### Connect flow
1. User opens “Connect Apple Calendar”.
2. User enters Apple ID email + app-specific password.
3. System validates credentials against CalDAV endpoint.
4. System lists discovered calendars (Work, Home, etc.).
5. User chooses:
   - import direction: Apple -> ours only OR two-way
   - which calendars to sync
   - sync frequency (e.g., every 5–15 min)

### Ongoing behavior
- Initial sync imports historical events (configurable lookback, e.g., 6–12 months).
- Incremental sync runs on schedule and on local event mutation.
- UI shows connection health, last successful sync, and unresolved conflicts.

### Disconnect flow
- User can pause or disconnect integration.
- Credentials are revoked/deleted from our encrypted store.
- Existing imported events remain unless user chooses cleanup.

---

## 5) Data model additions

Add integration tables/entities:

1. `calendar_connections`
   - `id`, `user_id`, `provider` (`apple_caldav`), `status`
   - `credential_ref` (pointer to encrypted secret)
   - `created_at`, `updated_at`, `last_success_at`, `last_error`

2. `external_calendars`
   - `id`, `connection_id`, `remote_calendar_id` (CalDAV collection URL)
   - `display_name`, `timezone`, `sync_enabled`, `sync_direction`
   - `sync_token`, `ctag`, `last_synced_at`

3. `external_event_links`
   - `id`, `internal_event_id`, `external_calendar_id`
   - `remote_uid`, `remote_resource_url`, `remote_etag`
   - `last_source` (`internal|apple`), `last_source_updated_at`

4. `calendar_sync_jobs` / `calendar_sync_runs`
   - status, duration, counts (created/updated/deleted/conflicts), error details

---

## 6) Sync algorithm design

### A. Initial import (Apple -> ours)
1. Discover selected calendars.
2. Fetch events in window (e.g., now - 12 months to now + 12 months).
3. For each event:
   - parse iCal object
   - upsert internal event
   - create `external_event_link` with UID, resource URL, ETag
4. Persist sync token/ctag per calendar.

### B. Incremental pull (Apple -> ours)
1. Use sync token (or fallback by ctag + time range scan).
2. Get changed/deleted resources since last token.
3. For each change:
   - if mapped link exists, update internal event
   - if no link, create new internal event + link
   - if remote deleted, soft-delete/cancel internal event per policy
4. Update sync token and run metrics.

### C. Incremental push (ours -> Apple)
Triggered by local event writes for connected calendars.

1. Build canonical iCalendar payload from internal event.
2. If linked remote resource exists:
   - send conditional `PUT` with known ETag (`If-Match`) to prevent blind overwrite.
3. If no link exists:
   - create new remote event (`PUT` with UID) and store returned ETag/resource URL.
4. On delete in our system:
   - issue remote `DELETE` if two-way sync is enabled.

### D. Conflict handling
Conflict scenario: both sides changed same event between syncs.

Proposed policy (v1):
- If ETag mismatch on push:
  1. Pull latest remote copy.
  2. Compare `last_modified` timestamps + field-level diff.
  3. Apply deterministic rule:
     - default: latest-write-wins for non-critical fields
     - preserve locally edited attendee notes/metadata when possible
  4. Write merged result to both systems.
  5. Log conflict artifact for audit/debug.

---

## 7) Field mapping and recurrence strategy

### Core field mapping
- `SUMMARY` <-> `title`
- `DESCRIPTION` <-> `description`
- `LOCATION` <-> `location`
- `DTSTART`/`DTEND` <-> `start_at`/`end_at`
- `RRULE`, `EXDATE`, `RECURRENCE-ID` <-> recurrence model
- `STATUS:CANCELLED` <-> cancelled state
- `UID` as stable cross-system event identity

### Recurrence rollout
- Phase 1: simple recurring series (daily/weekly/monthly) without complex exception editing.
- Phase 2: exception instances (`RECURRENCE-ID`) and detached edits.
- Phase 3: parity hardening for edge cases (timezone boundary, DST transitions).

---

## 8) Security and compliance

- Store credentials in encrypted secret manager (never plaintext in DB logs).
- Redact auth headers and calendar payload PII in logs.
- Use least-privilege access patterns in internal services.
- Add explicit user consent text describing data accessed and sync behavior.
- Add rate limiting and exponential backoff to avoid account lockouts.
- Support credential rotation and connection re-validation.

---

## 9) Reliability and observability

### Job controls
- Queue-based sync workers with idempotent job keys.
- Per-connection lock to prevent concurrent overlapping sync.
- Retry policy:
  - transient 5xx/network errors: exponential backoff + jitter
  - auth failures: mark connection degraded and notify user

### Metrics
- sync run success/failure rate
- events pulled/pushed per run
- conflict rate
- end-to-end sync latency (internal write to remote reflected)

### Alerting
- sustained provider auth failures
- elevated conflict/error rates
- backlog growth in sync queue

---

## 10) API and UI surfaces

### Backend endpoints (proposed)
- `POST /calendar/integrations/apple/connect`
- `GET /calendar/integrations/apple/calendars`
- `POST /calendar/integrations/apple/calendars/select`
- `POST /calendar/integrations/apple/sync-now`
- `POST /calendar/integrations/apple/disconnect`
- `GET /calendar/integrations/apple/status`

### Admin/support tooling
- Inspect connection health and last errors.
- Re-run sync for specific connection/calendar.
- Safe “repair links” operation for UID mismatches.

### UI requirements
- Integration settings page with:
  - connected calendars list
  - last sync timestamp and status
  - pause/resume/disconnect controls
  - conflict notification center

---

## 11) Delivery phases and timeline

### Phase 0 — Discovery and technical spike (1–2 weeks)
- Validate CalDAV auth/discovery against iCloud test accounts.
- Prove event read/write + ETag behavior.
- Confirm recurrence parsing library choices.

### Phase 1 — Read sync GA baseline (2–3 weeks)
- Connection flow + calendar discovery.
- Initial import + incremental pull.
- Sync status UI and logs/metrics.

### Phase 2 — Write sync (2–3 weeks)
- Internal -> Apple push for create/update/delete.
- ETag preconditions + basic conflict resolver.
- Retry and degraded connection handling.

### Phase 3 — Recurrence and hardening (2–4 weeks)
- Recurrence exceptions support.
- Backfill/repair utilities.
- Load, chaos, and long-run reliability tests.

### Phase 4 — Rollout
- Beta cohort (feature flag).
- Monitor SLOs and error budgets.
- Gradual percentage rollout to all users.

---

## 12) Testing strategy

### Unit tests
- iCal <-> internal model mapping
- RRULE parsing/serialization
- conflict resolution decisions

### Integration tests
- CalDAV adapter contract tests (discovery, sync token flow, CRUD, ETag collisions)
- simulated incremental sync with deletions and recurrence updates

### End-to-end tests
- connect account -> import events -> edit both sides -> verify convergence
- disconnect/reconnect and credential rotation flow

### Non-functional tests
- scale test with high event volumes
- resilience test for provider outages/timeouts
- DST/timezone boundary correctness suite

---

## 13) Risks and mitigations

1. **CalDAV provider variability**
   - Mitigation: strict adapter layer + provider-specific compatibility tests.

2. **Credential friction (app-specific password setup)**
   - Mitigation: guided UI walkthrough and in-product troubleshooting.

3. **Complex recurrence semantics**
   - Mitigation: phased recurrence support and explicit user messaging for unsupported edge cases.

4. **No push webhooks from Apple**
   - Mitigation: adaptive polling frequency and sync-now control.

5. **Conflict-heavy shared calendars**
   - Mitigation: clear source-of-truth indicators + conflict feed + robust audit logs.

---

## 14) Definition of done (v1)

- User can successfully connect Apple Calendar credentials and select calendars.
- Historical Apple events import into our calendar with correct timezone handling.
- New/updated/deleted internal events sync back to Apple within target SLA.
- Incremental pull sync reflects Apple-side edits/deletes within polling interval.
- Conflict handling is deterministic and observable.
- Metrics, logs, and runbooks exist for operational support.
