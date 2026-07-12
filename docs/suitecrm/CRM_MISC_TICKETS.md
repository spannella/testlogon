# CRM Events, Maps, Surveys, Documents & Misc — Implementation Tickets

**Area**: Events, Maps, Surveys, Documents & Misc
**Source**: SuiteCRM gap analysis (`docs/suitecrm/SUITECRM_GAP_ANALYSIS.md`, section "[T4] Events, Maps, Surveys, Documents & misc — 15 tickets")

## What SuiteCRM provides in this area

SuiteCRM's FP Events module provides a full event lifecycle: invitee list management with bulk import, delegate/registration management with acceptance/decline workflow and attendance tracking, capacity limits with automatic waitlist promotion, PDF badge/certificate generation. The Maps add-on geocodes contact and account addresses and exposes proximity/radius search with a visual map view. The Surveys module (built on AOS_PDF_Templates) supports survey distribution via email invitation, per-question answer-frequency analytics, and bulk CSV/Excel export of all responses. The Documents module provides a versioned document library with categories, revision history, expiration dates, and expiry alerts. Outbound SMS can be sent from a contact record or broadcast to a contact list. The Admin panel has a live global activity audit log for real-time cross-module browsing.

## Cross-cutting constraints

- **Additive only, default-off**: Every ticket introduces a feature flag in `app/core/settings.py` (e.g. `CRM_EVENTS_ENABLED`). With the flag off all new routes return 404 and new background workers are no-ops. No existing code is modified.
- **Single-table DynamoDB, SECOPS-007 dev/prod parity**: All new tables use the `TableDef` pattern in `scripts/local-ddb-init.py`. Numeric GSI sort keys **must** declare `attr_types={"<key>": "N"}` (CLAUDE.md gotcha; omitting causes `ValidationException` at query time).
- **Reuse existing primitives — never fork**:
  - Email: `app/services/alerts.send_alert_email` (`app/services/alerts.py:459`) for all invitation/notification email dispatch.
  - In-app alert/audit: `app/services/alerts.write_alert` and `audit_event` (`app/services/alerts.py:356`, `644`).
  - SMS: `app/services/sms_delivery.send_sms` (`app/services/sms_delivery.py:207`) and `send_sms_bulk` (line 308); respects suppression list and per-number daily rate limit.
  - S3 upload: `app.core.aws_clients.s3_client` factory (pattern: `app/services/kyc_partner_api.py` `_store_document_bytes`).
  - Geocoding mock: `app/services/kyc_address_verification._geocode` (lines 210–224) — deterministic SHA-256-derived lat/lng, gated by `S.kyc_address_geocoding_enabled`; extend this pattern, do not re-implement.
  - Questionnaire analytics: `_compute_questionnaire_analytics` in `app/routers/questionnaires.py:150` already computes completion rates and drop-offs; extend with per-question frequency distributions.
  - CSV export: `app/routers/csv_export.py` `VALID_SOURCES` set at line 20; extend, do not fork.
  - Calendar events: `T.calendar` table (single-table, PK=`calendar_id`, SK=`sk`); `EventCreateIn`/`EventOut` models at `app/models.py:1256`; `create_event` at `app/routers/calendar.py:1551`.
  - Background loops: `app.add_event_handler("startup", ...)` in `app/main.py` for schedulers.
  - Cursor pagination: `app/core/cursor.encode_cursor` / `decode_cursor`.
  - HMAC tokens: `app/core/crypto.mint_ws_token` / `verify_ws_token` (same scheme as cart recovery links, CLAUDE.md).
  - Auth: `app/services/sessions.require_ui_session`; `app/auth/roles.Role` enum; `app/auth/deps.require_admin_session`.
- **Planned upstream dependencies**: PTY-001..PTY-015 (`PARTY_CRM_TICKETS.md`) deliver Party/Contact/Account. Where tickets reference contacts or accounts, they carry opaque `contact_id`/`account_id` string foreign keys that resolve once PTY ships. MKT-003/MKT-009 deliver the marketing campaign/contact-list layer; EVT-014 (bulk SMS) depends on MKT contact-list resolution.
- **Hermetic offline tests**: All pytest files must use moto-backed DDB tables bound via `object.__setattr__` on frozen `T`/`S` handles (canonical form: `tests/test_gap_0220_0221_ssh_stored_key.py`). No real AWS/network calls.

---

### EVT-001: Feature flag, settings & DynamoDB scaffolding for CRM Events

**Type:** Chore  **Priority:** P1  **Estimate:** 1d

**Description**

All CRM Events module work is gated behind a single flag. This ticket:

1. Adds `crm_events_enabled: bool = os.environ.get("CRM_EVENTS_ENABLED", "false") == "1"` to `app/core/settings.py`.
2. Creates two new DynamoDB tables in `scripts/local-ddb-init.py`:
   - `crm_events` — PK=`event_id` (S), SK=`sk` (S). GSI `ByOwner`: PK=`owner_sub` (S), SK=`created_at` (N). GSI `ByCalendar`: PK=`calendar_event_id` (S), SK=`created_at` (N). `attr_types={"created_at": "N"}`.
   - `crm_event_registrations` — PK=`event_id` (S), SK=`registrant_sub` (S). GSI `ByRegistrant`: PK=`registrant_sub` (S), SK=`registered_at` (N). `attr_types={"registered_at": "N"}`.
3. Adds corresponding `Table` handles to `app/core/tables.py` (`T.crm_events`, `T.crm_event_registrations`).
4. Adds a guard helper `_require_crm_events_enabled()` used in all EVT routers.

Reuses the `TableDef` scaffolding pattern from `scripts/local-ddb-init.py:29`.

**Acceptance Criteria**
- `just restart` creates both tables without error.
- With `CRM_EVENTS_ENABLED=0`, all EVT-* routes return 404.
- Settings unit test confirms flag default is `false`.

**Dependencies** — None (foundation ticket).

---

### EVT-002: CRM Event invitee list management (add/remove/import, invitation email)

**Type:** Feature  **Priority:** P1  **Estimate:** 3d

**Description**

Adds invitee management to CRM events. A CRM Event wraps a `calendar_event_id` (referencing the existing `T.calendar` table) and adds an invitee sub-list with per-invitee invitation status (`pending`, `sent`, `accepted`, `declined`, `attended`).

**DynamoDB model** (in `crm_events` table from EVT-001):
- `PK=event_id`, `SK=META` — stores `name`, `description`, `calendar_event_id`, `owner_sub`, `max_attendance` (nullable), `created_at` (N).
- `PK=event_id`, `SK=INVITEE#{invitee_sub}` — stores `invitee_sub`, `invite_status`, `invited_at` (N), `responded_at` (N).

**Service**: `app/services/crm_events.py` — new file.
- `create_crm_event(owner_sub, calendar_event_id, name, description, max_attendance=None)` — writes META row, emits `audit_event`.
- `add_invitee(event_id, invitee_sub)` — writes INVITEE row with `invite_status="pending"`.
- `remove_invitee(event_id, invitee_sub)` — deletes INVITEE row.
- `bulk_import_invitees(event_id, user_subs: list[str])` — calls `add_invitee` in a loop, skips duplicates.
- `send_invitations(event_id, owner_sub)` — queries all INVITEE rows with `invite_status="pending"`, calls `send_alert_email` per invitee (from `app/services/alerts.py:459`), updates status to `"sent"`.
- `list_invitees(event_id)` — queries SK prefix `INVITEE#`, returns list with pagination via `encode_cursor`.

**Router**: `app/routers/crm_events.py` — new file, prefix `/ui/crm/events`, tags `["crm_events"]`.
- `POST /` — create event.
- `POST /{event_id}/invitees` — add single invitee.
- `DELETE /{event_id}/invitees/{invitee_sub}` — remove.
- `POST /{event_id}/invitees/bulk-import` — bulk import list of `user_subs`.
- `POST /{event_id}/invitees/send-invitations` — dispatch invitation emails.
- `GET /{event_id}/invitees` — paginated list.

All routes use `Depends(require_ui_session)` and `_require_crm_events_enabled()`.

**Acceptance Criteria**
- Invitees can be added/removed individually and in bulk.
- `send-invitations` calls `send_alert_email` for each pending invitee; subsequent call skips already-sent.
- Bulk import of 100 user_subs succeeds without error.
- E2E: Playwright spec `frontend/e2e/crm-events.spec.ts` section 1 (API only).

**Dependencies** — EVT-001.

---

### EVT-003: CRM Event delegate/registration, acceptance/decline, attendance check-in

**Type:** Feature  **Priority:** P1  **Estimate:** 3d

**Description**

Adds the delegate/registration layer to CRM events: any invitee (or any platform user if the event is open) can register; organiser can check in attendees. Uses `crm_event_registrations` table from EVT-001.

**DynamoDB model** (in `crm_event_registrations` table):
- `PK=event_id`, `SK=registrant_sub` — stores `registrant_sub`, `status` (registered / accepted / declined / attended / waitlisted), `registered_at` (N), `responded_at` (N), `checked_in_at` (N), `waitlist_position` (N, nullable).

**Service additions** to `app/services/crm_events.py`:
- `register_for_event(event_id, registrant_sub)` — checks capacity via EVT-004 waitlist logic; writes registration row; emits `audit_event("crm_event_register", ...)`.
- `respond_to_invitation(event_id, registrant_sub, status: Literal["accepted","declined"])` — updates `status` and `responded_at`.
- `check_in_attendee(event_id, registrant_sub, actor_sub)` — sets `status="attended"`, `checked_in_at`; requires `actor_sub == event.owner_sub` or role >= ADMIN.
- `list_registrations(event_id)` — queries all registration rows; supports cursor pagination.

**Router additions** to `app/routers/crm_events.py`:
- `POST /{event_id}/register` — self-register.
- `PUT /{event_id}/registrations/{registrant_sub}/respond` — accept/decline (own registration or owner).
- `POST /{event_id}/registrations/{registrant_sub}/check-in` — admin/owner only.
- `GET /{event_id}/registrations` — paginated list (owner/admin only).

**Acceptance Criteria**
- A user can register, accept, decline; organiser can check in.
- Registration is rejected (409) if user is already registered.
- Check-in returns 403 for non-owners.

**Dependencies** — EVT-002.

---

### EVT-004: CRM Event capacity limits and waitlist with auto-promotion

**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

Adds `max_attendance` enforcement to CRM events. When `max_attendance` is set on the META row and the accepted registration count equals `max_attendance`, new registrations are added to a waitlist queue with monotonically incrementing `waitlist_position`. On cancellation/decline of an existing registration, the top waitlisted entry is automatically promoted.

**Service additions** to `app/services/crm_events.py`:
- `_count_accepted(event_id)` — scans `crm_event_registrations` and counts `status` in `{"registered","accepted","attended"}`.
- In `register_for_event`: if `max_attendance` is set and `_count_accepted >= max_attendance`, assign `status="waitlisted"` and `waitlist_position = current_max + 1` (DDB atomic increment via `update_item`).
- `_promote_from_waitlist(event_id)` — queries registrations with `status="waitlisted"` ordered by `waitlist_position`, promotes the smallest to `status="registered"`, sends an email notification via `send_alert_email`.
- Hook `_promote_from_waitlist` into `respond_to_invitation` when status is `"declined"` and into a `DELETE /{event_id}/registrations/{sub}` cancel endpoint.

**Router additions**:
- `DELETE /{event_id}/registrations/{registrant_sub}` — cancel own registration, triggering waitlist promotion.
- `GET /{event_id}/capacity` — returns `{max_attendance, accepted_count, waitlisted_count, available_spots}`.

**Acceptance Criteria**
- When capacity is full, new registrant receives `status="waitlisted"`.
- On decline/cancel, next waitlist entry is promoted and email notification sent.
- `GET .../capacity` returns correct counts.

**Dependencies** — EVT-003.

---

### EVT-005: Geocode contact and account addresses, store lat/lng

**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

Extends the existing KYC address geocoding pattern (`app/services/kyc_address_verification._geocode`, lines 210–224) to general contact and account address records. This is the foundation required by EVT-006 (proximity search) and EVT-007 (map view).

New flag: `crm_geocoding_enabled: bool = os.environ.get("CRM_GEOCODING_ENABLED", "false") == "1"` in `app/core/settings.py`.

**Service**: `app/services/crm_geocoding.py` — new file.
- `geocode_address(address: dict) -> dict[str, float] | None` — wraps the same SHA-256 mock geocoding logic from `kyc_address_verification._geocode` (lines 210–224) behind the new flag; in prod, calls a configured `CRM_GEOCODING_PROVIDER_URL` (Nominatim or Google Maps); dev always uses the deterministic mock.
- `geocode_party_address(party_id: str, address: dict) -> None` — calls `geocode_address`, writes `lat`, `lng`, `geocoded_at` onto the party record in `T.party` (PTY prerequisite; write is skipped when party table is absent).

In `app/routers/contacts.py`, add a background call to `geocode_party_address` after contact creation/update when `crm_geocoding_enabled` is true (best-effort, never raises).

**Acceptance Criteria**
- Mock geocoding returns deterministic lat/lng from a hash of the address fields.
- Geocoding is skipped (no-op) when `CRM_GEOCODING_ENABLED=0`.
- `geocode_party_address` tolerates a missing party table without crashing.
- Unit test confirms deterministic output for a fixed address.

**Dependencies** — EVT-001 (flag pattern). PTY-001 (party table) is a soft prerequisite; lat/lng write is conditional on table presence.

---

### EVT-006: Contact/account proximity search (Haversine radius endpoint)

**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

Adds a proximity search endpoint that returns contacts/accounts within a radius of a given lat/lng pair, using the Haversine formula against stored `lat`/`lng` fields written by EVT-005. Requires `crm_geocoding_enabled=true`.

**Service additions** to `app/services/crm_geocoding.py`:
- `haversine_km(lat1, lng1, lat2, lng2) -> float` — pure Python Haversine distance calculation.
- `proximity_search(user_sub: str, center_lat: float, center_lng: float, radius_km: float, limit: int = 50) -> list[dict]` — scans the party GSI (via `T.party` once PTY ships), filters by `haversine_km <= radius_km`, returns list of `{party_id, name, lat, lng, distance_km}` sorted by distance.

**Router**: new endpoint in `app/routers/crm_geocoding.py`, prefix `/ui/crm/maps`.
- `GET /contacts/proximity?lat=&lng=&radius_km=&limit=` — returns proximity-ordered list; 404 when `crm_geocoding_enabled=false`.

**Acceptance Criteria**
- Returns contacts within specified radius ordered by distance ascending.
- `radius_km=0` returns empty list; `radius_km=20000` returns all geocoded contacts.
- Returns 404 when `CRM_GEOCODING_ENABLED=0`.
- Unit test confirms Haversine formula output against known coordinates.

**Dependencies** — EVT-005.

---

### EVT-007: Map view — frontend page with geocoded pin-drop rendering

**Type:** Feature  **Priority:** P2  **Estimate:** 3d

**Description**

Adds a frontend map page at `/crm/maps` that renders geocoded contact/account pins using a Leaflet embed. Consumes the EVT-006 proximity endpoint; supports a centre-point search with adjustable radius.

**Frontend** (`frontend/src/pages/crm/maps/`):
- `CrmMapsPage.tsx` — Leaflet `MapContainer` with `TileLayer` (OpenStreetMap); fetches contacts via `GET /ui/crm/maps/contacts/proximity?lat=&lng=&radius_km=` using React Query `useQuery`; renders one `Marker` per result with a `Popup` showing name and distance.
- `api/endpoints/crmMaps.ts` — axios wrappers for the proximity endpoint.
- Route added to `frontend/src/App.tsx`: `/crm/maps` → lazy `CrmMapsPage`.

Sidebar link added to `AppShell` under a CRM section (same approach as existing sidebar entries in `components/layout/`), only rendered when user has role >= USER and `crm_geocoding_enabled` is surfaced via a feature-flags endpoint.

**Acceptance Criteria**
- Map renders with OpenStreetMap tiles.
- Markers appear for contacts returned by the proximity endpoint.
- Empty state shown when no geocoded contacts exist.
- Page is not linked in sidebar when `CRM_GEOCODING_ENABLED=0` (feature-flag gate).

**Dependencies** — EVT-006.

---

### EVT-008: Survey distribution — email invitation to contact list or questionnaire link

**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Adds survey distribution: an owner of a published questionnaire can send an email invitation carrying the public survey link to a list of email addresses or (once PTY ships) a party contact-list segment.

New flag: `crm_survey_distribution_enabled: bool = os.environ.get("CRM_SURVEY_DISTRIBUTION_ENABLED", "false") == "1"` in `app/core/settings.py`.

**Service**: `app/services/crm_survey_distribution.py` — new file.
- `send_survey_invitations(questionnaire_id: str, owner_sub: str, recipients: list[str], message: str | None = None) -> dict` — for each recipient email calls `send_alert_email(to_emails=[email], subject=..., body_text=survey_link + message)` from `app/services/alerts.py:459`; writes a `SURVEY_INVITE#{questionnaire_id}#{recipient}` record to the `questionnaires` DDB table (PK/SK single-table) with `status="sent"`, `sent_at` (N); returns `{sent: N, failed: N}`.
- `get_distribution_summary(questionnaire_id: str, owner_sub: str) -> dict` — queries all `SURVEY_INVITE#` rows, returns `{total_sent, total_responses, response_rate}`.

**Router additions** in `app/routers/questionnaires.py`:
- `POST /drafts/{questionnaire_id}/distribute` — `DistributeSurveyReq(recipients: list[EmailStr], message: str | None)`; verifies ownership via `_owned_questionnaire_or_404`; calls service; returns `{sent, failed}`.
- `GET /drafts/{questionnaire_id}/distribution-summary` — owner-only; returns distribution summary.

**Acceptance Criteria**
- Survey invite email is dispatched for each recipient.
- Duplicate recipient (already `sent`) is skipped with idempotent behaviour.
- Distribution summary returns correct `response_rate` based on submitted sessions.
- Returns 404 when `CRM_SURVEY_DISTRIBUTION_ENABLED=0`.

**Dependencies** — EVT-001 (flag pattern). Requires existing `app/routers/questionnaires.py` (REPO singleton, `_owned_questionnaire_or_404`).

---

### EVT-009: Survey analytics — per-question answer frequency distribution

**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Extends `_compute_questionnaire_analytics` in `app/routers/questionnaires.py:150` to add per-question answer-frequency distributions for `select`, `multiselect`, and `radio` question types. The existing function computes completion rates and drop-offs but does not aggregate answer values.

**Service additions** in `app/routers/questionnaires.py` (inline helper extending `_compute_questionnaire_analytics`):
- For each submitted session, load `list_session_answers` from `DynamoQuestionnaireRepository` (`questionnaires_repository.py:573`).
- For questions with `type in {"select", "multiselect", "radio"}`, accumulate value frequencies into `{question_id: {option_value: count}}`.
- Return as `question_frequencies: list[{question_id, question_label, type, options: [{value, label, count, pct}]}]` added to the existing `analytics` response dict.

No new table or flag needed; the change extends the existing `GET /questionnaires/drafts/{id}/analytics` endpoint.

**Acceptance Criteria**
- `analytics.question_frequencies` is present in response.
- Option counts sum to the number of submitted sessions (for single-select) or across all submitted answers (for multiselect).
- Skips `text`, `slider`, `date`, `time`, `address` question types (no frequency breakdown).
- `pct` for each option = `count / total_responses * 100`, rounded to 1 decimal.

**Dependencies** — None (extends existing `_compute_questionnaire_analytics`).

---

### EVT-010: Survey bulk response export (CSV)

**Type:** Feature  **Priority:** P1  **Estimate:** 1d

**Description**

Adds `questionnaire_responses` as a valid source in `app/routers/csv_export.py` (already listed in `VALID_SOURCES` at line 20) and implements the corresponding generator in `app/services/csv_export.py`. Currently the endpoint accepts `questionnaire_responses` but the generator raises a `ValueError` for unimplemented sources.

**Service additions** in `app/services/csv_export.py`:
- New branch for `source == "questionnaire_responses"` in `generate_csv_rows`.
- Loads all `RESPONSE_SESSION` rows for the questionnaire via `DynamoQuestionnaireRepository.list_response_sessions(questionnaire_id=...)` (`questionnaires_repository.py:492`).
- For each submitted session, loads `list_session_answers`; flattens answer dict to one column per question_id.
- Header row: `session_id, respondent_id, submitted_at, status, <question_id_1>, <question_id_2>, ...`.
- Streams rows as a generator with UTF-8 BOM (RFC 4180, matches existing billing_ledger export pattern in `csv_export.py`).

**Acceptance Criteria**
- `GET /ui/export/csv?source=questionnaire_responses&questionnaire_id=<id>` downloads a valid CSV.
- Header row contains one column per question (from the schema snapshot).
- Only `status=submitted` sessions are included by default.
- Returns 403 if caller does not own the questionnaire.
- Rate-limiting (5/60s, existing `_bucket_limit` at `csv_export.py:66`) applies.

**Dependencies** — None (extends `app/routers/csv_export.py` + `app/services/csv_export.py`).

---

### EVT-011: Document library — category, description, and record-link fields on file nodes

**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

Adds CRM document library metadata to file-manager file nodes: an optional `crm_category` string, a `crm_description` (up to 2000 chars), and an optional `linked_record_type` / `linked_record_id` pair that links the document to a contact, ticket, or account record. All fields are additive attributes on the existing DDB file-node item (stored in the `filemgr` table via `filemanager._table()`, `app/services/filemanager.py:104`).

New flag: `crm_document_library_enabled: bool = os.environ.get("CRM_DOCUMENT_LIBRARY_ENABLED", "false") == "1"`.

**Service additions** in `app/services/filemanager.py`:
- `update_crm_metadata(owner: str, path: str, *, crm_category: str | None, crm_description: str | None, linked_record_type: str | None, linked_record_id: str | None) -> dict` — `update_item` on the node PK/SK; validates `linked_record_type in {"contact","ticket","account","party"}` when set.

**Router additions** in `app/routers/filemanager.py`:
- `PATCH /files/{path:path}/crm-metadata` — `CrmMetadataIn(crm_category, crm_description, linked_record_type, linked_record_id)`; gated by flag.
- `GET /files/crm-search?linked_record_type=&linked_record_id=` — scans user's file nodes filtered by `linked_record_type` + `linked_record_id` (uses `FilterExpression`, paginates via `LastEvaluatedKey` per CLAUDE.md DDB gotcha).

**Acceptance Criteria**
- `PATCH` stores all four fields; fields are nullable (omitting them leaves existing values unchanged).
- `GET /files/crm-search` returns only files with matching record link.
- Fields do not appear in existing `GET /files` list response (additive only).
- Returns 404 when `CRM_DOCUMENT_LIBRARY_ENABLED=0`.

**Dependencies** — EVT-001 (flag pattern). Soft dependency on PTY-001 for `account`/`contact` record types.

---

### EVT-012: Document revision history (version on overwrite, download prior versions)

**Type:** Feature  **Priority:** P2  **Estimate:** 3d

**Description**

Adds document revision tracking to the file manager. When a file is overwritten (same path, new upload), the prior version is archived as a revision row instead of being lost. Revision rows live in the same `filemgr` DDB table as a sparse SK variant: `SK=REVISION#{revision_number}#{iso_timestamp}`.

New flag: `crm_document_revisions_enabled: bool = os.environ.get("CRM_DOCUMENT_REVISIONS_ENABLED", "false") == "1"`.

**Service additions** in `app/services/filemanager.py`:
- Before overwriting an existing file node in `upload_file` (`app/services/filemanager.py:2110`), when flag is enabled: read current node, write a snapshot at `SK=REVISION#{n}#{now_iso()}` carrying the same fields plus `revision_number` (N), `superseded_at`, `superseded_by_s3_key`; then proceed with the regular upload.
- `list_revisions(owner: str, path: str) -> list[dict]` — queries SK prefix `REVISION#` on the node's PK; returns list newest-first.
- `download_revision(owner: str, path: str, revision_number: int) -> dict` — resolves the S3 object from the archived revision row; returns presigned download URL (same pattern as `download_file`).

**Router additions** in `app/routers/filemanager.py`:
- `GET /files/{path:path}/revisions` — returns revision list.
- `GET /files/{path:path}/revisions/{revision_number}/download` — redirect to presigned URL for that revision.

**Acceptance Criteria**
- On second upload of same path, old file is archived as revision 1; new upload is revision 2 (current).
- `GET .../revisions` returns both with correct `revision_number`.
- Prior revision can be downloaded via presigned URL.
- When `CRM_DOCUMENT_REVISIONS_ENABLED=0`, overwrite behaves identically to today (no revision stored).

**Dependencies** — EVT-011 (flag pattern, file node model).

---

### EVT-013: Document expiration date and expiry notification alerts

**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

Adds an optional `expires_at` (Unix timestamp N) field to file-manager file nodes and a background scheduler that fires in-app and email alerts before expiry. Mirrors the pattern from `app/services/license_agreements.py` which defines `EXPIRY_WARNING_DAYS = 30` and `EXPIRY_WARNING_SECONDS = EXPIRY_WARNING_DAYS * 86400` (lines 54–55) and calls `write_alert` on expiry approach.

New flag: `crm_document_expiry_enabled: bool = os.environ.get("CRM_DOCUMENT_EXPIRY_ENABLED", "false") == "1"`.

**Service additions** in `app/services/filemanager.py`:
- `set_file_expiry(owner: str, path: str, expires_at: int | None) -> dict` — `update_item` adding `expires_at` (N) and `expiry_alert_sent: False` to the file node; validates `expires_at > now_ts()`.
- `check_expiring_documents()` — scans/queries file nodes where `expires_at BETWEEN now_ts() AND now_ts() + 30*86400` and `expiry_alert_sent = False`; for each calls `write_alert` (in-app) and `send_alert_email` (email); sets `expiry_alert_sent = True` atomically.

**Background worker**: `start_document_expiry_checker_task()` registered in `app/main.py` startup, gated by `crm_document_expiry_enabled`; polls every 3600s.

**Router additions** in `app/routers/filemanager.py`:
- `PATCH /files/{path:path}/expiry` — `FileExpiryIn(expires_at: int | None)`; sets or clears expiry.

**Acceptance Criteria**
- `PATCH .../expiry` stores/clears `expires_at` on the node.
- Background checker sends alert for files expiring within 30 days.
- Alert is sent exactly once per file (`expiry_alert_sent` guard).
- Returns 404 when `CRM_DOCUMENT_EXPIRY_ENABLED=0`.

**Dependencies** — EVT-011 (flag pattern, file node model). Existing `license_agreements.py` pattern serves as reference, not a dependency.

---

### EVT-014: Outbound SMS from contact record (individual send from UI)

**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Exposes an SMS compose-and-send action on a contact record in the frontend, wiring to `app/services/sms_delivery.send_sms` (`sms_delivery.py:207`). The platform SMS infrastructure (suppression, daily rate limit, dev-mode stub) is already complete; this ticket surfaces it at the CRM layer.

New flag: `crm_contact_sms_enabled: bool = os.environ.get("CRM_CONTACT_SMS_ENABLED", "false") == "1"`.

**Service additions**: `app/services/crm_contact_sms.py` — new file.
- `send_contact_sms(sender_sub: str, contact_phone: str, body: str) -> dict` — validates phone via `app/core/normalize.normalize_phone`; calls `send_sms(contact_phone, body)` from `sms_delivery.py:207` (honours suppression + daily limit); calls `audit_event("crm_contact_sms_sent", sender_sub, ...)`.

**Router**: `app/routers/crm_contact_sms.py`, prefix `/ui/crm/contacts/{contact_id}/sms`.
- `POST /` — `ContactSmsIn(body: str = Field(max_length=1600))`; resolves `contact_phone` from the contacts table (`T.contacts`, key `owner_id=user_sub, contact_id=contact_id`; 404 if missing or phone absent); calls service.

**Frontend** (`frontend/src/pages/contacts/`):
- `ContactSmsDialog.tsx` — `Dialog` with a textarea for the message body and a Send button. Invoked from a contact detail page SMS button (hidden when `crm_contact_sms_enabled=false`).
- `api/endpoints/crmContactSms.ts` — axios wrapper.

**Acceptance Criteria**
- POST sends SMS and returns `{ok: true, message_id, status}`.
- 404 if contact has no `phone` field.
- SMS respects existing suppression list (returns `{status: "suppressed"}`).
- Returns 404 when `CRM_CONTACT_SMS_ENABLED=0`.

**Dependencies** — EVT-001 (flag pattern). Soft dependency on PTY-001 for enriched contact phone field.

---

### EVT-015: Global activity audit log — paginated admin browse endpoint

**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Adds a live paginated admin endpoint for real-time browsing of the cross-module audit log without spawning a background export job (complements the existing `POST /ui/admin/audit-exports` job-based path in `app/routers/audit_export.py`). Requires ROOT role (same guard `_require_root` from `app/routers/audit_export.py:34`).

New flag: `crm_audit_log_browse_enabled: bool = os.environ.get("CRM_AUDIT_LOG_BROWSE_ENABLED", "false") == "1"`.

**Service**: `app/services/audit_log_browse.py` — new file.
- `browse_audit_log(*, from_ts: int, to_ts: int, user_sub_filter: str | None, event_type_filter: str | None, limit: int = 50, cursor: str | None) -> dict` — queries `T.alerts` using the existing GSI (same query path as `audit_adapters.py` adapters, `app/services/audit_adapters.py`); applies `FilterExpression` for `user_sub_filter` and `event_type_filter`; paginates via `encode_cursor`/`decode_cursor`; returns `{items: list[dict], cursor: str | None, total_scanned: int}`.

**Router additions** in `app/routers/audit_export.py`:
- `GET /ui/admin/audit-log` — query params: `from_ts`, `to_ts`, `user_sub` (optional filter), `event_type` (optional filter), `limit` (max 200), `cursor`; ROOT only; gated by flag.

**Frontend** (`frontend/src/pages/admin/`):
- `AuditLogBrowsePage.tsx` — filterable data table using `useInfiniteQuery` (React Query); columns: `user_sub`, `event_type`, `created_at`, `details`; date-range pickers for `from_ts`/`to_ts`.
- Route `/admin/audit-log` added to `App.tsx`; link added to admin sidebar.

**Acceptance Criteria**
- `GET /ui/admin/audit-log?from_ts=&to_ts=` returns paginated audit events.
- `user_sub` and `event_type` filters narrow results correctly.
- 403 for non-ROOT callers.
- Returns 404 when `CRM_AUDIT_LOG_BROWSE_ENABLED=0`.
- Frontend table renders with infinite scroll loading.

**Dependencies** — EVT-001 (flag pattern). Reuses `audit_adapters.VALID_CATEGORIES` (`app/services/audit_adapters.py`) and existing `T.alerts` table.
