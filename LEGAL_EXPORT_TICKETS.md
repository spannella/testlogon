# Legal & DSAR Data Export — Implementation Tickets

This backlog adds three legal/compliance export capabilities on top of the existing ROOT-only audit-export pipeline (`app/services/audit_export_pipeline.py`, `app/routers/audit_export.py`, `frontend/src/pages/admin/AuditExportPage.tsx`) and the partial GDPR service (`app/services/gdpr_service.py`, `app/routers/privacy.py`): a complete per-user DSAR ("download my data") package, a legal-hold marker that suspends deletion/retention, and a chain-of-custody law-enforcement/subpoena export. All three reuse the audit-export PDF renderer, HMAC manifest signing (`_compute_manifest_signature` at `app/services/audit_export_pipeline.py:670`), and S3 plumbing.

## Milestone 1 — DSAR / "Download My Data" full per-user export

### LEX-001: Inventory every per-user data subsystem and define the DSAR package schema
**Type:** Spike  
**Priority:** P0  
**Estimate:** 2 day(s)

**Description**
- The current export (`process_export` at `app/services/gdpr_service.py:415`) only assembles profile, addresses, billing, messages, contacts, calendar, subscriptions, sessions, api_keys, files-metadata, newsfeed posts, and tickets — and several of those are best-effort `try/except` that silently swallow gaps (e.g. messages at `app/services/gdpr_service.py:448-494`).
- Cross-reference the deletion path (`process_deletion` at `app/services/gdpr_service.py:673`) which already enumerates more subsystems (video_metadata at `:804`, file-manager S3 objects at `:879`, KYC key destruction at `app/services/gdpr_service.py:151`) to find subsystems the export currently misses.
- Catalogue remaining per-user data: KYC cases (`app/services/kyc_cases.py`), questionnaires/responses, signing packets (`SIGNATURE_PDF_ENABLED`), shop orders/cart, projects, host inventory + SSH keys (`app/services/ssh_key_manager.py`), wallet/ledger, alerts (`T.alerts`), and uploaded file *bytes* (export currently exports manifest only — `app/services/gdpr_service.py:535`).
- Produce a written schema mapping each subsystem → DDB table/PK pattern → JSON file path inside the package → fields to redact (mirror existing `redact_keys` usage at `app/services/gdpr_service.py:443`).

**Acceptance Criteria**
- Document lists every per-user subsystem with its DDB table handle/name, key pattern, and redaction rules.
- Schema defines the package layout (folder per subsystem + top-level `manifest.json` + `README.txt`).
- Gaps between export and deletion coverage are explicitly enumerated.

**Dependencies**
- None.

---

### LEX-002: Per-user full-data-export builder service
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 day(s)

**Description**
- Create `app/services/dsar_export.py` with `build_user_package(user_sub, categories)` that assembles all subsystems from LEX-001 into a single ZIP, replacing the partial inline logic in `process_export` (`app/services/gdpr_service.py:415`).
- Reuse `_query_all` (`app/services/gdpr_service.py:377`) and `_serialize_items` (`app/services/gdpr_service.py:395`) for Decimal/set-safe JSON; reuse `redact_keys` for secrets (`session_token`, `csrf_token`, `key_hash`, `card_number`).
- Compute a per-file SHA-256 and an overall content SHA-256 over the canonical concatenation (mirror the NDJSON-canonical-hash approach at `app/services/audit_export_pipeline.py:396-398`).
- Optionally include actual file bytes from the file-manager bucket (`S.filemgr_bucket`) when `include_file_bytes` is set, capped by a size budget; otherwise manifest-only as today.

**Acceptance Criteria**
- `build_user_package` returns ZIP bytes + a manifest dict listing every file with its SHA-256, size, and source table.
- Every subsystem from LEX-001 is represented (empty subsystems produce an empty JSON, not a missing file).
- Secrets are redacted; unit test asserts no `card_number`/`*_token`/`key_hash` appears in output.

**Dependencies**
- LEX-001.

---

### LEX-003: Signed manifest + README for the DSAR package
**Type:** Feature  
**Priority:** P0  
**Estimate:** 1 day(s)

**Description**
- Add a `manifest.json` to the DSAR ZIP signed with the existing HMAC scheme: call `_compute_manifest_signature` (`app/services/audit_export_pipeline.py:670`) and embed `signing_key_id` (`S.audit_export_signing_key_id`, settings line ~2068) exactly as the audit pipeline does at `app/services/audit_export_pipeline.py:455-461`.
- Manifest fields: `user_sub`, `request_id`, `generated_at`, `categories`, `files[]` (path/sha256/size), `package_sha256`, `signature`, `contains_pii: true`.
- Add a human-readable `README.txt` describing each folder and how to verify the signature with `verify_manifest_signature` (`app/services/audit_export_pipeline.py:681`).

**Acceptance Criteria**
- `verify_manifest_signature(manifest)` returns True for a freshly built package and False after any file is altered.
- README enumerates every folder produced by LEX-002.

**Dependencies**
- LEX-002.

---

### LEX-004: Wire DSAR builder into privacy.py request + download flow
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 day(s)

**Description**
- Replace the body of `process_export` so it delegates to `build_user_package` (LEX-002) while preserving the existing S3 upload + DDB status update (`app/services/gdpr_service.py:566-617`) and `_run_export_safe` background invocation (`app/routers/privacy.py:80,85`).
- Keep the existing endpoints (`POST /ui/privacy/export` at `app/routers/privacy.py:52`, `GET /ui/privacy/export/{request_id}/download` at `:153`) and rate limit (`has_recent_export` at `app/services/gdpr_service.py:250`) unchanged.
- Extend `ExportRequestIn`/`DataRequestOut` (`app/models.py`) and `create_export_request` categories (`app/routers/privacy.py:66-71`) to carry the new subsystem toggles + optional `include_file_bytes`.
- Surface `package_sha256` on the request status response (`get_request_status` at `app/routers/privacy.py:132`).

**Acceptance Criteria**
- `POST /ui/privacy/export` produces a complete signed package via the new builder; status flips pending→completed; download returns a presigned URL (`get_export_download_url` at `app/services/gdpr_service.py:634`).
- New category toggles are honoured; omitting them defaults to a full export.
- Existing privacy E2E/unit behaviour (rate limit 429, failed-on-error) still holds.

**Dependencies**
- LEX-003.

---

### LEX-005: Frontend DSAR request + download UI
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 day(s)

**Description**
- Add a "Download my data" panel under `frontend/src/pages/security/` (or settings/privacy) calling the privacy endpoints via a new `frontend/src/api/endpoints/privacy.ts`, mirroring the admin `AuditExportPage.tsx` query/poll/download pattern.
- Show category checkboxes (messages, files, billing, profile, …), request status with polling, package size + `package_sha256`, and a download button that follows the 302 to the presigned URL.

**Acceptance Criteria**
- User can request, see live status, and download their package from the UI.
- Displays the package SHA-256 and expiry (`S.privacy_export_ttl_days`, settings line 1784).
- Disabled / rate-limited states render a clear message (403 / 429).

**Dependencies**
- LEX-004.

---

## Milestone 2 — Legal hold

### LEX-006: Legal-hold data model + service
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 day(s)

**Description**
- Create `app/services/legal_hold.py` storing holds in a new `legal_holds` DDB table (register a `TableDef` in `scripts/local-ddb-init.py` near the other handles ~line 96, PK `pk`, SK `sk`) keyed `HOLD#{hold_id}` / `META`, plus a `USER#{user_sub}` GSI for fast "is this user held?" lookups (the existing `has_retention_hold` at `app/services/gdpr_service.py:270` scans all of a user's requests — too coarse for a standalone hold).
- A hold carries: `hold_id`, scope (`user_sub` and/or `case_id`), `reason`, `created_by`, `created_at`, `status` (active/released), `released_by`/`released_at`, optional `expires_at`.
- CRUD: `place_hold`, `release_hold`, `get_hold`, `list_active_holds`, and `is_user_on_hold(user_sub)`.

**Acceptance Criteria**
- Placing a hold writes the META row + the user GSI row; `is_user_on_hold` returns True in O(1) query (no table scan).
- Releasing a hold sets status=released and stops blocking deletion (LEX-007) without deleting the audit row.
- Unit tests cover place/release/expiry and multiple holds per user.

**Dependencies**
- None.

---

### LEX-007: Enforce legal hold in deletion + retention paths
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 day(s)

**Description**
- Block `request_deletion` (`app/routers/privacy.py:165`) when `is_user_on_hold` is True, alongside the existing `has_retention_hold` check at `app/routers/privacy.py:176`, returning 403 with a legal-hold reason.
- Guard `process_deletion` (`app/services/gdpr_service.py:673`) and the admin-approve auto-process path (`app/routers/privacy.py:286-296`) so a held user is never erased even if a stale request exists.
- Guard the retention/anonymization sweep and any TTL-driven expiry (DSAR package TTL at `app/services/gdpr_service.py:603`, request TTL `_REQUEST_TTL_DAYS` at `:28`) so held users' data is preserved past normal retention.
- Re-use the admin retention-hold endpoints in `app/routers/account_deletion.py:197,221` or supersede them with the new legal-hold service (decide in LEX-006).

**Acceptance Criteria**
- Deletion request and processing both refuse a held user with a distinct, audited error.
- Released hold immediately re-enables deletion.
- Test: place hold → deletion blocked; release → deletion proceeds; TTL expiry skips held users.

**Dependencies**
- LEX-006.

---

### LEX-008: Legal-hold admin API + minimal UI
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 day(s)

**Description**
- Add ROOT/legal-role-gated endpoints (router `app/routers/legal_hold.py`, registered in `app/main.py`) to place, release, list, and get holds, mirroring the `_require_root` pattern at `app/routers/audit_export.py:34`.
- Every place/release writes an audit event via `audit_event` (`app/services/alerts.py:644`).
- Add an admin UI page (`frontend/src/pages/admin/LegalHoldPage.tsx`) + route in `frontend/src/App.tsx` listing active holds with place/release actions.

**Acceptance Criteria**
- Only ROOT (or the legal role from LEX-011) can call the endpoints; others get 403.
- UI lists active holds and supports place/release; actions appear in the audit trail.

**Dependencies**
- LEX-006, LEX-011.

---

## Milestone 3 — Law-enforcement / subpoena scoped export

### LEX-009: Subpoena/warrant intake record
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 day(s)

**Description**
- Create `app/services/legal_export.py` + a `legal_exports` DDB table (`TableDef` in `scripts/local-ddb-init.py`) capturing the chain-of-custody intake: `legal_export_id`, `matter_ref` (subpoena/warrant number), `requesting_authority`, `requested_by` (internal actor), `reason`/`legal_basis`, target `user_sub`(s), `date_range` (from/to), `data_types`, `created_at`, `status`.
- Reuse `create_export_job`'s filter parameters as a model: `actor_user_id`/`target_user_id`/`event_actions`/`from_ts`/`to_ts` (`app/services/audit_export_pipeline.py:304-313`).

**Acceptance Criteria**
- Intake persists who/when/why + scope and returns a `legal_export_id`.
- `matter_ref`, `requesting_authority`, and `legal_basis` are required; missing fields → 400.

**Dependencies**
- None.

---

### LEX-010: Scoped sealed export builder (chain-of-custody package)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 day(s)

**Description**
- Build a scoped package combining (a) the targeted user's data (reuse `build_user_package` from LEX-002, filtered by `data_types` and `date_range`) and (b) the matching audit-trail slice via `_merge_sorted_events` with `actor`/`target`/date filters (`app/services/audit_export_pipeline.py:264`).
- Render an audit-grade PDF cover/index reusing `_render_audit_pdf` (`app/services/audit_export_pipeline.py:160`) for the included events, and a tamper-evident `manifest.json` (signed via `_compute_manifest_signature` at `:670`) that records every file's SHA-256, the matter/authority/actor metadata, and a `chain_of_custody` block.
- Upload to S3 (reuse `app/core.aws_clients.s3_client` + `ServerSideEncryption: AES256` as at `app/services/audit_export_pipeline.py:582-591`) under a `legal-exports/{legal_export_id}/` prefix; mark "sealed" (no in-place mutation after completion).

**Acceptance Criteria**
- Output is a single sealed package: user data (scoped) + audit events (scoped) + signed manifest + PDF index.
- Manifest signature verifies; altering any file fails `verify_manifest_signature`.
- Date-range and data-type filters are honoured; out-of-scope data is absent.

**Dependencies**
- LEX-002, LEX-009.

---

### LEX-011: Legal role + ROOT access control for legal exports
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 day(s)

**Description**
- Add a `LEGAL` capability — either a new `Role`/`AdminScope` in `app/auth/roles.py:8,14` or a dedicated allowlist — gating all Milestone-2/3 endpoints; ROOT is always permitted.
- Add a `_require_legal(ctx)` helper modelled on `_require_root` (`app/routers/audit_export.py:34`) and apply it to LEX-008/LEX-012 routers.
- Legal exports must NOT be accessible to ordinary ADMIN (the existing audit export is ROOT-only — preserve that bar).

**Acceptance Criteria**
- Only ROOT or the legal role can place holds / create-and-download legal exports; ADMIN and USER get 403.
- Role/scope normalization round-trips through the cookie JWT (`app/auth/deps.py`).
- Unit tests assert 403 for non-legal roles on every protected endpoint.

**Dependencies**
- None.

---

### LEX-012: Legal-export API + full audit of every legal action
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 day(s)

**Description**
- Add `app/routers/legal_export.py` (registered in `app/main.py`) with create-intake, generate, list, get-status, and download endpoints, all behind `_require_legal` (LEX-011) and the SECOPS-007 dev/prod parity rules used by the audit pipeline.
- Emit an `audit_event` (`app/services/alerts.py:644`) for every action — intake created, package generated, download issued, status viewed — recording actor, `matter_ref`, target user_sub(s), and scope, so each legal export is itself fully audited.
- Download returns a short-lived presigned URL (reuse `generate_presigned_url` pattern at `app/services/gdpr_service.py:658`) and logs an access event each time.

**Acceptance Criteria**
- Every create/generate/download writes an audit event with actor + matter_ref + scope; events are queryable via the audit adapters.
- Download URL is short-lived; each download is independently audited.
- Non-legal roles are rejected before any data is touched.

**Dependencies**
- LEX-010, LEX-011.

---

### LEX-013: Retention & expiry of generated legal/DSAR packages
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 day(s)

**Description**
- Set DDB `ttl_epoch` + S3 lifecycle/expiry on generated DSAR packages (already partly present: `export_expires_at` at `app/services/gdpr_service.py:603`, `S.privacy_export_ttl_days` line 1784) and on legal-export packages via a new `S.legal_export_ttl_days` setting.
- A held user's packages (LEX-006) must be exempt from auto-expiry — gate the expiry sweep on `is_user_on_hold` / active matter.
- Add a janitor (mirror `audit_export_worker` loop pattern, `app/services/audit_export_worker.py`) that deletes expired S3 objects + flips DDB status to `expired`, gated behind a feature flag like the existing `audit_export_worker_enabled` (settings line 2072).

**Acceptance Criteria**
- Expired packages return 404 on download (existing check at `app/services/gdpr_service.py:648`) and their S3 objects are removed.
- Packages tied to an active legal hold/matter are never expired.
- Sweep is idempotent and feature-flag gated.

**Dependencies**
- LEX-006, LEX-010.

---

### LEX-014: Tests for DSAR, legal hold, and legal export
**Type:** Chore  
**Priority:** P0  
**Estimate:** 3 day(s)

**Description**
- Add offline/hermetic pytest suites under `tests/` (moto-backed tables patched onto frozen `T` via `object.__setattr__`, `S` flags via `object.__setattr__`, S3 stubbed) following the patterns described in CLAUDE.md "common gotchas".
- `tests/test_lex_dsar_export.py`: full package builder includes every subsystem, redaction holds, manifest signature verifies/fails-on-tamper, privacy endpoints flow pending→completed→download.
- `tests/test_lex_legal_hold.py`: place/release/expiry, `is_user_on_hold` O(1) lookup, deletion blocked while held and re-enabled on release, TTL exemption.
- `tests/test_lex_legal_export.py`: intake validation, scoped builder honours date-range/data-type filters, PDF + signed manifest produced, `_require_legal` rejects ADMIN/USER, every action emits an audit event, expiry sweep removes packages.

**Acceptance Criteria**
- All suites pass offline with no real AWS/network.
- Coverage includes access-control 403 paths, tamper-detection, and retention/expiry.
- Tests run green under `just test`.

**Dependencies**
- LEX-004, LEX-007, LEX-012, LEX-013.

---
