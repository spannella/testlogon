# KYC Implementation Plan (Questionnaire + File Manager + Signature Packets + Tickets)

## 1) Goal
Ship a KYC workflow that reuses existing platform primitives:
- **Questionnaire** for collecting declared identity and risk answers.
- **File Manager** for photo/document uploads.
- **Signature Packets** for policy acknowledgements and legally binding consent.
- **Tickets** for manual/admin review and final disposition.

## 2) Existing capabilities we will reuse

### Questionnaire system
- Draft/publish lifecycle and versioned schemas already exist.
- Public/unlisted response sessions can be started, validated, submitted, and exported to PDF.
- Response analytics/events already support completion and validation hotspot monitoring.

### File manager system
- Existing file APIs support list/info/upload and shared upload workflows.
- Upload auditing and metadata are already produced.
- Can store KYC photos and supporting files under user-scoped folders.

### Signature packet system
- Packets are created from existing uploaded PDFs.
- Fields can be assigned/fill-completed by signers; packet status transitions and event trails are present.
- Legal notice acknowledgement and final PDF retrieval are already supported.

### Ticket system
- User/admin ticket flows already support assign, status transitions, messaging, and audit activity.
- Schema supports admin queues by status and assignee.
- Optimistic concurrency strategy already documented for safe state updates.

## 3) KYC target state
A single KYC case should include:
1. **Questionnaire submission** (identity + compliance declarations).
2. **File bundle** (selfie, ID front/back, optional proof of address).
3. **Policy signature artifact** (signed consent/disclosure packet).
4. **Review ticket** with links to all artifacts, reviewer checklist, and decision trail.

Final outcomes:
- `approved`
- `rejected`
- `needs_more_info`

## 4) Data model extension plan

## 4.1 New KYC case aggregate
Add a new KYC store (single-table family or dedicated table) with core fields:
- `kyc_case_id`
- `user_sub`
- `status` (`draft|submitted|under_review|needs_more_info|approved|rejected|expired`)
- `questionnaire`: `{ questionnaire_id, version_id, response_session_id, response_pdf_ref }`
- `files`: list of `{ path, type, uploaded_at, checksum?, verification_state }`
- `signature`: `{ packet_id, status, final_pdf_ref }`
- `review`: `{ ticket_id, assigned_admin_sub, decision, decided_at, reason_codes[] }`
- timestamps + version for concurrency

## 4.2 Cross-system references
Persist explicit references to avoid expensive lookups:
- Questionnaire response session ID.
- File manager paths (canonical paths only).
- Signature packet ID.
- Ticket ID.

## 4.3 Idempotency + replay safety
- `submit_kyc` and ticket creation must be idempotent per case.
- Event-driven updates should tolerate retries (e.g., signature complete webhook/event).

## 5) API/workflow design

## 5.1 Applicant flow endpoints
- `POST /v1/kyc/cases` → create draft case.
- `POST /v1/kyc/cases/{id}/start-questionnaire` → create response session from published slug.
- `POST /v1/kyc/cases/{id}/files/presign-or-upload` (or direct passthrough to file-manager upload conventions).
- `POST /v1/kyc/cases/{id}/signature-packet` → create packet from policy PDF in user files.
- `POST /v1/kyc/cases/{id}/submit` → validates all prerequisites and atomically marks submitted + opens review ticket.

## 5.2 Admin flow endpoints
- `GET /v1/kyc/admin/queue` (status + risk filters).
- `GET /v1/kyc/admin/cases/{id}` (joined KYC view).
- `POST /v1/kyc/admin/cases/{id}/request-info` (sets `needs_more_info`, posts ticket message).
- `POST /v1/kyc/admin/cases/{id}/approve`
- `POST /v1/kyc/admin/cases/{id}/reject`

## 5.3 Ticket integration
When case is submitted:
- Create ticket in KYC-dedicated space/category.
- Include links/IDs to questionnaire PDF, uploaded files, and signature final PDF.
- Keep ticket as reviewer collaboration channel; mirror decision status back to KYC case.

## 6) Orchestration/state machine

Transitions:
- `draft` → `submitted` (all artifacts complete)
- `submitted` → `under_review` (auto on ticket assignment or first admin touch)
- `under_review` → `needs_more_info|approved|rejected`
- `needs_more_info` → `submitted` (user resubmits)

Guards:
- Submit requires questionnaire status `submitted`, required file types uploaded, and signature packet completed.
- Approve/reject requires admin role + reviewer notes/reason codes.

## 7) Security/compliance controls
- Restrict KYC artifact access to owner + scoped admins only.
- Enforce immutable evidence snapshots on submission (or hash manifests).
- Capture audit events for every state transition and admin action.
- Add data retention + purge policy for rejected/expired cases.
- Redact sensitive fields in logs/analytics.

## 8) Rollout plan

### Phase 1 — Foundation
- Add KYC case model + APIs for draft lifecycle.
- Add references to questionnaire session, file paths, signature packet, and ticket.

### Phase 2 — Submission gate
- Implement prerequisite checks and atomic `submit` behavior.
- Create review ticket automatically.

### Phase 3 — Admin review experience
- Admin queue/list/detail APIs.
- Decision actions + ticket/KYC status synchronization.

### Phase 4 — Hardening
- Metrics, alerting, audit completeness, retry/idempotency tests.
- Retention and backfill jobs.

## 9) Metrics and SLAs
Track:
- Case funnel: draft → submitted → approved/rejected.
- Median/95p time in review.
- `needs_more_info` rate.
- Rejection reason distribution.
- Signature completion latency.

Service objectives:
- Submission endpoint success >99.9%.
- No orphaned submitted cases without tickets.
- No approved/rejected case without immutable evidence references.

## 10) Testing strategy
- Unit tests for state transition guards and idempotency.
- Integration tests across questionnaire, file upload, signature packet, and ticket creation.
- Admin concurrency tests for conflicting decisions (expect conflict handling).
- E2E scenario:
  1. User completes questionnaire,
  2. uploads files,
  3. signs policy,
  4. submits,
  5. admin approves/rejects,
  6. user sees final status.

## 11) Open decisions
- Whether KYC requires dedicated table vs. item family in existing table.
- Whether file scanning/face-match providers are in-scope for MVP.
- Whether policy signature is always required or risk-tier conditional.
- Exact retention windows by jurisdiction.

## 12) Suggested implementation tickets
1. **KYC-001**: KYC case persistence model + repository.
2. **KYC-002**: Applicant APIs (create/read/update draft).
3. **KYC-003**: Questionnaire linkage + submit prerequisite checks.
4. **KYC-004**: File attachment policy + required document validator.
5. **KYC-005**: Signature packet linkage + completion verifier.
6. **KYC-006**: Ticket auto-creation and sync hooks.
7. **KYC-007**: Admin queue + decision APIs.
8. **KYC-008**: Audit/metrics dashboards and alerts.
9. **KYC-009**: End-to-end test suite + failure-mode tests.
