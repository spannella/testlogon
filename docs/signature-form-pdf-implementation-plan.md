# Signature Form PDF Implementation Plan

## 1. Goals and scope

- Introduce a new **signature form PDF** workflow on top of existing PDF upload support.
- Allow **User 1 (sender/originator)** to:
  - upload a PDF,
  - place required fields/boxes of type: `signature`, `initials`, `date`, and `text`,
  - assign each field to a signer,
  - send the document via existing **share** flow or **messaging**.
- Allow **User 2+ (signers)** to:
  - open assigned document,
  - fill only fields assigned to them,
  - mark themselves done.
- Emit a completed signed PDF only after **all required signers finish**.
- Deliver the completed document to all participants.

Out of scope for first release:
- Identity verification beyond current account/session authentication.
- Regulatory e-sign compliance certification (e.g., SOC/legal opinion) beyond audit-friendly logs.
- Advanced field types (checkbox/radio/dropdown/file attachment).

## 2. Product behaviors

### 2.1 Document lifecycle states

Define explicit states for a signature packet:

1. `draft` - uploaded, fields editable by sender.
2. `sent` - locked field layout, awaiting signer actions.
3. `partially_signed` - at least one signer completed.
4. `completed` - all required signers completed; final PDF rendered.
5. `cancelled` / `expired` - no further signing allowed.

State transition rules:
- `draft -> sent` when sender confirms recipients + field assignments.
- `sent -> partially_signed` when first signer completes.
- `sent/partially_signed -> completed` only when all required signers have status `completed`.
- `completed` is immutable; only download/audit actions allowed.

### 2.2 Signer completion semantics

- Each signer has a checklist of required assigned fields.
- Signer can click “Mark done” only if all required assigned fields are filled.
- Packet completion gate is: `every required signer done == true`.

### 2.3 Delivery semantics

On completion:
- Generate final flattened signed PDF.
- Store immutable final artifact.
- Notify all participants (sender + signers).
- Attach/share final PDF in both:
  - share object (if initiated from share flow),
  - messaging thread (if initiated from messenger).

## 3. Data model additions

Add a dedicated signature packet model family (DynamoDB-style naming shown as example):

- `signature_packets`
  - `packet_id`, `owner_user_id`, `source_file_id`, `status`, `created_at`, `sent_at`, `completed_at`, `expires_at`, `origin_channel` (`share`/`message`).
- `signature_packet_signers`
  - `packet_id`, `signer_id`, `role` (`sender`, `signer`), `order_index` (for future sequential signing), `status`, `completed_at`.
- `signature_packet_fields`
  - `field_id`, `packet_id`, `page`, `x`, `y`, `width`, `height`, `field_type`, `assigned_signer_id`, `required`, `value`, `filled_at`.
- `signature_packet_events` (append-only audit trail)
  - `event_id`, `packet_id`, `actor_user_id`, `event_type`, `event_payload`, `timestamp`.
- `signature_packet_artifacts`
  - `packet_id`, `draft_pdf_file_id`, `final_pdf_file_id`, `render_version`.

Indexing needs:
- By `owner_user_id + created_at` for sender list.
- By `signer_id + status` for signer inbox.
- By `packet_id` fan-out for packet detail loading.

## 4. API and backend service plan

### 4.1 New endpoints (or route expansions)

- `POST /signature-packets`
  - create draft from uploaded PDF.
- `POST /signature-packets/{id}/fields`
  - add/update/delete field placements in draft.
- `POST /signature-packets/{id}/send`
  - lock draft and dispatch invitations.
- `GET /signature-packets/{id}`
  - packet detail + signer progress + field metadata.
- `POST /signature-packets/{id}/fields/{field_id}/fill`
  - signer fills one field.
- `POST /signature-packets/{id}/mark-done`
  - signer completion action.
- `GET /signature-packets/{id}/final-pdf`
  - authorized download of completed artifact.

### 4.2 Service-layer responsibilities

Create `app/services/signature_packets.py`:
- Field validation (bounds, page number, supported types).
- Assignment validation (assignee is valid packet signer).
- Permission checks:
  - sender can edit only in `draft`.
  - signers can fill only assigned fields in `sent/partially_signed`.
- Completion gating and finalization trigger.
- Audit-event emission for every mutating action.

### 4.3 Rendering pipeline

- Reuse existing file storage/upload infrastructure.
- Add a rendering worker/job to:
  - draw visual values for text/date/initials/signatures,
  - flatten overlays into final PDF,
  - checksum final artifact and store immutable reference.

Signature visual representation (phase 1):
- Signature/initials can be typed-style or drawn path (choose typed first for faster delivery).
- Include signer metadata page or embedded audit summary as optional attachment.

## 5. Frontend UX plan

### 5.1 Sender composer UI

In PDF preview/editor:
- Toggle “Create signature form”.
- Toolbar with 4 field types.
- Click/drag placement boxes on pages.
- Right panel: assign field to signer, set required/optional.
- “Send for signature” CTA with recipient picker (share or messaging recipient selection).

### 5.2 Signer fill UI

- Highlight only fields assigned to current signer.
- Per-field controls:
  - signature input,
  - initials input,
  - date picker/default today,
  - free text.
- Progress banner: `n remaining required fields`.
- “Mark done” enabled only when requirements satisfied.

### 5.3 Completion UX

- Status timeline: sent -> signer completed events -> completed.
- Download final PDF button when completed.
- Notifications in-app and via existing messaging/share surfaces.

## 6. Messaging and share integration

- Extend existing share payload/message attachment schema with optional `signature_packet_id`.
- Conversation rendering:
  - show packet status chip (`awaiting your signature`, `waiting on others`, `completed`).
- Access checks must ensure only packet participants can view/fill/download.
- If packet started in messaging, keep thread-aware updates; if started in share, preserve share-centric audit trail.

## 7. Security, integrity, and audit

- Record immutable audit events for:
  - packet creation,
  - field placement/changes,
  - send action,
  - each field fill,
  - signer done,
  - finalization.
- Protect against tampering:
  - lock field geometry after `sent`.
  - prohibit edits after signer has completed.
  - sign/fingerprint final artifact (hash persisted in DB).
- Enforce strict authorization for packet participants only.
- Add rate limits on signing endpoints to mitigate abuse.

## 8. Multi-signer behavior

Phase 1 recommendation: parallel signing
- Any signer can sign anytime.
- Packet completes when all required signers done.

Phase 2 (optional): sequential signing
- Use `order_index` to require signer N before signer N+1.
- UI shows “Waiting for previous signer”.

## 9. Rollout plan

### Milestone A - schema + core APIs
- Add models/migrations.
- Implement create draft, fields, send, read APIs.
- Basic audit log.

### Milestone B - signer completion + final render
- Implement fill field + mark done.
- Completion gating across multiple signers.
- Final PDF render and immutable storage.

### Milestone C - frontend workflows
- Sender field placement UI.
- Signer fill experience.
- Status indicators.

### Milestone D - integration + observability
- Messaging/share integration.
- Notifications.
- Metrics, dashboards, alerts, and support runbook.

### Milestone E - hardening
- Permission/security tests.
- Performance/load validation for large PDFs and many signers.
- Feature-flagged rollout with internal/beta cohorts.

## 10. Testing strategy

- Unit tests:
  - field validation and assignment rules,
  - state transitions,
  - completion gate logic.
- Integration tests:
  - sender creates + sends packet,
  - one signer completion,
  - multi-signer completion and finalization.
- Authorization tests:
  - non-participants denied,
  - signer cannot edit others’ fields,
  - sender cannot edit after send.
- End-to-end tests:
  - share-originated and message-originated flows,
  - final PDF availability for all parties.

## 11. Operational metrics

Track:
- packets created/sent/completed,
- median time-to-complete,
- per-step failure rates (render/fill/send),
- signer drop-off by stage,
- final render latency.

Alert on:
- stuck packets (no progress threshold),
- render job failures,
- unauthorized access spikes.

## 12. Open decisions for product/engineering

- Should signatures be draw-only, type-only, or both in v1?
- Do we need explicit legal consent checkbox before “Mark done”?
- Should completed document include certificate/audit appendix page?
- Expiration/reminder rules for pending signatures.
- Should sender be allowed to be a required signer in the same packet?

## 13. Suggested first implementation slice (2-3 sprints)

1. Backend packet + field models, create/send/read APIs.
2. Basic sender UI to place and assign fields.
3. Signer fill + mark done with multi-signer completion gate.
4. Final PDF render + artifact delivery.
5. Feature flag + internal dogfood rollout.

This slice delivers the requested core behavior quickly while leaving advanced legal/compliance and sequential-signing options for follow-on iterations.


## 14. Feature flag and runtime defaults

Use configuration to control rollout and operational limits:

- `SIGNATURE_PDF_ENABLED` (default `false`)
  - `false` in local/dev/prod by default until rollout approval.
  - Required to enable signature packet APIs/UI paths.
- `SIGNATURE_PACKET_EXPIRATION_HOURS` (default `168`)
  - Default 7-day expiry window for pending packets.
- `SIGNATURE_PACKET_MAX_SIGNERS` (default `10`)
  - Upper bound to prevent oversized packets.
- `SIGNATURE_PACKET_MAX_FIELDS` (default `200`)
  - Upper bound for rendering and UX safety.
- `SIGNATURE_PACKET_RENDERER_TIMEOUT_SECONDS` (default `60`)
  - Guardrail timeout for final PDF rendering jobs.

Recommended environment posture:
- **Local**: keep disabled by default; enable manually for feature work.
- **Dev/Staging**: enable only for internal/beta cohorts behind the flag.
- **Prod**: keep disabled until readiness checks pass, then enable progressively.
