# Signature Form PDF — Implementation Tickets

This ticket set maps to `docs/signature-form-pdf-implementation-plan.md` and is sequenced by dependency/risk so teams can ship incrementally behind a feature flag.

---

## Milestone 0 — Foundations, schema, and contracts

### SFP-001: Create signature packet persistence schema
**Scope**
- Add storage models/tables for:
  - `signature_packets`
  - `signature_packet_signers`
  - `signature_packet_fields`
  - `signature_packet_events`
  - `signature_packet_artifacts`
- Add required indexes for sender list and signer inbox queries.

**Acceptance criteria**
- Schema objects created in infra + local dev stack.
- Query paths support:
  - list packets by sender,
  - list packets by signer/status,
  - load packet aggregate by packet ID.

**Dependencies**
- None.

---

### SFP-002: Add domain models + enums for packet lifecycle
**Scope**
- Implement canonical enums/types for:
  - packet status (`draft`, `sent`, `partially_signed`, `completed`, `cancelled`, `expired`)
  - signer status (`pending`, `completed`)
  - field types (`signature`, `initials`, `date`, `text`)
- Add shared validation helpers for status transitions.

**Acceptance criteria**
- Transition guard blocks invalid transitions.
- All services/routes use shared enums (no ad-hoc strings).

**Dependencies**
- SFP-001.

---

### SFP-003: Feature flag and config plumbing
**Scope**
- Add `SIGNATURE_PDF_ENABLED` feature flag.
- Add settings for packet expiration, max signer count, max field count, and renderer timeout.

**Acceptance criteria**
- All signature endpoints/UX are flag-gated.
- Safe defaults documented for local/dev/prod.

**Dependencies**
- None.

---

## Milestone 1 — Sender draft + send flow (backend)

### SFP-010: `POST /signature-packets` (create draft)
**Scope**
- Create draft packet from an existing uploaded PDF.
- Persist origin metadata (share vs messaging source).

**Acceptance criteria**
- Sender can create draft packet linked to source file.
- Non-PDF uploads are rejected with clear validation errors.

**Dependencies**
- SFP-001, SFP-002, SFP-003.

---

### SFP-011: `POST /signature-packets/{id}/fields` (field CRUD)
**Scope**
- Add/update/delete field boxes in `draft` state only.
- Validate page bounds, size limits, and field type support.
- Validate assigned signer references.

**Acceptance criteria**
- Field operations succeed only for sender while packet is `draft`.
- Invalid coordinates/pages/assignees are rejected deterministically.

**Dependencies**
- SFP-010.

---

### SFP-012: `POST /signature-packets/{id}/send` (lock + dispatch)
**Scope**
- Lock field geometry and assignments.
- Validate at least one signer and required-field completeness before send.
- Transition `draft -> sent` and emit invitations.

**Acceptance criteria**
- Sent packet cannot be edited by sender.
- Send action emits signer invitation notifications/events.

**Dependencies**
- SFP-011.

---

### SFP-013: `GET /signature-packets/{id}` (detail/read model)
**Scope**
- Return packet metadata, signer progress, field list, and participant-aware capabilities.

**Acceptance criteria**
- Sender and signers receive role-appropriate payloads.
- Non-participants are denied access.

**Dependencies**
- SFP-010.

---

## Milestone 2 — Signer fill + completion gate (backend)

### SFP-020: `POST /signature-packets/{id}/fields/{field_id}/fill`
**Scope**
- Allow signer to fill only fields assigned to them.
- Enforce type-specific validation:
  - signature/initials text constraints,
  - date format normalization,
  - text max length.

**Acceptance criteria**
- Cross-signer field edits are rejected.
- Filled value and timestamp are persisted with audit event.

**Dependencies**
- SFP-012, SFP-013.

---

### SFP-021: `POST /signature-packets/{id}/mark-done`
**Scope**
- Mark signer complete only when all required assigned fields are filled.
- Transition packet to `partially_signed` after first completion.

**Acceptance criteria**
- Mark-done fails with actionable errors when required fields remain.
- Signer completion status updates atomically.

**Dependencies**
- SFP-020.

---

### SFP-022: Multi-signer completion gate + finalization trigger
**Scope**
- Add packet-level completion evaluator (`all required signers completed`).
- Trigger finalize job when last required signer completes.

**Acceptance criteria**
- Packet transitions to `completed` only once all required signers are done.
- Duplicate finalize attempts are idempotent.

**Dependencies**
- SFP-021.

---

## Milestone 3 — Final render artifact + delivery

### SFP-030: Implement PDF overlay rendering worker
**Scope**
- Build worker/job to render signer values onto source PDF pages.
- Flatten overlays into immutable final PDF artifact.

**Acceptance criteria**
- Final artifact is generated for completed packets.
- Rendering failures are retriable and observable.

**Dependencies**
- SFP-022.

---

### SFP-031: Store artifact hash + immutability metadata
**Scope**
- Persist checksum/fingerprint for final PDF and render metadata.
- Block post-completion field/value mutations.

**Acceptance criteria**
- Final artifact has verifiable hash in persistence.
- Completed packet write attempts are rejected except audit/reads.

**Dependencies**
- SFP-030.

---

### SFP-032: `GET /signature-packets/{id}/final-pdf` + delivery fan-out
**Scope**
- Add authorized download endpoint for completed packet artifact.
- Send completion notifications to sender + all signers.

**Acceptance criteria**
- Participants can download completed PDF.
- Non-participants cannot access artifact.
- Completion notices emitted exactly once per packet.

**Dependencies**
- SFP-031.

---

## Milestone 4 — Frontend sender/signer experiences

### SFP-040: Sender “Create signature form” composer
**Scope**
- Add PDF editor mode for signature packets.
- Add field toolbar (`signature`, `initials`, `date`, `text`) and placement interactions.
- Add signer assignment controls and required/optional toggles.

**Acceptance criteria**
- Sender can place fields on document pages and assign signers.
- Save/send flows use backend draft and field endpoints.

**Dependencies**
- SFP-011, SFP-012.

---

### SFP-041: Signer fill UI + validation feedback
**Scope**
- Render only fields assigned to current signer as editable.
- Show remaining required fields count and field-level validation.

**Acceptance criteria**
- Signer can fill assigned boxes and submit updates.
- “Mark done” remains disabled until requirements are met.

**Dependencies**
- SFP-020, SFP-021.

---

### SFP-042: Packet status timeline and completed-download UX
**Scope**
- Show status chips (`awaiting your signature`, `waiting on others`, `completed`).
- Add completion timeline and download call-to-action.

**Acceptance criteria**
- Sender/signers see real-time status and completion state.
- Completed packets expose final download entry point.

**Dependencies**
- SFP-032, SFP-040, SFP-041.

---

## Milestone 5 — Share/messaging integration

### SFP-050: Extend attachment/share contracts with `signature_packet_id`
**Scope**
- Add optional packet linkage in share payloads and message attachments.
- Ensure compatibility for existing non-signature attachments.

**Acceptance criteria**
- Signature packets can be initiated from share flow.
- Signature packets can be initiated from messaging flow.

**Dependencies**
- SFP-012.

---

### SFP-051: Thread/share status updates for packet progress
**Scope**
- Publish state changes to originating channel (share or message thread).
- Render participant-specific status text/chips.

**Acceptance criteria**
- Participants see packet progress updates in originating surface.
- Completed artifact appears in originating surface at completion.

**Dependencies**
- SFP-050, SFP-032.

---

## Milestone 6 — Security, compliance posture, and observability

### SFP-060: Authorization and tamper hardening
**Scope**
- Enforce participant-only access across all packet endpoints.
- Lock field geometry after send.
- Block sender edits once sent and all edits after completion.

**Acceptance criteria**
- Access control test matrix passes for sender/signer/non-participant roles.
- Tamper attempts return audited authorization/validation failures.

**Dependencies**
- SFP-013, SFP-020, SFP-031.

---

### SFP-061: Append-only audit event coverage
**Scope**
- Emit audit events for create, field changes, send, fill, done, complete, download.
- Add packet event query tooling for support/debug workflows.

**Acceptance criteria**
- Every mutating path emits an event with actor + timestamp.
- Support tooling can reconstruct packet history from events.

**Dependencies**
- SFP-010 through SFP-032.

---

### SFP-062: Metrics, dashboard, and alerting
**Scope**
- Add metrics for packet lifecycle funnel and render latency/failures.
- Ship dashboard + alerts for stuck packets and render errors.

**Acceptance criteria**
- Dashboard committed and available in target environments.
- Alert policies documented with ownership/escalation paths.

**Dependencies**
- SFP-022, SFP-030, SFP-032.

---

## Milestone 7 — QA and rollout

### SFP-070: Automated test suite expansion
**Scope**
- Add unit tests for validation and state transition logic.
- Add integration tests for:
  - single signer completion,
  - multi-signer completion gate,
  - authorization boundaries,
  - share/message origin behavior.

**Acceptance criteria**
- New tests pass in CI.
- Critical regressions covered for sender/signer flows.

**Dependencies**
- SFP-010 through SFP-062.

---

### SFP-071: Internal dogfood + staged rollout playbook
**Scope**
- Launch behind feature flag for internal users first.
- Define beta cohort criteria, success metrics, rollback triggers.

**Acceptance criteria**
- Rollout checklist and runbook documented.
- Decision gate defined for general availability.

**Dependencies**
- SFP-070.

---

## Optional follow-on tickets (Phase 2)

### SFP-080: Sequential signing order enforcement
**Scope**
- Enforce signer order using `order_index` and waiting-state UX.

**Acceptance criteria**
- A signer cannot fill/mark-done until prior ordered signer has completed.
- Sender and signers can see current “waiting on signer X” state.

**Dependencies**
- SFP-021, SFP-022, SFP-042.

---

## Design enhancement tickets (requested follow-on)

### SFP-081: Signature/initials input modes (typed + drawn)
**Scope**
- Support both typed and drawn inputs for `signature` and `initials` fields.
- Persist capture mode + normalized render payload (vector path or typed text) per filled field.
- Add signer UX to choose input mode per field with reusable preference defaults.

**Acceptance criteria**
- Signers can complete `signature` and `initials` fields using either typed or drawn mode.
- Final render worker correctly flattens both typed and drawn signatures into the completed PDF.
- Validation enforces mode-specific constraints (stroke payload bounds, typed length limits).

**Dependencies**
- SFP-020, SFP-030.

---

### SFP-083: First-open legally binding consent notice
**Scope**
- Show a required legal notice when signer first opens a packet, stating the signature is legally binding.
- Capture signer acknowledgement event with timestamp before allowing fill/mark-done actions.
- Store notice version so legal text changes are auditable over time.

**Acceptance criteria**
- Signers must acknowledge legal notice once per packet before they can submit field fills.
- Audit events include notice-shown and notice-accepted records with actor + timestamp.
- Notice is not repeatedly shown after acknowledgement unless legal version changes.

**Dependencies**
- SFP-013, SFP-061.

---

### SFP-084: Scheduled reminder email workflow for pending signers
**Scope**
- Add configurable reminder schedule for unsigned packets (e.g., 24h, 72h, 7d).
- Send reminder emails only to pending signers and stop reminders after signer completion/cancel/expiry.
- Include packet context and secure deep-link back to signing UI.

**Acceptance criteria**
- Pending signers receive reminders on schedule while packet remains actionable.
- No reminders sent for completed/cancelled/expired packets or completed signers.
- Reminder sends are idempotent and audit/metric observable.

**Dependencies**
- SFP-022, SFP-062.

---

### SFP-085: Final artifact audit appendix page (signing timeline + IP evidence)
**Scope**
- Append an audit appendix page to completed PDF including:
  - first shared/sent timestamp,
  - signer completion timestamps,
  - signer source IPs at signing time,
  - packet completion timestamp.
- Ensure appendix content is generated from append-only packet events and signer completion metadata.

**Acceptance criteria**
- Completed artifact includes a deterministic audit appendix page for every packet.
- Appendix values match persisted event/signing records and are covered by artifact checksum.
- Support can reconstruct appendix source records through packet event history tooling.

**Dependencies**
- SFP-030, SFP-031, SFP-061.
