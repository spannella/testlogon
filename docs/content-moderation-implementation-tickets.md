# Content Moderation Implementation Tickets

This document breaks `docs/content-moderation-plan.md` into implementable engineering tickets.

## Conventions
- **Priority**: P0 (must-have MVP), P1 (post-MVP), P2 (later).
- **Estimate**: S (<=2 days), M (3-5 days), L (1-2 weeks).
- **Dependencies**: Ticket IDs that should land first.

---

## Epic A — Reporting Entry Points (User-Facing)

### MOD-001 — Add unified `ReportContentModal` component
- **Priority**: P0
- **Estimate**: M
- **Scope**:
  - Build reusable modal with:
    - Topic multi-select: `sexual`, `extortion`, `criminal`, `spam`, `racist`.
    - Reason textarea.
    - Client-side validation + error states.
  - Emit normalized payload for API.
- **Acceptance criteria**:
  - Modal can be mounted from feed/message/profile contexts.
  - Prevent submit without at least one topic.
  - Displays server validation errors.

### MOD-002 — Add report action to Newsfeed post/comment/media UI
- **Priority**: P0
- **Estimate**: M
- **Dependencies**: MOD-001
- **Scope**:
  - Add “Report” action in post actions menu, comment actions, media viewer.
  - Pass correct `content_type` and `content_id` into modal.
- **Acceptance criteria**:
  - Report action visible only for eligible content.
  - Correct content metadata sent for post/comment/media.

### MOD-003 — Add report action to Messages UI
- **Priority**: P0
- **Estimate**: M
- **Dependencies**: MOD-001
- **Scope**:
  - Add report action for message bubble and message attachments.
  - Handle DM and group conversation contexts.
- **Acceptance criteria**:
  - Reporting works for text + media messages.
  - UI confirms successful submission.

### MOD-004 — Add report action to Profile photo UI
- **Priority**: P0
- **Estimate**: S
- **Dependencies**: MOD-001
- **Scope**:
  - Add report entry point on profile photo view.
- **Acceptance criteria**:
  - Profile-photo report submits with `content_type=profile_photo`.

---

## Epic B — Report Intake API + Persistence

### MOD-005 — Create DB schema for `content_reports`
- **Priority**: P0
- **Estimate**: M
- **Scope**:
  - Migration for `content_reports` table.
  - Enum/check constraint for topic taxonomy.
  - Indices: `content_type+content_id`, `reporter_user_id`, `created_at`.
- **Acceptance criteria**:
  - Migration applies cleanly in local/test env.
  - Invalid topic values rejected at DB boundary.

### MOD-006 — Implement `POST /v1/moderation/reports`
- **Priority**: P0
- **Estimate**: M
- **Dependencies**: MOD-005
- **Scope**:
  - Request validation.
  - Content existence + reportability checks.
  - Insert report record.
  - Return report ID + linked ticket ID.
- **Acceptance criteria**:
  - 2xx on valid payload.
  - 4xx on invalid content/topic.
  - Idempotency guard for repeated rapid submissions from same user/content.

### MOD-007 — Add abuse controls on report endpoint
- **Priority**: P0
- **Estimate**: S
- **Dependencies**: MOD-006
- **Scope**:
  - Rate limiting per user/IP.
  - Basic anti-spam heuristics/logging.
- **Acceptance criteria**:
  - Requests beyond threshold return controlled error.
  - Security events logged.

---

## Epic C — Ticket Creation + Queueing

### MOD-008 — Create DB schema for `moderation_tickets`
- **Priority**: P0
- **Estimate**: M
- **Scope**:
  - Migration for ticket table + status/priority fields.
  - Indexes on `status`, `queue`, `assigned_admin_user_id`, `latest_report_at`.
- **Acceptance criteria**:
  - Tickets queryable by board filters with performant index plan.

### MOD-009 — Implement dedup/aggregation service (report → ticket)
- **Priority**: P0
- **Estimate**: M
- **Dependencies**: MOD-006, MOD-008
- **Scope**:
  - Map report to existing open ticket by `content_type+content_id` or create new.
  - Increment `report_count`, aggregate topics, update timestamps.
- **Acceptance criteria**:
  - Multiple reports on same content map to one open ticket.
  - Race conditions handled (transaction/locking/upsert).

### MOD-010 — Priority scoring rules for initial SLA
- **Priority**: P1
- **Estimate**: S
- **Dependencies**: MOD-009
- **Scope**:
  - Encode first-pass priority rules (e.g., extortion/criminal → high/critical).
- **Acceptance criteria**:
  - Priority set deterministically from report metadata.

---

## Epic D — Admin Moderation Board

### MOD-011 — Build admin tickets list endpoint
- **Priority**: P0
- **Estimate**: M
- **Dependencies**: MOD-008, MOD-009
- **Scope**:
  - `GET /v1/admin/moderation/tickets` with filters: status/queue/topic/assignee.
- **Acceptance criteria**:
  - Supports pagination + stable ordering.
  - Unauthorized roles blocked.

### MOD-012 — Build admin ticket detail endpoint
- **Priority**: P0
- **Estimate**: M
- **Dependencies**: MOD-011
- **Scope**:
  - `GET /v1/admin/moderation/tickets/{ticket_id}`.
  - Include content snapshot + linked reports + offender history summary.
- **Acceptance criteria**:
  - Returns all data required for moderation decision in one response.

### MOD-013 — Create moderation board UI (list + filters + assignment)
- **Priority**: P0
- **Estimate**: L
- **Dependencies**: MOD-011
- **Scope**:
  - New admin page with queues (newsfeed/messages/profile), filters, and assignment.
- **Acceptance criteria**:
  - Moderator can browse and claim tickets.
  - Empty/loading/error states implemented.

### MOD-014 — Build ticket detail UI with decision panel
- **Priority**: P0
- **Estimate**: L
- **Dependencies**: MOD-012, MOD-013
- **Scope**:
  - Show reported content, topics, reasons, prior enforcement history.
  - Decision controls for no-violation/remove/warn/ban.
- **Acceptance criteria**:
  - Admin can complete full moderation workflow from ticket detail.

---

## Epic E — Resolution + Enforcement Actions

### MOD-015 — Create schema for `moderation_actions` and `user_enforcement_history`
- **Priority**: P0
- **Estimate**: M
- **Scope**:
  - Migrations and indexes for action audit + enforcement history queries.
- **Acceptance criteria**:
  - Warning/ban actions persist with source ticket reference.

### MOD-016 — Implement resolve endpoint with transactional action pipeline
- **Priority**: P0
- **Estimate**: L
- **Dependencies**: MOD-012, MOD-015
- **Scope**:
  - `POST /v1/admin/moderation/tickets/{ticket_id}/resolve`.
  - Support combinations:
    - no_violation + none
    - content_removed + none/warn/ban
  - Ensure atomic writes or compensating retry logic.
- **Acceptance criteria**:
  - Ticket status/resolution/action records always consistent.
  - Reject invalid state transitions.

### MOD-017 — Implement content removal adapters by content type
- **Priority**: P0
- **Estimate**: L
- **Dependencies**: MOD-016
- **Scope**:
  - Feed: soft-remove post/comment/media.
  - Messages: hide/remove from UI; preserve compliance storage as configured.
  - Profile: revert photo to previous approved/default avatar.
- **Acceptance criteria**:
  - Removed content no longer appears in user-facing surfaces.
  - Evidence retention behavior documented and verified.

### MOD-018 — Implement warning/ban policy engine integration
- **Priority**: P1
- **Estimate**: M
- **Dependencies**: MOD-016
- **Scope**:
  - Issue warning notifications.
  - Apply temporary/permanent ban with duration support.
- **Acceptance criteria**:
  - Banned user restrictions enforced system-wide.

---

## Epic F — History, Auditability, and Admin Safety Controls

### MOD-019 — Add `GET /v1/admin/moderation/users/{user_id}/history`
- **Priority**: P0
- **Estimate**: S
- **Dependencies**: MOD-015
- **Scope**:
  - Query warning/ban timeline for user.
- **Acceptance criteria**:
  - Ticket detail can fetch and render prior enforcement quickly.

### MOD-020 — Implement `moderation_audit_log` write path
- **Priority**: P0
- **Estimate**: M
- **Dependencies**: MOD-006, MOD-016
- **Scope**:
  - Log report creation, assignment, resolution, enforcement actions.
- **Acceptance criteria**:
  - Every moderation action has an immutable audit record.

### MOD-021 — Role-based permissions for moderation capabilities
- **Priority**: P0
- **Estimate**: M
- **Dependencies**: MOD-011, MOD-016
- **Scope**:
  - Moderator vs senior-admin gates (e.g., permanent ban).
- **Acceptance criteria**:
  - Unauthorized actions return 403.
  - Permission checks covered by tests.

### MOD-022 — Optional dual-approval flow for permanent bans
- **Priority**: P2
- **Estimate**: M
- **Dependencies**: MOD-021
- **Scope**:
  - Feature flag for requiring second approver.
- **Acceptance criteria**:
  - Permanent ban cannot finalize without second approver when enabled.

---

## Epic G — Notifications + User Communication

### MOD-023 — Reporter acknowledgement notification
- **Priority**: P1
- **Estimate**: S
- **Dependencies**: MOD-006
- **Scope**:
  - In-app/toast confirmation and optional inbox event.
- **Acceptance criteria**:
  - Reporter sees “report received” confirmation.

### MOD-024 — Offender moderation outcome notifications
- **Priority**: P0
- **Estimate**: M
- **Dependencies**: MOD-016, MOD-018
- **Scope**:
  - Notify on content removal, warning, or ban.
- **Acceptance criteria**:
  - Notification templates include policy category and effective duration for bans.

---

## Epic H — QA, Observability, and Rollout

### MOD-025 — Add backend unit/integration tests for report + ticket lifecycle
- **Priority**: P0
- **Estimate**: L
- **Dependencies**: MOD-006, MOD-009, MOD-016
- **Scope**:
  - Validate happy path + invalid payloads + race conditions + permission errors.
- **Acceptance criteria**:
  - CI test coverage for core moderation workflows.

### MOD-026 — Add frontend tests for reporting and admin moderation workflows
- **Priority**: P0
- **Estimate**: M
- **Dependencies**: MOD-001, MOD-014
- **Scope**:
  - Component tests for modal validation.
  - UI tests for ticket resolution decision panel.
- **Acceptance criteria**:
  - Key moderation UX paths covered by automated tests.

### MOD-027 — Dashboard + alerts for moderation KPIs
- **Priority**: P1
- **Estimate**: M
- **Dependencies**: MOD-020
- **Scope**:
  - Metrics: ticket volume, resolution latency, warning/ban rates, critical backlog.
  - Alerts: extortion/criminal surge, SLA breach.
- **Acceptance criteria**:
  - On-call receives alerts for configured thresholds.

### MOD-028 — Feature flags and staged rollout plan
- **Priority**: P0
- **Estimate**: S
- **Dependencies**: MOD-002, MOD-003, MOD-004, MOD-013
- **Scope**:
  - Gradual enablement by surface and role.
- **Acceptance criteria**:
  - Moderation features can be toggled without redeploy.

---

## Suggested Delivery Slices

### Slice 1 (MVP Core)
- MOD-001, MOD-002, MOD-003, MOD-004
- MOD-005, MOD-006, MOD-008, MOD-009
- MOD-011, MOD-012, MOD-013, MOD-014
- MOD-015, MOD-016, MOD-017, MOD-019, MOD-020, MOD-021
- MOD-024, MOD-025, MOD-026, MOD-028

### Slice 2 (Operational hardening)
- MOD-007, MOD-010, MOD-023, MOD-027

### Slice 3 (Advanced governance)
- MOD-018, MOD-022

---

## Jira/Linear Ticket Template (copy/paste)

**Title**: `[MOD-XXX] <short action-oriented title>`

**Problem**
- What user/admin pain this ticket solves.

**Scope**
- In scope bullets.
- Out of scope bullets.

**Implementation notes**
- Data model/API/UI details.
- Dependency tickets.

**Acceptance criteria**
- Testable Given/When/Then outcomes.

**Testing**
- Unit/integration/e2e coverage required.

**Rollout**
- Feature flag name.
- Metrics to monitor post-release.
