# Ticketing System Implementation Plan

## Objective
Build a production-ready ticketing system where:
- users can open and respond to help tickets,
- admins can view a dashboard, assign tickets to themselves/other admins, reply, and mark tickets done,
- ticket activity sends email alerts to appropriate participants.

## Current Gaps
- Ticket data is currently in-memory and not durable.
- Admin queue/dashboard concerns (filters, pagination, summaries) are minimal.
- Ticket events are not fully modeled in alert taxonomy for notifications.
- Email notification behavior is not yet implemented end-to-end for ticket activity.

---

## Epic 1: Persistence & Data Model

### TKT-001 — Add ticket settings and table bindings
**Goal:** Add configuration and app-wide table bindings for tickets.

**Tasks**
- Add `TICKETS_TABLE_NAME` (and related index names) to settings.
- Add tickets table to `app/core/tables.py`.

**Acceptance Criteria**
- App boots with ticket table defaults.
- Ticket service can reference `T.tickets`.

---

### TKT-002 — Define DynamoDB schema and access patterns
**Goal:** Model ticket header, message thread, and activity entities for efficient reads.

**Tasks**
- Define PK/SK patterns for ticket metadata + threaded messages + activity timeline.
- Define GSIs for:
  - user ticket list,
  - admin queue by status,
  - assignee-specific queue.
- Add versioning/conditional update strategy for concurrency.

**Acceptance Criteria**
- All user/admin list and detail query patterns are covered without full-table scan paths.
- Schema documented in the repo.

---

### TKT-003 — Replace in-memory ticket store with Dynamo-backed service
**Goal:** Persist tickets durably and support multi-instance deployments.

**Tasks**
- Rewrite ticket service methods to read/write DynamoDB.
- Keep method behavior compatible with router use.

**Acceptance Criteria**
- Ticket create/get/list/assign/reply/status survives restarts.
- In-memory dictionary is removed as source-of-truth.

---

## Epic 2: Workflow Rules & State Management

### TKT-004 — Implement ticket lifecycle state machine
**Goal:** Enforce valid transitions and consistent workflow.

**Target states**
- `open`, `in_progress`, `waiting_on_user`, `done` (optionally `reopened`).

**Acceptance Criteria**
- Invalid transitions return structured 400 responses.
- User/admin actions trigger deterministic transitions.

---

### TKT-005 — Assignment validation and metadata
**Goal:** Ensure assignment is secure and auditable.

**Tasks**
- Validate assignee is admin/root.
- Save `assigned_admin_sub`, `assigned_by`, `assigned_at`.

**Acceptance Criteria**
- Assign-to-self and assign-to-other-admin both work.
- Assigning to non-admin fails.

---

### TKT-006 — Add optimistic concurrency for writes
**Goal:** Prevent clobbering updates under concurrent admin actions.

**Tasks**
- Add `version` attribute and conditional writes.
- Return conflict errors for stale updates.

**Acceptance Criteria**
- Concurrent state/assignment updates are conflict-safe.

---

## Epic 3: API Contract Hardening

### TKT-007 — Add pagination and filters for ticket lists
**Goal:** Support admin dashboard scale.

**Tasks**
- Add cursor + limit.
- Add filters (`status`, `assignee`, owner/admin views).

**Acceptance Criteria**
- Admins can query queue slices efficiently.
- Users only see their own tickets.

---

### TKT-008 — Normalize response envelopes and errors
**Goal:** Stabilize contract for frontend integration.

**Tasks**
- Standardize list/detail response shape.
- Standardize validation/authorization error payloads.

**Acceptance Criteria**
- OpenAPI accurately reflects request/response structures.

---

### TKT-009 — Add admin dashboard summary endpoint
**Goal:** Support KPI cards in admin UI.

**Tasks**
- Return counts by status, unassigned tickets, and stale ticket counts.

**Acceptance Criteria**
- Admin/root-only access.
- Efficient query strategy.

---

## Epic 4: Alerts & Email Notifications

### TKT-010 — Add ticket event types to alerts taxonomy
**Goal:** First-class ticket alert events.

**Events**
- `ticket_created`
- `ticket_assigned`
- `ticket_replied`
- `ticket_status_changed`
- `ticket_reopened`

**Acceptance Criteria**
- Ticket actions map cleanly to alert event types.

---

### TKT-011 — Implement ticket email fanout logic
**Goal:** Send notifications to users/admins based on ticket activity.

**Rules (initial)**
- User notified when admin assigns/replies/changes status.
- Assigned admin notified on user replies and assignment changes.

**Acceptance Criteria**
- Correct recipient selection per action.
- Respect alert preferences.

---

### TKT-012 — Add email templates for ticket notifications
**Goal:** Deliver clear, action-oriented email content.

**Tasks**
- Add subject/body templates with ticket ID, subject, actor, and deep links.
- Add tests for template rendering.

**Acceptance Criteria**
- All ticket email scenarios render correctly.

---

## Epic 5: Frontend Experience

### TKT-013 — User ticket UI
**Goal:** Let users open/view/reply from the existing UI.

**Scope**
- Open-ticket form.
- My-tickets list.
- Ticket thread + reply composer.

**Acceptance Criteria**
- User can complete full ticket lifecycle interactions from UI.

---

### TKT-014 — Admin ticket dashboard UI
**Goal:** Provide admin triage and resolution workflow.

**Scope**
- Queue table with filters.
- Assignment controls (self/other admin).
- Reply/status controls.

**Acceptance Criteria**
- Admin can move ticket from open to done in UI.

---

### TKT-015 — Live updates (polling or SSE)
**Goal:** Keep ticket views fresh with minimal manual refresh.

**Acceptance Criteria**
- New messages/status updates appear automatically within configured interval.

---

## Epic 6: QA, Security, and Rollout

### TKT-016 — Expand authorization and workflow test matrix
**Goal:** Validate user/admin/root behavior and state transitions.

**Acceptance Criteria**
- Endpoint-level authorization matrix covered.
- Transition and assignment edge cases tested.

---

### TKT-017 — Notification behavior tests
**Goal:** Ensure email/alert fanout is correct and non-duplicative.

**Acceptance Criteria**
- Recipient and event mapping tests pass for all ticket events.

---

### TKT-018 — Feature flags and deployment runbook
**Goal:** Safe progressive rollout.

**Tasks**
- Add `TICKETS_ENABLED` and `TICKETS_EMAIL_NOTIFICATIONS_ENABLED` flags.
- Document rollout + monitoring checklist.

**Acceptance Criteria**
- Ticket features can be enabled gradually and rolled back safely.

---

## Suggested Delivery Slices

### Slice A (Backend MVP)
- TKT-001, TKT-002, TKT-003, TKT-004, TKT-005, TKT-007

### Slice B (Notifications)
- TKT-010, TKT-011, TKT-012

### Slice C (User/Admin UI)
- TKT-013, TKT-014, TKT-015

### Slice D (Hardening)
- TKT-006, TKT-008, TKT-009, TKT-016, TKT-017, TKT-018
