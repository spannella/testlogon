# Ticket Spaces / Boards + Contact Assignment — Implementation Tickets

## Overview
This backlog expands the existing helpdesk-focused ticketing system into collaborative, user-owned ticket spaces/boards while preserving current `/tickets` helpdesk behavior.

## Scope assumptions
- Existing helpdesk routes remain available and backward-compatible.
- New collaborative functionality is introduced under a space-scoped API surface.
- Assignment for space tickets supports contacts/members, not only admin/root users.
- Rollout is guarded by feature flags:
  - `TICKET_SPACES_ENABLED`
  - `TICKET_CONTACT_ASSIGNMENT_ENABLED`
  - `TICKET_SPACE_NOTIFICATIONS_ENABLED`

---

## Epic A — Data model and persistence

### SPC-001 — Space entity + membership persistence
**Goal:** Add durable entities for ticket spaces and memberships.

**Tasks**
- Add `TicketSpace` model with: `space_id`, `owner_sub`, `name`, `visibility`, `created_at`, `updated_at`.
- Add `SpaceMembership` model with: `space_id`, `member_sub`, `role` (`owner`, `editor`, `viewer`), timestamps.
- Extend ticket metadata with `space_id` and `assigned_to_sub` while preserving `assigned_admin_sub` for helpdesk compatibility.

**Acceptance Criteria**
- Space and membership entities are persisted in DynamoDB.
- Ticket records can be associated with a `space_id`.
- Existing helpdesk ticket records continue functioning without migration breakage.

**Dependencies:** none  
**Estimate:** M (1–2 days)

---

### SPC-006 — Space indexes + query optimization
**Goal:** Add index strategy for board-scale queries.

**Tasks**
- Add access patterns for:
  - tickets by `space_id`,
  - tickets by `space_id + status`,
  - tickets by `space_id + assigned_to_sub`,
  - spaces by `member_sub`.
- Implement key/index attributes aligned to:
  - `gsi_space_pk = SPACE#{space_id}`,
  - `gsi_space_sk = UPDATED#{ts}#TICKET#{id}`,
  - `gsi_space_status_pk = SPACE#{space_id}#STATUS#{status}`,
  - `gsi_space_assignee_pk = SPACE#{space_id}#ASSIGNEE#{sub}`,
  - `gsi_member_pk = MEMBER#{user_sub}`,
  - `gsi_member_sk = SPACE#{space_id}`.
- Ensure list endpoints avoid full-table scans.

**Acceptance Criteria**
- All primary list/filter reads are index-backed.
- Cursor pagination works on space ticket lists and space membership views.
- Query latency is acceptable for dashboard-scale usage.

**Dependencies:** SPC-001  
**Estimate:** M (1–2 days)

---

## Epic B — Authorization and assignment rules

### SPC-002 — Space ACL middleware/policy
**Goal:** Introduce membership-based authorization for space operations.

**Tasks**
- Add policy checks for roles:
  - `owner`: full control,
  - `editor`: create/update/assign/reply,
  - `viewer`: read-only.
- Apply ACL checks consistently across all space endpoints.
- Preserve existing admin-centric auth logic for `/tickets` helpdesk routes.

**Acceptance Criteria**
- Unauthorized users cannot read or mutate space resources.
- Viewers are blocked from mutation actions.
- ACL evaluation is unit-tested for owner/editor/viewer/non-member.

**Dependencies:** SPC-001  
**Estimate:** M (1 day)

---

### SPC-005 — Contact/member assignee validation
**Goal:** Ensure assignments in spaces are secure and valid.

**Tasks**
- Validate `assigned_to_sub` is an eligible space member/contact.
- Reject assignment to users outside the allowed scope.
- Track assignment audit fields (`assigned_by`, `assigned_at`) for space tickets.

**Acceptance Criteria**
- Assign-to-self and assign-to-other-member workflows succeed when authorized.
- Invalid assignee requests fail with structured 400/403 payloads.
- Assignment metadata is persisted and returned in ticket detail responses.

**Dependencies:** SPC-002, SPC-004  
**Estimate:** S/M (0.5–1 day)

---

## Epic C — Space API surface

### SPC-003 — Space CRUD APIs
**Goal:** Add APIs for creating and managing ticket spaces.

**Tasks**
- Implement endpoints:
  - `POST /ticket-spaces`
  - `GET /ticket-spaces`
  - `GET /ticket-spaces/{space_id}`
  - `POST /ticket-spaces/{space_id}/members`
  - `DELETE /ticket-spaces/{space_id}/members/{member_sub}`
- Add request/response models and OpenAPI docs.
- Add cursor + limit support for space list endpoints where needed.

**Acceptance Criteria**
- Users can create spaces and manage members according to role.
- List endpoint returns owned + shared spaces.
- API contract is documented and test-covered.

**Dependencies:** SPC-001, SPC-002, SPC-006  
**Estimate:** M/L (1–2 days)

---

### SPC-004 — Space-scoped ticket CRUD APIs
**Goal:** Add collaborative ticket workflows inside spaces.

**Tasks**
- Implement endpoints:
  - `POST /ticket-spaces/{space_id}/tickets`
  - `GET /ticket-spaces/{space_id}/tickets`
  - `GET /ticket-spaces/{space_id}/tickets/{ticket_id}`
  - `POST /ticket-spaces/{space_id}/tickets/{ticket_id}/assign`
  - `POST /ticket-spaces/{space_id}/tickets/{ticket_id}/messages`
  - `POST /ticket-spaces/{space_id}/tickets/{ticket_id}/status`
- Add filters: `status`, `assignee_sub`, `cursor`, `limit`.
- Keep helpdesk routes (`/tickets`) unchanged.

**Acceptance Criteria**
- Space members can create/view/reply/update tickets based on ACL.
- Filtering and pagination are available for board usage.
- Helpdesk workflows continue to function without contract changes.

**Dependencies:** SPC-001, SPC-002, SPC-006  
**Estimate:** L (2–3 days)

---

## Epic D — Notifications and alert fanout

### SPC-007 — Notification fanout for space events
**Goal:** Extend ticket notifications for collaborative spaces.

**Tasks**
- Implement recipient rules:
  - assignment: assignee + creator + optional watchers,
  - reply/status: thread participants + assignee + creator.
- Ensure per-user alert preferences are honored.
- Add/extend event taxonomy for space-ticket events if required.

**Acceptance Criteria**
- Recipient selection is correct per action.
- No duplicate fanout for the same recipient/event.
- Preference opt-outs are respected.

**Dependencies:** SPC-004, SPC-005  
**Estimate:** M (1–2 days)

---

## Epic E — TypeScript UI expansion

### SPC-008 — TS UI: spaces list + create
**Goal:** Introduce space discovery and creation UX.

**Tasks**
- Add `/tickets/spaces` page with:
  - owned/shared spaces list,
  - create-space form,
  - navigation into space detail.
- Add API client methods and typed models for space endpoints.

**Acceptance Criteria**
- User can create a space and see it in owned/shared lists.
- Page is fully TypeScript-driven and integrated into app navigation.

**Dependencies:** SPC-003  
**Estimate:** M (1–2 days)

---

### SPC-009 — TS UI: board view + filters
**Goal:** Provide board-scale ticket triage inside a space.

**Tasks**
- Add `/tickets/spaces/:spaceId` ticket board/list view.
- Add filters: status, assignee, mine/unassigned.
- Add ticket detail thread pane with reply/status actions.

**Acceptance Criteria**
- Users can list/filter tickets within a selected space.
- Message/status changes are reflected in UI state without full page reload.
- Pagination and refresh behavior work for larger queues.

**Dependencies:** SPC-004, SPC-008  
**Estimate:** M/L (1–2 days)

---

### SPC-010 — TS UI: assignee picker + member management
**Goal:** Make collaborative assignment and membership management easy.

**Tasks**
- Add member management modal for owner/editor flows.
- Add assignee picker sourced from space members/contacts.
- Add one-click assign-to-me action in board ticket detail actions.

**Acceptance Criteria**
- Authorized users can add/remove members and assign tickets from picker.
- Invalid assignments are prevented in UI and surfaced with clear errors.
- UX supports full space collaboration workflow.

**Dependencies:** SPC-003, SPC-005, SPC-009  
**Estimate:** M (1–2 days)

---

## Epic F — Quality, rollout, and migration

### SPC-011 — End-to-end tests (ACL matrix + assignment + notifications)
**Goal:** Validate collaborative ticketing behavior across backend and frontend.

**Tasks**
- Add backend tests for ACL matrix (owner/editor/viewer/non-member).
- Add tests for assignment validation, status transitions, and fanout recipients.
- Add frontend integration tests for space create/list/assign/reply workflows.

**Acceptance Criteria**
- Core space collaboration flows are fully covered by automated tests.
- Regression tests prove `/tickets` helpdesk flows are unaffected.
- CI passes with feature flags on/off paths as applicable.

**Dependencies:** SPC-002 through SPC-010  
**Estimate:** M/L (2 days)

---

## Suggested delivery slices

### Release S1 — Data + APIs (behind flags)
- SPC-001, SPC-006, SPC-002, SPC-003, SPC-004

### Release S2 — Assignment + notifications
- SPC-005, SPC-007

### Release S3 — TypeScript UX
- SPC-008, SPC-009, SPC-010

### Release S4 — Hardening
- SPC-011

---

## Notes on backward compatibility
- Keep `/tickets` as helpdesk mode and avoid behavior drift for existing admin workflows.
- Treat ticket spaces as additive feature set with independent endpoints.
- Consider optional migration path later: bootstrap a personal default space per user for non-helpdesk tickets.
