# Messaging Message Controls — Implementation Tickets

This ticket set maps directly to `docs/messaging-message-controls-plan.md` and breaks delivery into scoped work items across API, frontend UX, moderation, and hardening.

---

## Epic A — API contracts and persistence foundations

### MMC-001 — Finalize API contract for message controls
- **Type:** Backend / API
- **Priority:** P0
- **Size:** S
- **Description:** Define and publish request/response schemas for hide/unhide, pins, and report endpoints.
- **Deliverables:**
  - OpenAPI updates for:
    - `POST /conversations/:id/messages/:messageId/hide`
    - `DELETE /conversations/:id/messages/:messageId/hide`
    - `GET /conversations/:id/hidden-messages`
    - `POST /conversations/:id/messages/:messageId/pin`
    - `DELETE /conversations/:id/messages/:messageId/pin`
    - `GET /conversations/:id/pins`
    - `POST /conversations/:id/messages/:messageId/report`
  - Error schema definitions for unauthorized, validation, rate-limit, and not-found paths.
- **Acceptance criteria:**
  - Contracts are documented and versioned.
  - Frontend type definitions can be generated/updated from the contract with no manual patching.
- **Dependencies:** None.

### MMC-002 — Add DB migration for per-user hidden state
- **Type:** Backend / Data
- **Priority:** P0
- **Size:** S
- **Description:** Create `message_visibility_overrides` storage for user-scoped hidden status.
- **Deliverables:**
  - Migration for `conversation_id`, `message_id`, `user_id`, `state`, `updated_at`.
  - Unique composite key on `(conversation_id, message_id, user_id)`.
  - Index supporting hidden list query by `(conversation_id, user_id, updated_at)`.
- **Acceptance criteria:**
  - Migration applies and rolls back cleanly.
  - Duplicate override writes are prevented by schema constraints.
- **Dependencies:** MMC-001.

### MMC-003 — Add DB migration for conversation pins
- **Type:** Backend / Data
- **Priority:** P0
- **Size:** S
- **Description:** Create `conversation_pins` table for active pin lifecycle.
- **Deliverables:**
  - Migration for `conversation_id`, `message_id`, `pinned_by_user_id`, `pinned_at`, `is_active`, `unpinned_by_user_id`, `unpinned_at`.
  - Indexes for active pins by conversation and latest active pin retrieval.
- **Acceptance criteria:**
  - Pin query patterns are index-backed.
  - Soft-unpin lifecycle fields supported and queryable.
- **Dependencies:** MMC-001.

### MMC-004 — Add DB migration for message moderation reports
- **Type:** Backend / Data
- **Priority:** P0
- **Size:** S
- **Description:** Create `message_reports` storage and context linkage.
- **Deliverables:**
  - Migration for `report_id`, `conversation_id`, `message_id`, `reported_by_user_id`, `reason_code`, `statement`, `created_at`, `status`.
  - Context snapshot field (`context_message_ids`) or normalized join table.
- **Acceptance criteria:**
  - Report records include immutable linkage to context snapshot.
  - Schema supports moderation queue processing states.
- **Dependencies:** MMC-001.

---

## Epic B — Hide/unhide feature delivery

### MMC-005 — Implement hide message endpoint
- **Type:** Backend / API
- **Priority:** P0
- **Size:** M
- **Description:** Implement hide operation scoped to current user in conversation.
- **Deliverables:**
  - Endpoint handler for `POST .../hide`.
  - Upsert logic into visibility overrides.
  - Membership check against conversation participants.
- **Acceptance criteria:**
  - Hiding is idempotent for repeated requests.
  - User cannot hide messages in conversations they cannot access.
- **Dependencies:** MMC-002.

### MMC-006 — Implement unhide endpoint
- **Type:** Backend / API
- **Priority:** P0
- **Size:** M
- **Description:** Implement unhide operation scoped to current user.
- **Deliverables:**
  - Endpoint handler for `DELETE .../hide`.
  - Override state transition back to visible.
- **Acceptance criteria:**
  - Unhide is idempotent and safe if message is already visible.
  - Only caller’s visibility override is modified.
- **Dependencies:** MMC-002.

### MMC-007 — Implement hidden messages listing endpoint
- **Type:** Backend / API
- **Priority:** P0
- **Size:** M
- **Description:** Provide paginated hidden message retrieval for hidden-items panel.
- **Deliverables:**
  - `GET /conversations/:id/hidden-messages` with cursor/limit.
  - Chronological ordering and message payload shaping.
- **Acceptance criteria:**
  - Endpoint returns only hidden messages for requesting user.
  - Pagination is deterministic and stable.
- **Dependencies:** MMC-005, MMC-006.

### MMC-008 — Add timeline filtering for hidden messages
- **Type:** Backend
- **Priority:** P0
- **Size:** M
- **Description:** Ensure standard conversation message reads exclude user-hidden messages.
- **Deliverables:**
  - Conversation read-path filter join with visibility overrides.
  - Feature-flagged rollout support if needed.
- **Acceptance criteria:**
  - Hidden messages are absent from default timeline for the hiding user.
  - Other users still see unaffected messages.
- **Dependencies:** MMC-005.

### MMC-009 — Build frontend hidden messages panel
- **Type:** Frontend
- **Priority:** P1
- **Size:** M
- **Description:** Add conversation-level menu entry and panel to inspect hidden items.
- **Deliverables:**
  - Conversation menu action `Hidden messages`.
  - Hidden messages panel/drawer with item list and metadata.
  - Per-item actions: `Unhide`, `Jump to original position`.
- **Acceptance criteria:**
  - Hidden panel lists items in chronological order.
  - Unhide reflects immediately in panel and timeline state.
- **Dependencies:** MMC-007.

### MMC-010 — Add message menu hide/unhide actions in UI
- **Type:** Frontend
- **Priority:** P1
- **Size:** M
- **Description:** Add hide action in message menu and reconcile optimistic UI behavior.
- **Deliverables:**
  - `Hide for me` action on visible messages.
  - `Unhide` action when rendered via hidden panel context.
  - Toast/feedback states and failure rollback.
- **Acceptance criteria:**
  - Hidden messages disappear from timeline immediately on success.
  - API failure path restores prior state and shows recoverable error.
- **Dependencies:** MMC-005, MMC-006, MMC-008.

---

## Epic C — Pinning feature delivery

### MMC-011 — Implement pin endpoint
- **Type:** Backend / API
- **Priority:** P0
- **Size:** M
- **Description:** Implement active pin creation for a conversation message.
- **Deliverables:**
  - `POST .../pin` handler.
  - Authorization policy enforcement (v1 policy selected by product/security).
  - Event/audit emission for pin action.
- **Acceptance criteria:**
  - Pin operation marks message active in pin table.
  - Unauthorized pin attempts are rejected with deterministic error.
- **Dependencies:** MMC-003.

### MMC-012 — Implement unpin endpoint
- **Type:** Backend / API
- **Priority:** P0
- **Size:** M
- **Description:** Implement pin deactivation lifecycle.
- **Deliverables:**
  - `DELETE .../pin` handler.
  - `is_active` transition and unpin actor/timestamp storage.
- **Acceptance criteria:**
  - Unpin hides message from active pins list.
  - Audit trail captures unpin actor and time.
- **Dependencies:** MMC-003, MMC-011.

### MMC-013 — Implement list pins + latest pin projection
- **Type:** Backend / API
- **Priority:** P0
- **Size:** M
- **Description:** Return active pins and expose latest pin for conversation header banner.
- **Deliverables:**
  - `GET /conversations/:id/pins` endpoint.
  - `latestPinnedMessage` projection for conversation read payload (or dedicated endpoint).
- **Acceptance criteria:**
  - Pins endpoint returns active pins sorted by `pinned_at` descending.
  - Latest pin projection always matches first active pin.
- **Dependencies:** MMC-011, MMC-012.

### MMC-014 — Build pinned message banner in conversation header
- **Type:** Frontend
- **Priority:** P1
- **Size:** M
- **Description:** Add compact top banner showing most recently pinned message.
- **Deliverables:**
  - Banner with truncated message preview.
  - Actions: `View all pins`, `Jump`, `Dismiss` (UI-only dismissal).
- **Acceptance criteria:**
  - Banner updates when latest pin changes.
  - Dismissal hides banner for current session without unpinning message.
- **Dependencies:** MMC-013.

### MMC-015 — Build pins panel with unpin and jump actions
- **Type:** Frontend
- **Priority:** P1
- **Size:** M
- **Description:** Add conversation-level `Pinned messages` menu and full active pins list.
- **Deliverables:**
  - Pins panel/drawer list with author, pinned-by, and timestamp metadata.
  - Per-item actions: `Unpin`, `Jump to message`.
- **Acceptance criteria:**
  - Panel lists all active pins and updates after unpin.
  - Jump action scrolls and highlights corresponding message.
- **Dependencies:** MMC-013, MMC-014.

### MMC-016 — Implement shared jump-to-message helper for hidden/pins flows
- **Type:** Frontend
- **Priority:** P1
- **Size:** S
- **Description:** Unify deep-link/jump behavior used by hidden and pinned message panels.
- **Deliverables:**
  - Reusable helper for loading, scrolling, and temporary highlight by message ID.
  - Fallback behavior when message is unavailable/deleted.
- **Acceptance criteria:**
  - Jump works from both hidden and pins UI surfaces.
  - Missing message path is handled gracefully with user feedback.
- **Dependencies:** MMC-009, MMC-015.

---

## Epic D — Message copy action

### MMC-017 — Add copy-to-clipboard action and feedback
- **Type:** Frontend
- **Priority:** P1
- **Size:** S
- **Description:** Add `Copy` action for messages and canonical attachment label copy behavior.
- **Deliverables:**
  - Message menu `Copy` action with clipboard integration.
  - Text and attachment-specific copy formatter.
  - Inline/toast confirmation (`Copied`) with timeout.
- **Acceptance criteria:**
  - Text messages copy full text content accurately.
  - Attachment messages copy expected canonical string.
  - Failure path surfaces actionable feedback.
- **Dependencies:** None.

---

## Epic E — Moderation reporting

### MMC-018 — Implement report message endpoint with validation
- **Type:** Backend / API
- **Priority:** P0
- **Size:** M
- **Description:** Implement `POST .../report` with reason and statement validation.
- **Deliverables:**
  - Input validation for required reason and statement length bounds.
  - Report record creation in persistence layer.
  - AuthZ check to require conversation participation.
- **Acceptance criteria:**
  - Missing/invalid statement is rejected with clear validation errors.
  - Valid reports are persisted and return success response.
- **Dependencies:** MMC-004.

### MMC-019 — Add server-side contextual snapshot capture for reports
- **Type:** Backend / Moderation
- **Priority:** P0
- **Size:** M
- **Description:** Include bounded nearby context in each report and store immutable references.
- **Deliverables:**
  - Context selection strategy (e.g., ±5 messages) with policy filters.
  - Snapshot linkage persisted with report.
- **Acceptance criteria:**
  - Context is generated server-side (client cannot override message IDs).
  - Snapshot respects retention/access/compliance constraints.
- **Dependencies:** MMC-018.

### MMC-020 — Build report message modal UX in frontend
- **Type:** Frontend
- **Priority:** P1
- **Size:** M
- **Description:** Add report workflow to message menu with required statement and context notice.
- **Deliverables:**
  - `Report message` menu action and modal/sheet.
  - Reason selector + required free-text statement input.
  - Explicit notice text that recent conversation context is included.
  - Submit/cancel flow and success toast.
- **Acceptance criteria:**
  - Submit is blocked until required fields pass validation.
  - Success and recoverable failure states are user-friendly and accessible.
- **Dependencies:** MMC-018, MMC-019.

### MMC-021 — Add report rate-limiting and abuse controls
- **Type:** Backend / Security
- **Priority:** P1
- **Size:** S
- **Description:** Protect reporting endpoint from spam and automation abuse.
- **Deliverables:**
  - Per-user and per-conversation rate limits.
  - Monitoring hooks for repeated violations.
- **Acceptance criteria:**
  - Excessive report bursts are rejected with rate-limit response.
  - Limits are configurable via environment/feature flags.
- **Dependencies:** MMC-018.

---

## Epic F — QA, observability, and rollout hardening

### MMC-022 — Add backend tests for hide/unhide/pin/report paths
- **Type:** Backend / QA
- **Priority:** P0
- **Size:** M
- **Description:** Build deterministic unit/integration coverage for endpoint behavior and auth boundaries.
- **Deliverables:**
  - Tests for idempotency, auth failures, pagination, and lifecycle transitions.
  - Tests verifying user-scoped hide overrides and pin authorization policy.
- **Acceptance criteria:**
  - Critical backend paths covered in CI.
  - Unauthorized cross-user mutations are prevented by tests.
- **Dependencies:** MMC-005 through MMC-013, MMC-018.

### MMC-023 — Add frontend tests for message controls UX
- **Type:** Frontend / QA
- **Priority:** P1
- **Size:** M
- **Description:** Add component/integration tests for menus, panels, banner, copy, and report flows.
- **Deliverables:**
  - Tests for hidden panel lifecycle and jump behavior.
  - Tests for pin banner + pins panel interactions.
  - Tests for report modal validation and submit behavior.
- **Acceptance criteria:**
  - Regressions in message controls UX are caught automatically.
  - Accessibility checks added for new interactive components.
- **Dependencies:** MMC-009, MMC-010, MMC-014, MMC-015, MMC-017, MMC-020.

### MMC-024 — Add observability metrics, logs, and dashboards
- **Type:** Backend + Ops
- **Priority:** P1
- **Size:** S
- **Description:** Instrument and surface operational signals for new message controls.
- **Deliverables:**
  - Metrics: hide/unhide/pin/unpin/report/report-validation-error counters.
  - Structured logs for actor/conversation/message/action/result.
  - Dashboard + alert thresholds for report spikes and API errors.
- **Acceptance criteria:**
  - Metrics are visible in staging and production observability stack.
  - Alerts fire on configured thresholds in test/simulation.
- **Dependencies:** MMC-005 through MMC-021.

### MMC-025 — Feature flags and staged rollout plan execution
- **Type:** Platform / Release
- **Priority:** P1
- **Size:** S
- **Description:** Gate release by capability and support incremental rollout.
- **Deliverables:**
  - Flags for hide/unhide, pins, and report independently.
  - Rollout checklist with canary phases and rollback criteria.
- **Acceptance criteria:**
  - Each capability can be enabled/disabled safely without deploy.
  - Rollback playbook validated in staging.
- **Dependencies:** MMC-024.

---

## Suggested implementation order
1. **Foundation:** MMC-001 → MMC-004
2. **Hide/Unhide MVP:** MMC-005 → MMC-010
3. **Pinning MVP:** MMC-011 → MMC-016
4. **Moderation reporting:** MMC-018 → MMC-021 (with MMC-020 in parallel after contract stable)
5. **Copy action:** MMC-017
6. **Hardening + rollout:** MMC-022 → MMC-025
