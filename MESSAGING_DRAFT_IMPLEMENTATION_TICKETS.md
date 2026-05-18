# Messaging Drafts — Implementation Ticket Set

This ticket set translates the draft-message plan into actionable, sequenced work across frontend, API, quality, and rollout.

## Epic: Messaging Drafts (Save / Load / Remove)

### Goal
Allow users to save in-progress messages as drafts before sending, then load or remove those drafts from the message composer UI.

### Scope assumptions
- Drafts are scoped to a conversation.
- Initial implementation is client-side storage (`localStorage`) for text drafts.
- Attachments, scheduled metadata, and encryption payloads are out of scope unless explicitly added by a follow-up ticket.

---

## Ticket 1 — Product/UX spec for draft interactions
**Type:** Product + UX  
**Priority:** P0  
**Owner:** Product Designer / PM

### Description
Define exact user flows and edge-case behavior for drafts in the composer.

### Requirements
- Specify what gets saved (e.g., trimmed text vs raw text).
- Define max drafts per conversation and display cap in UI.
- Define ordering (newest first), timestamp display, and truncation behavior.
- Define behavior when user saves empty text.
- Define whether loading a draft replaces or appends existing composer content.
- Define mobile and desktop layouts.

### Acceptance Criteria
- Signed UX spec (wireframes + interaction notes) for save/load/remove flows.
- Edge cases explicitly documented (empty draft, duplicates, long text, multi-tab).
- Engineering-ready annotations delivered.

---

## Ticket 2 — Frontend data model + storage adapter for drafts
**Type:** Frontend  
**Priority:** P0  
**Owner:** FE Engineer
**Status:** ✅ Implemented (2026-03-24)

### Description
Implement a dedicated draft storage adapter/hook to isolate localStorage logic from UI components.

### Requirements
- Create `useConversationDrafts(conversationId)` (or equivalent service module).
- Store under namespaced key: `messaging:drafts:<conversationId>`.
- Validate parsed objects and discard malformed entries safely.
- Enforce max count (e.g., 20 drafts) at write time.
- Keep deterministic sort order (descending by saved timestamp).
- Return API: `drafts`, `saveDraft(text)`, `loadDraft(id)`, `deleteDraft(id)`, `refresh()`.

### Acceptance Criteria
- Composer no longer contains raw localStorage parsing/writing logic.
- Malformed storage values never crash UI.
- Unit tests cover schema validation, cap enforcement, and ordering.

---

## Ticket 3 — Composer UI: Save Draft control
**Type:** Frontend UI  
**Priority:** P0  
**Owner:** FE Engineer

### Description
Add explicit Save Draft action in composer controls.

### Requirements
- Add `Save draft` action with loading/disabled behavior aligned to current send state.
- Prevent saving empty/whitespace-only messages.
- Show success/error feedback using existing toast patterns.
- Ensure keyboard and screen-reader accessibility.

### Acceptance Criteria
- User can save current text without sending.
- Empty draft attempts are blocked with user feedback.
- No regressions in send button behavior.
- a11y checks pass for new control (label, focus, keyboard).

---

## Ticket 4 — Composer UI: Saved Drafts panel (Load + Remove)
**Type:** Frontend UI  
**Priority:** P0  
**Owner:** FE Engineer

### Description
Render a drafts list in or near composer with explicit actions to load and remove draft entries.

### Requirements
- Show most recent drafts for active conversation.
- `Load` replaces composer text and focuses the textarea.
- `Remove` deletes selected draft and updates list immediately.
- Show empty state when no drafts exist.
- Prevent layout instability for long drafts (truncate/line clamp).

### Acceptance Criteria
- Draft list updates immediately after save/remove.
- Loading a draft sets composer text and keeps send flow intact.
- Remove action persists across page refresh.

---

## Ticket 5 — Conversation integration + prop contract hardening
**Type:** Frontend integration  
**Priority:** P1  
**Owner:** FE Engineer

### Description
Ensure conversation context is always provided to composer and draft scope is guaranteed.

### Requirements
- Make `conversationId` required in all `ComposeBar` usages.
- Ensure draft state refreshes when switching conversations.
- Add type-level safeguards and test coverage for prop contract.

### Acceptance Criteria
- No compile-time or runtime callsites missing `conversationId`.
- Switching conversations never leaks drafts from a different conversation.

---

## Ticket 6 — Automated tests for draft behavior
**Type:** Frontend tests  
**Priority:** P0  
**Owner:** FE Engineer / QA
**Status:** ✅ Implemented (2026-03-24)

### Description
Add focused test coverage for all draft scenarios.

### Test matrix
- Save non-empty draft persists to scoped key.
- Save empty draft is rejected.
- List renders newest-first.
- Load draft writes text into composer.
- Remove draft deletes only selected entry.
- Switching conversations isolates lists.
- Malformed localStorage data is ignored without crash.

### Acceptance Criteria
- New unit/integration tests pass in CI.
- Existing composer tests updated for any required prop changes.

---

## Ticket 7 — E2E scenario for draft lifecycle
**Type:** E2E  
**Priority:** P1  
**Owner:** QA / FE Engineer
**Status:** ✅ Implemented (2026-03-24)

### Description
Add browser-level test proving real user workflow.

### Scenario
1. Open conversation A, type text, save draft.
2. Refresh page; confirm draft still visible.
3. Load draft and send message.
4. Open conversation B; confirm draft from A is not shown.
5. Back to A, remove remaining draft; confirm it is gone after refresh.

### Acceptance Criteria
- E2E spec runs reliably in CI.
- No flaky waits; selectors based on stable labels/test IDs.

---

## Ticket 8 — Telemetry + observability for feature adoption
**Type:** Analytics  
**Priority:** P2  
**Owner:** FE Engineer / Data

### Description
Instrument draft usage to measure adoption and failure cases.

### Events
- `messaging_draft_saved`
- `messaging_draft_loaded`
- `messaging_draft_removed`
- `messaging_draft_save_rejected_empty`
- `messaging_draft_storage_parse_failed`

### Acceptance Criteria
- Events emitted with conversation context (non-PII-safe identifiers only).
- Dashboard or query recipe documented.

---

## Ticket 9 — Documentation + release notes
**Type:** Documentation  
**Priority:** P2  
**Owner:** FE Engineer / PM

### Description
Document behavior for support, QA, and future devs.

### Requirements
- Update messaging feature docs with draft behavior and scope limits.
- Add troubleshooting notes (clearing localStorage, malformed state recovery).
- Add release note entry.

### Acceptance Criteria
- Docs merged with screenshots/gifs where possible.
- QA checklist references new draft cases.

---

## Ticket 10 — Future enhancement spike: server-synced drafts (optional)
**Type:** Technical spike  
**Priority:** P3  
**Owner:** FE + BE

### Description
Investigate moving from local-only drafts to cross-device synchronized drafts.

### Investigation areas
- API shape (`GET/POST/DELETE /messaging/conversations/{id}/drafts`).
- Data retention policy and encryption/privacy constraints.
- Conflict strategy (last-write-wins vs merge).
- Offline behavior and fallback to local cache.

### Acceptance Criteria
- RFC or design doc with recommended architecture and migration plan.

---

## Suggested delivery sequence
1. Ticket 1 (spec)
2. Ticket 2 (storage adapter)
3. Tickets 3 + 4 + 5 (UI/integration)
4. Tickets 6 + 7 (validation)
5. Tickets 8 + 9 (operationalization)
6. Ticket 10 (future sync)

## Definition of done (Epic)
- Users can save, load, and remove conversation-scoped drafts in composer.
- Behavior is covered by unit/integration and at least one e2e flow.
- UX and docs reflect final implemented behavior.
