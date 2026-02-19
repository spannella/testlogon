# Messaging Conversation Galleries — Ticket Breakdown

This ticket set maps directly to `docs/messaging-gallery-plan.md` and is sequenced to deliver a usable MVP first, then improve performance, UX, and observability.

---

## Epic A — Contract, API, and backend foundation

### MGL-001 — Finalize gallery API contract and schema
- **Type:** Backend / API
- **Priority:** P0
- **Size:** S
- **Description:** Define canonical request/response schema for conversation gallery retrieval.
- **Deliverables:**
  - API contract for `GET /messaging/conversations/{conversation_id}/gallery`.
  - Query params: `type`, `cursor`, `limit`.
  - Normalized gallery item schema across image/video/file/link types.
- **Acceptance criteria:**
  - Contract documented in OpenAPI and synced with frontend types.
  - Validation rejects invalid `type` and malformed cursors with deterministic errors.
  - Pagination response includes stable `next_cursor` behavior.
- **Dependencies:** None.

### MGL-002 — Implement gallery read endpoint (phase 1 backing store)
- **Type:** Backend / API
- **Priority:** P0
- **Size:** M
- **Description:** Add endpoint implementation that returns conversation-scoped gallery items with pagination.
- **Deliverables:**
  - Endpoint handler and service layer query path.
  - Filtering by conversation and gallery `type`.
  - Reverse-chronological results.
- **Acceptance criteria:**
  - Endpoint returns only items from requested conversation.
  - Results are deterministic and paginated.
  - Latency remains within agreed baseline for medium conversations.
- **Dependencies:** MGL-001.

### MGL-003 — Enforce auth/authorization and visibility rules
- **Type:** Backend / Security
- **Priority:** P0
- **Size:** M
- **Description:** Reuse messaging access controls so only authorized participants can query gallery data.
- **Deliverables:**
  - Participant membership checks for DM/group conversations.
  - Consistent behavior for users who left a group (per existing policy).
  - Data suppression for revoked/deleted messages.
- **Acceptance criteria:**
  - Non-participants receive forbidden response.
  - Revoked/deleted content never appears in gallery payloads.
  - Access behavior matches message-list endpoint policy.
- **Dependencies:** MGL-002.

### MGL-004 — Gallery classification and normalization logic
- **Type:** Backend
- **Priority:** P0
- **Size:** M
- **Description:** Convert message payloads into deterministic gallery entries.
- **Deliverables:**
  - Classification rules:
    - image: `kind=image` + `image.url`
    - video: `kind=video` + `file.url`
    - file: `kind=file` (and optional `audio` policy)
    - link: `preview.url`
  - Normalized metadata mapping (`url`, `thumbnail_url`, `title`, `file_name`, etc.).
- **Acceptance criteria:**
  - Classification is deterministic and covered by tests.
  - No duplicate/ambiguous type assignment for the same gallery query.
- **Dependencies:** MGL-002.

---

## Epic B — Frontend gallery experience (MVP)

### MGL-005 — Add conversation header entry point
- **Type:** Frontend
- **Priority:** P0
- **Size:** S
- **Description:** Add a **Media & Links** action in conversation header to launch gallery UI.
- **Deliverables:**
  - Header button/action in `ConversationView`.
  - Open/close state wiring for gallery panel/dialog.
- **Acceptance criteria:**
  - Entry point visible in DM and group conversations.
  - Keyboard and screen-reader accessible trigger.
- **Dependencies:** None.

### MGL-006 — Build gallery container with tab navigation
- **Type:** Frontend
- **Priority:** P0
- **Size:** M
- **Description:** Implement panel/dialog container with tabs for Images, Videos, Files, Links.
- **Deliverables:**
  - Reusable `ConversationGallery` container.
  - Tab state and per-tab content loading.
  - Loading, empty, and recoverable error states per tab.
- **Acceptance criteria:**
  - All four tabs render and switch without full page reload.
  - Empty/error states meet UX copy requirements.
- **Dependencies:** MGL-005.

### MGL-007 — Implement frontend API client and query hooks
- **Type:** Frontend / API
- **Priority:** P0
- **Size:** M
- **Description:** Add endpoint client + React Query hooks for paginated gallery reads.
- **Deliverables:**
  - API client method for gallery endpoint.
  - Typed request/response models.
  - Infinite pagination hook keyed by conversation + type.
- **Acceptance criteria:**
  - Paging fetches next results correctly and preserves cache isolation by tab.
  - Type contract aligns with OpenAPI-generated/declared types.
- **Dependencies:** MGL-001, MGL-006.

### MGL-008 — Renderers for image/video/file/link items (MVP)
- **Type:** Frontend
- **Priority:** P1
- **Size:** M
- **Description:** Build tab-specific item renderers.
- **Deliverables:**
  - Image/video grid cards.
  - File/link list rows/cards.
  - Per-item sender, timestamp, open/download action.
- **Acceptance criteria:**
  - Each tab shows expected metadata and action affordances.
  - Broken URL states handled gracefully.
- **Dependencies:** MGL-006, MGL-007.

### MGL-009 — Jump-to-message deep link behavior
- **Type:** Frontend
- **Priority:** P1
- **Size:** M
- **Description:** Support navigation from gallery item back to original message in timeline.
- **Deliverables:**
  - `jumpToMessage(message_id)` interaction model.
  - Scroll/highlight behavior in conversation view.
- **Acceptance criteria:**
  - Clicking jump action lands on correct message in same conversation.
  - Works from each tab type.
- **Dependencies:** MGL-008.

---

## Epic C — Security, encryption, and resilience

### MGL-010 — Encrypted-content gallery policy
- **Type:** Backend / Security / Product
- **Priority:** P1
- **Size:** S
- **Description:** Define and enforce what encrypted messages expose in gallery payloads.
- **Deliverables:**
  - Policy for encrypted messages without preview metadata.
  - Backend filtering/redaction logic according to policy.
- **Acceptance criteria:**
  - No plaintext leakage through gallery endpoint.
  - Behavior documented and validated by tests.
- **Dependencies:** MGL-001, MGL-003.

### MGL-011 — Expired URL and unavailable asset handling
- **Type:** Backend + Frontend
- **Priority:** P1
- **Size:** M
- **Description:** Gracefully handle expired signed URLs or removed objects.
- **Deliverables:**
  - Backend metadata-first response remains available even if asset URL invalid.
  - Frontend unavailable-state UI and retry path.
- **Acceptance criteria:**
  - UI does not crash on unavailable assets.
  - User sees deterministic unavailable state.
- **Dependencies:** MGL-008.

---

## Epic D — Testing and contract drift protection

### MGL-012 — Backend unit/integration tests for gallery endpoint
- **Type:** Backend / QA
- **Priority:** P0
- **Size:** M
- **Description:** Add comprehensive test coverage for endpoint behavior.
- **Deliverables:**
  - Type filter tests.
  - Cursor pagination tests.
  - Authorization tests.
  - Revoked/deleted visibility tests.
- **Acceptance criteria:**
  - All major success/failure paths covered.
  - Tests are deterministic and pass in CI.
- **Dependencies:** MGL-002, MGL-003, MGL-004.

### MGL-013 — Frontend component/hook tests for gallery UI
- **Type:** Frontend / QA
- **Priority:** P1
- **Size:** M
- **Description:** Add test coverage for tabbed UI and pagination hooks.
- **Deliverables:**
  - Tests for loading/empty/error/content states per tab.
  - Hook tests for pagination and cache keys.
  - Interaction tests for open/download/jump actions.
- **Acceptance criteria:**
  - Core gallery interactions covered by automated tests.
  - Regressions in tab state and pagination are detected.
- **Dependencies:** MGL-006, MGL-007, MGL-008, MGL-009.

### MGL-014 — Messaging contract drift coverage update
- **Type:** Backend + Frontend / QA
- **Priority:** P1
- **Size:** S
- **Description:** Extend contract drift checks to include gallery endpoint/types.
- **Deliverables:**
  - Drift tests for gallery request/response schema.
  - CI step update (if needed) for new contract surface.
- **Acceptance criteria:**
  - Contract drift test fails on schema mismatch.
  - Frontend types remain aligned with backend OpenAPI.
- **Dependencies:** MGL-001.

---

## Epic E — Rollout, observability, and scale

### MGL-015 — Feature flag and staged rollout controls
- **Type:** Backend + Frontend / Ops
- **Priority:** P0
- **Size:** S
- **Description:** Add `messaging_gallery_enabled` flag and rollout controls.
- **Deliverables:**
  - Environment-level defaults.
  - Kill-switch behavior.
  - Gate in UI and API paths as needed.
- **Acceptance criteria:**
  - Feature can be enabled/disabled without redeploy.
  - Flag behavior validated in lower environments.
- **Dependencies:** MGL-002, MGL-006.

### MGL-016 — Gallery observability and operational dashboards
- **Type:** Ops / Backend
- **Priority:** P1
- **Size:** M
- **Description:** Add metrics and monitoring for gallery reliability and cost.
- **Deliverables:**
  - Metrics: request rate, error rate, p95 latency, cursor page depth.
  - Dashboard + alerts for elevated failures/latency.
- **Acceptance criteria:**
  - On-call can diagnose gallery degradation quickly.
  - Alert thresholds tuned and documented.
- **Dependencies:** MGL-002.

### MGL-017 — Materialized gallery index for scale (phase 2)
- **Type:** Backend / Data
- **Priority:** P2
- **Size:** L
- **Description:** Introduce an indexed/gallery projection store for efficient reads in large conversations.
- **Deliverables:**
  - Storage design keyed by `conversation_id` + timestamp.
  - Event-driven index updates for message create/edit/delete/revoke.
  - Backfill strategy for historical data.
- **Acceptance criteria:**
  - API contract remains unchanged.
  - Read latency/cost improves vs phase 1 for large conversations.
  - Index consistency checks pass.
- **Dependencies:** MGL-002, MGL-004, MGL-016.

---

## Suggested milestone sequencing

### Milestone 1 (MVP)
- MGL-001 → MGL-004
- MGL-005 → MGL-008
- MGL-012
- MGL-015

### Milestone 2 (Polish + trust)
- MGL-009
- MGL-010, MGL-011
- MGL-013, MGL-014
- MGL-016

### Milestone 3 (Scale)
- MGL-017

