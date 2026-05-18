# Newsfeed Draft Posts — Implementation Tickets

This backlog translates the draft-post feature request into concrete tickets that address a production-ready implementation (not just local-only drafts), including API contracts, persistence, UX, and rollout.

## Conventions

- Priority: `P0` (must-have), `P1` (important), `P2` (nice-to-have)
- Size: `S` (~0.5–1 day), `M` (~1–3 days), `L` (~3–5 days)
- Type: `Backend`, `Frontend`, `API`, `Data`, `Security`, `QA`, `Ops`

---

## Epic DRAFT-A — Product + Contract Definition

### NFD-001 — Finalize draft post scope and UX behaviors
- **Status:** ✅ Implemented in `docs/newsfeed-draft-post-scope.md`
- **Type:** API / Frontend
- **Priority:** P0
- **Size:** S
- **Description:** Define canonical draft behavior so implementation is predictable across clients.
- **Deliverables:**
  - Decision doc covering: manual save vs autosave, draft limits, ordering, edit semantics, and draft-to-publish flow.
  - Error/empty/loading states for draft list panel.
- **Acceptance criteria:**
  - Product sign-off on edge cases (empty body + attachments, lock-price drafts, unsaved changes).
  - UX spec includes create, load, overwrite/update, and delete draft interactions.
- **Dependencies:** none

### NFD-002 — Add draft entities to API contract
- **Status:** ✅ Implemented via draft DTO contract models and `docs/newsfeed-draft-post-api-contract.md`
- **Type:** API / Backend
- **Priority:** P0
- **Size:** M
- **Description:** Extend newsfeed contract with first-class draft resources.
- **Deliverables:**
  - DTOs for `DraftPost`, `CreateDraftPostRequest`, `UpdateDraftPostRequest`, list response with pagination.
  - Contract examples for rich/plain/markdown and attachment references.
- **Acceptance criteria:**
  - Contract covers all composer fields currently used for publish.
  - Backward compatibility documented for clients without draft support.
- **Dependencies:** NFD-001

---

## Epic DRAFT-B — Backend Persistence + Endpoints

### NFD-101 — Add draft storage model and indexes
- **Status:** ✅ Implemented with draft key/index helpers + contract tests (`tests/test_newsfeed_draft_storage_contract.py`)
- **Type:** Backend / Data
- **Priority:** P0
- **Size:** M
- **Description:** Introduce durable storage for per-user draft posts with efficient list/sort.
- **Deliverables:**
  - New item schema (e.g., `DRAFT#<draft_id>`) including timestamps, author, payload, and status.
  - Index/query strategy for “my drafts ordered by updated_at desc”.
- **Acceptance criteria:**
  - Draft fetch is O(log n) / indexed and supports pagination.
  - Draft rows are isolated by user and inaccessible cross-user.
- **Dependencies:** NFD-002

### NFD-102 — Implement draft CRUD endpoints
- **Status:** ✅ Implemented in `app/routers/newsfeed.py` (`POST/GET/PATCH/DELETE /posts/drafts*`)
- **Type:** Backend / API
- **Priority:** P0
- **Size:** L
- **Description:** Provide server endpoints for create/list/get/update/delete draft posts.
- **Deliverables:**
  - `POST /posts/drafts`
  - `GET /posts/drafts`
  - `GET /posts/drafts/{draft_id}`
  - `PATCH /posts/drafts/{draft_id}`
  - `DELETE /posts/drafts/{draft_id}`
- **Acceptance criteria:**
  - Auth + ownership checks enforced on all routes.
  - Validation parity with publish payload shape (where relevant).
  - Deterministic 4xx errors for invalid/foreign draft ids.
- **Dependencies:** NFD-101

### NFD-103 — Add publish-from-draft endpoint semantics
- **Status:** ✅ Implemented in `app/routers/newsfeed.py` (`POST /posts/drafts/{draft_id}/publish`)
- **Type:** Backend / API
- **Priority:** P0
- **Size:** M
- **Description:** Allow converting a draft into a published post atomically.
- **Deliverables:**
  - Endpoint: `POST /posts/drafts/{draft_id}/publish`.
  - Behavior option: delete draft on success (default) with optional keep-copy flag.
- **Acceptance criteria:**
  - Publish uses existing post creation pipeline and metering/moderation hooks.
  - Failure does not create partial post or corrupt draft.
- **Dependencies:** NFD-102

### NFD-104 — Draft quotas and retention policy
- **Status:** ✅ Implemented via configurable quota/payload/TTL policy in `app/routers/newsfeed.py`
- **Type:** Backend / Ops
- **Priority:** P1
- **Size:** S
- **Description:** Prevent unbounded growth and clarify lifecycle.
- **Deliverables:**
  - Per-user maximum drafts (e.g., 50) and payload size constraints.
  - Optional TTL/retention policy and admin override settings.
- **Acceptance criteria:**
  - Quota enforcement returns typed error usable by UI.
  - Policy is configurable and documented.
- **Dependencies:** NFD-101

---

## Epic DRAFT-C — Frontend UX + Integration

### NFD-201 — Add typed client endpoints for draft API
- **Status:** ✅ Implemented in `frontend/src/api/endpoints/newsfeed.ts` + `newsfeed.drafts.test.ts`
- **Type:** Frontend / API
- **Priority:** P0
- **Size:** S
- **Description:** Add draft API functions and types in frontend endpoint layer.
- **Deliverables:**
  - `createDraftPost`, `listDraftPosts`, `getDraftPost`, `updateDraftPost`, `deleteDraftPost`, `publishDraftPost`.
  - Types in `frontend/src/api/types.ts`.
- **Acceptance criteria:**
  - All functions typed and covered by unit tests/mocks.
- **Dependencies:** NFD-002, NFD-102, NFD-103

### NFD-202 — Replace local-only drafts with server-backed draft panel
- **Status:** ✅ Implemented in `frontend/src/pages/feed/CreatePost.tsx` with React Query draft API wiring
- **Type:** Frontend
- **Priority:** P0
- **Size:** M
- **Description:** Implement draft list UI backed by query/mutation APIs instead of only localStorage.
- **Deliverables:**
  - “Save draft” action persists to backend.
  - “Saved drafts” section loads from backend with loading/empty/error states.
  - “Load” and “Remove” operations wired to server.
- **Acceptance criteria:**
  - Drafts survive logout/login and are visible across devices.
  - UI remains responsive with optimistic or skeleton states.
- **Dependencies:** NFD-201

### NFD-203 — Add update-existing-draft flow
- **Status:** ✅ Implemented in `CreatePost.tsx` (save-changes mode + unsaved-change confirmation)
- **Type:** Frontend
- **Priority:** P1
- **Size:** M
- **Description:** Support editing an already loaded draft and saving back to same draft id.
- **Deliverables:**
  - “Save changes” state when editing a loaded draft.
  - Dirty-state indicator and overwrite confirmation when switching drafts.
- **Acceptance criteria:**
  - Users can repeatedly edit and save one draft without creating duplicates.
  - Unsaved-change warnings prevent accidental loss.
- **Dependencies:** NFD-202

### NFD-204 — Optional autosave for in-progress drafts
- **Status:** ✅ Implemented in `CreatePost.tsx` (debounced autosave status + retry/backoff)
- **Type:** Frontend
- **Priority:** P2
- **Size:** M
- **Description:** Autosave draft every N seconds after debounced changes.
- **Deliverables:**
  - Debounced autosave + visible “Saved just now” status.
  - Retry/backoff handling for transient API errors.
- **Acceptance criteria:**
  - No excessive request bursts during typing.
  - Autosave never publishes content.
- **Dependencies:** NFD-203

---

## Epic DRAFT-D — Attachments, Validation, and Security

### NFD-301 — Validate draft payload parity with composer fields
- **Status:** ✅ Implemented in `newsfeed.py` (field validation + normalization for draft save/update)
- **Type:** Backend / Security
- **Priority:** P0
- **Size:** S
- **Description:** Ensure draft payload shape/limits align with publish constraints.
- **Deliverables:**
  - Field-level validation for body formats, lock price, image/file references.
  - Sanitization/normalization on draft save where needed.
- **Acceptance criteria:**
  - Invalid payloads are rejected with actionable validation messages.
- **Dependencies:** NFD-102

### NFD-302 — Attachment reference integrity for drafts
- **Status:** ✅ Implemented in backend+composer (save/publish ownership checks + missing-file load fallback)
- **Type:** Backend / Frontend
- **Priority:** P1
- **Size:** M
- **Description:** Prevent stale or unauthorized file references from being loaded/published from drafts.
- **Deliverables:**
  - Ownership checks on file paths and image URLs on save/publish.
  - UI fallback for missing/deleted attachments in loaded drafts.
- **Acceptance criteria:**
  - Publishing a draft with invalid attachments fails safely and clearly.
- **Dependencies:** NFD-103, NFD-202

---

## Epic DRAFT-E — Migration, Telemetry, and Rollout

### NFD-401 — LocalStorage compatibility migration
- **Status:** ✅ Implemented in `CreatePost.tsx` (one-time importer + cleanup + user toast messaging)
- **Type:** Frontend / Data
- **Priority:** P1
- **Size:** S
- **Description:** Smoothly migrate existing local-only drafts into server-backed drafts.
- **Deliverables:**
  - One-time importer reading old localStorage keys and creating server drafts.
  - Post-import cleanup strategy and user messaging.
- **Acceptance criteria:**
  - Existing local drafts are not silently lost during upgrade.
- **Dependencies:** NFD-202

### NFD-402 — Instrument draft lifecycle telemetry
- **Status:** ✅ Implemented with backend+frontend draft lifecycle telemetry events and ops thresholds
- **Type:** Frontend / Backend / Ops
- **Priority:** P1
- **Size:** S
- **Description:** Add observability for draft feature adoption and failures.
- **Deliverables:**
  - Events: save_success/fail, load_success/fail, delete_success/fail, publish_from_draft.
  - Dashboard counters and error-rate alert thresholds.
  - Suggested alert thresholds:
    - `save_fail / (save_success + save_fail) > 5%` over 15 minutes
    - `load_fail / (load_success + load_fail) > 3%` over 15 minutes
    - `delete_fail / (delete_success + delete_fail) > 2%` over 15 minutes
    - `publish_from_draft{outcome=\"fail\"} > 1%` over 30 minutes
- **Acceptance criteria:**
  - Product can track draft usage funnel and failure hotspots.
- **Dependencies:** NFD-202, NFD-103

### NFD-403 — Feature flag + staged rollout
- **Status:** ✅ Implemented with backend+frontend draft feature flags and cohort overrides
- **Type:** Ops / Frontend / Backend
- **Priority:** P0
- **Size:** S
- **Description:** Gate draft functionality for safe incremental rollout.
- **Deliverables:**
  - Feature flag at UI and API layers.
  - Rollout checklist with pilot cohort, metrics, and rollback plan.
- **Rollout checklist (implemented guidance):**
  1. Enable `NEWSFEED_DRAFTS_ENABLED=true` in staging; keep production off or cohort-only.
  2. Add pilot cohort via `NEWSFEED_DRAFTS_ENABLED_USER_IDS`.
  3. Monitor NFD-402 telemetry fail-rate thresholds for 24h.
  4. Expand cohort gradually; keep rollback path via `NEWSFEED_DRAFTS_DISABLED_USER_IDS` or global disable.
- **Acceptance criteria:**
  - Draft endpoints/UI can be enabled per environment/user cohort.
- **Dependencies:** NFD-102, NFD-202

---

## Epic DRAFT-F — Testing and Quality

### NFD-501 — Backend tests for draft CRUD/publish semantics
- **Status:** ✅ Implemented with deterministic route-level unit coverage in `test_newsfeed_draft_storage_contract.py`
- **Type:** QA / Backend
- **Priority:** P0
- **Size:** M
- **Description:** Add unit/integration tests for draft APIs and ownership validation.
- **Deliverables:**
  - Coverage for create/list/get/update/delete and publish-from-draft.
  - Negative tests for authz, invalid payload, quota, and missing attachments.
- **Acceptance criteria:**
  - CI includes deterministic coverage for all draft routes.
- **Dependencies:** NFD-102, NFD-103, NFD-301

### NFD-502 — Frontend tests for composer draft UX
- **Status:** ✅ Implemented with expanded `CreatePost.drafts.test.tsx` coverage including cross-session publish flow
- **Type:** QA / Frontend
- **Priority:** P0
- **Size:** M
- **Description:** Expand component/e2e tests around draft controls and edge cases.
- **Deliverables:**
  - Component tests: save/load/remove/update, error states, stale data handling.
  - E2E: create draft on one session, load on another, publish from draft.
- **Acceptance criteria:**
  - Tests prove multi-device/server-persistence behavior (not local-only).
- **Dependencies:** NFD-202, NFD-203

### NFD-503 — Regression tests for publish flow parity
- **Status:** ✅ Implemented with publish-from-draft parity assertions for media/lock metadata
- **Type:** QA
- **Priority:** P1
- **Size:** S
- **Description:** Verify publishing from draft matches direct publish output.
- **Deliverables:**
  - Contract-level assertions for resulting post shape/metadata.
  - Checks for lock/tip/media fields after draft publish.
- **Acceptance criteria:**
  - No behavior regressions between draft publish and standard post publish.
- **Dependencies:** NFD-103

---

## Suggested Delivery Order (MVP)

1. `NFD-001` → `NFD-002` → `NFD-101` → `NFD-102`
2. `NFD-201` → `NFD-202`
3. `NFD-103` + `NFD-501` + `NFD-502`
4. Roll out behind `NFD-403`

## Stretch / Follow-up

- `NFD-203` (update-existing draft UX)
- `NFD-204` (autosave)
- `NFD-401` (localStorage import)
- `NFD-402` (advanced telemetry)
