# Messaging frontend/backend contract drift investigation and fix plan

## Scope

This plan focuses on contract mismatches between:

- `frontend/src/api/endpoints/messaging.ts`
- `frontend/src/api/types.ts`
- `app/routers/messaging.py`

The goal is to eliminate runtime shape drift and move to an API-first workflow.

---

## Investigation findings (validated mismatches)

| Area | Frontend currently sends/expects | Backend currently expects/returns | Risk |
|---|---|---|---|
| Send text message request | `SendTextMessageReq` uses `body` | `SendTextMessageIn` requires `text` | Message send failures / dropped content |
| Start DM request | `StartConversationReq` uses `participant_id` | `StartConversationIn` requires `participant_ids: List[str]` | Conversation creation failures |
| Mark read request | sends `{ last_read_message_id }` | `MarkReadIn` requires `{ last_read_at }` | Read state not updated |
| Mute request | sends `{ muted: boolean }` | `MuteIn` requires `{ muted_until: int }` | Mute semantics broken |
| Edit message request | sends `{ body: string }` | `EditMessageIn` requires `{ text: string }` | Edit request rejected |
| Message response shape | expects flat fields (`body`, `image_url`, `file_url`) | `MessageOut` returns `text`, nested `image`, nested `file` | Rendering bugs / undefined fields |

---

## Root causes

1. **Handwritten TS API types/endpoints drifted from server models** over time.
2. **No CI contract check** verifies frontend typings against FastAPI OpenAPI.
3. **No compatibility window strategy** when changing request/response fields.

---

## Remediation strategy

### Phase 0 — Contain risk (1–2 days)

1. Define a canonical contract source as FastAPI OpenAPI (`/docs/swagger.json` in repo).
2. Add a temporary drift checklist to PR template for any messaging endpoint change.
3. Add focused integration tests for the 5 high-risk requests (send/start/read/mute/edit).

**Deliverable:** failing tests that reproduce current drift and guard regressions.

### Phase 1 — Restore compatibility quickly (2–4 days)

Implement server-side tolerant parsing for one release window while frontend is updated:

- Accept aliases in request models (e.g., allow `body` as alias for `text`).
- Accept single `participant_id` and normalize to `participant_ids`.
- Accept `last_read_message_id` only if resolvable to timestamp; otherwise reject with clear 422 detail.
- Accept `muted: boolean` by converting `true -> now + default_mute_window`, `false -> 0`.
- Accept `body` alias for edits.

**Important:** keep canonical response contract unchanged; compatibility applies to input parsing only.

**Deliverable:** old + new client payloads both work, with deprecation warnings in logs.

### Phase 2 — Align frontend to canonical backend schema (2–3 days)

Update frontend messaging client/types to canonical fields:

- `SendTextMessageReq` => `{ text, reply_to_message_id?, preview? }`
- `StartConversationReq` => `{ participant_ids: string[], type?: "dm" | "group" }`
- `markRead` => `{ last_read_at }` (calculated from selected message timestamp)
- `muteConversation` => `{ muted_until }`
- `editMessage` => `{ text }`
- `Message` UI model updated to server output (`text`, `image`, `file`, etc.) with adapter layer for UI convenience.

**Deliverable:** frontend no longer relies on drifted field names.

### Phase 3 — Move to API-first generation (3–5 days)

1. Generate TS API client/types from backend OpenAPI as build artifact.
2. Replace handwritten messaging endpoint/type definitions with generated equivalents.
3. Add CI check that fails if generated artifacts are stale.

**Deliverable:** drift becomes mechanically difficult to reintroduce.

### Phase 4 — Remove temporary compatibility (1 release later)

1. Remove alias handling and deprecated payload support in backend.
2. Keep migration notes in changelog.
3. Keep integration tests for canonical payloads only.

**Deliverable:** single clean contract, no legacy branches.

---

## Work breakdown by file area

### Backend (`app/routers/messaging.py`)

- Add request alias compatibility (Phase 1 only).
- Add explicit validation errors for ambiguous fields.
- Add deprecation logging for legacy payload keys.

### Frontend API layer (`frontend/src/api/endpoints/messaging.ts`, `frontend/src/api/types.ts`)

- Replace drifted request/response types with canonical schema.
- Introduce adapter helpers where UI expects flattened fields.

### Tests

- Backend: extend `tests/test_messaging_routes.py` for alias + canonical acceptance (Phase 1) and canonical-only behavior (Phase 4).
- Frontend: add contract tests around serialization/parsing of messaging payloads.

---

## Acceptance criteria

1. Send/start/read/mute/edit flows pass end-to-end with canonical payloads.
2. Frontend uses only canonical fields in code.
3. Generated API artifacts are checked in CI and kept up to date.
4. No new handwritten messaging type files diverge from OpenAPI.

---

## Suggested implementation order

1. Phase 0 tests first.
2. Phase 1 backend compatibility shim.
3. Phase 2 frontend migration.
4. Phase 3 generated client rollout.
5. Phase 4 compatibility removal.

This order minimizes production risk while quickly restoring correctness.
